// Package truffler is a full reimplementation of trufflehog v3's secret detection
// engine, written from scratch to avoid the AGPL-3.0 license.
//
// Source reference: truffleHog v3 (AGPL-3.0): https://github.com/trufflesecurity/trufflehog
// This module does NOT copy trufflehog source. It reimplements the same algorithm:
//  1. Scan content line-by-line with a library of named regex detectors
//  2. Apply Shannon entropy threshold to reduce false positives
//  3. Extract surrounding context (line number, surrounding text)
//  4. Classify by detector rule (credential type, severity)
//
// The detector patterns in this module are independently authored based on
// publicly documented secret formats (AWS docs, GitHub docs, Stripe docs, etc.),
// NOT copied from trufflehog's detector sources.
//
// What is implemented:
//   - Detector struct with name, regex, entropy threshold, and severity
//   - 45+ high-signal detectors covering AWS, GCP, GitHub, Slack, Stripe, JWT,
//     private keys, API keys, connection strings, OAuth tokens, and more
//   - Shannon entropy calculation (mirrors trufflehog entropy.go)
//   - Line-by-line scanning with surrounding context (mirrors trufflehog lineScanner)
//   - Detector filter by name, tag, or severity
//   - io.LimitReader on every body read                  (dicas.md §5)
//   - log/slog structured observability                  (dicas.md §16)
//   - errgroup.SetLimit bounded fan-out                  (guia-go §9)
//   - context propagation and cancellation               (guia-go §9)
package truffler

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	// maxBodyRead is the memory ceiling per response body — dicas.md §5.
	maxBodyRead = 10 * 1024 * 1024 // 10 MiB

	// defaultTimeout per HTTP request.
	defaultTimeout = 15 * time.Second

	// defaultThreads — errgroup limit for concurrent URL scanning.
	defaultThreads = 10

	// contextLines is the number of lines of surrounding context to capture.
	contextLines = 2

	// defaultEntropyThreshold — minimum Shannon entropy to flag a match.
	// Mirrors trufflehog's default entropy threshold.
	defaultEntropyThreshold = 3.5
)

// ─── Detector (mirrors trufflehog detector interface) ─────────────────────────

// Detector represents a single secret detection rule.
// Mirrors trufflehog's detectors.Detector interface fields.
type Detector struct {
	// Name is the human-readable detector name (e.g. "AWS Access Key").
	Name string

	// Tags are classification labels (e.g. "cloud", "api-key", "private-key").
	Tags []string

	// Pattern is the compiled regex for matching secrets.
	Pattern *regexp.Regexp

	// EntropyThreshold is the minimum Shannon entropy for a match to be flagged.
	// Set to 0 to disable entropy check (e.g. for structured tokens with low entropy).
	EntropyThreshold float64

	// Severity is the default severity for findings from this detector.
	Severity module.Severity

	// Description explains what this detector finds.
	Description string

	// Verify indicates the match should also be checked against a live API.
	// (Not implemented in MVP — reserved for future online verification.)
	Verify bool
}

// ─── Finding detail ──────────────────────────────────────────────────────────

// secretMatch is an internal match result before conversion to module.Finding.
type secretMatch struct {
	detector Detector
	raw      string // matched text (masked for output)
	lineNum  int
	context  string // surrounding lines
	url      string
	entropy  float64
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements module.Module for secret/credential detection.
type Module struct {
	logger    *slog.Logger
	client    *http.Client
	detectors []Detector
}

// New returns a Module with the built-in detector set.
func New() *Module {
	return &Module{
		logger:    slog.Default().With("module", "truffler"),
		client:    defaultClient(),
		detectors: builtinDetectors(),
	}
}

// NewWithClient returns a Module with an injected http.Client (for tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{
		logger:    slog.Default().With("module", "truffler"),
		client:    c,
		detectors: builtinDetectors(),
	}
}

// NewWithDetectors returns a Module with a custom detector set (for tests/extensions).
func NewWithDetectors(detectors []Detector) *Module {
	return &Module{
		logger:    slog.Default().With("module", "truffler"),
		client:    defaultClient(),
		detectors: detectors,
	}
}

// NewWithClientAndDetectors returns a Module with injected client and detectors (for tests).
func NewWithClientAndDetectors(c *http.Client, detectors []Detector) *Module {
	return &Module{
		logger:    slog.Default().With("module", "truffler"),
		client:    c,
		detectors: detectors,
	}
}

// Name satisfies module.Module.
func (m *Module) Name() string { return "truffler" }

// Run satisfies module.Module.
// Input.Target or Input.URLs are URLs to scan for secrets.
// Input.RawContent (if populated) is scanned directly without HTTP fetch.
//
// Options:
//
//	"threads"    — concurrent URL scans (default: 10)
//	"timeout"    — per-request timeout in seconds (default: 15)
//	"detectors"  — comma-separated detector names to run (default: all)
//	"tags"       — comma-separated tag filter (default: all)
//	"min_entropy"— minimum entropy override (default: per-detector setting)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	// Collect targets.
	var targets []string
	if input.Target != "" {
		targets = append(targets, normalizeURL(input.Target))
	}
	for _, u := range input.URLs {
		targets = append(targets, normalizeURL(u))
	}

	// If no URL targets but raw content is provided, scan it directly.
	if len(targets) == 0 && input.RawContent != "" {
		return m.scanContent(ctx, input.RawContent, "raw-content", input.Options)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("truffler: no target provided")
	}

	// Per-run timeout.
	if ts, ok := input.Options["timeout"]; ok {
		if secs := atoi(ts, 15); secs > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(secs)*time.Second)
			defer cancel()
		}
	}

	// Concurrency.
	threads := defaultThreads
	if t, ok := input.Options["threads"]; ok {
		if n := atoi(t, defaultThreads); n > 0 {
			threads = n
		}
	}

	eg, gctx := errgroup.WithContext(ctx)
	eg.SetLimit(threads)

	findingsCh := make(chan module.Finding, 64)

	for _, target := range targets {
		target := target
		eg.Go(func() error {
			content, err := m.fetchContent(gctx, target)
			if err != nil {
				m.logger.WarnContext(gctx, "fetch error", "url", target, "err", err)
				return nil
			}
			fs, err := m.scanContent(gctx, content, target, input.Options)
			if err != nil {
				m.logger.WarnContext(gctx, "scan error", "url", target, "err", err)
				return nil
			}
			for _, f := range fs {
				select {
				case findingsCh <- f:
				case <-gctx.Done():
					return nil
				}
			}
			return nil
		})
	}

	go func() {
		_ = eg.Wait()
		close(findingsCh)
	}()

	var findings []module.Finding
	for f := range findingsCh {
		findings = append(findings, f)
	}

	return findings, eg.Wait()
}

// ─── Core scan ───────────────────────────────────────────────────────────────

// scanContent scans a text content string with all active detectors.
// Mirrors trufflehog's engine.go scan loop.
func (m *Module) scanContent(ctx context.Context, content, source string, opts map[string]string) ([]module.Finding, error) {
	// Build active detector set from options.
	active := m.filterDetectors(opts)

	// Build entropy override.
	minEntropy := -1.0
	if me, ok := opts["min_entropy"]; ok {
		if v := atof(me); v >= 0 {
			minEntropy = v
		}
	}

	// Split content into lines for context capture.
	lines := strings.Split(content, "\n")

	m.logger.InfoContext(ctx, "scanning content",
		"source", source,
		"lines", len(lines),
		"detectors", len(active),
	)

	var findings []module.Finding

	for _, det := range active {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Run detector against full content for efficiency.
		allMatches := det.Pattern.FindAllStringIndex(content, -1)
		if len(allMatches) == 0 {
			continue
		}

		for _, loc := range allMatches {
			matched := content[loc[0]:loc[1]]

			// Entropy check — mirrors trufflehog entropy filter.
			threshold := det.EntropyThreshold
			if minEntropy >= 0 {
				threshold = minEntropy
			}
			entropy := shannonEntropy(matched)
			if threshold > 0 && entropy < threshold {
				continue
			}

			// Find the line number for this match.
			lineNum := countNewlines(content[:loc[0]]) + 1

			// Extract surrounding context lines — mirrors trufflehog context extraction.
			ctxText := extractContext(lines, lineNum-1, contextLines)

			sm := secretMatch{
				detector: det,
				raw:      matched,
				lineNum:  lineNum,
				context:  ctxText,
				url:      source,
				entropy:  entropy,
			}

			findings = append(findings, sm.toFinding())

			m.logger.InfoContext(ctx, "secret detected",
				"detector", det.Name,
				"source", source,
				"line", lineNum,
				"entropy", fmt.Sprintf("%.2f", entropy),
			)
		}
	}

	return findings, nil
}

// toFinding converts an internal secretMatch to a module.Finding.
func (sm secretMatch) toFinding() module.Finding {
	// Mask the secret value — show only first 6 chars + ***.
	masked := maskSecret(sm.raw)

	detail := fmt.Sprintf("Secret detected by '%s' at line %d in %s: %s",
		sm.detector.Name, sm.lineNum, sm.url, masked)

	return module.Finding{
		Type:     "secret",
		Severity: sm.detector.Severity,
		URL:      sm.url,
		Detail:   detail,
		Extra: map[string]string{
			"detector":    sm.detector.Name,
			"description": sm.detector.Description,
			"line":        fmt.Sprintf("%d", sm.lineNum),
			"entropy":     fmt.Sprintf("%.2f", sm.entropy),
			"masked":      masked,
			"context":     sm.context,
			"tags":        strings.Join(sm.detector.Tags, ","),
			"confidence":  sm.confidenceScore(),
		},
	}
}

// confidenceScore maps Shannon entropy → confidence per dicas.md §4.
// High entropy (>4.5) = very likely real credential → 0.95.
// Medium entropy (3.5–4.5) = above threshold but borderline → 0.80.
// Structured tokens (entropy == 0, e.g. JWT header.payload.sig) → 0.90.
func (sm secretMatch) confidenceScore() string {
	switch {
	case sm.entropy == 0:
		return "0.90" // structured token pattern — deterministic match
	case sm.entropy >= 4.5:
		return "0.95"
	case sm.entropy >= 4.0:
		return "0.88"
	case sm.entropy >= 3.5:
		return "0.80"
	default:
		return "0.75"
	}
}

// ─── Detector filtering ──────────────────────────────────────────────────────

// filterDetectors returns the subset of detectors to run based on options.
func (m *Module) filterDetectors(opts map[string]string) []Detector {
	// Name filter.
	nameFilter := parseCSV(opts["detectors"])
	// Tag filter.
	tagFilter := parseCSV(opts["tags"])

	if len(nameFilter) == 0 && len(tagFilter) == 0 {
		return m.detectors
	}

	var out []Detector
	for _, d := range m.detectors {
		// Name filter.
		if len(nameFilter) > 0 {
			found := false
			for _, name := range nameFilter {
				if strings.EqualFold(d.Name, name) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		// Tag filter.
		if len(tagFilter) > 0 {
			matched := false
			for _, tag := range tagFilter {
				for _, dtag := range d.Tags {
					if strings.EqualFold(dtag, tag) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				continue
			}
		}
		out = append(out, d)
	}
	return out
}

// ─── Entropy (mirrors trufflehog entropy.go) ─────────────────────────────────

// shannonEntropy calculates the Shannon entropy of a string.
// Mirrors trufflehog pkg/common/entropy.go ShannonEntropy().
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// ─── Context extraction ──────────────────────────────────────────────────────

// extractContext returns surrounding lines around lineIdx (0-based).
// Mirrors trufflehog's context window extraction.
func extractContext(lines []string, lineIdx, window int) string {
	start := lineIdx - window
	if start < 0 {
		start = 0
	}
	end := lineIdx + window + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

// countNewlines counts the number of '\n' characters in s.
func countNewlines(s string) int {
	count := 0
	for _, c := range s {
		if c == '\n' {
			count++
		}
	}
	return count
}

// ─── Secret masking ──────────────────────────────────────────────────────────

// maskSecret masks a secret value for safe logging.
// Shows first 4 characters + "***" + last 4 characters.
// Mirrors trufflehog's redact pattern.
func maskSecret(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "***" + s[len(s)-4:]
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

// fetchContent fetches a URL and returns its body as a string.
func (m *Module) fetchContent(ctx context.Context, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-truffler/1.0)")

	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	return string(body), nil
}

// ─── Utilities ───────────────────────────────────────────────────────────────

func defaultClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
				MinVersion:         tls.VersionTLS10,
			},
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
		},
	}
}

func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "https://" + raw
	}
	return raw
}

func atoi(s string, def int) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return def
	}
	return n
}

func atof(s string) float64 {
	var f float64
	if _, err := fmt.Sscanf(s, "%f", &f); err != nil {
		return -1
	}
	return f
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// mustCompile compiles a regex or panics — used at init time only.
func mustCompile(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}

// ─── Built-in detector library ────────────────────────────────────────────────
// Detectors below are independently authored based on publicly documented
// secret formats. They are NOT copied from trufflehog or any other AGPL source.
//
// Pattern sources:
//   - AWS key formats: https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds.html
//   - GitHub token formats: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github
//   - Stripe key formats: https://stripe.com/docs/keys
//   - Private key PEM formats: IETF RFC 7468
//   - JWT format: RFC 7519
//   - Generic high-entropy patterns: independently derived

func builtinDetectors() []Detector {
	return []Detector{

		// ── Cloud credentials ─────────────────────────────────────────────────

		{
			Name:             "AWS Access Key ID",
			Tags:             []string{"cloud", "aws", "api-key"},
			Pattern:          mustCompile(`(?:A3T[A-Z0-9]|AKIA|AGPA|AROA|ASCA|ASIA)[A-Z0-9]{16}`),
			EntropyThreshold: 3.0,
			Severity:         module.SeverityCritical,
			Description:      "AWS Access Key ID — grants programmatic access to AWS services",
		},
		{
			Name:             "AWS Secret Access Key",
			Tags:             []string{"cloud", "aws", "secret-key"},
			Pattern:          mustCompile(`(?i)(?:aws_secret|aws_secret_access_key|secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+]{40})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityCritical,
			Description:      "AWS Secret Access Key — paired with Access Key ID for AWS API auth",
		},
		{
			Name:             "AWS Session Token",
			Tags:             []string{"cloud", "aws", "session-token"},
			Pattern:          mustCompile(`(?i)aws_session_token\s*[=:]\s*["']?([A-Za-z0-9/+=]{100,})["']?`),
			EntropyThreshold: 4.5,
			Severity:         module.SeverityCritical,
			Description:      "AWS Session Token — temporary credential from STS",
		},
		{
			Name:             "GCP Service Account Key",
			Tags:             []string{"cloud", "gcp", "private-key"},
			Pattern:          mustCompile(`"type"\s*:\s*"service_account"`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "GCP Service Account JSON key file",
		},
		{
			Name:             "Azure Client Secret",
			Tags:             []string{"cloud", "azure", "secret-key"},
			Pattern:          mustCompile(`(?i)(?:client_secret|azure_client_secret)\s*[=:]\s*["']?([A-Za-z0-9~._-]{34,})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityCritical,
			Description:      "Azure Active Directory client secret",
		},

		// ── Source control ────────────────────────────────────────────────────

		{
			Name:             "GitHub Personal Access Token (classic)",
			Tags:             []string{"vcs", "github", "api-token"},
			Pattern:          mustCompile(`ghp_[A-Za-z0-9]{36}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "GitHub Personal Access Token (classic) — full repo access",
		},
		{
			Name:             "GitHub OAuth App Token",
			Tags:             []string{"vcs", "github", "oauth"},
			Pattern:          mustCompile(`gho_[A-Za-z0-9]{36}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "GitHub OAuth App access token",
		},
		{
			Name:             "GitHub App Token",
			Tags:             []string{"vcs", "github", "app-token"},
			Pattern:          mustCompile(`(?:ghs_|ghu_)[A-Za-z0-9]{36}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "GitHub App installation or user-to-server token",
		},
		{
			Name:             "GitHub Fine-Grained PAT",
			Tags:             []string{"vcs", "github", "api-token"},
			Pattern:          mustCompile(`github_pat_[A-Za-z0-9_]{82}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "GitHub Fine-Grained Personal Access Token",
		},
		{
			Name:             "GitLab Personal Access Token",
			Tags:             []string{"vcs", "gitlab", "api-token"},
			Pattern:          mustCompile(`glpat-[A-Za-z0-9_-]{20}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "GitLab Personal Access Token",
		},

		// ── Payment ──────────────────────────────────────────────────────────

		{
			Name:             "Stripe Secret Key",
			Tags:             []string{"payment", "stripe", "secret-key"},
			Pattern:          mustCompile(`sk_live_[A-Za-z0-9]{24,}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "Stripe live secret key — full API access",
		},
		{
			Name:             "Stripe Restricted Key",
			Tags:             []string{"payment", "stripe", "api-key"},
			Pattern:          mustCompile(`rk_live_[A-Za-z0-9]{24,}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Stripe restricted key",
		},
		{
			Name:             "PayPal Client Secret",
			Tags:             []string{"payment", "paypal", "secret-key"},
			Pattern:          mustCompile(`(?i)(?:paypal_secret|paypal_client_secret)\s*[=:]\s*["']?([A-Za-z0-9_-]{40,})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityCritical,
			Description:      "PayPal OAuth client secret",
		},

		// ── Messaging / Collaboration ─────────────────────────────────────────

		{
			Name:             "Slack Bot Token",
			Tags:             []string{"messaging", "slack", "api-token"},
			Pattern:          mustCompile(`xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Slack Bot User OAuth Token",
		},
		{
			Name:             "Slack User Token",
			Tags:             []string{"messaging", "slack", "api-token"},
			Pattern:          mustCompile(`xoxp-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]+`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Slack User OAuth Token",
		},
		{
			Name:             "Slack Webhook URL",
			Tags:             []string{"messaging", "slack", "webhook"},
			Pattern:          mustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`),
			EntropyThreshold: 0,
			Severity:         module.SeverityHigh,
			Description:      "Slack Incoming Webhook URL",
		},
		{
			Name:             "Discord Bot Token",
			Tags:             []string{"messaging", "discord", "api-token"},
			Pattern:          mustCompile(`[MN][A-Za-z0-9]{23}\.[\w-]{6}\.[\w-]{27,}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Discord Bot Token",
		},
		{
			Name:             "Telegram Bot Token",
			Tags:             []string{"messaging", "telegram", "api-token"},
			Pattern:          mustCompile(`[0-9]{8,10}:[A-Za-z0-9_-]{35}`),
			EntropyThreshold: 3.0,
			Severity:         module.SeverityHigh,
			Description:      "Telegram Bot API Token",
		},

		// ── Private keys (PEM) ───────────────────────────────────────────────

		{
			Name:             "RSA Private Key",
			Tags:             []string{"crypto", "private-key", "rsa"},
			Pattern:          mustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "RSA Private Key (PKCS#1 PEM format)",
		},
		{
			Name:             "EC Private Key",
			Tags:             []string{"crypto", "private-key", "ec"},
			Pattern:          mustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "Elliptic Curve Private Key (SEC1 PEM format)",
		},
		{
			Name:             "PKCS8 Private Key",
			Tags:             []string{"crypto", "private-key"},
			Pattern:          mustCompile(`-----BEGIN PRIVATE KEY-----`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "Generic private key (PKCS#8 PEM format)",
		},
		{
			Name:             "OpenSSH Private Key",
			Tags:             []string{"crypto", "private-key", "ssh"},
			Pattern:          mustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "OpenSSH private key",
		},
		{
			Name:             "PGP Private Key",
			Tags:             []string{"crypto", "private-key", "pgp"},
			Pattern:          mustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "PGP/GPG Private Key Block",
		},

		// ── JSON Web Tokens ──────────────────────────────────────────────────

		{
			Name:             "JSON Web Token",
			Tags:             []string{"auth", "jwt"},
			Pattern:          mustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.+/=-]+`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityMedium,
			Description:      "JSON Web Token (JWT) — may contain sensitive claims",
		},

		// ── Database connection strings ───────────────────────────────────────

		{
			Name:             "Database Connection String (generic)",
			Tags:             []string{"database", "connection-string"},
			Pattern:          mustCompile(`(?i)(?:mysql|postgres|mongodb|redis|mssql|oracle):\/\/[^:]+:[^@]+@[^/\s]+`),
			EntropyThreshold: 3.0,
			Severity:         module.SeverityCritical,
			Description:      "Database connection string with embedded credentials",
		},
		{
			Name:             "PostgreSQL DSN",
			Tags:             []string{"database", "postgresql", "connection-string"},
			Pattern:          mustCompile(`(?i)postgres(?:ql)?:\/\/[^:]+:[^@]+@`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "PostgreSQL Data Source Name with credentials",
		},
		{
			Name:             "MySQL DSN",
			Tags:             []string{"database", "mysql", "connection-string"},
			Pattern:          mustCompile(`(?i)mysql:\/\/[^:]+:[^@]+@`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "MySQL Data Source Name with credentials",
		},
		{
			Name:             "Redis URL with Password",
			Tags:             []string{"database", "redis", "connection-string"},
			Pattern:          mustCompile(`redis:\/\/:[^@]+@`),
			EntropyThreshold: 0,
			Severity:         module.SeverityHigh,
			Description:      "Redis URL with embedded password",
		},

		// ── Generic API keys ─────────────────────────────────────────────────

		{
			Name:             "Google API Key",
			Tags:             []string{"cloud", "google", "api-key"},
			Pattern:          mustCompile(`AIza[0-9A-Za-z_-]{35}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Google API Key (Maps, Firebase, etc.)",
		},
		{
			Name:             "Twilio Account SID",
			Tags:             []string{"messaging", "twilio", "api-key"},
			Pattern:          mustCompile(`AC[0-9a-f]{32}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Twilio Account SID",
		},
		{
			Name:             "Twilio Auth Token",
			Tags:             []string{"messaging", "twilio", "secret-key"},
			Pattern:          mustCompile(`(?i)twilio_auth_token\s*[=:]\s*["']?([0-9a-f]{32})["']?`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "Twilio Auth Token — full API access",
		},
		{
			Name:             "SendGrid API Key",
			Tags:             []string{"email", "sendgrid", "api-key"},
			Pattern:          mustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "SendGrid API Key",
		},
		{
			Name:             "Mailgun API Key",
			Tags:             []string{"email", "mailgun", "api-key"},
			Pattern:          mustCompile(`key-[0-9a-zA-Z]{32}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Mailgun API Key",
		},
		{
			Name:             "NPM Access Token",
			Tags:             []string{"devtools", "npm", "api-token"},
			Pattern:          mustCompile(`npm_[A-Za-z0-9]{36}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "NPM Access Token",
		},
		{
			Name:             "PyPI Token",
			Tags:             []string{"devtools", "pypi", "api-token"},
			Pattern:          mustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "PyPI API Token",
		},
		{
			Name:             "Datadog API Key",
			Tags:             []string{"monitoring", "datadog", "api-key"},
			Pattern:          mustCompile(`(?i)datadog[_-]api[_-]key\s*[=:]\s*["']?([A-Za-z0-9]{32,40})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityHigh,
			Description:      "Datadog API Key",
		},
		{
			Name:             "Sentry DSN",
			Tags:             []string{"monitoring", "sentry"},
			Pattern:          mustCompile(`https://[0-9a-f]{32}@[a-z0-9.]+sentry\.io/[0-9]+`),
			EntropyThreshold: 0,
			Severity:         module.SeverityMedium,
			Description:      "Sentry DSN — exposes project ID and error ingestion key",
		},

		// ── Environment / config ──────────────────────────────────────────────

		{
			Name:             "Generic Secret Assignment",
			Tags:             []string{"config", "generic"},
			Pattern:          mustCompile(`(?i)(?:secret|password|passwd|pwd|token|api_key|apikey|access_key|auth_key|auth_token)\s*[=:]\s*["']([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{12,})["']`),
			EntropyThreshold: 3.8,
			Severity:         module.SeverityMedium,
			Description:      "Generic secret/password/token assignment in config or code",
		},
		{
			Name:             ".env File Pattern",
			Tags:             []string{"config", "env-file"},
			Pattern:          mustCompile(`(?i)^(?:export\s+)?(?:SECRET|PASSWORD|PASSWD|TOKEN|KEY|APIKEY|API_KEY)[A-Z0-9_]*\s*=\s*\S+`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityMedium,
			Description:      "Environment variable assignment of a sensitive key in .env file format",
		},

		// ── Bearer tokens ────────────────────────────────────────────────────

		{
			Name:             "Bearer Token in Header",
			Tags:             []string{"auth", "bearer"},
			Pattern:          mustCompile(`(?i)Authorization:\s*Bearer\s+([A-Za-z0-9_-]{20,})`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityMedium,
			Description:      "HTTP Bearer token — may be a live session token",
		},

		// ── HashiCorp Vault ──────────────────────────────────────────────────

		{
			Name:             "HashiCorp Vault Token",
			Tags:             []string{"secrets-manager", "vault", "api-token"},
			Pattern:          mustCompile(`hvs\.[A-Za-z0-9_-]{24,}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "HashiCorp Vault Service Token",
		},

		// ── Docker / Container ───────────────────────────────────────────────

		{
			Name:             "Docker Hub Token",
			Tags:             []string{"devtools", "docker", "api-token"},
			Pattern:          mustCompile(`dckr_pat_[A-Za-z0-9_-]{27}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Docker Hub Personal Access Token",
		},

		// ── Azure ────────────────────────────────────────────────────────────

		{
			Name:             "Azure Connection String",
			Tags:             []string{"cloud", "azure", "connection-string"},
			Pattern:          mustCompile(`DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "Azure Storage Account connection string with account key",
		},
		{
			Name:             "Azure SAS Token",
			Tags:             []string{"cloud", "azure", "api-token"},
			Pattern:          mustCompile(`(?i)(?:sv|se|ss|srt|sp|sig)=[A-Za-z0-9%+/=]{20,}&(?:sv|se|ss|srt|sp|sig)=`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Azure Shared Access Signature (SAS) token",
		},
		{
			Name:             "Azure Client Secret",
			Tags:             []string{"cloud", "azure", "secret-key"},
			Pattern:          mustCompile(`(?i)(?:azure_client_secret|AZURE_CLIENT_SECRET|client_secret)\s*[=:]\s*["']?([A-Za-z0-9~._-]{34,40})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityCritical,
			Description:      "Azure Active Directory client secret",
		},
		{
			Name:             "Azure DevOps PAT",
			Tags:             []string{"cloud", "azure", "vcs", "api-token"},
			Pattern:          mustCompile(`[a-z2-7]{52}AZDO`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "Azure DevOps Personal Access Token",
		},

		// ── GCP ──────────────────────────────────────────────────────────────

		{
			Name:             "GCP Service Account Key",
			Tags:             []string{"cloud", "gcp", "credentials"},
			Pattern:          mustCompile(`"type"\s*:\s*"service_account"[^}]*"private_key_id"\s*:`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "Google Cloud Platform service account JSON key",
		},
		{
			Name:             "GCP OAuth Refresh Token",
			Tags:             []string{"cloud", "gcp", "oauth"},
			Pattern:          mustCompile(`1//0[A-Za-z0-9_-]{43}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "Google OAuth 2.0 refresh token",
		},
		{
			Name:             "Firebase Database URL",
			Tags:             []string{"cloud", "gcp", "firebase"},
			Pattern:          mustCompile(`https://[a-z0-9-]+\.firebaseio\.com`),
			EntropyThreshold: 0,
			Severity:         module.SeverityMedium,
			Description:      "Firebase Realtime Database URL",
		},

		// ── AWS (additional) ─────────────────────────────────────────────────

		{
			Name:             "AWS Secret Access Key",
			Tags:             []string{"cloud", "aws", "secret-key"},
			Pattern:          mustCompile(`(?i)(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+]{40})["']?`),
			EntropyThreshold: 4.2,
			Severity:         module.SeverityCritical,
			Description:      "AWS Secret Access Key in environment variable or config",
		},
		{
			Name:             "AWS Session Token",
			Tags:             []string{"cloud", "aws", "api-token"},
			Pattern:          mustCompile(`FwoGZXIvYXdzE[A-Za-z0-9+/=]{200,}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "AWS Temporary Session Token (STS)",
		},
		{
			Name:             "AWS SNS ARN",
			Tags:             []string{"cloud", "aws", "arn"},
			Pattern:          mustCompile(`arn:aws:sns:[a-z0-9-]+:\d{12}:[a-zA-Z0-9_-]+`),
			EntropyThreshold: 0,
			Severity:         module.SeverityLow,
			Description:      "AWS SNS Topic ARN — may expose account ID",
		},
		{
			Name:             "AWS Account ID",
			Tags:             []string{"cloud", "aws"},
			Pattern:          mustCompile(`(?i)(?:account_id|account-id|accountid)\s*[=:]\s*["']?(\d{12})["']?`),
			EntropyThreshold: 0,
			Severity:         module.SeverityLow,
			Description:      "AWS Account ID — used for ARN construction and phishing",
		},

		// ── CI/CD platforms ───────────────────────────────────────────────────

		{
			Name:             "CircleCI API Token",
			Tags:             []string{"ci-cd", "circleci", "api-token"},
			Pattern:          mustCompile(`(?i)(?:circleci_token|CIRCLE_TOKEN)\s*[=:]\s*["']?([a-f0-9]{40})["']?`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "CircleCI Personal API Token",
		},
		{
			Name:             "Travis CI Token",
			Tags:             []string{"ci-cd", "travis", "api-token"},
			Pattern:          mustCompile(`(?i)travis_?(?:ci_)?token\s*[=:]\s*["']?([A-Za-z0-9_-]{22,})["']?`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Travis CI API Token",
		},
		{
			Name:             "GitHub Actions Token",
			Tags:             []string{"ci-cd", "github", "api-token"},
			Pattern:          mustCompile(`ghs_[A-Za-z0-9]{36}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "GitHub Actions server token",
		},
		{
			Name:             "Jenkins API Token",
			Tags:             []string{"ci-cd", "jenkins", "api-token"},
			Pattern:          mustCompile(`(?i)jenkins[_-]?(?:api[_-]?)?token\s*[=:]\s*["']?([A-Za-z0-9]{34,})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityHigh,
			Description:      "Jenkins API token",
		},

		// ── Communication APIs ────────────────────────────────────────────────

		{
			Name:             "Twilio API Key SID",
			Tags:             []string{"messaging", "twilio", "api-key"},
			Pattern:          mustCompile(`SK[0-9a-f]{32}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Twilio API Key SID",
		},
		{
			Name:             "Mailchimp API Key",
			Tags:             []string{"email", "mailchimp", "api-key"},
			Pattern:          mustCompile(`[0-9a-f]{32}-us\d{1,2}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Mailchimp API Key with datacenter suffix",
		},
		{
			Name:             "AWS SES SMTP Password",
			Tags:             []string{"email", "aws", "smtp"},
			Pattern:          mustCompile(`(?i)(?:ses_smtp|aws_ses)\s*[=:]\s*["']?([A-Za-z0-9/+]{44})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityHigh,
			Description:      "AWS SES SMTP password",
		},
		{
			Name:             "Postmark Server Token",
			Tags:             []string{"email", "postmark", "api-token"},
			Pattern:          mustCompile(`(?i)postmark[_-]?(?:server[_-]?)?token\s*[=:]\s*["']?([A-Za-z0-9-]{36})["']?`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Postmark Server API Token",
		},

		// ── Infrastructure ─────────────────────────────────────────────────────

		{
			Name:             "Terraform Cloud Token",
			Tags:             []string{"infra", "terraform", "api-token"},
			Pattern:          mustCompile(`[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "Terraform Cloud / Terraform Enterprise API token",
		},
		{
			Name:             "Ansible Vault Password",
			Tags:             []string{"infra", "ansible", "secret-key"},
			Pattern:          mustCompile(`\$ANSIBLE_VAULT;\d+\.\d+`),
			EntropyThreshold: 0,
			Severity:         module.SeverityHigh,
			Description:      "Ansible Vault encrypted content header",
		},
		{
			Name:             "Kubernetes Service Account Token",
			Tags:             []string{"infra", "kubernetes", "api-token"},
			Pattern:          mustCompile(`eyJhbGciOiJSUzI1NiIsImtpZCI6`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "Kubernetes service account JWT token (RS256)",
		},
		{
			Name:             "DigitalOcean Personal Access Token",
			Tags:             []string{"cloud", "digitalocean", "api-token"},
			Pattern:          mustCompile(`dop_v1_[a-f0-9]{64}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "DigitalOcean Personal Access Token",
		},
		{
			Name:             "DigitalOcean OAuth Token",
			Tags:             []string{"cloud", "digitalocean", "oauth"},
			Pattern:          mustCompile(`doo_v1_[a-f0-9]{64}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "DigitalOcean OAuth Token",
		},

		// ── Source control ────────────────────────────────────────────────────

		{
			Name:             "Bitbucket App Password",
			Tags:             []string{"vcs", "bitbucket", "api-token"},
			Pattern:          mustCompile(`(?i)bitbucket[_-]?(?:app[_-]?)?(?:password|token)\s*[=:]\s*["']?([A-Za-z0-9]{20,})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityHigh,
			Description:      "Bitbucket App Password",
		},
		{
			Name:             "Sourcegraph Token",
			Tags:             []string{"vcs", "sourcegraph", "api-token"},
			Pattern:          mustCompile(`sgp_(?:local_)?[A-Za-z0-9]{40}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Sourcegraph personal access token",
		},

		// ── Cryptocurrency ───────────────────────────────────────────────────

		{
			Name:             "Ethereum Private Key",
			Tags:             []string{"crypto", "ethereum", "private-key"},
			Pattern:          mustCompile(`(?i)(?:eth_private_key|ethereum_key|PRIVATE_KEY)\s*[=:]\s*["']?0x([a-f0-9]{64})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityCritical,
			Description:      "Ethereum wallet private key",
		},
		{
			Name:             "Ethereum Mnemonic Phrase",
			Tags:             []string{"crypto", "ethereum", "mnemonic"},
			Pattern:          mustCompile(`(?i)(?:mnemonic|seed_phrase|seed phrase)\s*[=:]\s*["']?(\w+(?:\s+\w+){11,23})["']?`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "Cryptocurrency wallet mnemonic / seed phrase",
		},
		{
			Name:             "Infura API Key",
			Tags:             []string{"crypto", "ethereum", "api-key"},
			Pattern:          mustCompile(`(?i)infura[_-]?(?:api[_-]?)?(?:key|project_id)\s*[=:]\s*["']?([a-f0-9]{32})["']?`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Infura Project ID (Ethereum node gateway)",
		},

		// ── SaaS / productivity ────────────────────────────────────────────────

		{
			Name:             "Atlassian API Token",
			Tags:             []string{"saas", "atlassian", "api-token"},
			Pattern:          mustCompile(`(?i)(?:jira|confluence|atlassian)[_-]?(?:api[_-]?)?token\s*[=:]\s*["']?([A-Za-z0-9]{24,})["']?`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Atlassian (Jira/Confluence) API token",
		},
		{
			Name:             "Linear API Key",
			Tags:             []string{"saas", "linear", "api-key"},
			Pattern:          mustCompile(`lin_api_[A-Za-z0-9]{40}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Linear API key",
		},
		{
			Name:             "Notion Integration Token",
			Tags:             []string{"saas", "notion", "api-token"},
			Pattern:          mustCompile(`secret_[A-Za-z0-9]{43}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Notion Integration Token",
		},
		{
			Name:             "Figma Personal Token",
			Tags:             []string{"saas", "figma", "api-token"},
			Pattern:          mustCompile(`(?i)figma[_-]?(?:personal[_-]?)?(?:access[_-]?)?token\s*[=:]\s*["']?([A-Za-z0-9_-]{43,})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityMedium,
			Description:      "Figma Personal Access Token",
		},
		{
			Name:             "Airtable API Key",
			Tags:             []string{"saas", "airtable", "api-key"},
			Pattern:          mustCompile(`(?:pat|key)[A-Za-z0-9]{14}\.[A-Za-z0-9]{64}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Airtable Personal Access Token or legacy API key",
		},
		{
			Name:             "Zendesk Token",
			Tags:             []string{"saas", "zendesk", "api-token"},
			Pattern:          mustCompile(`(?i)zendesk[_-]?(?:api[_-]?)?token\s*[=:]\s*["']?([A-Za-z0-9/]{40,})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityHigh,
			Description:      "Zendesk API token",
		},
		{
			Name:             "HubSpot API Key",
			Tags:             []string{"saas", "hubspot", "api-key"},
			Pattern:          mustCompile(`(?i)(?:hubspot[_-]?(?:api[_-]?)?key|HUBSPOT_KEY)\s*[=:]\s*["']?([A-Za-z0-9-]{36})["']?`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "HubSpot API key",
		},
		{
			Name:             "Shopify Partner Token",
			Tags:             []string{"ecommerce", "shopify", "api-token"},
			Pattern:          mustCompile(`shppa_[A-Za-z0-9]{32}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "Shopify Partner API token",
		},
		{
			Name:             "Shopify Custom App Token",
			Tags:             []string{"ecommerce", "shopify", "api-token"},
			Pattern:          mustCompile(`shpat_[A-Za-z0-9]{32}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "Shopify Custom App access token",
		},
		{
			Name:             "Shopify Shared Secret",
			Tags:             []string{"ecommerce", "shopify", "secret-key"},
			Pattern:          mustCompile(`shpss_[A-Za-z0-9]{32}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Shopify shared secret",
		},
		{
			Name:             "Square Access Token",
			Tags:             []string{"payment", "square", "api-token"},
			Pattern:          mustCompile(`sq0atp-[A-Za-z0-9_-]{22}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityCritical,
			Description:      "Square OAuth access token",
		},
		{
			Name:             "Braintree Access Token",
			Tags:             []string{"payment", "braintree", "api-token"},
			Pattern:          mustCompile(`access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32}`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "Braintree production access token",
		},

		// ── Observability / monitoring ────────────────────────────────────────

		{
			Name:             "Pagerduty Integration Key",
			Tags:             []string{"monitoring", "pagerduty", "api-key"},
			Pattern:          mustCompile(`(?i)pagerduty[_-]?(?:integration[_-]?)?(?:key|token)\s*[=:]\s*["']?([A-Za-z0-9_-]{20,})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityHigh,
			Description:      "PagerDuty integration or API key",
		},
		{
			Name:             "Grafana Service Account Token",
			Tags:             []string{"monitoring", "grafana", "api-token"},
			Pattern:          mustCompile(`glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Grafana Service Account Token",
		},
		{
			Name:             "Splunk HEC Token",
			Tags:             []string{"monitoring", "splunk", "api-token"},
			Pattern:          mustCompile(`(?i)splunk[_-]?(?:hec[_-]?)?token\s*[=:]\s*["']?([A-Za-z0-9-]{36})["']?`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Splunk HTTP Event Collector token",
		},
		{
			Name:             "Elastic Cloud API Key",
			Tags:             []string{"monitoring", "elastic", "api-key"},
			Pattern:          mustCompile(`(?i)elastic[_-]?(?:cloud[_-]?)?(?:api[_-]?)?(?:key|token)\s*[=:]\s*["']?([A-Za-z0-9+/=]{40,})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityHigh,
			Description:      "Elastic Cloud API key",
		},

		// ── Cryptocurrency exchange ────────────────────────────────────────────

		{
			Name:             "Binance API Key",
			Tags:             []string{"crypto", "binance", "api-key"},
			Pattern:          mustCompile(`(?i)binance[_-]?(?:api[_-]?)?key\s*[=:]\s*["']?([A-Za-z0-9]{64})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityCritical,
			Description:      "Binance API key",
		},
		{
			Name:             "Coinbase API Secret",
			Tags:             []string{"crypto", "coinbase", "secret-key"},
			Pattern:          mustCompile(`(?i)coinbase[_-]?(?:api[_-]?)?(?:secret|key)\s*[=:]\s*["']?([A-Za-z0-9/+]{44,})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityCritical,
			Description:      "Coinbase API secret key",
		},

		// ── Cloud expanded ────────────────────────────────────────────────────

		{
			Name:             "Azure Storage Account Key",
			Tags:             []string{"cloud", "azure", "storage"},
			Pattern:          mustCompile(`(?i)(?:azure[_-]?storage[_-]?(?:account[_-]?)?key|accountkey)\s*[=:]\s*["']?([A-Za-z0-9+/=]{88})["']?`),
			EntropyThreshold: 4.5,
			Severity:         module.SeverityCritical,
			Description:      "Azure Storage Account access key",
		},
		{
			Name:             "Azure Cosmos DB Key",
			Tags:             []string{"cloud", "azure", "cosmosdb"},
			Pattern:          mustCompile(`(?i)(?:cosmos[_-]?(?:db[_-]?)?key|documentdb[_-]?key)\s*[=:]\s*["']?([A-Za-z0-9+/=]{88})["']?`),
			EntropyThreshold: 4.5,
			Severity:         module.SeverityCritical,
			Description:      "Azure Cosmos DB / DocumentDB key",
		},
		{
			Name:             "GCP Service Account Indicator",
			Tags:             []string{"cloud", "gcp", "service-account"},
			Pattern:          mustCompile(`"type"\s*:\s*"service_account"`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "GCP service account JSON credential fragment",
		},
		{
			Name:             "GCP API Key",
			Tags:             []string{"cloud", "gcp", "api-key"},
			Pattern:          mustCompile(`AIza[0-9A-Za-z_-]{35}`),
			EntropyThreshold: 0,
			Severity:         module.SeverityHigh,
			Description:      "GCP / Google API key (AIza prefix)",
		},
		{
			Name:             "Firebase Database URL",
			Tags:             []string{"cloud", "firebase"},
			Pattern:          mustCompile(`https://[a-zA-Z0-9-]+\.firebaseio\.com`),
			EntropyThreshold: 0,
			Severity:         module.SeverityMedium,
			Description:      "Firebase Realtime Database URL",
		},
		{
			Name:             "Cloudflare API Token",
			Tags:             []string{"cloud", "cloudflare", "api-token"},
			Pattern:          mustCompile(`(?i)cloudflare[_-]?(?:api[_-]?)?token\s*[=:]\s*["']?([A-Za-z0-9_-]{40})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityHigh,
			Description:      "Cloudflare API token",
		},

		// ── Database connection strings ────────────────────────────────────────

		{
			Name:             "PostgreSQL Connection String",
			Tags:             []string{"database", "postgresql"},
			Pattern:          mustCompile(`postgres(?:ql)?://[^:]+:[^@]+@[^/\s"']+/\S+`),
			EntropyThreshold: 3.0,
			Severity:         module.SeverityHigh,
			Description:      "PostgreSQL connection string with embedded credentials",
		},
		{
			Name:             "MySQL Connection String",
			Tags:             []string{"database", "mysql"},
			Pattern:          mustCompile(`mysql://[^:]+:[^@]+@[^/\s"']+/\S+`),
			EntropyThreshold: 3.0,
			Severity:         module.SeverityHigh,
			Description:      "MySQL connection string with embedded credentials",
		},
		{
			Name:             "MongoDB Atlas Connection String",
			Tags:             []string{"database", "mongodb"},
			Pattern:          mustCompile(`mongodb\+srv://[^:]+:[^@]+@[^/\s"']+`),
			EntropyThreshold: 3.0,
			Severity:         module.SeverityHigh,
			Description:      "MongoDB Atlas SRV connection string with credentials",
		},
		{
			Name:             "Redis URL with Password",
			Tags:             []string{"database", "redis"},
			Pattern:          mustCompile(`redis://:[^@]+@[^\s"']+`),
			EntropyThreshold: 3.0,
			Severity:         module.SeverityHigh,
			Description:      "Redis URL with embedded password",
		},

		// ── Payment / e-commerce ──────────────────────────────────────────────

		{
			Name:             "PayPal Client Secret",
			Tags:             []string{"payment", "paypal"},
			Pattern:          mustCompile(`(?i)paypal[_-]?(?:client[_-]?)?secret\s*[=:]\s*["']?([A-Za-z0-9_-]{80,})["']?`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityCritical,
			Description:      "PayPal OAuth client secret",
		},
		{
			Name:             "Square Access Token",
			Tags:             []string{"payment", "square"},
			Pattern:          mustCompile(`(?:EAAAl|sq0[a-z]+)[A-Za-z0-9_-]{20,}`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityCritical,
			Description:      "Square access token or application secret",
		},
		{
			Name:             "SendGrid API Key",
			Tags:             []string{"email", "sendgrid"},
			Pattern:          mustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityHigh,
			Description:      "SendGrid API key (SG. prefix)",
		},
		{
			Name:             "Mailchimp API Key",
			Tags:             []string{"email", "mailchimp"},
			Pattern:          mustCompile(`[0-9a-f]{32}-us[0-9]+`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Mailchimp API key with datacenter suffix",
		},

		// ── Communications ────────────────────────────────────────────────────

		{
			Name:             "Twilio Auth Token",
			Tags:             []string{"sms", "twilio", "auth-token"},
			Pattern:          mustCompile(`(?i)twilio[_-]?auth[_-]?token\s*[=:]\s*["']?([0-9a-f]{32})["']?`),
			EntropyThreshold: 3.8,
			Severity:         module.SeverityCritical,
			Description:      "Twilio account auth token",
		},
		{
			Name:             "Vonage (Nexmo) API Secret",
			Tags:             []string{"sms", "vonage"},
			Pattern:          mustCompile(`(?i)(?:vonage|nexmo)[_-]?api[_-]?secret\s*[=:]\s*["']?([A-Za-z0-9]{16,})["']?`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Vonage/Nexmo API secret",
		},
		{
			Name:             "Postmark Server Token",
			Tags:             []string{"email", "postmark"},
			Pattern:          mustCompile(`(?i)postmark[_-]?(?:server[_-]?)?token\s*[=:]\s*["']?([0-9a-f-]{36})["']?`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Postmark email service server token",
		},

		// ── Version control / collaboration ───────────────────────────────────

		{
			Name:             "RSA Private Key",
			Tags:             []string{"crypto", "rsa", "private-key"},
			Pattern:          mustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "RSA private key header",
		},
		{
			Name:             "EC Private Key",
			Tags:             []string{"crypto", "ec", "private-key"},
			Pattern:          mustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "Elliptic curve private key header",
		},
		{
			Name:             "PKCS8 Private Key",
			Tags:             []string{"crypto", "pkcs8", "private-key"},
			Pattern:          mustCompile(`-----BEGIN PRIVATE KEY-----`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "PKCS#8 private key header",
		},
		{
			Name:             "GitLab Personal Access Token",
			Tags:             []string{"vcs", "gitlab", "pat"},
			Pattern:          mustCompile(`glpat-[A-Za-z0-9_-]{20}`),
			EntropyThreshold: 0,
			Severity:         module.SeverityHigh,
			Description:      "GitLab personal access token (glpat- prefix)",
		},
		{
			Name:             "npm Publish Token",
			Tags:             []string{"npm", "token"},
			Pattern:          mustCompile(`npm_[A-Za-z0-9]{36}`),
			EntropyThreshold: 0,
			Severity:         module.SeverityHigh,
			Description:      "npm publish token (npm_ prefix)",
		},

		// ── Social / ads ──────────────────────────────────────────────────────

		{
			Name:             "Facebook App Secret",
			Tags:             []string{"social", "facebook"},
			Pattern:          mustCompile(`(?i)facebook[_-]?(?:app[_-]?)?secret\s*[=:]\s*["']?([0-9a-f]{32})["']?`),
			EntropyThreshold: 3.5,
			Severity:         module.SeverityHigh,
			Description:      "Facebook/Meta application secret",
		},
		{
			Name:             "YouTube Data API Key",
			Tags:             []string{"google", "youtube"},
			Pattern:          mustCompile(`(?i)youtube[_-]?api[_-]?key\s*[=:]\s*["']?(AIza[0-9A-Za-z_-]{35})["']?`),
			EntropyThreshold: 0,
			Severity:         module.SeverityHigh,
			Description:      "YouTube Data API key",
		},

		// ── Productivity ──────────────────────────────────────────────────────

		{
			Name:             "Notion Integration Token",
			Tags:             []string{"productivity", "notion"},
			Pattern:          mustCompile(`secret_[A-Za-z0-9]{43}`),
			EntropyThreshold: 4.0,
			Severity:         module.SeverityHigh,
			Description:      "Notion integration token (secret_ prefix)",
		},
		{
			Name:             "Linear API Key",
			Tags:             []string{"productivity", "linear"},
			Pattern:          mustCompile(`lin_api_[A-Za-z0-9]{40}`),
			EntropyThreshold: 0,
			Severity:         module.SeverityHigh,
			Description:      "Linear project management API key",
		},

		// ── Infrastructure / secrets managers ────────────────────────────────

		{
			Name:             "HashiCorp Vault Token",
			Tags:             []string{"secrets", "vault", "hashicorp"},
			Pattern:          mustCompile(`(?i)vault[_-]?token\s*[=:]\s*["']?(s\.[A-Za-z0-9]{24})["']?`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "HashiCorp Vault token (s. prefix)",
		},
		{
			Name:             "Docker Hub Access Token",
			Tags:             []string{"containers", "docker"},
			Pattern:          mustCompile(`dckr_pat_[A-Za-z0-9_-]{24,}`),
			EntropyThreshold: 0,
			Severity:         module.SeverityHigh,
			Description:      "Docker Hub personal access token (dckr_pat_ prefix)",
		},

		// ── PII patterns ─────────────────────────────────────────────────────

		{
			Name:             "US Social Security Number",
			Tags:             []string{"pii", "ssn"},
			Pattern:          mustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "Potential US Social Security Number pattern",
		},
		{
			Name:             "IBAN Bank Account",
			Tags:             []string{"pii", "banking"},
			Pattern:          mustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b`),
			EntropyThreshold: 0,
			Severity:         module.SeverityHigh,
			Description:      "IBAN bank account number",
		},

		// ── AI / ML APIs ──────────────────────────────────────────────────────

		{
			Name:             "OpenAI API Key",
			Tags:             []string{"ai", "openai"},
			Pattern:          mustCompile(`sk-[A-Za-z0-9]{48}`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "OpenAI API key (sk- legacy prefix)",
		},
		{
			Name:             "OpenAI Project API Key",
			Tags:             []string{"ai", "openai"},
			Pattern:          mustCompile(`sk-proj-[A-Za-z0-9_-]{100,}`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "OpenAI Project API key (sk-proj- prefix, new format as of 2024)",
		},
		{
			Name:             "OpenAI Service Account Key",
			Tags:             []string{"ai", "openai"},
			Pattern:          mustCompile(`sk-svcacct-[A-Za-z0-9_-]{100,}`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "OpenAI Service Account API key (sk-svcacct- prefix)",
		},
		{
			Name:             "Anthropic API Key",
			Tags:             []string{"ai", "anthropic"},
			Pattern:          mustCompile(`sk-ant-api[0-9]+-[A-Za-z0-9_-]{95}`),
			EntropyThreshold: 0,
			Severity:         module.SeverityCritical,
			Description:      "Anthropic API key",
		},
		{
			Name:             "Hugging Face API Token",
			Tags:             []string{"ai", "huggingface"},
			Pattern:          mustCompile(`hf_[A-Za-z0-9]{39}`),
			EntropyThreshold: 0,
			Severity:         module.SeverityHigh,
			Description:      "Hugging Face API token (hf_ prefix)",
		},
		{
			Name:             "Replicate API Token",
			Tags:             []string{"ai", "replicate"},
			Pattern:          mustCompile(`r8_[A-Za-z0-9]{40}`),
			EntropyThreshold: 0,
			Severity:         module.SeverityHigh,
			Description:      "Replicate API token (r8_ prefix)",
		},
	}
}
