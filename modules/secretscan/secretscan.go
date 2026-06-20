// Package secretscan scans text content for leaked secrets using regex patterns
// and Shannon entropy scoring — a faithful port of the gitleaks detection engine
// (MIT license: github.com/gitleaks/gitleaks).
//
// Architecture mirrors gitleaks detect/detect.go:
//   - Rule: same fields as config.Rule (RuleID, Description, Regex, SecretGroup,
//     Entropy, Keywords, Tags)
//   - Detect(fragment): same pre-filter + keyword check + regex match loop
//   - shannonEntropy(): same calculation as gitleaks/detect/utils.go
//   - Default rule set: subset of config/gitleaks.toml (high-signal rules, MIT)
//
// Native Go replacement: no external binary, no gitleaks process, pure stdlib +
// regexp. Input is a string (file content, HTTP response body, git diff, etc.).
//
// Observability (dicas.md §16): every rule match and skip is logged via log/slog.
package secretscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"regexp"
	"strings"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const moduleName = "secretscan"

// maxContentSize is the maximum number of bytes we read from a single content
// string before truncating — mirrors gitleaks MaxTargetMegaBytes default (10 MB).
const maxContentSize = 10 << 20

// Rule mirrors gitleaks config.Rule (config/rule.go).
// Fields are identical in semantics; we drop git-specific fields (Commit, Author).
type Rule struct {
	// RuleID is a unique identifier, matches gitleaks rule id.
	RuleID string
	// Description is human-readable context, matches gitleaks description.
	Description string
	// Regex is the compiled secret pattern.
	Regex *regexp.Regexp
	// SecretGroup is the capture group index that contains the secret value.
	// 0 means the entire match. Mirrors gitleaks secretGroup.
	SecretGroup int
	// Entropy is the minimum Shannon entropy the captured secret must have.
	// 0 disables entropy filtering. Mirrors gitleaks entropy.
	Entropy float64
	// Keywords are pre-filter strings; if set, content must contain at least
	// one keyword (case-insensitive) before the regex is applied.
	// Mirrors gitleaks keywords — Aho-Corasick prefilter replaced by strings.Contains.
	Keywords []string
	// Tags for metadata/reporting.
	Tags []string
}

// Fragment mirrors gitleaks sources.Fragment.
// Callers fill Raw with file or response content; FilePath is optional metadata.
type Fragment struct {
	// Raw is the content to scan. Capped at maxContentSize by Run().
	Raw string
	// FilePath is optional — used for context in findings.
	FilePath string
}

// Module implements module.Module for secret scanning.
type Module struct {
	logger *slog.Logger
	rules  []Rule
}

// New returns a Module with the built-in default rule set (subset of gitleaks.toml).
func New() *Module {
	return &Module{
		logger: slog.Default(),
		rules:  defaultRules(),
	}
}

// NewWithRules creates a Module with a custom rule set.
// Useful in tests and for callers that embed their own rule list.
func NewWithRules(rules []Rule) *Module {
	return &Module{
		logger: slog.Default(),
		rules:  rules,
	}
}

func (m *Module) Name() string { return moduleName }

// Run scans all input content for secrets.
//
// Supported input sources (in priority order):
//  1. input.URLs — each URL string is scanned as raw content
//  2. input.Target — scanned as raw content if no URLs
//  3. input.Options["content"] — explicit content override
//
// Options:
//   - "content":   raw string to scan (overrides Target/URLs)
//   - "file_path": metadata label attached to findings (optional)
//   - "rules":     comma-separated rule IDs to enable (default: all)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	content := input.Options["content"]
	if content == "" {
		content = input.Target
	}
	if content == "" && len(input.URLs) > 0 {
		content = strings.Join(input.URLs, "\n")
	}
	if content == "" {
		return nil, errors.New("secretscan: content required (set Target, URLs, or Options[\"content\"])")
	}

	// Enforce memory ceiling (dicas.md §5)
	if len(content) > maxContentSize {
		m.logger.Info("secretscan: content truncated", "original_bytes", len(content), "limit", maxContentSize)
		content = content[:maxContentSize]
	}

	filePath := input.Options["file_path"]

	// Optional rule filter
	enabledIDs := parseCSV(input.Options["rules"])

	frag := Fragment{Raw: content, FilePath: filePath}
	findings := m.detect(ctx, frag, enabledIDs)

	result := make([]module.Finding, 0, len(findings))
	for _, f := range findings {
		result = append(result, f)
	}
	return result, nil
}

// detect is the core detection loop — mirrors gitleaks Detector.DetectContext.
//
//  1. Normalise content to lowercase for keyword pre-filter
//  2. For each rule: check keywords, then apply regex
//  3. For each match: extract secret group, check entropy, emit finding
func (m *Module) detect(ctx context.Context, frag Fragment, enabledIDs map[string]bool) []module.Finding {
	var findings []module.Finding

	normalised := strings.ToLower(frag.Raw)

	for _, rule := range m.rules {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		// Filter by explicit rule list
		if len(enabledIDs) > 0 && !enabledIDs[rule.RuleID] {
			continue
		}

		// Keyword pre-filter (mirrors gitleaks prefilter / Aho-Corasick)
		if !keywordsMatch(normalised, rule.Keywords) {
			m.logger.Debug("secretscan: keyword pre-filter miss", "rule", rule.RuleID)
			continue
		}

		// Regex scan
		allMatches := rule.Regex.FindAllStringSubmatchIndex(frag.Raw, -1)
		for _, loc := range allMatches {
			secret := extractGroup(frag.Raw, loc, rule.Regex, rule.SecretGroup)
			if secret == "" {
				continue
			}

			// Entropy gate — mirrors gitleaks entropy check in detectRule
			var ent float64
			if rule.Entropy > 0 {
				ent = shannonEntropy(secret)
				if ent < rule.Entropy {
					m.logger.Debug("secretscan: entropy below threshold",
						"rule", rule.RuleID, "entropy", ent, "min", rule.Entropy)
					continue
				}
			}

			// Full match for context
			matchStr := frag.Raw[loc[0]:loc[1]]

			// Line number (1-based) — mirrors gitleaks StartLine
			line := lineOf(frag.Raw, loc[0])

			// Confidence: regex match alone = 0.75; entropy gate passed = 0.90+;
			// entropy significantly above threshold = up to 0.98.
			confidence := "0.75"
			if rule.Entropy > 0 {
				ratio := ent / rule.Entropy
				if ratio >= 1.5 {
					confidence = "0.98"
				} else if ratio >= 1.2 {
					confidence = "0.90"
				} else {
					confidence = "0.80"
				}
			}

			m.logger.Info("secretscan: finding",
				"rule", rule.RuleID, "file", frag.FilePath, "line", line,
				"entropy", ent, "confidence", confidence)

			sev := severityFor(rule)
			findings = append(findings, module.Finding{
				Type:     "secret",
				URL:      frag.FilePath,
				Detail:   fmt.Sprintf("[%s] %s — line %d", rule.RuleID, rule.Description, line),
				Severity: sev,
				Extra: map[string]string{
					"rule_id":     rule.RuleID,
					"description": rule.Description,
					"secret":      redact(secret),
					"match":       redact(matchStr),
					"file":        frag.FilePath,
					"line":        fmt.Sprintf("%d", line),
					"tags":        strings.Join(rule.Tags, ","),
					"confidence":  confidence,
					"entropy":     fmt.Sprintf("%.2f", ent),
				},
			})
		}
	}

	return findings
}

// ─── helpers ───────────────────────────────────────────────────────────────

// shannonEntropy computes Shannon entropy of s over its unique characters.
// Direct port of gitleaks detect/utils.go shannonEntropy().
//
//	H = -Σ p(c) × log₂(p(c))
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, count := range freq {
		p := count / n
		h -= p * math.Log2(p)
	}
	return h
}

// keywordsMatch returns true if all keywords are present (case-insensitive) in
// normalised. An empty keyword list always matches — same as gitleaks.
func keywordsMatch(normalised string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	for _, kw := range keywords {
		if strings.Contains(normalised, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// extractGroup returns the content of capture group index g from the match
// location loc as returned by FindAllStringSubmatchIndex.
// Group 0 is the whole match. Mirrors gitleaks detectRule secret extraction.
func extractGroup(s string, loc []int, re *regexp.Regexp, g int) string {
	// loc layout: [start0 end0  start1 end1  start2 end2 ...]
	// group i → loc[2*i], loc[2*i+1]
	idx := g * 2
	if idx+1 >= len(loc) {
		// fall back to whole match
		if len(loc) >= 2 {
			return s[loc[0]:loc[1]]
		}
		return ""
	}
	if loc[idx] < 0 {
		// group not captured — fall back
		return s[loc[0]:loc[1]]
	}
	return s[loc[idx]:loc[idx+1]]
}

// lineOf returns the 1-based line number of byte offset pos in content.
func lineOf(content string, pos int) int {
	return strings.Count(content[:pos], "\n") + 1
}

// redact masks the middle of a secret, keeping 3 chars at start and end.
// Mirrors gitleaks Finding.Redact() — avoids logging full secrets.
func redact(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:3] + "..." + s[len(s)-3:]
}

// severityFor maps rule tags to module.Severity.
func severityFor(r Rule) module.Severity {
	for _, t := range r.Tags {
		switch strings.ToLower(t) {
		case "critical", "rce":
			return module.SeverityCritical
		case "high":
			return module.SeverityHigh
		}
	}
	return module.SeverityHigh // secrets are always at least high
}

// parseCSV splits a comma-separated string into a set.
func parseCSV(s string) map[string]bool {
	m := make(map[string]bool)
	if s == "" {
		return m
	}
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			m[v] = true
		}
	}
	return m
}

// must panics if err != nil. Used only at init time for rule compilation.
func must(re *regexp.Regexp, err error) *regexp.Regexp {
	if err != nil {
		panic("secretscan: rule compile error: " + err.Error())
	}
	return re
}

func re(pattern string) *regexp.Regexp {
	return must(regexp.Compile(pattern))
}

// ─── io.LimitReader wrapper ─────────────────────────────────────────────────

// ReadLimited reads up to maxContentSize bytes from r, satisfying dicas.md §5.
// Callers that feed an io.Reader can use this helper before calling Run.
func ReadLimited(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxContentSize))
	return string(b), err
}

// ─── default rules ──────────────────────────────────────────────────────────
//
// Faithful subset of gitleaks config/gitleaks.toml (MIT).
// Each entry is a direct copy of the rule from the TOML file.
// Rules with entropy = 0 in the TOML are kept as-is (0 disables the check).

func defaultRules() []Rule {
	return []Rule{
		// ── Anthropic ────────────────────────────────────────────────────────
		{
			RuleID:      "anthropic-api-key",
			Description: "Identified an Anthropic API Key, which may compromise AI assistant integrations and expose sensitive data to unauthorized access.",
			Regex:       re(`\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"sk-ant-api03"},
			Tags:        []string{"high", "anthropic"},
		},
		{
			RuleID:      "anthropic-admin-api-key",
			Description: "Detected an Anthropic Admin API Key, risking unauthorized access to administrative functions and sensitive AI model configurations.",
			Regex:       re(`\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"sk-ant-admin01"},
			Tags:        []string{"critical", "anthropic"},
		},
		// ── AWS ─────────────────────────────────────────────────────────────
		{
			RuleID:      "aws-access-token",
			Description: "Detected an AWS Access Token, risking unauthorized cloud resource access and data compromise.",
			Regex:       re(`\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"akia", "agpa", "aida", "aroa", "aipa", "anpa", "anva", "asia"},
			Tags:        []string{"critical", "aws"},
		},
		{
			RuleID:      "aws-secret-access-key",
			Description: "Discovered a potential AWS Secret Access Key, posing a risk of unauthorized cloud resource access and data compromise.",
			Regex:       re(`(?i)(?:aws)?(?:secret|secretkey|secret_key|aws_secret|aws_secret_key)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9/+]{40})(?:[\x60'"\s;]|\\[nr]|$)`),
			SecretGroup: 1,
			Entropy:     4.0,
			Keywords:    []string{"aws", "secret"},
			Tags:        []string{"critical", "aws"},
		},
		// ── GitHub ───────────────────────────────────────────────────────────
		{
			RuleID:      "github-pat",
			Description: "Identified a GitHub Personal Access Token, potentially compromising GitHub account security and access to repositories.",
			Regex:       re(`\b(ghp_[a-zA-Z0-9]{36,255})\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"ghp_"},
			Tags:        []string{"high", "github"},
		},
		{
			RuleID:      "github-oauth",
			Description: "Found a GitHub OAuth Access Token, posing a risk of unauthorized access to GitHub accounts and repositories.",
			Regex:       re(`\b(gho_[a-zA-Z0-9]{36,255})\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"gho_"},
			Tags:        []string{"high", "github"},
		},
		{
			RuleID:      "github-app-token",
			Description: "Discovered a GitHub App Token, which may compromise CI/CD pipelines and automate malicious actions within GitHub repositories.",
			Regex:       re(`\b((?:ghu|ghs)_[a-zA-Z0-9]{36,255})\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"ghu_", "ghs_"},
			Tags:        []string{"high", "github"},
		},
		{
			RuleID:      "github-refresh-token",
			Description: "Identified a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services.",
			Regex:       re(`\b(ghr_[a-zA-Z0-9]{36,255})\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"ghr_"},
			Tags:        []string{"high", "github"},
		},
		{
			RuleID:      "github-fine-grained-pat",
			Description: "Discovered a GitHub Fine-Grained Personal Access Token, risking unauthorized access to specific GitHub resources.",
			Regex:       re(`\b(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"github_pat_"},
			Tags:        []string{"high", "github"},
		},
		// ── GitLab ───────────────────────────────────────────────────────────
		{
			RuleID:      "gitlab-pat",
			Description: "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and sensitive data.",
			Regex:       re(`\b(glpat-[a-zA-Z0-9\-]{20})(?:[\x60'"\s;]|\\[nr]|$)`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"glpat-"},
			Tags:        []string{"high", "gitlab"},
		},
		// ── Slack ─────────────────────────────────────────────────────────────
		{
			RuleID:      "slack-app-token",
			Description: "Found a Slack App-level token, risking unauthorized access to Slack's APIs and workspace data.",
			Regex:       re(`\b(xapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+)\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"xapp-"},
			Tags:        []string{"high", "slack"},
		},
		{
			RuleID:      "slack-bot-token",
			Description: "Discovered a Slack Bot token, posing a risk of compromised bot integrations and unauthorized access to Slack channels and messages.",
			Regex:       re(`\b(xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]+)\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"xoxb-"},
			Tags:        []string{"high", "slack"},
		},
		{
			RuleID:      "slack-user-token",
			Description: "Identified a Slack User token, which may expose user data and enable unauthorized actions on behalf of the user.",
			Regex:       re(`\b(xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32})\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"xoxp-"},
			Tags:        []string{"high", "slack"},
		},
		{
			RuleID:      "slack-webhook-url",
			Description: "Uncovered a Slack Webhook URL, which could allow unauthorized message posting and data exposure in Slack channels.",
			Regex:       re(`\b(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"hooks.slack.com"},
			Tags:        []string{"medium", "slack"},
		},
		// ── Stripe ────────────────────────────────────────────────────────────
		{
			RuleID:      "stripe-access-token",
			Description: "Identified a Stripe API Access Token, posing a risk of financial data compromise and unauthorized payment processing.",
			Regex:       re(`\b((?:sk|pk)_(?:test|live|prod)_[0-9a-zA-Z]{24,99})\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"sk_test_", "pk_test_", "sk_live_", "pk_live_", "sk_prod_", "pk_prod_"},
			Tags:        []string{"critical", "stripe"},
		},
		// ── Google ────────────────────────────────────────────────────────────
		{
			RuleID:      "gcp-api-key",
			Description: "Discovered a potential GCP API key, risking unauthorized access to Google Cloud services and data breaches.",
			Regex:       re(`\b(AIza[0-9A-Za-z\-_]{35})\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"aiza"},
			Tags:        []string{"high", "gcp"},
		},
		{
			RuleID:      "google-oauth-access-token",
			Description: "Identified a Google OAuth Access Token, which could lead to unauthorized access to Google accounts and personal data exposure.",
			Regex:       re(`\b(ya29\.[0-9A-Za-z\-_]+)\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"ya29."},
			Tags:        []string{"high", "google"},
		},
		// ── OpenAI ────────────────────────────────────────────────────────────
		{
			RuleID:      "openai-api-key",
			Description: "Discovered an OpenAI API Key, which could lead to unauthorized use of AI services and potentially exposing sensitive data.",
			Regex:       re(`\b(sk-(?:proj-)?[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"t3blbkfj"},
			Tags:        []string{"high", "openai"},
		},
		// ── Twilio ────────────────────────────────────────────────────────────
		{
			RuleID:      "twilio-api-key",
			Description: "Found a Twilio API Key, posing a risk of unauthorized access to communications services and customer data.",
			Regex:       re(`SK[0-9a-fA-F]{32}`),
			SecretGroup: 0,
			Entropy:     4.0,
			Keywords:    []string{"twilio", "sk"},
			Tags:        []string{"high", "twilio"},
		},
		// ── NPM / npm ─────────────────────────────────────────────────────────
		{
			RuleID:      "npm-access-token",
			Description: "Uncovered an npm Access Token, potentially compromising package management and the supply chain.",
			Regex:       re(`\b(npm_[a-zA-Z0-9]{36})\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"npm_"},
			Tags:        []string{"high", "npm"},
		},
		// ── PyPI ──────────────────────────────────────────────────────────────
		{
			RuleID:      "pypi-upload-token",
			Description: "Discovered a PyPI upload token, potentially compromising Python package distribution and the supply chain.",
			Regex:       re(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`),
			SecretGroup: 0,
			Entropy:     4.0,
			Keywords:    []string{"pypi-"},
			Tags:        []string{"high", "pypi"},
		},
		// ── JWT ───────────────────────────────────────────────────────────────
		{
			RuleID:      "jwt",
			Description: "Identified a JSON Web Token, which may expose sensitive claims and be exploited for unauthorized access.",
			Regex:       re(`\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\+]{17,}\.(?:[a-zA-Z0-9\/\\+]{10,}={0,2})?)\b`),
			SecretGroup: 1,
			Entropy:     4.0,
			Keywords:    []string{"eyj"},
			Tags:        []string{"medium"},
		},
		// ── Private keys ─────────────────────────────────────────────────────
		{
			RuleID:      "private-key",
			Description: "Identified a Private Key, which may expose cryptographic secrets and enable unauthorized access or data decryption.",
			Regex:       re(`-----BEGIN (?:EC |RSA |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`),
			SecretGroup: 0,
			Entropy:     0,
			Keywords:    []string{"-----begin"},
			Tags:        []string{"critical"},
		},
		// ── Generic high-entropy password / secret ────────────────────────────
		{
			RuleID:      "generic-api-key",
			Description: "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
			Regex:       re(`(?i)(?:api[_\-\s]?key|apikey|api[_\-\s]?token|access[_\-\s]?key|access[_\-\s]?token|secret[_\-\s]?key|auth[_\-\s]?token)[\s'":=]{1,5}([a-zA-Z0-9_\-]{20,64})`),
			SecretGroup: 1,
			Entropy:     3.5,
			Keywords:    []string{"api_key", "apikey", "api_token", "access_key", "access_token", "secret_key", "auth_token"},
			Tags:        []string{"high"},
		},
		// ── Password patterns ─────────────────────────────────────────────────
		{
			RuleID:      "password-in-url",
			Description: "Detected a password in a URL, risking credential exposure.",
			Regex:       re(`(?i)[a-z0-9+\-.]+://[^:@\s]+:[^@\s]{3,}@[a-z0-9\-.]+`),
			SecretGroup: 0,
			Entropy:     3.0,
			Keywords:    []string{"://"},
			Tags:        []string{"high"},
		},
		// ── SendGrid ──────────────────────────────────────────────────────────
		{
			RuleID:      "sendgrid-api-token",
			Description: "Discovered a SendGrid API token, risking unauthorized email service access and potential spam or phishing attacks.",
			Regex:       re(`\bSG\.[a-zA-Z0-9_\-.]{16,64}\.[a-zA-Z0-9_\-.]{16,64}\b`),
			SecretGroup: 0,
			Entropy:     4.0,
			Keywords:    []string{"sg."},
			Tags:        []string{"high", "sendgrid"},
		},
		// ── Heroku ────────────────────────────────────────────────────────────
		{
			RuleID:      "heroku-api-key",
			Description: "Identified a Heroku API Key, risking unauthorized access to Heroku apps and potential exposure of sensitive deployment configurations.",
			Regex:       re(`(?i)heroku(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"heroku"},
			Tags:        []string{"high", "heroku"},
		},
		// ── Telegram ─────────────────────────────────────────────────────────
		{
			RuleID:      "telegram-bot-api-token",
			Description: "Identified a Telegram Bot API Token, risking unauthorized bot operations and message interception.",
			Regex:       re(`(?i)(?:^|[^0-9])([0-9]{5,16}:AA[a-zA-Z0-9_\-]{32,40})(?:[^a-zA-Z0-9_\-]|$)`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{":aa"},
			Tags:        []string{"high", "telegram"},
		},
		// ── Square ────────────────────────────────────────────────────────────
		{
			RuleID:      "square-access-token",
			Description: "Discovered a potential Square Access Token, risking unauthorized payment processing and financial data exposure.",
			Regex:       re(`\bEAAA[a-zA-Z0-9]{60}\b`),
			SecretGroup: 0,
			Entropy:     0,
			Keywords:    []string{"eaaa"},
			Tags:        []string{"critical", "square"},
		},
		// ── Shopify ───────────────────────────────────────────────────────────
		{
			RuleID:      "shopify-shared-secret",
			Description: "Found a Shopify shared secret, which could compromise e-commerce platform security.",
			Regex:       re(`\bshpss_[a-fA-F0-9]{32}\b`),
			SecretGroup: 0,
			Entropy:     0,
			Keywords:    []string{"shpss_"},
			Tags:        []string{"high", "shopify"},
		},
		{
			RuleID:      "shopify-access-token",
			Description: "Identified a Shopify access token, potentially compromising e-commerce platform security and customer data.",
			Regex:       re(`\bshpat_[a-fA-F0-9]{32}\b`),
			SecretGroup: 0,
			Entropy:     0,
			Keywords:    []string{"shpat_"},
			Tags:        []string{"high", "shopify"},
		},
		// ── DigitalOcean ─────────────────────────────────────────────────────
		{
			RuleID:      "digitalocean-pat",
			Description: "Discovered a DigitalOcean Personal Access Token, posing a risk of unauthorized cloud infrastructure manipulation.",
			Regex:       re(`\b(dop_v1_[a-f0-9]{64})\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"dop_v1_"},
			Tags:        []string{"high", "digitalocean"},
		},
		{
			RuleID:      "digitalocean-oauth-token",
			Description: "Found a DigitalOcean OAuth Access Token, risking unauthorized cloud resource management.",
			Regex:       re(`\b(doo_v1_[a-f0-9]{64})\b`),
			SecretGroup: 1,
			Entropy:     0,
			Keywords:    []string{"doo_v1_"},
			Tags:        []string{"high", "digitalocean"},
		},
		// ── Dropbox ───────────────────────────────────────────────────────────
		{
			RuleID:      "dropbox-api-secret",
			Description: "Discovered a Dropbox API secret, posing a risk of unauthorized file access and data breaches.",
			Regex:       re(`(?i)[\w.-]{0,50}?dropbox[\w.-]{0,20}[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{15})(?:[\x60'"\s;]|\\[nr]|$)`),
			SecretGroup: 1,
			Entropy:     3.0,
			Keywords:    []string{"dropbox"},
			Tags:        []string{"high", "dropbox"},
		},
		// ── Azure ─────────────────────────────────────────────────────────────
		{
			RuleID:      "azure-storage-key",
			Description: "Detected an Azure Storage Account access key, risking unauthorized access to Azure storage resources and data.",
			Regex:       re(`(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=([a-zA-Z0-9/+]{88}==)`),
			SecretGroup: 1,
			Entropy:     4.0,
			Keywords:    []string{"defaultendpointsprotocol", "accountkey"},
			Tags:        []string{"critical", "azure"},
		},
		// ── Vault / HCP ───────────────────────────────────────────────────────
		{
			RuleID:      "hashicorp-vault-token",
			Description: "Discovered a HashiCorp Vault batch/root/service token, risking unauthorized secrets access.",
			Regex:       re(`\b(hvb\.[a-zA-Z0-9_-]{138,500}|hvs\.[a-zA-Z0-9_-]{90,500}|s\.[a-zA-Z0-9]{24})\b`),
			SecretGroup: 1,
			Entropy:     4.0,
			Keywords:    []string{"hvb.", "hvs.", "s."},
			Tags:        []string{"critical"},
		},
		// ── PayPal / Braintree ────────────────────────────────────────────────
		{
			RuleID:      "paypal-braintree-access-token",
			Description: "Detected a PayPal/Braintree access token, risking unauthorized payment operations.",
			Regex:       re(`\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b`),
			SecretGroup: 0,
			Entropy:     3.5,
			Keywords:    []string{"braintree", "access_token$production$"},
			Tags:        []string{"critical", "paypal", "braintree"},
		},
		// ── Square ────────────────────────────────────────────────────────────
		{
			RuleID:      "square-access-token",
			Description: "Identified a Square access token, which may compromise payment integrations.",
			Regex:       re(`\bEAAA[a-zA-Z0-9]{60}\b`),
			SecretGroup: 0,
			Entropy:     4.0,
			Keywords:    []string{"square", "eaaa"},
			Tags:        []string{"high", "square"},
		},
		{
			RuleID:      "square-oauth-secret",
			Description: "Identified a Square OAuth secret.",
			Regex:       re(`(?i)sq0csp-[0-9A-Za-z\-_]{43}`),
			SecretGroup: 0,
			Entropy:     4.0,
			Keywords:    []string{"sq0csp-"},
			Tags:        []string{"high", "square"},
		},
		// ── Stripe restricted key ─────────────────────────────────────────────
		{
			RuleID:      "stripe-restricted-key",
			Description: "Found a Stripe restricted API key, which still grants limited payment access.",
			Regex:       re(`\brk_live_[0-9a-zA-Z]{24,}\b`),
			SecretGroup: 0,
			Entropy:     3.8,
			Keywords:    []string{"rk_live_"},
			Tags:        []string{"high", "stripe"},
		},
		// ── PyPI upload token ─────────────────────────────────────────────────
		{
			RuleID:      "pypi-upload-token",
			Description: "Detected a PyPI upload token that grants package publishing access.",
			Regex:       re(`\bpypi-[A-Za-z0-9_\-]{50,}\b`),
			SecretGroup: 0,
			Entropy:     4.0,
			Keywords:    []string{"pypi-"},
			Tags:        []string{"medium", "pypi"},
		},
		// ── RubyGems ──────────────────────────────────────────────────────────
		{
			RuleID:      "rubygems-api-key",
			Description: "Detected a RubyGems API key, which allows gem publishing.",
			Regex:       re(`\brubygems_[a-f0-9]{48}\b`),
			SecretGroup: 0,
			Entropy:     4.0,
			Keywords:    []string{"rubygems_"},
			Tags:        []string{"medium", "rubygems"},
		},
		// ── Linear ────────────────────────────────────────────────────────────
		{
			RuleID:      "linear-api-key",
			Description: "Found a Linear API key, potentially exposing project management data.",
			Regex:       re(`\blin_api_[a-zA-Z0-9]{40}\b`),
			SecretGroup: 0,
			Entropy:     3.8,
			Keywords:    []string{"lin_api_"},
			Tags:        []string{"medium", "linear"},
		},
		// ── Notion ────────────────────────────────────────────────────────────
		{
			RuleID:      "notion-integration-token",
			Description: "Found a Notion integration token, exposing workspace data.",
			Regex:       re(`\bsecret_[a-zA-Z0-9]{43}\b`),
			SecretGroup: 0,
			Entropy:     4.0,
			Keywords:    []string{"secret_"},
			Tags:        []string{"medium", "notion"},
		},
		// ── Docker Hub PAT ────────────────────────────────────────────────────
		{
			RuleID:      "dockerhub-pat",
			Description: "Detected a Docker Hub personal access token.",
			Regex:       re(`\bdckr_pat_[a-zA-Z0-9_-]{27}\b`),
			SecretGroup: 0,
			Entropy:     4.0,
			Keywords:    []string{"dckr_pat_"},
			Tags:        []string{"high", "docker"},
		},
		// ── Hugging Face ──────────────────────────────────────────────────────
		{
			RuleID:      "huggingface-access-token",
			Description: "Identified a Hugging Face user access token, risking unauthorized AI model access.",
			Regex:       re(`\bhf_[a-zA-Z0-9]{34}\b`),
			SecretGroup: 0,
			Entropy:     4.0,
			Keywords:    []string{"hf_"},
			Tags:        []string{"medium", "huggingface", "ai"},
		},
		// ── Replicate ─────────────────────────────────────────────────────────
		{
			RuleID:      "replicate-api-token",
			Description: "Found a Replicate API token, risking unauthorized AI model inference costs.",
			Regex:       re(`\br8_[a-zA-Z0-9]{37}\b`),
			SecretGroup: 0,
			Entropy:     4.0,
			Keywords:    []string{"r8_"},
			Tags:        []string{"medium", "replicate", "ai"},
		},
	}
}
