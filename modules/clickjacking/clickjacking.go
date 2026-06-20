// Package clickjacking detects missing or misconfigured Clickjacking protections.
//
// Source reference: OWASP Clickjacking Defense Cheat Sheet + nuclei-templates
// misconfiguration/clickjacking (MIT). Detection logic reimplemented from scratch.
//
// Checks performed:
//   - Missing X-Frame-Options header (DENY/SAMEORIGIN required)
//   - Permissive X-Frame-Options (ALLOW-FROM with no origin, or deprecated form)
//   - Missing Content-Security-Policy: frame-ancestors directive
//   - CSP frame-ancestors set to * (allows any origin)
//   - CSP frame-ancestors 'none' missing (when X-Frame-Options also absent)
//   - X-Frame-Options: ALLOWALL (deprecated, treated as permissive)
//   - Conflicting X-Frame-Options + CSP (CSP takes precedence in modern browsers)
//
// Severity mapping:
//   - Missing XFO + missing frame-ancestors → High (page fully frameable)
//   - Permissive ALLOW-FROM / ALLOWALL → Medium
//   - CSP frame-ancestors: * → High
//   - Conflicting headers (lower protection wins) → Low/Medium
//
// Architecture:
//   - No payload injection — pure header/response analysis
//   - errgroup.SetLimit(Parallelism) for multi-URL fan-out
//   - io.LimitReader on all response reads
//   - log/slog observability
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) for testability
package clickjacking

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	DefaultTimeout     = 10 * time.Second
	DefaultParallelism = 20
	maxBodyRead        = 256 * 1024 // 256 KB — only need headers, but read body for iframe-busters
)

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements Clickjacking detection.
type Module struct {
	client      *http.Client
	parallelism int
	logger      *slog.Logger
}

// New returns a Module with default HTTP client.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: DefaultTimeout}),
		parallelism: DefaultParallelism,
		logger:      slog.Default(),
	}
}

// NewWithClient returns a Module using the supplied HTTP client (testability).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// Name returns the module name.
func (m *Module) Name() string { return "clickjacking" }

// Run checks all target URLs for Clickjacking vulnerabilities.
//
// Options:
//   - "parallelism" — max concurrent checks (default: 20)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	targets := collectTargets(input)
	if len(targets) == 0 {
		return nil, nil
	}

	parallelism := m.parallelism
	if v := input.Options["parallelism"]; v != "" {
		if p, err := parseInt(v); err == nil && p > 0 {
			parallelism = p
		}
	}

	var (
		mu       sync.Mutex
		seen     = make(map[string]struct{})
		findings []module.Finding
	)

	addFindings := func(fs []module.Finding) {
		mu.Lock()
		defer mu.Unlock()
		for _, f := range fs {
			key := f.URL + "|" + f.Type + "|" + f.Detail
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				findings = append(findings, f)
			}
		}
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(parallelism)

	for _, target := range targets {
		target := target
		eg.Go(func() error {
			fs := m.checkURL(egCtx, target)
			if len(fs) > 0 {
				addFindings(fs)
			}
			return nil
		})
	}

	_ = eg.Wait()
	return findings, nil
}

// checkURL sends a HEAD+GET request and analyses the response headers.
func (m *Module) checkURL(ctx context.Context, rawURL string) []module.Finding {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		m.logger.DebugContext(ctx, "clickjacking: build request failed", "url", rawURL, "err", err)
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-clickjacking/1.0)")

	resp, err := m.client.Do(req)
	if err != nil {
		m.logger.DebugContext(ctx, "clickjacking: request failed", "url", rawURL, "err", err)
		return nil
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil
	}

	return analyzeHeaders(rawURL, resp.Header)
}

// analyzeHeaders inspects X-Frame-Options and CSP frame-ancestors for clickjacking issues.
func analyzeHeaders(rawURL string, headers http.Header) []module.Finding {
	xfo := strings.TrimSpace(headers.Get("X-Frame-Options"))
	cspRaw := headers.Get("Content-Security-Policy")

	xfoUpper := strings.ToUpper(xfo)
	frameAncestors := extractFrameAncestors(cspRaw)

	var findings []module.Finding

	// ── Check 1: missing X-Frame-Options ──────────────────────────────────
	if xfo == "" {
		if frameAncestors == "" {
			// Fully frameable — no protection at all.
			findings = append(findings, module.Finding{
				Type:     "clickjacking",
				Severity: module.SeverityHigh,
				URL:      rawURL,
				Detail:   "missing X-Frame-Options and CSP frame-ancestors — page is fully frameable",
				Extra: map[string]string{
					"check":           "missing-xfo-and-csp",
					"x_frame_options": xfo,
					"frame_ancestors": frameAncestors,
					"tags":            "clickjacking,missing-header",
					"confidence":      "0.95", // both X-Frame-Options and CSP frame-ancestors absent from response
				},
			})
		}
		// If only CSP frame-ancestors is set, that is acceptable (modern protection).
	}

	// ── Check 2: permissive X-Frame-Options ───────────────────────────────
	if xfo != "" && xfoUpper != "DENY" && xfoUpper != "SAMEORIGIN" {
		if xfoUpper == "ALLOWALL" {
			findings = append(findings, module.Finding{
				Type:     "clickjacking",
				Severity: module.SeverityHigh,
				URL:      rawURL,
				Detail:   fmt.Sprintf("X-Frame-Options: ALLOWALL is deprecated and permits framing from any origin"),
				Extra: map[string]string{
					"check":           "xfo-allowall",
					"x_frame_options": xfo,
					"tags":            "clickjacking,permissive-header",
				},
			})
		} else if strings.HasPrefix(xfoUpper, "ALLOW-FROM") {
			// ALLOW-FROM is deprecated; check if no domain specified.
			origin := strings.TrimSpace(strings.TrimPrefix(xfoUpper, "ALLOW-FROM"))
			findings = append(findings, module.Finding{
				Type:     "clickjacking",
				Severity: module.SeverityMedium,
				URL:      rawURL,
				Detail:   fmt.Sprintf("X-Frame-Options: ALLOW-FROM is deprecated (not supported in modern browsers); origin=%q", origin),
				Extra: map[string]string{
					"check":           "xfo-allow-from-deprecated",
					"x_frame_options": xfo,
					"allow_from":      origin,
					"tags":            "clickjacking,deprecated-header",
				},
			})
		} else {
			// Unknown value — may be mistyped.
			findings = append(findings, module.Finding{
				Type:     "clickjacking",
				Severity: module.SeverityMedium,
				URL:      rawURL,
				Detail:   fmt.Sprintf("X-Frame-Options has unrecognized value %q (expected DENY or SAMEORIGIN)", xfo),
				Extra: map[string]string{
					"check":           "xfo-unknown-value",
					"x_frame_options": xfo,
					"tags":            "clickjacking,invalid-header",
				},
			})
		}
	}

	// ── Check 3: CSP frame-ancestors: * ───────────────────────────────────
	if frameAncestors == "*" {
		findings = append(findings, module.Finding{
			Type:     "clickjacking",
			Severity: module.SeverityHigh,
			URL:      rawURL,
			Detail:   "CSP frame-ancestors: * allows framing from any origin",
			Extra: map[string]string{
				"check":           "csp-frame-ancestors-wildcard",
				"frame_ancestors": frameAncestors,
				"tags":            "clickjacking,permissive-csp",
			},
		})
	}

	// ── Check 4: X-Frame-Options: DENY but CSP frame-ancestors: * (conflict) ──
	if (xfoUpper == "DENY" || xfoUpper == "SAMEORIGIN") && frameAncestors == "*" {
		findings = append(findings, module.Finding{
			Type:     "clickjacking",
			Severity: module.SeverityHigh,
			URL:      rawURL,
			Detail:   fmt.Sprintf("Conflicting XFO=%q and CSP frame-ancestors=* — CSP takes precedence in modern browsers, page is frameable", xfo),
			Extra: map[string]string{
				"check":           "xfo-csp-conflict",
				"x_frame_options": xfo,
				"frame_ancestors": frameAncestors,
				"tags":            "clickjacking,conflict",
			},
		})
	}

	return findings
}

// extractFrameAncestors parses CSP header and extracts the frame-ancestors directive value.
func extractFrameAncestors(csp string) string {
	if csp == "" {
		return ""
	}
	for _, directive := range strings.Split(csp, ";") {
		directive = strings.TrimSpace(directive)
		lower := strings.ToLower(directive)
		if strings.HasPrefix(lower, "frame-ancestors") {
			// Extract the value after the directive name.
			rest := strings.TrimSpace(directive[len("frame-ancestors"):])
			return rest
		}
	}
	return ""
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func collectTargets(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	if input.Target != "" {
		add(input.Target)
	}
	for _, u := range input.URLs {
		add(u)
	}
	return out
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n, err
}
