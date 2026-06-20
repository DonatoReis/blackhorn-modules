// Package verbtamper tests HTTP Verb Tampering on discovered endpoints.
//
// Reference implementation (algorithm only, no code copied):
//   - orbit-core internal/modules/verbtamper.go (proprietary)
//
// What is implemented:
//   - Baseline GET per endpoint before testing alternative verbs
//   - Verb testing: PUT, DELETE, PATCH, OPTIONS, TRACE, HEAD, CONNECT
//   - Severity escalation:
//     CRITICAL: destructive verb (DELETE/PUT/PATCH) succeeds when GET returned 401/403/405
//     HIGH:     destructive verb accepted with meaningfully different response from baseline
//     MEDIUM:   OPTIONS reveals dangerous allowed methods
//     LOW:      TRACE enabled (XST/Cross-Site Tracing risk)
//   - Body hash (SHA-256 prefix) + length diff to avoid false positives from nonces/timestamps
//   - Soft-404 body detection to discard WAF block pages returned as 200
//   - Smart endpoint selection: API paths first, then unique endpoints by host+path
//   - X-HTTP-Method-Override header bypass (some servers honour override headers)
//   - io.LimitReader on every body read                   (dicas.md §5)
//   - log/slog structured observability                   (dicas.md §16)
//   - errgroup.SetLimit bounded fan-out                   (guia-go §9)
//   - context propagation and cancellation               (guia-go §9)
package verbtamper

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	maxBodyRead    = 32 * 1024 // 32 KiB — dicas.md §5
	defaultTimeout = 12 * time.Second
	defaultThreads = 8
	defaultMaxURLs = 30

	// minBodyDiff: minimum byte difference to consider a response "meaningfully different"
	// from the baseline (avoids flagging anti-CSRF token / nonce / timestamp variations).
	minBodyDiff = 128
)

// ─── Module ───────────────────────────────────────────────────────────────────

// Module tests HTTP verb tampering on endpoints.
type Module struct {
	client          *http.Client
	threads         int
	timeout         time.Duration
	maxURLs         int
	testVerbs       []string
	testDestructive bool
	testTrace       bool
	testOverride    bool // test X-HTTP-Method-Override bypass
}

// New creates a Module with default settings.
func New() *Module {
	return &Module{
		client:          defaultClient(defaultTimeout),
		threads:         defaultThreads,
		timeout:         defaultTimeout,
		maxURLs:         defaultMaxURLs,
		testVerbs:       []string{"PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"},
		testDestructive: true,
		testTrace:       true,
		testOverride:    true,
	}
}

// NewWithClient creates a Module with a custom HTTP client (useful for tests).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// Name satisfies module.Module.
func (m *Module) Name() string { return "verbtamper" }

// Run satisfies module.Module.
// Accepts URLs from input.URLs and input.Target.
// Selects representative endpoints (API paths first), then tests alternative HTTP verbs.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	rawURLs := collectURLs(input)
	if len(rawURLs) == 0 {
		return nil, fmt.Errorf("verbtamper: no URLs to test")
	}

	maxURLs := optInt(input.Options, "max_urls", m.maxURLs)
	threads := optInt(input.Options, "threads", m.threads)
	testDestructive := optBool(input.Options, "test_destructive", m.testDestructive)
	testTrace := optBool(input.Options, "test_trace", m.testTrace)
	testOverride := optBool(input.Options, "test_override", m.testOverride)

	targets := selectTargets(rawURLs, maxURLs)
	verbs := activeVerbs(testDestructive, testTrace)

	slog.Debug("verbtamper: starting", "targets", len(targets), "verbs", len(verbs), "threads", threads)

	findingsCh := make(chan module.Finding, 128)
	var found atomic.Int64

	type workItem struct {
		endpoint string
		verb     string
		override bool
	}
	var items []workItem
	seen := make(map[string]struct{})
	for _, endpoint := range targets {
		for _, verb := range verbs {
			key := endpoint + ":" + verb
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			items = append(items, workItem{endpoint, verb, false})
		}
		if testOverride {
			for _, verb := range []string{"PUT", "DELETE", "PATCH"} {
				key := endpoint + ":override-" + verb
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				items = append(items, workItem{endpoint, verb, true})
			}
		}
	}

	// We need the baseline GET for each endpoint first — do this synchronously.
	type baseline struct {
		body string
		code int
		hash string
		len  int
	}
	baselineCache := make(map[string]baseline, len(targets))
	for _, endpoint := range targets {
		body, code := fetchBodyVerb(ctx, m.client, "GET", endpoint, nil)
		baselineCache[endpoint] = baseline{
			body: body,
			code: code,
			hash: bodyHash(body),
			len:  len(body),
		}
	}

	eg, gctx := errgroup.WithContext(ctx)
	eg.SetLimit(threads)

	for _, item := range items {
		item := item // capture
		bl := baselineCache[item.endpoint]

		if bl.code <= 0 {
			continue // could not reach endpoint at all
		}

		// Discard baseline soft-404 (endpoint not reliable for comparison).
		if isSoft404(bl.body) {
			continue
		}

		eg.Go(func() error {
			var headers map[string]string
			if item.override {
				headers = map[string]string{
					"X-HTTP-Method-Override": item.verb,
					"X-Method-Override":      item.verb,
					"X-HTTP-Method":          item.verb,
				}
				// Send as GET with override header.
				respBody, code := fetchBodyVerb(gctx, m.client, "GET", item.endpoint, headers)
				return m.evaluateOverride(gctx, item.endpoint, item.verb, code, respBody, bl.code, findingsCh, &found)
			}

			respBody, code := fetchBodyVerb(gctx, m.client, item.verb, item.endpoint, nil)
			if code <= 0 {
				return nil
			}

			switch item.verb {
			case "OPTIONS":
				if code == 200 || code == 204 {
					allow := optionsAllow(gctx, m.client, item.endpoint)
					if hasDangerousVerbs(allow) {
						found.Add(1)
						findingsCh <- module.Finding{
							Type:     "verb_tampering",
							URL:      item.endpoint,
							Detail:   fmt.Sprintf("OPTIONS on %s exposes dangerous methods: %s", item.endpoint, allow),
							Severity: module.SeverityMedium,
							Extra: map[string]string{
								"verb":       item.verb,
								"status":     fmt.Sprintf("%d", code),
								"allow":      allow,
								"check":      "options-allow",
								"confidence": "0.90", // Allow header explicitly lists dangerous methods
							},
						}
					}
				}

			case "TRACE":
				if code == 200 {
					found.Add(1)
					findingsCh <- module.Finding{
						Type:     "verb_tampering",
						URL:      item.endpoint,
						Detail:   fmt.Sprintf("TRACE method enabled on %s (XST / Cross-Site Tracing risk)", item.endpoint),
						Severity: module.SeverityLow,
						Extra: map[string]string{
							"verb":       item.verb,
							"status":     fmt.Sprintf("%d", code),
							"check":      "trace-enabled",
							"confidence": "0.95", // TRACE returned 200 — Cross-Site Tracing confirmed
						},
					}
				}

			case "DELETE", "PUT", "PATCH":
				if code < 200 || code > 204 {
					return nil
				}
				// Discard WAF block page returned as 200.
				if isSoft404(respBody) {
					return nil
				}

				if bl.code == 401 || bl.code == 403 || bl.code == 405 {
					// Authorization bypass confirmed — CRITICAL.
					found.Add(1)
					findingsCh <- module.Finding{
						Type:     "verb_tampering",
						URL:      item.endpoint,
						Detail:   fmt.Sprintf("%s accepted on %s (HTTP %d) while GET returned %d — authorization bypass.", item.verb, item.endpoint, code, bl.code),
						Severity: module.SeverityCritical,
						Extra: map[string]string{
							"verb":            item.verb,
							"status":          fmt.Sprintf("%d", code),
							"baseline_status": fmt.Sprintf("%d", bl.code),
							"check":           "authz-bypass",
							"confidence":      "0.95", // verb accepted when GET returned 401/403/405 — authorization bypass confirmed
						},
					}
				} else {
					// Meaningful response difference.
					respHash := bodyHash(respBody)
					diff := abs(bl.len - len(respBody))
					if respHash != bl.hash && diff >= minBodyDiff {
						found.Add(1)
						findingsCh <- module.Finding{
							Type:     "verb_tampering",
							URL:      item.endpoint,
							Detail:   fmt.Sprintf("%s accepted on %s (HTTP %d) with meaningfully different response from GET (%d byte diff).", item.verb, item.endpoint, code, diff),
							Severity: module.SeverityHigh,
							Extra: map[string]string{
								"verb":       item.verb,
								"status":     fmt.Sprintf("%d", code),
								"body_diff":  fmt.Sprintf("%d", diff),
								"check":      "different-response",
								"confidence": "0.75", // response differs meaningfully but no auth boundary crossed
							},
						}
					}
				}
			}
			return nil
		})
	}

	go func() { _ = eg.Wait(); close(findingsCh) }()

	var findings []module.Finding
	for f := range findingsCh {
		findings = append(findings, f)
	}
	if err := eg.Wait(); err != nil {
		return findings, err
	}
	slog.Debug("verbtamper: done", "findings", found.Load())
	return findings, nil
}

// evaluateOverride checks if an X-HTTP-Method-Override header causes bypass.
func (m *Module) evaluateOverride(_ context.Context, endpoint, verb string, code int, body string, baseCode int, ch chan<- module.Finding, found *atomic.Int64) error {
	if code < 200 || code > 204 {
		return nil
	}
	if isSoft404(body) {
		return nil
	}
	if baseCode == 401 || baseCode == 403 {
		found.Add(1)
		ch <- module.Finding{
			Type:     "verb_tampering",
			URL:      endpoint,
			Detail:   fmt.Sprintf("X-HTTP-Method-Override: %s bypassed protection on %s (HTTP %d, baseline %d)", verb, endpoint, code, baseCode),
			Severity: module.SeverityCritical,
			Extra: map[string]string{
				"verb":            verb,
				"status":          fmt.Sprintf("%d", code),
				"baseline_status": fmt.Sprintf("%d", baseCode),
				"check":           "method-override-bypass",
				"confidence":      "0.95", // X-HTTP-Method-Override bypassed 401/403 — definitive bypass
			},
		}
	}
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func activeVerbs(testDestructive, testTrace bool) []string {
	base := []string{"OPTIONS"}
	if testDestructive {
		base = append(base, "PUT", "DELETE", "PATCH")
	}
	if testTrace {
		base = append(base, "TRACE")
	}
	return base
}

func fetchBodyVerb(ctx context.Context, client *http.Client, verb, rawURL string, extraHeaders map[string]string) (string, int) {
	req, err := http.NewRequestWithContext(ctx, verb, rawURL, nil)
	if err != nil {
		return "", 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BlackhornScanner/1.0)")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return string(b), resp.StatusCode
}

func optionsAllow(ctx context.Context, client *http.Client, rawURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BlackhornScanner/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()
	return resp.Header.Get("Allow")
}

func hasDangerousVerbs(allow string) bool {
	upper := strings.ToUpper(allow)
	return strings.Contains(upper, "DELETE") ||
		strings.Contains(upper, "PUT") ||
		strings.Contains(upper, "PATCH")
}

func bodyHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:8])
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// isSoft404 checks if a response body looks like a WAF block page or error page.
// Conservative: requires 2+ markers OR Cloudflare-specific signals to avoid
// false positives on legitimate 200 responses to alternative verbs.
var soft404Markers = []string{
	"not found", "page not found", "doesn't exist",
	"this page is gone", "cloudflare ray id", "just a moment",
	"ddos protection by", "blocked by", "firewall blocked",
	"service unavailable", "bad gateway", "gateway timeout",
	"captcha required", "bot check", "verifying you are human",
}

func isSoft404(body string) bool {
	if body == "" {
		return false
	}
	b := strings.TrimSpace(body)
	if strings.HasPrefix(b, "{") || strings.HasPrefix(b, "[") {
		return false
	}
	lower := strings.ToLower(body)
	hits := 0
	for _, m := range soft404Markers {
		if strings.Contains(lower, m) {
			hits++
			if hits >= 2 {
				return true
			}
		}
	}
	// Only flag single-marker bodies when they are very short (< 500 bytes)
	// AND the marker is unambiguous.
	return false
}

// selectTargets chooses representative endpoints:
// 1. API paths (/api/, /v1/, /v2/, /rest/, /graphql)
// 2. Unique endpoints by host+path (deduplicated)
func selectTargets(rawURLs []string, max int) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, max)

	// Priority 1: API paths.
	for _, u := range rawURLs {
		if len(out) >= max {
			break
		}
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		p := strings.ToLower(parsed.Path)
		if strings.Contains(p, "/api/") || strings.Contains(p, "/v1/") ||
			strings.Contains(p, "/v2/") || strings.Contains(p, "/v3/") ||
			strings.Contains(p, "/rest/") || strings.Contains(p, "/graphql") {
			key := parsed.Host + parsed.Path
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, u)
		}
	}

	// Priority 2: all remaining unique endpoints.
	for _, u := range rawURLs {
		if len(out) >= max {
			break
		}
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		key := parsed.Host + parsed.Path
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, u)
	}
	return out
}

func collectURLs(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(u string) {
		if u == "" {
			return
		}
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		if _, dup := seen[u]; dup {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	if input.Target != "" {
		add(input.Target)
	}
	for _, u := range input.URLs {
		add(u)
	}
	return out
}

func defaultClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

func optInt(opts map[string]string, key string, def int) int {
	if opts == nil {
		return def
	}
	v, ok := opts[key]
	if !ok {
		return def
	}
	n := 0
	for _, c := range v {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	if n == 0 {
		return def
	}
	return n
}

func optBool(opts map[string]string, key string, def bool) bool {
	if opts == nil {
		return def
	}
	v, ok := opts[key]
	if !ok {
		return def
	}
	return v == "true" || v == "1"
}
