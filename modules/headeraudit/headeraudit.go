// Package headeraudit performs an HTTP Security Headers audit against one or more
// URLs, detecting missing, misconfigured, or weak security-related response
// headers. The check set is derived from:
//   - OWASP Secure Headers Project (Apache-2.0 documentation)
//   - Mozilla Observatory (MPL-2.0) — header checks
//   - projectdiscovery/nuclei-templates http/misconfiguration/ (MIT)
//   - securityheaders.com scanner logic (public specification)
//
// License note: no source code is copied from any of the above.
// All checks are independently implemented based on public RFCs and
// OWASP/Mozilla best-practice documentation.
package headeraudit

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

const (
	defaultTimeout = 12 * time.Second
	defaultConc    = 10
	maxBodyBytes   = 256 * 1024
)

// ─── module ──────────────────────────────────────────────────────────────────

// Module implements module.Module for HTTP security header auditing.
type Module struct {
	client      *http.Client
	concurrency int
}

// New returns a Module with production defaults.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		concurrency: defaultConc,
	}
}

// NewWithClient creates a Module using the provided HTTP client (useful in tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client:      c,
		concurrency: defaultConc,
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "headeraudit" }

// Run implements module.Module.
// Accepts Target (single URL), URLs (slice) or RawContent (newline-delimited).
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	urls := collectURLs(input)
	if len(urls) == 0 {
		return nil, fmt.Errorf("headeraudit: no URLs provided")
	}

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(m.concurrency)

	for _, rawURL := range urls {
		rawURL := rawURL
		g.Go(func() error {
			ff, err := m.auditURL(gctx, rawURL)
			if err != nil {
				slog.Debug("headeraudit: probe error", "url", rawURL, "err", err)
				return nil // non-fatal
			}
			if len(ff) > 0 {
				mu.Lock()
				findings = append(findings, ff...)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()
	return findings, nil
}

// ─── per-URL audit ───────────────────────────────────────────────────────────

func (m *Module) auditURL(ctx context.Context, rawURL string) ([]module.Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-headeraudit/1.0)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))

	return runChecks(rawURL, resp.StatusCode, resp.Header), nil
}

// ─── check engine ────────────────────────────────────────────────────────────

// runChecks applies all header checks to the given HTTP response headers.
func runChecks(rawURL string, code int, headers http.Header) []module.Finding {
	var findings []module.Finding

	for _, chk := range allChecks {
		if f := chk(rawURL, code, headers); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings
}

// checkFn is a single header check function.
type checkFn func(rawURL string, code int, headers http.Header) *module.Finding

// allChecks is the ordered list of all header checks.
var allChecks = []checkFn{
	checkStrictTransportSecurity,
	checkContentSecurityPolicy,
	checkXContentTypeOptions,
	checkXFrameOptions,
	checkReferrerPolicy,
	checkPermissionsPolicy,
	checkCacheControlSensitive,
	checkServerInfoLeak,
	checkXPoweredByLeak,
	checkASPNetVersionLeak,
	checkCORSWildcard,
	checkAccessControlAllowCredentials,
	checkSetCookieSecure,
	checkSetCookieHttpOnly,
	checkSetCookieSameSite,
	checkCSPUnsafeInline,
	checkCSPUnsafeEval,
	checkHSTSMaxAge,
	checkHSTSPreload,
	checkClearSiteData,
}

// ─── individual checks ───────────────────────────────────────────────────────

func checkStrictTransportSecurity(rawURL string, code int, headers http.Header) *module.Finding {
	if !isHTTPS(rawURL) {
		return nil // HSTS is irrelevant for HTTP
	}
	hsts := headers.Get("Strict-Transport-Security")
	if hsts == "" {
		return finding(rawURL, "missing-hsts",
			"Strict-Transport-Security header is absent — HTTPS upgrade is not enforced",
			module.SeverityMedium,
			map[string]string{"header": "Strict-Transport-Security"})
	}
	return nil
}

func checkHSTSMaxAge(rawURL string, _ int, headers http.Header) *module.Finding {
	if !isHTTPS(rawURL) {
		return nil
	}
	hsts := headers.Get("Strict-Transport-Security")
	if hsts == "" {
		return nil // already caught by checkStrictTransportSecurity
	}
	maxAge := extractDirectiveValue(hsts, "max-age")
	if maxAge == "" {
		return finding(rawURL, "hsts-no-max-age",
			"HSTS header present but max-age directive is missing",
			module.SeverityMedium,
			map[string]string{"header": "Strict-Transport-Security", "value": hsts})
	}
	// OWASP recommends at least 1 year (31536000 seconds).
	if parseInt(maxAge) < 31536000 {
		return finding(rawURL, "hsts-short-max-age",
			fmt.Sprintf("HSTS max-age=%s is below the recommended 31536000 (1 year)", maxAge),
			module.SeverityLow,
			map[string]string{"header": "Strict-Transport-Security", "max-age": maxAge})
	}
	return nil
}

func checkHSTSPreload(rawURL string, _ int, headers http.Header) *module.Finding {
	if !isHTTPS(rawURL) {
		return nil
	}
	hsts := headers.Get("Strict-Transport-Security")
	if hsts == "" {
		return nil
	}
	if !strings.Contains(strings.ToLower(hsts), "preload") {
		return finding(rawURL, "hsts-no-preload",
			"HSTS header is missing the 'preload' directive — domain cannot be added to browser preload lists",
			module.SeverityInfo,
			map[string]string{"header": "Strict-Transport-Security", "value": hsts})
	}
	return nil
}

func checkContentSecurityPolicy(rawURL string, _ int, headers http.Header) *module.Finding {
	csp := headers.Get("Content-Security-Policy")
	if csp == "" {
		return finding(rawURL, "missing-csp",
			"Content-Security-Policy header is absent — XSS and injection attacks are not mitigated",
			module.SeverityMedium,
			map[string]string{"header": "Content-Security-Policy"})
	}
	return nil
}

func checkCSPUnsafeInline(rawURL string, _ int, headers http.Header) *module.Finding {
	csp := headers.Get("Content-Security-Policy")
	if csp == "" {
		return nil
	}
	if strings.Contains(csp, "'unsafe-inline'") {
		return finding(rawURL, "csp-unsafe-inline",
			"CSP contains 'unsafe-inline' which allows inline scripts/styles — significantly weakens XSS protection",
			module.SeverityMedium,
			map[string]string{"header": "Content-Security-Policy", "value": csp})
	}
	return nil
}

func checkCSPUnsafeEval(rawURL string, _ int, headers http.Header) *module.Finding {
	csp := headers.Get("Content-Security-Policy")
	if csp == "" {
		return nil
	}
	if strings.Contains(csp, "'unsafe-eval'") {
		return finding(rawURL, "csp-unsafe-eval",
			"CSP contains 'unsafe-eval' which allows eval() and similar — enables code injection",
			module.SeverityMedium,
			map[string]string{"header": "Content-Security-Policy", "value": csp})
	}
	return nil
}

func checkXContentTypeOptions(rawURL string, _ int, headers http.Header) *module.Finding {
	val := headers.Get("X-Content-Type-Options")
	if val == "" {
		return finding(rawURL, "missing-x-content-type-options",
			"X-Content-Type-Options: nosniff is absent — browser MIME-sniffing attacks are possible",
			module.SeverityLow,
			map[string]string{"header": "X-Content-Type-Options"})
	}
	if !strings.EqualFold(strings.TrimSpace(val), "nosniff") {
		return finding(rawURL, "invalid-x-content-type-options",
			fmt.Sprintf("X-Content-Type-Options value %q is not 'nosniff'", val),
			module.SeverityLow,
			map[string]string{"header": "X-Content-Type-Options", "value": val})
	}
	return nil
}

func checkXFrameOptions(rawURL string, _ int, headers http.Header) *module.Finding {
	val := strings.ToUpper(strings.TrimSpace(headers.Get("X-Frame-Options")))
	csp := headers.Get("Content-Security-Policy")
	// CSP frame-ancestors is the modern replacement for X-Frame-Options.
	if strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		return nil
	}
	if val == "" {
		return finding(rawURL, "missing-x-frame-options",
			"X-Frame-Options is absent and CSP frame-ancestors is not set — clickjacking attacks are possible",
			module.SeverityMedium,
			map[string]string{"header": "X-Frame-Options"})
	}
	if val != "DENY" && val != "SAMEORIGIN" && !strings.HasPrefix(val, "ALLOW-FROM") {
		return finding(rawURL, "invalid-x-frame-options",
			fmt.Sprintf("X-Frame-Options value %q is not a recognised value (DENY, SAMEORIGIN, ALLOW-FROM)", val),
			module.SeverityLow,
			map[string]string{"header": "X-Frame-Options", "value": val})
	}
	return nil
}

func checkReferrerPolicy(rawURL string, _ int, headers http.Header) *module.Finding {
	val := strings.ToLower(strings.TrimSpace(headers.Get("Referrer-Policy")))
	if val == "" {
		return finding(rawURL, "missing-referrer-policy",
			"Referrer-Policy header is absent — the full URL may be leaked to third parties via the Referer header",
			module.SeverityLow,
			map[string]string{"header": "Referrer-Policy"})
	}
	// Weak policies that leak the full URL.
	weakPolicies := []string{"unsafe-url", "no-referrer-when-downgrade"}
	for _, w := range weakPolicies {
		if val == w {
			return finding(rawURL, "weak-referrer-policy",
				fmt.Sprintf("Referrer-Policy value %q may leak the full URL to external origins", val),
				module.SeverityLow,
				map[string]string{"header": "Referrer-Policy", "value": val})
		}
	}
	return nil
}

func checkPermissionsPolicy(rawURL string, _ int, headers http.Header) *module.Finding {
	// Also accepts the older Feature-Policy header name.
	pp := headers.Get("Permissions-Policy")
	fp := headers.Get("Feature-Policy")
	if pp == "" && fp == "" {
		return finding(rawURL, "missing-permissions-policy",
			"Permissions-Policy header is absent — browser APIs (camera, microphone, geolocation) are not restricted",
			module.SeverityInfo,
			map[string]string{"header": "Permissions-Policy"})
	}
	return nil
}

func checkCacheControlSensitive(_ string, _ int, headers http.Header) *module.Finding {
	// Only flag if Cache-Control is completely absent (not for every URL — too noisy).
	// We specifically look for responses that don't disable caching on what looks
	// like an authenticated endpoint (indicated by Set-Cookie or Authorization).
	// This is a conservative heuristic.
	_ = headers
	return nil // intentionally no-op here; caching auditing belongs in cacheprobe
}

func checkServerInfoLeak(rawURL string, _ int, headers http.Header) *module.Finding {
	server := headers.Get("Server")
	if server == "" {
		return nil
	}
	// Flag when the server header reveals version information.
	if containsVersionNumber(server) {
		return finding(rawURL, "server-version-disclosure",
			fmt.Sprintf("Server header discloses version information: %q", server),
			module.SeverityLow,
			map[string]string{"header": "Server", "value": server})
	}
	return nil
}

func checkXPoweredByLeak(rawURL string, _ int, headers http.Header) *module.Finding {
	val := headers.Get("X-Powered-By")
	if val != "" {
		return finding(rawURL, "x-powered-by-disclosure",
			fmt.Sprintf("X-Powered-By header reveals technology stack: %q", val),
			module.SeverityLow,
			map[string]string{"header": "X-Powered-By", "value": val})
	}
	return nil
}

func checkASPNetVersionLeak(rawURL string, _ int, headers http.Header) *module.Finding {
	val := headers.Get("X-AspNet-Version")
	if val != "" {
		return finding(rawURL, "aspnet-version-disclosure",
			fmt.Sprintf("X-AspNet-Version header discloses .NET version: %q", val),
			module.SeverityLow,
			map[string]string{"header": "X-AspNet-Version", "value": val})
	}
	val2 := headers.Get("X-AspNetMvc-Version")
	if val2 != "" {
		return finding(rawURL, "aspnetmvc-version-disclosure",
			fmt.Sprintf("X-AspNetMvc-Version header discloses MVC version: %q", val2),
			module.SeverityLow,
			map[string]string{"header": "X-AspNetMvc-Version", "value": val2})
	}
	return nil
}

func checkCORSWildcard(rawURL string, _ int, headers http.Header) *module.Finding {
	acao := headers.Get("Access-Control-Allow-Origin")
	if acao == "*" {
		return finding(rawURL, "cors-wildcard",
			"Access-Control-Allow-Origin: * allows any origin to read responses — may expose sensitive data",
			module.SeverityMedium,
			map[string]string{"header": "Access-Control-Allow-Origin", "value": acao})
	}
	return nil
}

func checkAccessControlAllowCredentials(rawURL string, _ int, headers http.Header) *module.Finding {
	acao := strings.TrimSpace(headers.Get("Access-Control-Allow-Origin"))
	acac := strings.ToLower(strings.TrimSpace(headers.Get("Access-Control-Allow-Credentials")))
	if acao == "*" && acac == "true" {
		// Browsers actually block this combination, but flag it as a misconfiguration.
		return finding(rawURL, "cors-credentials-wildcard",
			"Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true is a CORS misconfiguration",
			module.SeverityHigh,
			map[string]string{
				"header": "Access-Control-Allow-Credentials",
				"acao":   acao,
				"acac":   acac,
			})
	}
	return nil
}

func checkSetCookieSecure(rawURL string, _ int, headers http.Header) *module.Finding {
	if !isHTTPS(rawURL) {
		return nil
	}
	for _, cookie := range headers["Set-Cookie"] {
		lower := strings.ToLower(cookie)
		if !strings.Contains(lower, "; secure") && !strings.Contains(lower, ";secure") {
			name := cookieName(cookie)
			return finding(rawURL, "cookie-missing-secure",
				fmt.Sprintf("Set-Cookie for %q is missing the Secure flag — cookie may be sent over HTTP", name),
				module.SeverityMedium,
				map[string]string{"header": "Set-Cookie", "cookie": name})
		}
	}
	return nil
}

func checkSetCookieHttpOnly(_ string, _ int, headers http.Header) *module.Finding {
	for _, cookie := range headers["Set-Cookie"] {
		lower := strings.ToLower(cookie)
		if !strings.Contains(lower, "; httponly") && !strings.Contains(lower, ";httponly") {
			name := cookieName(cookie)
			return finding("", "cookie-missing-httponly",
				fmt.Sprintf("Set-Cookie for %q is missing the HttpOnly flag — cookie is accessible via JavaScript", name),
				module.SeverityMedium,
				map[string]string{"header": "Set-Cookie", "cookie": name})
		}
	}
	return nil
}

func checkSetCookieSameSite(_ string, _ int, headers http.Header) *module.Finding {
	for _, cookie := range headers["Set-Cookie"] {
		lower := strings.ToLower(cookie)
		if !strings.Contains(lower, "samesite=") {
			name := cookieName(cookie)
			return finding("", "cookie-missing-samesite",
				fmt.Sprintf("Set-Cookie for %q is missing the SameSite attribute — CSRF risk", name),
				module.SeverityLow,
				map[string]string{"header": "Set-Cookie", "cookie": name})
		}
	}
	return nil
}

func checkClearSiteData(rawURL string, _ int, headers http.Header) *module.Finding {
	// Only relevant for logout endpoints — skip for now (false-positive prone without context).
	_ = rawURL
	_ = headers
	return nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func finding(rawURL, checkID, detail string, sev module.Severity, extra map[string]string) *module.Finding {
	if extra == nil {
		extra = make(map[string]string)
	}
	extra["check"] = checkID
	if _, ok := extra["confidence"]; !ok {
		extra["confidence"] = "0.95" // header absent or value confirmed in response — deterministic check
	}
	return &module.Finding{
		Type:     "security_header",
		URL:      rawURL,
		Detail:   detail,
		Severity: sev,
		Extra:    extra,
	}
}

func collectURLs(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	if input.Target != "" {
		add(input.Target)
	}
	for _, u := range input.URLs {
		add(u)
	}
	if input.RawContent != "" {
		for _, line := range strings.Split(input.RawContent, "\n") {
			add(line)
		}
	}
	return out
}

func isHTTPS(rawURL string) bool {
	return strings.HasPrefix(strings.ToLower(rawURL), "https://")
}

// extractDirectiveValue returns the value of a semicolon-separated directive,
// e.g. extractDirectiveValue("max-age=31536000; includeSubDomains", "max-age") → "31536000".
func extractDirectiveValue(header, directive string) string {
	lower := strings.ToLower(header)
	dir := strings.ToLower(directive) + "="
	idx := strings.Index(lower, dir)
	if idx == -1 {
		return ""
	}
	rest := header[idx+len(dir):]
	if i := strings.IndexAny(rest, " ;,"); i >= 0 {
		return strings.TrimSpace(rest[:i])
	}
	return strings.TrimSpace(rest)
}

// parseInt parses a decimal string, returning 0 on error.
func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// containsVersionNumber returns true if the string contains a version-like token
// (e.g. "Apache/2.4.51", "nginx/1.21.6", "PHP/8.1.0").
func containsVersionNumber(s string) bool {
	// A version is: slash + digit, or digit.digit, or digit/digit.
	prevSlash := false
	for i, c := range s {
		if c == '/' {
			prevSlash = true
			continue
		}
		if prevSlash && c >= '0' && c <= '9' {
			return true
		}
		prevSlash = false
		if c == '.' && i > 0 && i < len(s)-1 {
			prev := rune(s[i-1])
			next := rune(s[i+1])
			if prev >= '0' && prev <= '9' && next >= '0' && next <= '9' {
				return true
			}
		}
	}
	return false
}

// cookieName extracts the cookie name from a Set-Cookie header value.
func cookieName(cookie string) string {
	if i := strings.IndexByte(cookie, '='); i > 0 {
		return strings.TrimSpace(cookie[:i])
	}
	return cookie
}
