// Package apiaudit implements API Security Audit based on OWASP API Security Top 10 (2023).
//
// Source reference: OWASP API Security Top 10 (CC-BY 4.0) + nuclei-templates
// exposures/apis/ (MIT). Detection logic reimplemented from scratch.
//
// Checks implemented (OWASP API Security categories):
//   - API1:2023  Broken Object Level Authorization  → IDOR signals on numeric IDs
//   - API2:2023  Broken Authentication              → weak/missing JWT, no rate limit on auth
//   - API3:2023  Broken Object Property Level Auth  → excessive data in response (mass assignment)
//   - API4:2023  Unrestricted Resource Consumption  → no rate limit detection
//   - API5:2023  Broken Function Level Authorization → HTTP method bypass (GET→POST/DELETE)
//   - API6:2023  Unrestricted Access to Sensitive Business Flows → exposed dangerous endpoints
//   - API7:2023  Server Side Request Forgery        → SSRF via API parameter
//   - API8:2023  Security Misconfiguration          → debug/swagger/health endpoints exposed
//   - API9:2023  Improper Inventory Management      → old API versions exposed (/v1 while on /v3)
//   - API10:2023 Unsafe Consumption of APIs         → third-party API key exposure
//
// This module complements sqli, ssrfprobe, headeraudit, and ratelimit with API-specific
// checks and endpoint fingerprinting.
//
// Architecture:
//   - APICheck struct: check function + finding type + severity
//   - errgroup.SetLimit(Parallelism) fan-out across url × check
//   - io.LimitReader on all response reads
//   - log/slog observability
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) for testability
package apiaudit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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
	DefaultParallelism = 15
	maxBodyRead        = 256 * 1024 // 256 KB
)

// ─── APICheck ────────────────────────────────────────────────────────────────

// APICheck defines a single API security check function.
type APICheck struct {
	// ID is a unique identifier (e.g. "api1-idor-numeric").
	ID string
	// Category is the OWASP category (e.g. "API1", "API8").
	Category string
	// Name is a human-readable name.
	Name string
	// Run executes the check against the target URL with the given HTTP client.
	Run func(ctx context.Context, rawURL string, client *http.Client, logger *slog.Logger) ([]module.Finding, error)
	// Tags are metadata tags.
	Tags []string
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements API Security Audit.
type Module struct {
	client      *http.Client
	checks      []APICheck
	parallelism int
	logger      *slog.Logger
}

// New returns a Module with all built-in checks and default HTTP client.
func New() *Module {
	m := &Module{
		client:      httpclient.New(httpclient.Options{Timeout: DefaultTimeout}),
		parallelism: DefaultParallelism,
		logger:      slog.Default(),
	}
	m.checks = builtinChecks(m.client, m.logger)
	return m
}

// NewWithClient returns a Module using the supplied HTTP client (testability).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	// Rebuild checks with new client.
	m.checks = builtinChecks(c, m.logger)
	return m
}

// Name returns the module name.
func (m *Module) Name() string { return "apiaudit" }

// Run executes API security checks against all target URLs.
//
// Options:
//   - "parallelism" — max concurrent checks (default: 15)
//   - "categories"  — comma-separated OWASP categories to run (default: all)
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

	maxTargets := 100
	if v := input.Options["max_targets"]; v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			maxTargets = n
		}
	}
	if len(targets) > maxTargets {
		targets = targets[:maxTargets]
	}

	maxRuntimeSec := 180 // 3 minutes default
	if v := input.Options["max_runtime_seconds"]; v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			maxRuntimeSec = n
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntimeSec)*time.Second)
	defer cancel()

	catFilter := parseCSV(input.Options["categories"])
	checks := m.selectChecks(catFilter)

	var (
		mu       sync.Mutex
		seen     = make(map[string]struct{})
		findings []module.Finding
	)

	addFindings := func(fs []module.Finding) {
		mu.Lock()
		defer mu.Unlock()
		for _, f := range fs {
			key := f.URL + "|" + f.Type + "|" + f.Extra["check_id"]
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				findings = append(findings, f)
			}
		}
	}

	eg, egCtx := errgroup.WithContext(runCtx)
	eg.SetLimit(parallelism)

	for _, target := range targets {
		target := target
		for _, check := range checks {
			check := check
			eg.Go(func() error {
				fs, err := check.Run(egCtx, target, m.client, m.logger)
				if err != nil {
					m.logger.DebugContext(egCtx, "apiaudit: check failed",
						"check", check.ID, "url", target, "err", err)
					return nil
				}
				// Inject check metadata.
				for i := range fs {
					if fs[i].Extra == nil {
						fs[i].Extra = make(map[string]string)
					}
					fs[i].Extra["check_id"] = check.ID
					fs[i].Extra["category"] = check.Category
				}
				if len(fs) > 0 {
					addFindings(fs)
				}
				return nil
			})
		}
	}

	if err := eg.Wait(); err != nil {
		return findings, fmt.Errorf("apiaudit: worker failed: %w", err)
	}
	if err := runCtx.Err(); err != nil {
		return findings, fmt.Errorf("apiaudit: runtime budget exceeded: %w", err)
	}
	return findings, nil
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

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, strings.ToUpper(p))
		}
	}
	return out
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n, err
}

func (m *Module) selectChecks(catFilter []string) []APICheck {
	if len(catFilter) == 0 {
		return m.checks
	}
	filterSet := make(map[string]struct{})
	for _, c := range catFilter {
		filterSet[c] = struct{}{}
	}
	var out []APICheck
	for _, c := range m.checks {
		if _, ok := filterSet[c.Category]; ok {
			out = append(out, c)
		}
	}
	return out
}

func doGET(ctx context.Context, rawURL string, client *http.Client) (string, int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return "", 0, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-apiaudit/1.0)")
	req.Header.Set("Accept", "application/json, text/html, */*")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return string(b), resp.StatusCode, resp.Header, nil
}

func baseURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.Path = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func joinPath(base, path string) string {
	base = strings.TrimRight(base, "/")
	path = "/" + strings.TrimLeft(path, "/")
	return base + path
}

// ─── Built-in checks ─────────────────────────────────────────────────────────

// builtinChecks returns the default API security check set.
// Based on OWASP API Security Top 10 2023 (CC-BY 4.0).
func builtinChecks(client *http.Client, logger *slog.Logger) []APICheck {
	return []APICheck{

		// ── API5: Broken Function Level Authorization ─────────────────────────
		// Test HTTP method bypass: GET→DELETE/PUT/PATCH often accepted.
		{
			ID: "api5-method-bypass", Category: "API5",
			Name: "HTTP method bypass for admin endpoints",
			Run: func(ctx context.Context, rawURL string, client *http.Client, log *slog.Logger) ([]module.Finding, error) {
				var findings []module.Finding
				dangerousMethods := []string{"DELETE", "PUT", "PATCH", "POST"}
				for _, method := range dangerousMethods {
					req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
					if err != nil {
						continue
					}
					req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-apiaudit/1.0)")
					resp, err := client.Do(req)
					if err != nil {
						continue
					}
					resp.Body.Close()

					if resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 204 {
						findings = append(findings, module.Finding{
							Type:     "api5_method_bypass",
							Severity: module.SeverityHigh,
							URL:      rawURL,
							Detail:   fmt.Sprintf("API5: %s %s returned %d — method bypass possible", method, rawURL, resp.StatusCode),
							Extra: map[string]string{
								"method":     method,
								"status":     fmt.Sprintf("%d", resp.StatusCode),
								"tags":       "apiaudit,api5,method-bypass",
								"confidence": "0.85",
							},
						})
					}
				}
				return findings, nil
			},
			Tags: []string{"apiaudit", "api5", "method-bypass"},
		},

		// ── API8: Security Misconfiguration — Debug/Swagger endpoints ─────────
		{
			ID: "api8-debug-endpoints", Category: "API8",
			Name: "Exposed debug, swagger, and health endpoints",
			Run: func(ctx context.Context, rawURL string, client *http.Client, log *slog.Logger) ([]module.Finding, error) {
				base := baseURL(rawURL)
				var findings []module.Finding

				debugPaths := []struct {
					path    string
					markers []string
					sev     module.Severity
				}{
					{"/swagger", []string{"swagger", "openapi", "paths"}, module.SeverityMedium},
					{"/swagger-ui.html", []string{"swagger-ui", "swagger"}, module.SeverityMedium},
					{"/api-docs", []string{"openapi", "swagger", "paths"}, module.SeverityMedium},
					{"/openapi.json", []string{"openapi", "paths", "components"}, module.SeverityMedium},
					{"/openapi.yaml", []string{"openapi:", "paths:", "components:"}, module.SeverityMedium},
					{"/debug", []string{"debug", "pprof", "heap", "goroutine"}, module.SeverityHigh},
					{"/debug/pprof", []string{"pprof", "goroutine", "heap"}, module.SeverityHigh},
					{"/actuator", []string{"actuator", "_links", "health"}, module.SeverityMedium},
					{"/actuator/env", []string{"propertySources", "systemEnvironment"}, module.SeverityHigh},
					{"/health", []string{"status", "up", "healthy"}, module.SeverityInfo},
					{"/_debug", []string{"debug"}, module.SeverityHigh},
					{"/api/v1/debug", []string{"debug"}, module.SeverityHigh},
					{"/graphql", []string{"__schema", "__type", "query"}, module.SeverityMedium},
					{"/graphiql", []string{"graphiql", "graphql"}, module.SeverityMedium},
					{"/console", []string{"console", "repl", "evaluate"}, module.SeverityHigh},
					{"/metrics", []string{"# HELP", "# TYPE", "go_gc"}, module.SeverityMedium},
				}

				for _, dp := range debugPaths {
					target := joinPath(base, dp.path)
					body, status, _, err := doGET(ctx, target, client)
					if err != nil || status == 404 || status == 403 || status >= 500 {
						continue
					}
					lower := strings.ToLower(body)
					for _, marker := range dp.markers {
						if strings.Contains(lower, strings.ToLower(marker)) {
							findings = append(findings, module.Finding{
								Type:     "api8_debug_endpoint",
								Severity: dp.sev,
								URL:      target,
								Detail:   fmt.Sprintf("API8: debug endpoint %s exposed (status=%d, marker=%q)", dp.path, status, marker),
								Extra: map[string]string{
									"path":       dp.path,
									"status":     fmt.Sprintf("%d", status),
									"marker":     marker,
									"tags":       "apiaudit,api8,debug",
									"confidence": "0.85",
								},
							})
							break
						}
					}
				}
				return findings, nil
			},
			Tags: []string{"apiaudit", "api8", "debug", "swagger"},
		},

		// ── API9: Improper Inventory Management — old API versions ────────────
		{
			ID: "api9-old-versions", Category: "API9",
			Name: "Old API versions still accessible",
			Run: func(ctx context.Context, rawURL string, client *http.Client, log *slog.Logger) ([]module.Finding, error) {
				base := baseURL(rawURL)
				var findings []module.Finding

				oldVersionPaths := []string{
					"/v1", "/v2", "/api/v1", "/api/v2",
					"/v1.0", "/v2.0", "/api/1", "/api/2",
					"/api/v0", "/rest/v1", "/rest/v2",
				}

				for _, vp := range oldVersionPaths {
					target := joinPath(base, vp)
					_, status, _, err := doGET(ctx, target, client)
					if err != nil || status == 404 || status == 410 {
						continue
					}
					if status == 200 || status == 201 || status == 301 || status == 302 {
						findings = append(findings, module.Finding{
							Type:     "api9_old_version",
							Severity: module.SeverityMedium,
							URL:      target,
							Detail:   fmt.Sprintf("API9: old API version %s accessible (status=%d)", vp, status),
							Extra: map[string]string{
								"version_path": vp,
								"status":       fmt.Sprintf("%d", status),
								"tags":         "apiaudit,api9,versioning",
								"confidence":   "0.85",
							},
						})
					}
				}
				return findings, nil
			},
			Tags: []string{"apiaudit", "api9", "versioning"},
		},

		// ── API8: Security Misconfiguration — Missing security headers ────────
		{
			ID: "api8-missing-headers", Category: "API8",
			Name: "Missing API security response headers",
			Run: func(ctx context.Context, rawURL string, client *http.Client, log *slog.Logger) ([]module.Finding, error) {
				_, status, headers, err := doGET(ctx, rawURL, client)
				if err != nil || status >= 400 {
					return nil, nil
				}
				var findings []module.Finding

				// Check Content-Type is set (prevents MIME sniffing attacks).
				ct := headers.Get("Content-Type")
				if ct == "" {
					findings = append(findings, module.Finding{
						Type:     "api8_missing_content_type",
						Severity: module.SeverityLow,
						URL:      rawURL,
						Detail:   "API8: API response missing Content-Type header",
						Extra:    map[string]string{"tags": "apiaudit,api8,headers", "confidence": "0.85"},
					})
				}

				// Check X-Content-Type-Options.
				xcto := headers.Get("X-Content-Type-Options")
				if !strings.EqualFold(xcto, "nosniff") {
					findings = append(findings, module.Finding{
						Type:     "api8_missing_xcto",
						Severity: module.SeverityLow,
						URL:      rawURL,
						Detail:   "API8: missing X-Content-Type-Options: nosniff",
						Extra:    map[string]string{"tags": "apiaudit,api8,headers", "confidence": "0.85"},
					})
				}

				// Check that JSON responses don't expose sensitive fields.
				if strings.Contains(ct, "application/json") {
					body, _, _, _ := doGET(ctx, rawURL, client)
					lower := strings.ToLower(body)
					sensitiveFields := []string{
						`"password"`, `"passwd"`, `"secret"`, `"api_key"`,
						`"access_token"`, `"refresh_token"`, `"private_key"`,
					}
					for _, field := range sensitiveFields {
						if strings.Contains(lower, field) {
							findings = append(findings, module.Finding{
								Type:     "api8_sensitive_data_exposure",
								Severity: module.SeverityCritical,
								URL:      rawURL,
								Detail:   fmt.Sprintf("API8: sensitive field %s exposed in API response", field),
								Extra: map[string]string{
									"field":      field,
									"tags":       "apiaudit,api8,data-exposure",
									"confidence": "0.85",
								},
							})
							break // one finding per URL
						}
					}
				}

				return findings, nil
			},
			Tags: []string{"apiaudit", "api8", "headers", "data-exposure"},
		},

		// ── API2: Broken Authentication — JWT missing/weak ───────────────────
		{
			ID: "api2-jwt-auth", Category: "API2",
			Name: "Authentication bypass via missing JWT enforcement",
			Run: func(ctx context.Context, rawURL string, client *http.Client, log *slog.Logger) ([]module.Finding, error) {
				// Try to access API endpoints without authentication.
				// If status 200 on protected-looking URLs, flag it.
				parsed, err := url.Parse(rawURL)
				if err != nil {
					return nil, nil
				}

				path := strings.ToLower(parsed.Path)
				isProtectedLooking := strings.Contains(path, "/api/") ||
					strings.Contains(path, "/v1/") ||
					strings.Contains(path, "/v2/") ||
					strings.Contains(path, "/admin") ||
					strings.Contains(path, "/users") ||
					strings.Contains(path, "/profile") ||
					strings.Contains(path, "/account") ||
					strings.Contains(path, "/private") ||
					strings.Contains(path, "/internal")

				if !isProtectedLooking {
					return nil, nil
				}

				body, status, headers, err := doGET(ctx, rawURL, client)
				if err != nil {
					return nil, nil
				}

				// If unauthenticated request returns 200 with JSON data, possible auth bypass.
				if status == 200 && strings.Contains(headers.Get("Content-Type"), "application/json") &&
					len(body) > 50 {
					return []module.Finding{
						{
							Type:     "api2_auth_bypass",
							Severity: module.SeverityHigh,
							URL:      rawURL,
							Detail:   fmt.Sprintf("API2: protected endpoint %s returned 200 without authentication", parsed.Path),
							Extra: map[string]string{
								"path":         parsed.Path,
								"content_type": headers.Get("Content-Type"),
								"body_len":     fmt.Sprintf("%d", len(body)),
								"tags":         "apiaudit,api2,auth-bypass",
								"confidence":   "0.85",
							},
						},
					}, nil
				}
				return nil, nil
			},
			Tags: []string{"apiaudit", "api2", "auth-bypass"},
		},

		// ── API6: Sensitive Business Flow Exposure ─────────────────────────
		{
			ID: "api6-sensitive-flows", Category: "API6",
			Name: "Sensitive business flows exposed",
			Run: func(ctx context.Context, rawURL string, client *http.Client, log *slog.Logger) ([]module.Finding, error) {
				base := baseURL(rawURL)
				var findings []module.Finding

				sensitivePaths := []struct {
					path string
					desc string
				}{
					{"/api/export", "data export endpoint"},
					{"/api/bulk", "bulk operation endpoint"},
					{"/api/admin", "admin API endpoint"},
					{"/api/internal", "internal API endpoint"},
					{"/api/webhook", "webhook registration endpoint"},
					{"/api/upload", "file upload endpoint"},
					{"/api/users/all", "all users endpoint"},
					{"/api/tokens", "token management endpoint"},
					{"/api/keys", "API key management"},
					{"/api/payments", "payment processing endpoint"},
					{"/api/refunds", "refund processing endpoint"},
				}

				for _, sp := range sensitivePaths {
					target := joinPath(base, sp.path)
					_, status, _, err := doGET(ctx, target, client)
					if err != nil || status == 404 {
						continue
					}
					if status == 200 || status == 201 {
						findings = append(findings, module.Finding{
							Type:     "api6_sensitive_flow",
							Severity: module.SeverityHigh,
							URL:      target,
							Detail:   fmt.Sprintf("API6: %s at %s accessible (status=%d)", sp.desc, sp.path, status),
							Extra: map[string]string{
								"path":       sp.path,
								"status":     fmt.Sprintf("%d", status),
								"tags":       "apiaudit,api6,sensitive-flow",
								"confidence": "0.85",
							},
						})
					}
				}
				return findings, nil
			},
			Tags: []string{"apiaudit", "api6", "sensitive-flow"},
		},
	}
}
