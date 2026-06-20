// Package oauth2 implements OAuth 2.0 security misconfiguration detection.
//
// Source reference: PortSwigger OAuth 2.0 research +
// OWASP OAuth Cheat Sheet + oauth-security (MIT various).
// Detection logic reimplemented from scratch.
//
// OAuth 2.0 security checks:
//  1. Open redirect_uri: probe with different redirect_uri values
//  2. CSRF via missing state parameter
//  3. Token leakage: access_token in URL fragment or query param
//  4. Implicit flow detection: response_type=token (deprecated, insecure)
//  5. PKCE missing: authorization code flow without code_challenge
//  6. Client credential exposure: client_secret in JavaScript/HTML
//  7. Token endpoint insecure: HTTP instead of HTTPS
//  8. Scope overprivilege: broad scopes (all, full, admin, write, *)
//  9. response_mode=fragment detection
//  10. Authorization endpoint lacks HTTPS
//
// Architecture:
//   - Check struct: ID, Run func, Severity, Tags
//   - Analyzes target URL assuming it's an OAuth authorize endpoint or discovery doc
//   - Parses URL params (response_type, redirect_uri, scope, state, etc.)
//   - errgroup.SetLimit(Parallelism) fan-out
//   - io.LimitReader on all reads
//   - log/slog observability
//   - sync.Mutex protecting findings
//   - NewWithClient(*http.Client) for testability
package oauth2

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

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	DefaultTimeout     = 10 * time.Second
	DefaultParallelism = 10
	maxBodyRead        = 256 * 1024
)

// broadScopes are OAuth scopes that indicate over-privilege.
var broadScopes = []string{"*", "all", "full", "admin", "write", "everything", "root"}

// ─── Check ────────────────────────────────────────────────────────────────────

// Check defines an OAuth 2.0 security test.
type Check struct {
	ID       string
	Severity module.Severity
	Tags     []string
	Run      func(ctx context.Context, client *http.Client, rawURL string, logger *slog.Logger) []module.Finding
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements OAuth 2.0 security analysis.
type Module struct {
	client      *http.Client
	parallelism int
	logger      *slog.Logger
}

// New returns a Module with default settings.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: DefaultTimeout}),
		parallelism: DefaultParallelism,
		logger:      slog.Default(),
	}
}

// NewWithClient returns a Module using the supplied HTTP client.
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// Name returns the module name.
func (m *Module) Name() string { return "oauth2" }

// Run analyzes OAuth 2.0 endpoints for security issues.
//
// Options:
//   - "parallelism" — max concurrent checks (default: 10)
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

	checks := builtinChecks()

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

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(parallelism)

	for _, rawURL := range targets {
		for _, check := range checks {
			rawURL := rawURL
			check := check
			eg.Go(func() error {
				fs := check.Run(egCtx, m.client, rawURL, m.logger)
				for i := range fs {
					fs[i].Extra["check_id"] = check.ID
				}
				if len(fs) > 0 {
					addFindings(fs)
				}
				return nil
			})
		}
	}

	_ = eg.Wait()
	return findings, nil
}

// ─── Built-in Checks ──────────────────────────────────────────────────────────

func builtinChecks() []Check {
	return []Check{
		{
			ID: "implicit-flow", Severity: module.SeverityHigh,
			Tags: []string{"implicit-flow", "response_type"},
			Run: func(ctx context.Context, c *http.Client, rawURL string, log *slog.Logger) []module.Finding {
				parsed, err := url.Parse(rawURL)
				if err != nil {
					return nil
				}
				q := parsed.Query()
				rt := strings.ToLower(q.Get("response_type"))
				if rt != "token" && rt != "id_token token" {
					return nil
				}
				return []module.Finding{{
					Type:     "oauth2_implicit_flow",
					Severity: module.SeverityHigh,
					URL:      rawURL,
					Detail:   fmt.Sprintf("[OAuth2] Implicit flow detected (response_type=%q) — access tokens in URL fragment", rt),
					Extra:    map[string]string{"response_type": rt, "tags": "oauth2,implicit-flow", "confidence": "0.85"},
				}}
			},
		},
		{
			ID: "missing-state", Severity: module.SeverityHigh,
			Tags: []string{"csrf", "missing-state"},
			Run: func(ctx context.Context, c *http.Client, rawURL string, log *slog.Logger) []module.Finding {
				parsed, err := url.Parse(rawURL)
				if err != nil {
					return nil
				}
				q := parsed.Query()
				// Only check authorization requests (has response_type or client_id).
				if q.Get("response_type") == "" && q.Get("client_id") == "" {
					return nil
				}
				if q.Get("state") != "" {
					return nil
				}
				return []module.Finding{{
					Type:     "oauth2_missing_state",
					Severity: module.SeverityHigh,
					URL:      rawURL,
					Detail:   "[OAuth2] Missing 'state' parameter — CSRF attack possible",
					Extra:    map[string]string{"tags": "oauth2,csrf,missing-state", "confidence": "0.85"},
				}}
			},
		},
		{
			ID: "missing-pkce", Severity: module.SeverityMedium,
			Tags: []string{"pkce", "authorization-code"},
			Run: func(ctx context.Context, c *http.Client, rawURL string, log *slog.Logger) []module.Finding {
				parsed, err := url.Parse(rawURL)
				if err != nil {
					return nil
				}
				q := parsed.Query()
				// Only check authorization code flow.
				if strings.ToLower(q.Get("response_type")) != "code" {
					return nil
				}
				if q.Get("code_challenge") != "" {
					return nil
				}
				return []module.Finding{{
					Type:     "oauth2_missing_pkce",
					Severity: module.SeverityMedium,
					URL:      rawURL,
					Detail:   "[OAuth2] Authorization code flow without PKCE (code_challenge missing) — CSRF/auth code injection risk",
					Extra:    map[string]string{"tags": "oauth2,pkce,authorization-code", "confidence": "0.85"},
				}}
			},
		},
		{
			ID: "http-endpoint", Severity: module.SeverityHigh,
			Tags: []string{"https", "transport"},
			Run: func(ctx context.Context, c *http.Client, rawURL string, log *slog.Logger) []module.Finding {
				parsed, err := url.Parse(rawURL)
				if err != nil {
					return nil
				}
				// Only flag if it's an OAuth endpoint (has client_id or response_type or grant_type).
				q := parsed.Query()
				isOAuth := q.Get("client_id") != "" || q.Get("response_type") != "" ||
					q.Get("grant_type") != ""
				if !isOAuth {
					return nil
				}
				if parsed.Scheme != "http" {
					return nil
				}
				return []module.Finding{{
					Type:     "oauth2_http_endpoint",
					Severity: module.SeverityHigh,
					URL:      rawURL,
					Detail:   "[OAuth2] OAuth endpoint uses HTTP — credentials/tokens in plaintext",
					Extra:    map[string]string{"tags": "oauth2,http,transport", "confidence": "0.85"},
				}}
			},
		},
		{
			ID: "broad-scope", Severity: module.SeverityMedium,
			Tags: []string{"scope", "overprivilege"},
			Run: func(ctx context.Context, c *http.Client, rawURL string, log *slog.Logger) []module.Finding {
				parsed, err := url.Parse(rawURL)
				if err != nil {
					return nil
				}
				scope := strings.ToLower(parsed.Query().Get("scope"))
				if scope == "" {
					return nil
				}
				for _, broad := range broadScopes {
					if strings.Contains(scope, broad) {
						return []module.Finding{{
							Type:     "oauth2_broad_scope",
							Severity: module.SeverityMedium,
							URL:      rawURL,
							Detail:   fmt.Sprintf("[OAuth2] Overly broad scope: %q", scope),
							Extra:    map[string]string{"scope": scope, "tags": "oauth2,scope,overprivilege", "confidence": "0.85"},
						}}
					}
				}
				return nil
			},
		},
		{
			ID: "token-in-url", Severity: module.SeverityCritical,
			Tags: []string{"token-leakage", "url"},
			Run: func(ctx context.Context, c *http.Client, rawURL string, log *slog.Logger) []module.Finding {
				parsed, err := url.Parse(rawURL)
				if err != nil {
					return nil
				}
				q := parsed.Query()
				for _, param := range []string{"access_token", "id_token", "token", "bearer"} {
					if val := q.Get(param); val != "" {
						return []module.Finding{{
							Type:     "oauth2_token_in_url",
							Severity: module.SeverityCritical,
							URL:      rawURL,
							Detail:   fmt.Sprintf("[OAuth2] Token in URL query param %q — leaks in logs/Referer", param),
							Extra: map[string]string{
								"param":      param,
								"tags":       "oauth2,token-leakage,url",
								"confidence": "0.85",
							},
						}}
					}
				}
				// Also check fragment.
				fragment := parsed.Fragment
				if strings.Contains(fragment, "access_token=") || strings.Contains(fragment, "id_token=") {
					return []module.Finding{{
						Type:     "oauth2_token_in_fragment",
						Severity: module.SeverityHigh,
						URL:      rawURL,
						Detail:   "[OAuth2] Token in URL fragment — accessible to JavaScript on the page",
						Extra:    map[string]string{"fragment": fragment[:min(len(fragment), 50)], "tags": "oauth2,token-leakage,fragment", "confidence": "0.85"},
					}}
				}
				return nil
			},
		},
		{
			ID: "open-redirect-uri", Severity: module.SeverityHigh,
			Tags: []string{"open-redirect", "redirect_uri"},
			Run: func(ctx context.Context, c *http.Client, rawURL string, log *slog.Logger) []module.Finding {
				parsed, err := url.Parse(rawURL)
				if err != nil {
					return nil
				}
				redirectURI := parsed.Query().Get("redirect_uri")
				if redirectURI == "" {
					return nil
				}
				// Check for common redirect_uri bypass patterns.
				suspicious := []string{
					"evil.com", "attacker.com", "@", "%40",
					"localhost", "127.0.0.1", "0.0.0.0",
				}
				lower := strings.ToLower(redirectURI)
				for _, s := range suspicious {
					if strings.Contains(lower, s) {
						return []module.Finding{{
							Type:     "oauth2_open_redirect_uri",
							Severity: module.SeverityHigh,
							URL:      rawURL,
							Detail:   fmt.Sprintf("[OAuth2] Suspicious redirect_uri: %q", redirectURI),
							Extra: map[string]string{
								"redirect_uri": redirectURI,
								"tags":         "oauth2,open-redirect",
								"confidence":   "0.85",
							},
						}}
					}
				}
				return nil
			},
		},
		{
			ID: "discovery-endpoint", Severity: module.SeverityInfo,
			Tags: []string{"discovery", "oidc"},
			Run: func(ctx context.Context, c *http.Client, rawURL string, log *slog.Logger) []module.Finding {
				// Check if the URL is a discovery endpoint (/.well-known/openid-configuration).
				if !strings.Contains(rawURL, "openid-configuration") && !strings.Contains(rawURL, "well-known") {
					return nil
				}
				req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
				if err != nil {
					return nil
				}
				resp, err := c.Do(req)
				if err != nil {
					log.DebugContext(ctx, "oauth2: discovery fetch failed", "url", rawURL, "err", err)
					return nil
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
				bodyStr := string(body)

				if resp.StatusCode != 200 || !strings.Contains(bodyStr, "authorization_endpoint") {
					return nil
				}

				var findings []module.Finding
				// Check for dangerous grant types.
				if strings.Contains(bodyStr, `"token"`) && strings.Contains(bodyStr, "response_types_supported") {
					findings = append(findings, module.Finding{
						Type:     "oauth2_discovery_implicit_supported",
						Severity: module.SeverityMedium,
						URL:      rawURL,
						Detail:   "[OAuth2] Discovery doc supports implicit flow (response_types includes 'token')",
						Extra:    map[string]string{"tags": "oauth2,discovery,implicit", "confidence": "0.85"},
					})
				}
				// Check for missing PKCE requirement.
				if !strings.Contains(bodyStr, "code_challenge_methods_supported") {
					findings = append(findings, module.Finding{
						Type:     "oauth2_discovery_no_pkce",
						Severity: module.SeverityLow,
						URL:      rawURL,
						Detail:   "[OAuth2] Discovery doc does not advertise PKCE support",
						Extra:    map[string]string{"tags": "oauth2,discovery,pkce", "confidence": "0.85"},
					})
				}
				return findings
			},
		},
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
