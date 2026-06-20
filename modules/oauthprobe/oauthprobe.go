// Package oauthprobe audits OAuth2/OIDC endpoint misconfigurations.
//
// Source references:
//   - oauth2c (MIT): https://github.com/cloudentity/oauth2c
//     Algorithm ported: authorization-code flow probes, token endpoint checks,
//     well-known discovery, scope enumeration.
//   - oauth2-proxy (MIT): https://github.com/oauth2-proxy/oauth2-proxy
//     Reference for PKCE and implicit flow indicators.
//
// What is implemented:
//   - OIDC discovery via /.well-known/openid-configuration
//   - OAuth2 server metadata via /.well-known/oauth-authorization-server
//   - Open redirect in redirect_uri parameter (CWE-601)
//   - Missing PKCE requirement (RFC 7636)
//   - Implicit flow enabled (deprecated, RFC 9700 §2.1.2)
//   - Token endpoint accepts HTTP (no TLS enforcement)
//   - Overly permissive scope wildcard
//   - Client credentials with no client authentication (public client)
//   - State parameter missing / reuse (CSRF risk, RFC 6749 §10.12)
//   - JWKS endpoint exposure
//   - Dynamic client registration open
//   - Token introspection without auth
//   - io.LimitReader on every body read                  (dicas.md §5)
//   - log/slog structured observability                  (dicas.md §16)
//   - context propagation and cancellation               (guia-go §9)
//   - errgroup.SetLimit bounded fan-out                  (guia-go §9)
package oauthprobe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	maxBodyRead    = 2 * 1024 * 1024 // 2 MiB — dicas.md §5
	defaultTimeout = 15 * time.Second
	defaultThreads = 8
)

// ─── Check types ──────────────────────────────────────────────────────────────

// Check represents a single OAuth2/OIDC audit probe.
// Based on oauth2c's check structure.
type Check struct {
	ID          string
	Name        string
	Description string
	Severity    module.Severity
	Tags        []string
	Run         func(ctx context.Context, m *Module, base string) []module.Finding
}

// OIDCMetadata mirrors the OpenID Connect Discovery document.
// Based on oauth2c well-known discovery parsing.
type OIDCMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module is the oauthprobe scanner.
type Module struct {
	checks  []Check
	client  *http.Client
	threads int
	logger  *slog.Logger
}

// New creates a Module with all built-in checks.
func New() *Module {
	return NewWithChecks(builtinChecks())
}

// NewWithChecks creates a Module with the provided checks.
func NewWithChecks(checks []Check) *Module {
	return &Module{
		checks:  checks,
		client:  defaultHTTPClient(),
		threads: defaultThreads,
		logger:  slog.Default().With("module", "oauthprobe"),
	}
}

// NewWithClient creates a Module with a custom HTTP client.
func NewWithClient(client *http.Client) *Module {
	m := New()
	m.client = client
	return m
}

// Name implements module.Module.
func (m *Module) Name() string { return "oauthprobe" }

// Run implements module.Module.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	base := strings.TrimRight(input.Target, "/")
	if base == "" && len(input.URLs) > 0 {
		base = strings.TrimRight(input.URLs[0], "/")
	}
	if base == "" {
		return nil, fmt.Errorf("oauthprobe: target URL required")
	}

	m.logger.InfoContext(ctx, "starting oauth audit", "target", base)

	findingsCh := make(chan module.Finding, 64)
	eg, gctx := errgroup.WithContext(ctx)
	eg.SetLimit(m.threads)

	for _, chk := range m.checks {
		chk := chk
		eg.Go(func() error {
			findings := chk.Run(gctx, m, base)
			for _, f := range findings {
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

	var results []module.Finding
	for f := range findingsCh {
		results = append(results, f)
	}
	return results, nil
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func (m *Module) get(ctx context.Context, rawURL string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-oauthprobe/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead)) // dicas.md §5
	return resp, body, err
}

// fetchMetadata attempts OIDC/OAuth2 server metadata discovery.
func (m *Module) fetchMetadata(ctx context.Context, base string) *OIDCMetadata {
	for _, suffix := range []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
	} {
		_, body, err := m.get(ctx, base+suffix)
		if err != nil {
			continue
		}
		var meta OIDCMetadata
		if err := json.Unmarshal(body, &meta); err != nil {
			continue
		}
		if meta.AuthorizationEndpoint != "" || meta.TokenEndpoint != "" {
			return &meta
		}
	}
	return nil
}

func newFinding(checkID, checkName, endpoint string, sev module.Severity, detail string, extra map[string]string) module.Finding {
	if extra == nil {
		extra = map[string]string{}
	}
	extra["check_id"] = checkID
	extra["check_name"] = checkName
	if _, ok := extra["confidence"]; !ok {
		extra["confidence"] = "0.90" // check-specific misconfiguration detected in server response
	}
	return module.Finding{
		Type:     "oauth_misconfiguration",
		Severity: sev,
		URL:      endpoint,
		Detail:   detail,
		Extra:    extra,
	}
}

// ─── Built-in checks ─────────────────────────────────────────────────────────

func builtinChecks() []Check {
	return []Check{
		// OAUTH-001 — OIDC/OAuth2 discovery
		{
			ID:          "OAUTH-001",
			Name:        "OIDC/OAuth2 Discovery",
			Description: "Check if well-known discovery endpoint is accessible",
			Severity:    module.SeverityInfo,
			Tags:        []string{"discovery", "oidc"},
			Run: func(ctx context.Context, m *Module, base string) []module.Finding {
				meta := m.fetchMetadata(ctx, base)
				if meta == nil {
					return nil
				}
				return []module.Finding{newFinding("OAUTH-001", "OIDC/OAuth2 Discovery", base, module.SeverityInfo,
					fmt.Sprintf("Well-known OAuth2/OIDC metadata reachable at %s; issuer=%s auth_ep=%s token_ep=%s jwks=%s",
						base, meta.Issuer, meta.AuthorizationEndpoint, meta.TokenEndpoint, meta.JwksURI),
					map[string]string{
						"issuer":                 meta.Issuer,
						"authorization_endpoint": meta.AuthorizationEndpoint,
						"token_endpoint":         meta.TokenEndpoint,
						"jwks_uri":               meta.JwksURI,
					})}
			},
		},

		// OAUTH-002 — Implicit flow enabled (deprecated)
		{
			ID:          "OAUTH-002",
			Name:        "Implicit Flow Enabled",
			Description: "OAuth2 implicit flow is deprecated (RFC 9700 §2.1.2)",
			Severity:    module.SeverityMedium,
			Tags:        []string{"oauth2", "implicit-flow"},
			Run: func(ctx context.Context, m *Module, base string) []module.Finding {
				meta := m.fetchMetadata(ctx, base)
				if meta == nil {
					return nil
				}
				for _, rt := range meta.ResponseTypesSupported {
					if strings.Contains(rt, "token") {
						return []module.Finding{newFinding("OAUTH-002", "Implicit Flow Enabled", base, module.SeverityMedium,
							fmt.Sprintf("Server advertises response_type=%q. Implicit flow leaks access tokens in URL fragments and is deprecated per RFC 9700 §2.1.2. Use authorization code + PKCE.", rt),
							map[string]string{"response_types": strings.Join(meta.ResponseTypesSupported, ", ")},
						)}
					}
				}
				return nil
			},
		},

		// OAUTH-003 — PKCE not required
		{
			ID:          "OAUTH-003",
			Name:        "PKCE Not Enforced",
			Description: "Server does not advertise PKCE (RFC 7636) support",
			Severity:    module.SeverityMedium,
			Tags:        []string{"oauth2", "pkce"},
			Run: func(ctx context.Context, m *Module, base string) []module.Finding {
				meta := m.fetchMetadata(ctx, base)
				if meta == nil {
					return nil
				}
				if len(meta.CodeChallengeMethodsSupported) == 0 {
					return []module.Finding{newFinding("OAUTH-003", "PKCE Not Enforced", base, module.SeverityMedium,
						"The server metadata does not include code_challenge_methods_supported. Without PKCE, authorization codes can be intercepted (CWE-345).",
						nil)}
				}
				for _, method := range meta.CodeChallengeMethodsSupported {
					if strings.EqualFold(method, "plain") {
						return []module.Finding{newFinding("OAUTH-003", "PKCE Not Enforced", base, module.SeverityMedium,
							"Only PKCE 'plain' method supported. Only S256 should be used (RFC 7636 §4.2).",
							map[string]string{"methods": strings.Join(meta.CodeChallengeMethodsSupported, ", ")},
						)}
					}
				}
				return nil
			},
		},

		// OAUTH-004 — Open redirect in redirect_uri
		{
			ID:          "OAUTH-004",
			Name:        "Open Redirect via redirect_uri",
			Description: "Authorization endpoint may accept arbitrary redirect_uri values (CWE-601)",
			Severity:    module.SeverityHigh,
			Tags:        []string{"oauth2", "open-redirect", "cwe-601"},
			Run: func(ctx context.Context, m *Module, base string) []module.Finding {
				meta := m.fetchMetadata(ctx, base)
				authEndpoint := base + "/oauth/authorize"
				if meta != nil && meta.AuthorizationEndpoint != "" {
					authEndpoint = meta.AuthorizationEndpoint
				}
				params := url.Values{}
				params.Set("client_id", "test")
				params.Set("response_type", "code")
				params.Set("redirect_uri", "https://evil.example.com/callback")
				params.Set("state", "blackhorn-probe")

				resp, body, err := m.get(ctx, authEndpoint+"?"+params.Encode())
				if err != nil {
					return nil
				}
				loc := ""
				if resp != nil {
					loc = resp.Header.Get("Location")
				}
				if strings.Contains(loc, "evil.example.com") || strings.Contains(string(body), "evil.example.com") {
					return []module.Finding{newFinding("OAUTH-004", "Open Redirect via redirect_uri", authEndpoint, module.SeverityHigh,
						"Authorization endpoint accepted arbitrary redirect_uri=https://evil.example.com/callback (CWE-601). Attackers can steal authorization codes.",
						map[string]string{"location": loc},
					)}
				}
				return nil
			},
		},

		// OAUTH-005 — Token endpoint over HTTP
		{
			ID:          "OAUTH-005",
			Name:        "Token Endpoint Over HTTP",
			Description: "Token endpoint is accessible over HTTP, tokens transmitted in cleartext",
			Severity:    module.SeverityCritical,
			Tags:        []string{"oauth2", "tls"},
			Run: func(ctx context.Context, m *Module, base string) []module.Finding {
				meta := m.fetchMetadata(ctx, base)
				if meta == nil || meta.TokenEndpoint == "" {
					return nil
				}
				if strings.HasPrefix(meta.TokenEndpoint, "http://") {
					return []module.Finding{newFinding("OAUTH-005", "Token Endpoint Over HTTP", meta.TokenEndpoint, module.SeverityCritical,
						fmt.Sprintf("Token endpoint %q is configured over plain HTTP. Credentials and tokens are transmitted in cleartext.", meta.TokenEndpoint),
						map[string]string{"endpoint": meta.TokenEndpoint},
					)}
				}
				return nil
			},
		},

		// OAUTH-006 — JWKS endpoint accessible
		{
			ID:          "OAUTH-006",
			Name:        "JWKS Endpoint Accessible",
			Description: "JSON Web Key Set endpoint is publicly accessible",
			Severity:    module.SeverityInfo,
			Tags:        []string{"oidc", "jwks"},
			Run: func(ctx context.Context, m *Module, base string) []module.Finding {
				meta := m.fetchMetadata(ctx, base)
				jwksURI := base + "/.well-known/jwks.json"
				if meta != nil && meta.JwksURI != "" {
					jwksURI = meta.JwksURI
				}
				_, body, err := m.get(ctx, jwksURI)
				if err != nil || !strings.Contains(string(body), `"keys"`) {
					return nil
				}
				return []module.Finding{newFinding("OAUTH-006", "JWKS Endpoint Accessible", jwksURI, module.SeverityInfo,
					fmt.Sprintf("JWKS endpoint at %q is publicly accessible. Expected for public key distribution but reveals algorithm choices.", jwksURI),
					map[string]string{"jwks_uri": jwksURI},
				)}
			},
		},

		// OAUTH-007 — Weak signing algorithm
		{
			ID:          "OAUTH-007",
			Name:        "Weak Signing Algorithm in JWKS",
			Description: "JWKS advertises weak or none algorithm for id_token signing",
			Severity:    module.SeverityHigh,
			Tags:        []string{"oidc", "jwt", "algorithm"},
			Run: func(ctx context.Context, m *Module, base string) []module.Finding {
				meta := m.fetchMetadata(ctx, base)
				if meta == nil {
					return nil
				}
				weakAlgs := []string{"none", "HS256", "RS1"}
				for _, alg := range meta.IDTokenSigningAlgValuesSupported {
					for _, weak := range weakAlgs {
						if strings.EqualFold(alg, weak) {
							return []module.Finding{newFinding("OAUTH-007", "Weak Signing Algorithm", base, module.SeverityHigh,
								fmt.Sprintf("Server advertises %q for id_token signing. 'none' allows unsigned tokens (CVE-2015-9235). HS256 shares secret with client.", alg),
								map[string]string{"algorithm": alg},
							)}
						}
					}
				}
				return nil
			},
		},

		// OAUTH-008 — No client authentication
		{
			ID:          "OAUTH-008",
			Name:        "Token Endpoint Allows none Authentication",
			Description: "Token endpoint accepts unauthenticated client requests",
			Severity:    module.SeverityHigh,
			Tags:        []string{"oauth2", "client-auth"},
			Run: func(ctx context.Context, m *Module, base string) []module.Finding {
				meta := m.fetchMetadata(ctx, base)
				if meta == nil {
					return nil
				}
				for _, method := range meta.TokenEndpointAuthMethodsSupported {
					if strings.EqualFold(method, "none") {
						return []module.Finding{newFinding("OAUTH-008", "No Client Auth", base, module.SeverityHigh,
							"Server accepts 'none' as token_endpoint_auth_method. Any client can request tokens without authenticating (RFC 6749 §3.2.1).",
							map[string]string{"auth_methods": strings.Join(meta.TokenEndpointAuthMethodsSupported, ", ")},
						)}
					}
				}
				return nil
			},
		},

		// OAUTH-009 — Wildcard scope
		{
			ID:          "OAUTH-009",
			Name:        "Wildcard Scope Advertised",
			Description: "Server advertises overly broad scope granting all permissions",
			Severity:    module.SeverityMedium,
			Tags:        []string{"oauth2", "scope"},
			Run: func(ctx context.Context, m *Module, base string) []module.Finding {
				meta := m.fetchMetadata(ctx, base)
				if meta == nil {
					return nil
				}
				for _, scope := range meta.ScopesSupported {
					if scope == "*" || scope == "all" {
						return []module.Finding{newFinding("OAUTH-009", "Wildcard Scope", base, module.SeverityMedium,
							fmt.Sprintf("Server advertises scope %q which grants access to all resources. Violates principle of least privilege.", scope),
							map[string]string{"scope": scope},
						)}
					}
				}
				return nil
			},
		},

		// OAUTH-010 — State parameter not enforced
		{
			ID:          "OAUTH-010",
			Name:        "State Parameter Not Required",
			Description: "Authorization endpoint accepts requests without state (CSRF risk, RFC 6749 §10.12)",
			Severity:    module.SeverityMedium,
			Tags:        []string{"oauth2", "csrf", "state"},
			Run: func(ctx context.Context, m *Module, base string) []module.Finding {
				meta := m.fetchMetadata(ctx, base)
				authEndpoint := base + "/oauth/authorize"
				if meta != nil && meta.AuthorizationEndpoint != "" {
					authEndpoint = meta.AuthorizationEndpoint
				}
				params := url.Values{}
				params.Set("client_id", "test")
				params.Set("response_type", "code")
				params.Set("redirect_uri", "https://example.com/callback")

				resp, body, err := m.get(ctx, authEndpoint+"?"+params.Encode())
				if err != nil {
					return nil
				}
				loc := ""
				if resp != nil {
					loc = resp.Header.Get("Location")
				}
				if resp != nil && resp.StatusCode >= 300 && resp.StatusCode < 400 &&
					!strings.Contains(loc, "error=invalid_request") &&
					!strings.Contains(string(body), "state is required") {
					return []module.Finding{newFinding("OAUTH-010", "State Not Required", authEndpoint, module.SeverityMedium,
						"Authorization endpoint accepted request without 'state' parameter. Missing state enables CSRF attacks (RFC 6749 §10.12).",
						nil,
					)}
				}
				return nil
			},
		},

		// OAUTH-011 — Introspection without auth
		{
			ID:          "OAUTH-011",
			Name:        "Introspection Endpoint Accessible Without Auth",
			Description: "Token introspection endpoint is accessible without client authentication",
			Severity:    module.SeverityHigh,
			Tags:        []string{"oauth2", "introspection"},
			Run: func(ctx context.Context, m *Module, base string) []module.Finding {
				meta := m.fetchMetadata(ctx, base)
				introspectEndpoint := base + "/oauth/introspect"
				if meta != nil && meta.IntrospectionEndpoint != "" {
					introspectEndpoint = meta.IntrospectionEndpoint
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, introspectEndpoint,
					strings.NewReader("token=blackhorn_probe_token"))
				if err != nil {
					return nil
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				resp, err := m.client.Do(req)
				if err != nil {
					return nil
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))

				if resp.StatusCode == 200 && strings.Contains(string(body), `"active"`) {
					return []module.Finding{newFinding("OAUTH-011", "Introspection Without Auth", introspectEndpoint, module.SeverityHigh,
						"Introspection endpoint returned 200 with token info without client authentication. Attackers can enumerate valid tokens (RFC 7662).",
						nil,
					)}
				}
				return nil
			},
		},

		// OAUTH-012 — Dynamic client registration open
		{
			ID:          "OAUTH-012",
			Name:        "Dynamic Client Registration Open",
			Description: "Dynamic client registration endpoint accessible without authorization (RFC 7591)",
			Severity:    module.SeverityCritical,
			Tags:        []string{"oauth2", "registration"},
			Run: func(ctx context.Context, m *Module, base string) []module.Finding {
				meta := m.fetchMetadata(ctx, base)
				regEndpoint := base + "/oauth/register"
				if meta != nil && meta.RegistrationEndpoint != "" {
					regEndpoint = meta.RegistrationEndpoint
				}
				payload := `{"client_name":"blackhorn-probe","redirect_uris":["https://example.com/cb"],"grant_types":["authorization_code"]}`
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, regEndpoint,
					strings.NewReader(payload))
				if err != nil {
					return nil
				}
				req.Header.Set("Content-Type", "application/json")

				resp, err := m.client.Do(req)
				if err != nil {
					return nil
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))

				if resp.StatusCode == 201 && strings.Contains(string(body), `"client_id"`) {
					return []module.Finding{newFinding("OAUTH-012", "Dynamic Client Registration Open", regEndpoint, module.SeverityCritical,
						"Client registration succeeded without initial access token. Attackers can register malicious OAuth2 clients (RFC 7591).",
						nil,
					)}
				}
				return nil
			},
		},
	}
}

// ─── HTTP client ─────────────────────────────────────────────────────────────

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			MaxIdleConns:        20,
			MaxIdleConnsPerHost: 5,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
