package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/oauth2"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// discoveryServer: returns an OpenID Connect discovery document.
func discoveryServer(t *testing.T, includeImplicit bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responseTypes := `["code", "code id_token"]`
		if includeImplicit {
			responseTypes = `["code", "token", "id_token", "code token"]`
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{
			"issuer": "https://example.com",
			"authorization_endpoint": "https://example.com/oauth/authorize",
			"token_endpoint": "https://example.com/oauth/token",
			"response_types_supported": ` + responseTypes + `
		}`))
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := oauth2.New()
	if m.Name() != "oauth2" {
		t.Fatalf("expected 'oauth2', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = oauth2.New()
}

// TestImplicitFlowDetected: response_type=token.
func TestImplicitFlowDetected(t *testing.T) {
	m := oauth2.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "https://auth.example.com/oauth/authorize?response_type=token&client_id=app123&scope=read",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "oauth2_implicit_flow" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected oauth2_implicit_flow finding, got: %v", findings)
	}
}

// TestMissingStateDetected: no state param.
func TestMissingStateDetected(t *testing.T) {
	m := oauth2.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "https://auth.example.com/oauth/authorize?response_type=code&client_id=app123",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "oauth2_missing_state" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected oauth2_missing_state finding, got: %v", findings)
	}
}

// TestStatePresent: state param present → no CSRF finding.
func TestStatePresent(t *testing.T) {
	m := oauth2.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "https://auth.example.com/oauth/authorize?response_type=code&client_id=app123&state=random123",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type == "oauth2_missing_state" {
			t.Errorf("should not flag CSRF when state is present: %v", f)
		}
	}
}

// TestMissingPKCEDetected: code flow without code_challenge.
func TestMissingPKCEDetected(t *testing.T) {
	m := oauth2.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "https://auth.example.com/oauth/authorize?response_type=code&client_id=app123&state=x",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "oauth2_missing_pkce" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected oauth2_missing_pkce finding, got: %v", findings)
	}
}

// TestPKCEPresent: code_challenge present → no PKCE finding.
func TestPKCEPresent(t *testing.T) {
	m := oauth2.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "https://auth.example.com/oauth/authorize?response_type=code&client_id=app123&state=x&code_challenge=abc&code_challenge_method=S256",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type == "oauth2_missing_pkce" {
			t.Errorf("should not flag PKCE when code_challenge present: %v", f)
		}
	}
}

// TestHTTPEndpointDetected: OAuth via HTTP.
func TestHTTPEndpointDetected(t *testing.T) {
	m := oauth2.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "http://auth.example.com/oauth/authorize?response_type=code&client_id=app123",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "oauth2_http_endpoint" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected oauth2_http_endpoint finding, got: %v", findings)
	}
}

// TestBroadScopeDetected: scope=all.
func TestBroadScopeDetected(t *testing.T) {
	m := oauth2.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "https://auth.example.com/oauth/authorize?response_type=code&client_id=app123&scope=all&state=x",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "oauth2_broad_scope" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected oauth2_broad_scope finding, got: %v", findings)
	}
}

// TestTokenInURLDetected: access_token in query param.
func TestTokenInURLDetected(t *testing.T) {
	m := oauth2.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "https://app.example.com/callback?access_token=eyJhbGci.abc.def",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "oauth2_token_in_url" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected oauth2_token_in_url finding, got: %v", findings)
	}
}

// TestOpenRedirectURIDetected: redirect_uri pointing to attacker.
func TestOpenRedirectURIDetected(t *testing.T) {
	m := oauth2.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "https://auth.example.com/oauth/authorize?response_type=code&client_id=app&redirect_uri=https://evil.com/callback",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "oauth2_open_redirect_uri" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected oauth2_open_redirect_uri finding, got: %v", findings)
	}
}

// TestDiscoveryImplicitSupported: discovery doc with implicit flow.
func TestDiscoveryImplicitSupported(t *testing.T) {
	srv := discoveryServer(t, true)
	defer srv.Close()

	m := oauth2.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/.well-known/openid-configuration",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "oauth2_discovery_implicit_supported" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected oauth2_discovery_implicit_supported, got: %v", findings)
	}
}

// TestEmptyInput: no targets → nil.
func TestEmptyInput(t *testing.T) {
	m := oauth2.New()
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(findings))
	}
}

// TestContextCancellation: cancelled context does not panic.
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := oauth2.New()
	_, err := m.Run(ctx, module.Input{
		Target: "https://auth.example.com/oauth/authorize?response_type=token&client_id=app",
	})
	_ = err
}

// TestDeduplication: same check + URL not duplicated.
func TestDeduplication(t *testing.T) {
	u := "https://auth.example.com/oauth/authorize?response_type=token&client_id=app123"
	m := oauth2.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{u, u, u},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Type + "|" + f.Extra["check_id"]
		seen[key]++
	}
	for k, count := range seen {
		if count > 1 {
			t.Errorf("duplicate finding %q count=%d", k, count)
		}
	}
}

// TestFindingFields: all required fields populated.
func TestFindingFields(t *testing.T) {
	m := oauth2.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "https://auth.example.com/oauth/authorize?response_type=token&client_id=app",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type == "" {
		t.Error("Type empty")
	}
	if f.URL == "" {
		t.Error("URL empty")
	}
	if f.Detail == "" {
		t.Error("Detail empty")
	}
	if f.Severity == "" {
		t.Error("Severity empty")
	}
	if f.Extra["check_id"] == "" {
		t.Error("Extra.check_id empty")
	}
}

// TestDetailHasOAuth2Prefix: findings have [OAuth2] in detail.
func TestDetailHasOAuth2Prefix(t *testing.T) {
	m := oauth2.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "https://auth.example.com/oauth/authorize?response_type=token&client_id=app",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.Detail, "[OAuth2]") {
			t.Errorf("Detail %q missing '[OAuth2]'", f.Detail)
		}
	}
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	m := oauth2.New()
	_, err := m.Run(context.Background(), module.Input{
		Target:  "https://auth.example.com/oauth/authorize?response_type=code&client_id=app",
		Options: map[string]string{"parallelism": "3"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestNewWithClient: does not panic.
func TestNewWithClient(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := oauth2.NewWithClient(c)
	if m == nil || m.Name() != "oauth2" {
		t.Fatal("NewWithClient failed")
	}
}
