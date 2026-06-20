package oauthprobe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

func newTestModule(handler http.Handler) (*Module, *httptest.Server) {
	srv := httptest.NewTLSServer(handler)
	m := NewWithClient(srv.Client())
	return m, srv
}

func hasCheck(findings []module.Finding, checkID string) bool {
	for _, f := range findings {
		if f.Extra["check_id"] == checkID {
			return true
		}
	}
	return false
}

func run(t *testing.T, m *Module, target string) []module.Finding {
	t.Helper()
	findings, err := m.Run(context.Background(), module.Input{Target: target})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	return findings
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "oauthprobe" {
		t.Fatal("wrong name")
	}
}

func TestRun_EmptyTarget(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestDiscovery_Found(t *testing.T) {
	meta := OIDCMetadata{
		Issuer:                "https://test.example.com",
		AuthorizationEndpoint: "https://test.example.com/authorize",
		TokenEndpoint:         "https://test.example.com/token",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(meta)
	})
	m, srv := newTestModule(mux)
	defer srv.Close()

	if !hasCheck(run(t, m, srv.URL), "OAUTH-001") {
		t.Fatal("expected OAUTH-001 discovery finding")
	}
}

func TestDiscovery_NotFound(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	m := NewWithClient(srv.Client())
	if hasCheck(run(t, m, srv.URL), "OAUTH-001") {
		t.Fatal("should not find OAUTH-001 when no metadata")
	}
}

func TestImplicitFlow_Detected(t *testing.T) {
	meta := OIDCMetadata{
		AuthorizationEndpoint:  "https://x.example.com/authorize",
		TokenEndpoint:          "https://x.example.com/token",
		ResponseTypesSupported: []string{"code", "token"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(meta)
	})
	m, srv := newTestModule(mux)
	defer srv.Close()
	if !hasCheck(run(t, m, srv.URL), "OAUTH-002") {
		t.Fatal("expected OAUTH-002")
	}
}

func TestImplicitFlow_CodeOnly(t *testing.T) {
	meta := OIDCMetadata{
		AuthorizationEndpoint:  "https://x.example.com/authorize",
		TokenEndpoint:          "https://x.example.com/token",
		ResponseTypesSupported: []string{"code"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(meta)
	})
	m, srv := newTestModule(mux)
	defer srv.Close()
	if hasCheck(run(t, m, srv.URL), "OAUTH-002") {
		t.Fatal("should not flag OAUTH-002 for code-only")
	}
}

func TestPKCE_Missing(t *testing.T) {
	meta := OIDCMetadata{
		AuthorizationEndpoint: "https://x.example.com/authorize",
		TokenEndpoint:         "https://x.example.com/token",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(meta)
	})
	m, srv := newTestModule(mux)
	defer srv.Close()
	if !hasCheck(run(t, m, srv.URL), "OAUTH-003") {
		t.Fatal("expected OAUTH-003 for missing PKCE")
	}
}

func TestPKCE_PlainOnly(t *testing.T) {
	meta := OIDCMetadata{
		AuthorizationEndpoint:         "https://x.example.com/authorize",
		TokenEndpoint:                 "https://x.example.com/token",
		CodeChallengeMethodsSupported: []string{"plain"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(meta)
	})
	m, srv := newTestModule(mux)
	defer srv.Close()
	if !hasCheck(run(t, m, srv.URL), "OAUTH-003") {
		t.Fatal("expected OAUTH-003 for plain-only PKCE")
	}
}

func TestPKCE_S256OK(t *testing.T) {
	meta := OIDCMetadata{
		AuthorizationEndpoint:         "https://x.example.com/authorize",
		TokenEndpoint:                 "https://x.example.com/token",
		CodeChallengeMethodsSupported: []string{"S256"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(meta)
	})
	m, srv := newTestModule(mux)
	defer srv.Close()
	if hasCheck(run(t, m, srv.URL), "OAUTH-003") {
		t.Fatal("should not flag OAUTH-003 when S256 supported")
	}
}

func TestTokenEndpointHTTP(t *testing.T) {
	meta := OIDCMetadata{
		AuthorizationEndpoint: "https://x.example.com/authorize",
		TokenEndpoint:         "http://x.example.com/token",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(meta)
	})
	m, srv := newTestModule(mux)
	defer srv.Close()
	if !hasCheck(run(t, m, srv.URL), "OAUTH-005") {
		t.Fatal("expected OAUTH-005 for HTTP token endpoint")
	}
}

func TestWeakAlgorithm_None(t *testing.T) {
	meta := OIDCMetadata{
		AuthorizationEndpoint:            "https://x.example.com/authorize",
		TokenEndpoint:                    "https://x.example.com/token",
		IDTokenSigningAlgValuesSupported: []string{"none", "RS256"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(meta)
	})
	m, srv := newTestModule(mux)
	defer srv.Close()
	if !hasCheck(run(t, m, srv.URL), "OAUTH-007") {
		t.Fatal("expected OAUTH-007 for none algorithm")
	}
}

func TestWeakAlgorithm_Strong(t *testing.T) {
	meta := OIDCMetadata{
		AuthorizationEndpoint:            "https://x.example.com/authorize",
		TokenEndpoint:                    "https://x.example.com/token",
		IDTokenSigningAlgValuesSupported: []string{"RS256", "ES256"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(meta)
	})
	m, srv := newTestModule(mux)
	defer srv.Close()
	if hasCheck(run(t, m, srv.URL), "OAUTH-007") {
		t.Fatal("should not flag OAUTH-007 for strong algorithms")
	}
}

func TestNoClientAuth(t *testing.T) {
	meta := OIDCMetadata{
		AuthorizationEndpoint:             "https://x.example.com/authorize",
		TokenEndpoint:                     "https://x.example.com/token",
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "none"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(meta)
	})
	m, srv := newTestModule(mux)
	defer srv.Close()
	if !hasCheck(run(t, m, srv.URL), "OAUTH-008") {
		t.Fatal("expected OAUTH-008 for none auth method")
	}
}

func TestWildcardScope(t *testing.T) {
	meta := OIDCMetadata{
		AuthorizationEndpoint: "https://x.example.com/authorize",
		TokenEndpoint:         "https://x.example.com/token",
		ScopesSupported:       []string{"openid", "profile", "*"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(meta)
	})
	m, srv := newTestModule(mux)
	defer srv.Close()
	if !hasCheck(run(t, m, srv.URL), "OAUTH-009") {
		t.Fatal("expected OAUTH-009 for wildcard scope")
	}
}

func TestOpenRegistration(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(OIDCMetadata{
			AuthorizationEndpoint: r.Host + "/authorize",
			TokenEndpoint:         r.Host + "/token",
			RegistrationEndpoint:  "/oauth/register",
		})
	})
	mux.HandleFunc("/oauth/register", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"client_id":"abc123"}`))
	})
	m, srv := newTestModule(mux)
	defer srv.Close()
	// Registration endpoint in metadata is relative so OAUTH-012 uses base+"/oauth/register".
	findings := run(t, m, srv.URL)
	_ = findings // check no panic
}

func TestIntrospectionWithoutAuth(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(OIDCMetadata{
			AuthorizationEndpoint: "https://x.example.com/authorize",
			TokenEndpoint:         "https://x.example.com/token",
			IntrospectionEndpoint: r.Host + "/oauth/introspect",
		})
	})
	mux.HandleFunc("/oauth/introspect", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"active":false}`))
	})
	m, srv := newTestModule(mux)
	defer srv.Close()
	findings := run(t, m, srv.URL)
	_ = findings
}

func TestJWKSEndpointExposed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(OIDCMetadata{
			AuthorizationEndpoint: "https://x.example.com/authorize",
			TokenEndpoint:         "https://x.example.com/token",
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[{"kty":"RSA","use":"sig"}]}`))
	})
	m, srv := newTestModule(mux)
	defer srv.Close()
	if !hasCheck(run(t, m, srv.URL), "OAUTH-006") {
		t.Fatal("expected OAUTH-006 for exposed JWKS")
	}
}

func TestRun_URLsInput(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "openid-configuration") {
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	input := module.Input{URLs: []string{srv.URL}}
	_, err := m.Run(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
