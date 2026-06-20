package cacheprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

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

func TestName(t *testing.T) {
	if New().Name() != "cacheprobe" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoTarget(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCacheDetection_XCache(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Cache", "HIT from cdn")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	if !hasCheck(run(t, m, srv.URL), "CACHE-001") {
		t.Fatal("expected CACHE-001 for X-Cache header")
	}
}

func TestCacheDetection_None(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	if hasCheck(run(t, m, srv.URL), "CACHE-001") {
		t.Fatal("should not find CACHE-001 without cache headers")
	}
}

func TestXForwardedHostReflected(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host != "" {
			w.Write([]byte("Welcome to " + host))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	if !hasCheck(run(t, m, srv.URL), "CACHE-002") {
		t.Fatal("expected CACHE-002 for X-Forwarded-Host reflection")
	}
}

func TestXForwardedHostNotReflected(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("Hello world"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	if hasCheck(run(t, m, srv.URL), "CACHE-002") {
		t.Fatal("should not find CACHE-002 when header not reflected")
	}
}

func TestXHostReflected(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Host")
		if host != "" {
			w.Write([]byte(host))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	if !hasCheck(run(t, m, srv.URL), "CACHE-003") {
		t.Fatal("expected CACHE-003 for X-Host reflection")
	}
}

func TestFatGET_Reflected(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.ContentLength > 0 {
			// Reflect POST-style body from GET.
			buf := make([]byte, r.ContentLength)
			r.Body.Read(buf)
			w.Write(buf)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	if !hasCheck(run(t, m, srv.URL), "CACHE-005") {
		t.Fatal("expected CACHE-005 for fat GET body reflection")
	}
}

func TestCacheControlMissing_Login(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			// Return 200 without no-store.
			w.Header().Set("Cache-Control", "max-age=3600")
			w.Write([]byte("Login page"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	if !hasCheck(run(t, m, srv.URL), "CACHE-006") {
		t.Fatal("expected CACHE-006 for cacheable login page")
	}
}

func TestCacheControlMissing_Safe(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	if hasCheck(run(t, m, srv.URL), "CACHE-006") {
		t.Fatal("should not find CACHE-006 when no-store present")
	}
}

func TestVaryOriginMissing(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			// Respond with ACAO but no Vary: Origin.
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	if !hasCheck(run(t, m, srv.URL), "CACHE-007") {
		t.Fatal("expected CACHE-007 for missing Vary: Origin")
	}
}

func TestVaryOriginPresent(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Vary", "Origin")
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	if hasCheck(run(t, m, srv.URL), "CACHE-007") {
		t.Fatal("should not flag CACHE-007 when Vary: Origin present")
	}
}

func TestCacheBuster_Format(t *testing.T) {
	buster := cacheBuster()
	if len(buster) != 8 {
		t.Fatalf("expected 8-char buster, got %d chars: %q", len(buster), buster)
	}
}

func TestAddBuster(t *testing.T) {
	tests := []struct {
		url    string
		expect string
	}{
		{"https://example.com/page", "?"},
		{"https://example.com/page?foo=bar", "&"},
	}
	for _, tt := range tests {
		result := addBuster(tt.url, "abc123")
		if result == tt.url {
			t.Errorf("addBuster did not modify URL %q", tt.url)
		}
	}
}

func TestRun_URLsInput(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	input := module.Input{URLs: []string{srv.URL}}
	_, err := m.Run(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRun_ContextCancellationCacheprobe verifies module returns quickly on cancelled context.
func TestRun_ContextCancellationCacheprobe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := New()
	_, _ = m.Run(ctx, module.Input{Target: "http://localhost:1/page"})
	// no panic, no hang = pass
}

// TestRun_FindingHasDetailField verifies cache-related findings include detail.
func TestRun_FindingHasDetailField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Age header simulates cache hit.
		w.Header().Set("Age", "120")
		w.Header().Set("X-Cache", "HIT from cdn.example.com")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("cached response"))
	}))
	defer srv.Close()

	m, testSrv := newTestModule(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Age", "120")
		w.Header().Set("X-Cache", "HIT from cdn.example.com")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("cached response"))
	}))
	defer testSrv.Close()
	_ = srv

	findings, err := m.Run(context.Background(), module.Input{Target: testSrv.URL + "/page"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Detail == "" {
			t.Errorf("finding type %q missing Detail", f.Type)
		}
	}
}

// TestRun_FindingsHaveConfidence verifies all findings have a non-empty confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	m, srv := newTestModule(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache", "HIT from cdn")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := run(t, m, srv.URL)
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding missing Extra[confidence]: %+v", f)
		}
	}
}

// TestRun_FindingTypeValid verifies all findings have a non-empty Type field.
func TestRun_FindingTypeValid(t *testing.T) {
	m, srv := newTestModule(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host != "" {
			w.Write([]byte("host=" + host))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := run(t, m, srv.URL)
	for _, f := range findings {
		if f.Type == "" {
			t.Errorf("finding has empty Type: %+v", f)
		}
	}
}

// TestRun_FindingURLOrDetailSet verifies each finding has at least URL or Detail set.
func TestRun_FindingURLOrDetailSet(t *testing.T) {
	m, srv := newTestModule(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache", "HIT from cdn")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := run(t, m, srv.URL)
	for _, f := range findings {
		if f.URL == "" && f.Detail == "" {
			t.Errorf("finding has neither URL nor Detail: %+v", f)
		}
	}
}
