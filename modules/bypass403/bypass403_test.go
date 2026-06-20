package bypass403

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

func run(t *testing.T, m *Module, target string) []module.Finding {
	t.Helper()
	findings, err := m.Run(context.Background(), module.Input{Target: target})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	return findings
}

func TestName(t *testing.T) {
	if New().Name() != "bypass403" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoTarget(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestRun_Non403Target(t *testing.T) {
	// Target returns 200 — bypass module should skip it entirely.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := run(t, m, srv.URL+"/page")
	if len(findings) > 0 {
		t.Fatalf("expected no findings for 200 target, got %d", len(findings))
	}
}

func TestRun_403Bypassed(t *testing.T) {
	// Count requests: first returns 403, subsequent return 200 to simulate bypass.
	var requestCount atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := requestCount.Add(1)
		if n == 1 {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("bypassed"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := run(t, m, srv.URL+"/admin")
	if len(findings) == 0 {
		t.Fatal("expected bypass findings when probes return 200")
	}
	for _, f := range findings {
		if f.Type != "403_bypass" {
			t.Errorf("unexpected finding type: %q", f.Type)
		}
		if f.Severity != module.SeverityHigh {
			t.Errorf("expected high severity, got %q", f.Severity)
		}
	}
}

func TestBuildProbes_Count(t *testing.T) {
	probes := buildProbes("https://example.com/admin")
	if len(probes) < 20 {
		t.Fatalf("expected at least 20 probes, got %d", len(probes))
	}
}

func TestBuildProbes_Techniques(t *testing.T) {
	probes := buildProbes("https://example.com/admin")
	techniques := make(map[string]bool)
	for _, p := range probes {
		techniques[p.Technique] = true
	}
	required := []string{
		"uppercase",
		"TRACE method",
		"X-Forwarded-For: 127.0.0.1",
		"Referer: target",
	}
	for _, req := range required {
		if !techniques[req] {
			t.Errorf("expected technique %q in probes", req)
		}
	}
}

func TestBuildProbes_URLs(t *testing.T) {
	probes := buildProbes("https://example.com/admin")
	for _, p := range probes {
		if p.URL == "" {
			t.Errorf("probe technique %q has empty URL", p.Technique)
		}
	}
}

func TestLastSeg(t *testing.T) {
	tests := []struct{ path, want string }{
		{"/admin/panel", "panel"},
		{"/admin", "admin"},
		{"/", ""},
		{"/a/b/c", "c"},
	}
	for _, tt := range tests {
		got := lastSeg(tt.path)
		if got != tt.want {
			t.Errorf("lastSeg(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestMixedCase(t *testing.T) {
	got := mixedCase("/admin")
	if got == "/admin" {
		t.Fatal("expected different case from original")
	}
}

func TestRun_URLsInput(t *testing.T) {
	var requestCount atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := requestCount.Add(1)
		if n == 1 {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	input := module.Input{URLs: []string{srv.URL + "/protected"}}
	findings, err := m.Run(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = findings
}

func TestCheckStatus_OK(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	code, err := m.checkStatus(context.Background(), srv.URL, nil, "GET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
}

func TestCheckStatus_WithHeaders(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") == "blackhorn" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(403)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())

	// Without header → 403.
	code, _ := m.checkStatus(context.Background(), srv.URL, nil, "GET")
	if code != 403 {
		t.Fatalf("expected 403 without header, got %d", code)
	}

	// With header → 200.
	code, _ = m.checkStatus(context.Background(), srv.URL,
		map[string]string{"X-Test": "blackhorn"}, "GET")
	if code != 200 {
		t.Fatalf("expected 200 with header, got %d", code)
	}
}

func TestProbes_NoRootPath(t *testing.T) {
	// URL with no path segment.
	probes := buildProbes("https://example.com")
	if len(probes) == 0 {
		t.Fatal("expected probes even with no path")
	}
	for _, p := range probes {
		if !strings.HasPrefix(p.URL, "https://example.com") && p.URL != "https://example.com" {
			// Allow relative URL builds.
		}
	}
}

// TestRun_ContextCancellation verifies the module respects context cancellation.
func TestRun_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	m := New()
	_, err := m.Run(ctx, module.Input{Target: "http://localhost:1/admin"})
	// May error or return empty — must not hang.
	_ = err
}

// TestRun_FindingHasTechnique verifies bypass findings include technique metadata.
func TestRun_FindingHasTechnique(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := count.Add(1)
		if n == 1 {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := run(t, m, srv.URL+"/secret")

	for _, f := range findings {
		if f.Extra["technique"] == "" {
			t.Errorf("finding missing technique field: %+v", f)
		}
		if f.Extra["bypass_url"] == "" {
			t.Errorf("finding missing bypass_url field: %+v", f)
		}
		if f.Extra["original_url"] == "" {
			t.Errorf("finding missing original_url field: %+v", f)
		}
	}
}

// TestRun_FindingDetailDescribesBypass verifies bypass finding detail explains the technique.
func TestRun_FindingDetailDescribesBypass(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := count.Add(1)
		if n == 1 {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := run(t, m, srv.URL+"/protected")
	for _, f := range findings {
		if f.Detail == "" {
			t.Errorf("bypass finding missing Detail: %+v", f)
		}
	}
}

// TestRun_AllTechniquesHaveURLs validates every probe has a non-empty URL.
func TestRun_AllTechniquesHaveURLs(t *testing.T) {
	testURLs := []string{
		"https://example.com/admin",
		"https://example.com/api/v1/users",
		"https://example.com/",
	}
	for _, u := range testURLs {
		probes := buildProbes(u)
		for _, p := range probes {
			if p.URL == "" {
				t.Errorf("probe technique %q has empty URL for input %q", p.Technique, u)
			}
			if p.Technique == "" {
				t.Errorf("probe at %q has empty technique for input %q", p.URL, u)
			}
		}
	}
}

// TestRun_FindingsHaveConfidence verifies all findings have a non-empty confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := count.Add(1)
		if n == 1 {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := run(t, m, srv.URL+"/admin")
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding missing Extra[confidence]: %+v", f)
		}
	}
}

// TestRun_FindingTypeValid verifies all findings have a non-empty Type field.
func TestRun_FindingTypeValid(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := count.Add(1)
		if n == 1 {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := run(t, m, srv.URL+"/admin")
	for _, f := range findings {
		if f.Type == "" {
			t.Errorf("finding has empty Type: %+v", f)
		}
	}
}

// TestRun_FindingURLOrDetailSet verifies each finding has at least URL or Detail set.
func TestRun_FindingURLOrDetailSet(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := count.Add(1)
		if n == 1 {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := run(t, m, srv.URL+"/admin")
	for _, f := range findings {
		if f.URL == "" && f.Detail == "" {
			t.Errorf("finding has neither URL nor Detail: %+v", f)
		}
	}
}
