package pathprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func run(t *testing.T, m *Module, target string) []module.Finding {
	t.Helper()
	findings, err := m.Run(context.Background(), module.Input{Target: target})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	return findings
}

func hasCategory(findings []module.Finding, cat string) bool {
	for _, f := range findings {
		if f.Extra["category"] == cat {
			return true
		}
	}
	return false
}

func hasFindingPath(findings []module.Finding, path string) bool {
	for _, f := range findings {
		if f.Extra["path"] == path {
			return true
		}
	}
	return false
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "pathprobe" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoTarget(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestRun_ServerReturns404(t *testing.T) {
	// Server returns 404 for everything — no findings expected.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := run(t, m, srv.URL)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for 404 server, got %d", len(findings))
	}
}

func TestRun_EnvFileDetected(t *testing.T) {
	// Server returns 200 with .env content only for /.env path.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(200)
			w.Write([]byte("APP_KEY=secret\nDB_PASSWORD=pass\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	// Use small path list to avoid test timeout.
	m.paths = []Entry{
		{"/.env", "Environment File", module.SeverityCritical, "config"},
		{"/notexist.json", "Fake Entry", module.SeverityLow, "config"},
	}
	findings := run(t, m, srv.URL)
	if !hasFindingPath(findings, "/.env") {
		t.Fatal("expected finding for /.env")
	}
	for _, f := range findings {
		if f.Extra["path"] == "/.env" {
			if f.Severity != module.SeverityCritical {
				t.Errorf("expected critical severity for .env, got %q", f.Severity)
			}
			if f.Type != "sensitive_path" {
				t.Errorf("expected type sensitive_path, got %q", f.Type)
			}
		}
	}
}

func TestRun_AuthWallDiscarded(t *testing.T) {
	// Server returns 200 with a login page for the sensitive path — should be discarded.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html><body><form>Please sign in to continue</form></body></html>"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.paths = []Entry{{"/.env", "Environment File", module.SeverityCritical, "config"}}
	findings := run(t, m, srv.URL)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for auth wall, got %d", len(findings))
	}
}

func TestRun_Soft404Discarded(t *testing.T) {
	// Server returns 200 with a "page not found" body — should be discarded.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html><head><title>Page Not Found</title></head><body>404 - page not found, sorry!</body></html>"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.paths = []Entry{{"/.env", "Environment File", module.SeverityCritical, "config"}}
	findings := run(t, m, srv.URL)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for soft-404, got %d", len(findings))
	}
}

func TestRun_URLsInput(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if r.URL.Path == "/swagger.json" {
			w.WriteHeader(200)
			w.Write([]byte(`{"openapi":"3.0.0","info":{"title":"Test"}}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.paths = []Entry{{"/swagger.json", "Swagger JSON", module.SeverityMedium, "api-docs"}}
	findings, err := m.Run(context.Background(), module.Input{URLs: []string{srv.URL}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasFindingPath(findings, "/swagger.json") {
		t.Fatal("expected finding for swagger.json via URLs input")
	}
}

func TestRun_LowSeveritySkipped(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("content"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.paths = []Entry{
		{"/low.txt", "Low Severity File", module.SeverityLow, "config"},
		{"/high.txt", "High Severity File", module.SeverityHigh, "config"},
	}
	// Disable low severity.
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"include_low": "false"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["path"] == "/low.txt" {
			t.Fatal("low severity finding should be skipped")
		}
	}
}

func TestBuiltinPaths_Count(t *testing.T) {
	paths := builtinPaths()
	if len(paths) < 100 {
		t.Fatalf("expected at least 100 built-in paths, got %d", len(paths))
	}
}

func TestBuiltinPaths_Categories(t *testing.T) {
	required := []string{"api-docs", "config", "vcs", "actuator", "backup", "log", "manifest", "ci-cd", "cloud", "cms"}
	paths := builtinPaths()
	cats := make(map[string]bool)
	for _, p := range paths {
		cats[p.Category] = true
	}
	for _, req := range required {
		if !cats[req] {
			t.Errorf("expected category %q in built-in paths", req)
		}
	}
}

func TestBuiltinPaths_NoDuplicates(t *testing.T) {
	paths := builtinPaths()
	seen := make(map[string]int)
	for i, p := range paths {
		if prev, dup := seen[p.Path]; dup {
			t.Errorf("duplicate path %q at index %d (first at %d)", p.Path, i, prev)
		}
		seen[p.Path] = i
	}
}

func TestBuiltinPaths_AllHaveSeverity(t *testing.T) {
	valid := map[module.Severity]bool{
		module.SeverityLow: true, module.SeverityMedium: true,
		module.SeverityHigh: true, module.SeverityCritical: true,
	}
	for _, p := range builtinPaths() {
		if !valid[p.Severity] {
			t.Errorf("path %q has invalid severity %q", p.Path, p.Severity)
		}
	}
}

func TestNewWithPaths(t *testing.T) {
	custom := []Entry{{"/custom.txt", "Custom", module.SeverityMedium, "test"}}
	m := NewWithPaths(custom)
	if len(m.paths) != 1 {
		t.Fatal("expected 1 custom path")
	}
}

func TestRootBase_Normalisation(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://example.com/path?q=1", "https://example.com"},
		{"http://example.com:8080/", "http://example.com:8080"},
		{"example.com", "https://example.com"},
	}
	for _, tt := range tests {
		got := rootBase(tt.in)
		if got != tt.want {
			t.Errorf("rootBase(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRun_AntiBot_Discarded(t *testing.T) {
	// Cloudflare challenge page — should be discarded.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("cf-mitigated", "challenge")
		w.WriteHeader(200)
		w.Write([]byte("Just a moment... Checking your browser before accessing."))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.paths = []Entry{{"/.env", "Environment File", module.SeverityCritical, "config"}}
	findings := run(t, m, srv.URL)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for anti-bot page, got %d", len(findings))
	}
}

func TestRun_MultipleHits(t *testing.T) {
	// Server exposes both .env and .git/config.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.WriteHeader(200)
			w.Write([]byte("DB_PASS=secret"))
		case "/.git/config":
			w.WriteHeader(200)
			w.Write([]byte("[core]\nrepositoryformatversion = 0"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.paths = []Entry{
		{"/.env", "Environment File", module.SeverityCritical, "config"},
		{"/.git/config", "Git Config", module.SeverityCritical, "vcs"},
		{"/fake", "Fake", module.SeverityLow, "config"},
	}
	findings := run(t, m, srv.URL)
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}
}

func TestSimhash64_Deterministic(t *testing.T) {
	h1 := simhash64("the quick brown fox jumps over the lazy dog")
	h2 := simhash64("the quick brown fox jumps over the lazy dog")
	if h1 != h2 {
		t.Fatal("simhash64 should be deterministic")
	}
}

func TestSimhash64_Different(t *testing.T) {
	h1 := simhash64("hello world from page one")
	h2 := simhash64("totally different content here nothing shared")
	if h1 == h2 {
		t.Fatal("simhash64 should differ for very different inputs")
	}
}

func TestHammingDist(t *testing.T) {
	if hammingDist(0, 0) != 0 {
		t.Fatal("hamming(0,0) should be 0")
	}
	if hammingDist(0, ^uint64(0)) != 64 {
		t.Fatal("hamming(0, ^0) should be 64")
	}
}

func TestIsAntiBot(t *testing.T) {
	headers := http.Header{"Cf-Mitigated": []string{"challenge"}}
	if !isAntiBot(headers, "") {
		t.Fatal("expected anti-bot detection via cf-mitigated header")
	}
	if !isAntiBot(nil, "Just a moment... Checking your browser") {
		t.Fatal("expected anti-bot detection via body marker")
	}
}

func TestIsAuthWall(t *testing.T) {
	if !isAuthWall("<html><body>Please sign in to continue</body></html>") {
		t.Fatal("expected auth wall detection")
	}
	if isAuthWall("<html><body>Welcome to our API</body></html>") {
		t.Fatal("should not flag normal content as auth wall")
	}
}

func TestRun_FindingDetail(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".env") {
			w.WriteHeader(200)
			w.Write([]byte("DB_PASS=supersecret"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.paths = []Entry{{"/.env", "Environment File", module.SeverityCritical, "config"}}
	findings := run(t, m, srv.URL)
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	f := findings[0]
	if !strings.Contains(f.Detail, "200") {
		t.Errorf("expected Detail to mention HTTP 200, got: %q", f.Detail)
	}
	if f.Extra["category"] != "config" {
		t.Errorf("expected category=config, got %q", f.Extra["category"])
	}
}
