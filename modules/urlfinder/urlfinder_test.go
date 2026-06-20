package urlfinder

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func runFetch(t *testing.T, m *Module, urls []string) []module.Finding {
	t.Helper()
	findings, err := m.Run(context.Background(), module.Input{URLs: urls})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	return findings
}

func hasURL(findings []module.Finding, u string) bool {
	for _, f := range findings {
		if f.URL == u {
			return true
		}
	}
	return false
}

func hasURLContaining(findings []module.Finding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(f.URL, substr) {
			return true
		}
	}
	return false
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "urlfinder" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoInput(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestRun_TargetInput(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte(`<html><body><a href="/about">About</a></body></html>`))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	_, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_HTMLHrefExtraction(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte(`
<html><body>
  <a href="/api/users">Users</a>
  <a href="/api/products">Products</a>
  <form action="/submit">
    <img src="/images/logo.png">
  </form>
</body></html>`))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runFetch(t, m, []string{srv.URL})
	if !hasURLContaining(findings, "/api/users") {
		t.Fatal("expected /api/users to be extracted from href")
	}
	if !hasURLContaining(findings, "/api/products") {
		t.Fatal("expected /api/products to be extracted from href")
	}
}

func TestRun_JSFetchExtraction(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(200)
		w.Write([]byte(`
fetch('/api/v2/users', { method: 'GET' });
axios.post('/api/v2/auth/login', payload);
var x = axios.get('/internal/health');
`))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runFetch(t, m, []string{srv.URL + "/app.js"})
	if !hasURLContaining(findings, "/api/v2/users") {
		t.Fatal("expected /api/v2/users from fetch() call")
	}
	if !hasURLContaining(findings, "/api/v2/auth/login") {
		t.Fatal("expected /api/v2/auth/login from axios.post() call")
	}
}

func TestRun_AbsoluteURLExtraction(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`
var apiBase = "https://api.example.com/v1";
fetch("https://api.example.com/users");
`))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.IncludeExternal = true
	findings := runFetch(t, m, []string{srv.URL + "/bundle.js"})
	if !hasURLContaining(findings, "api.example.com") {
		t.Fatal("expected api.example.com URL to be extracted")
	}
}

func TestRun_SourceMapExtraction(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`
(function() { var x = 1; })();
//# sourceMappingURL=main.js.map
`))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runFetch(t, m, []string{srv.URL + "/main.js"})
	if !hasURLContaining(findings, "main.js.map") {
		t.Fatal("expected main.js.map from sourceMappingURL comment")
	}
}

func TestRun_APIBaseExtraction(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`
const apiBase = '/api/v3';
const BASE_URL = '/backend';
`))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runFetch(t, m, []string{srv.URL + "/config.js"})
	if !hasURLContaining(findings, "/api/v3") {
		t.Fatal("expected /api/v3 from apiBase variable")
	}
}

func TestRun_RawContent_Mode(t *testing.T) {
	content := `fetch("https://api.example.com/data");`
	m := New()
	m.IncludeExternal = true
	findings, err := m.Run(context.Background(), module.Input{RawContent: content})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected an absolute URL candidate from raw content")
	}
	for _, finding := range findings {
		if finding.Extra["promote_to_context"] != "false" {
			t.Fatalf("raw-content candidate must not be promoted: %+v", finding.Extra)
		}
		if finding.Extra["source_validated"] != "false" {
			t.Fatalf("raw-content source must remain unvalidated: %+v", finding.Extra)
		}
	}
}

func TestRun_ScopeFiltering(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`
fetch('https://api.example.com/data');
fetch('https://external.other.com/data');
`))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.Scope = []string{"example.com"}
	m.IncludeExternal = false
	findings := runFetch(t, m, []string{srv.URL + "/app.js"})
	// external.other.com should be excluded.
	for _, f := range findings {
		if strings.Contains(f.URL, "other.com") {
			t.Errorf("out-of-scope URL %q should not appear", f.URL)
		}
	}
}

func TestRun_DerivesScopeFromInput(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`
fetch('/api/local');
fetch('https://external.other.test/data');
`))
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	findings := runFetch(t, m, []string{srv.URL + "/app.js"})
	if !hasURLContaining(findings, "/api/local") {
		t.Fatal("expected same-host endpoint")
	}
	for _, f := range findings {
		if strings.Contains(f.URL, "external.other.test") {
			t.Fatalf("derived scope allowed external URL %q", f.URL)
		}
	}
}

func TestRun_MaxResults(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`
fetch('/api/one');
fetch('/api/two');
fetch('/api/three');
`))
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/app.js"},
		Options: map[string]string{"max_results": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected max 2 findings, got %d", len(findings))
	}
}

func TestRun_Dedup(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		// Same URL appears multiple times in content.
		w.Write([]byte(`
fetch('/api/users');
fetch('/api/users');
var x = '/api/users';
`))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runFetch(t, m, []string{srv.URL + "/app.js"})
	// Count occurrences of /api/users.
	count := 0
	for _, f := range findings {
		if strings.Contains(f.URL, "/api/users") {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected 1 deduplicated finding for /api/users, got %d", count)
	}
}

func TestRun_MultipleURLs(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/page1" {
			w.Write([]byte(`<a href="/endpoint1">E1</a>`))
		} else {
			w.Write([]byte(`<a href="/endpoint2">E2</a>`))
		}
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runFetch(t, m, []string{srv.URL + "/page1", srv.URL + "/page2"})
	if !hasURLContaining(findings, "/endpoint1") {
		t.Fatal("expected /endpoint1 from page1")
	}
	if !hasURLContaining(findings, "/endpoint2") {
		t.Fatal("expected /endpoint2 from page2")
	}
}

// ─── unit tests for helpers ───────────────────────────────────────────────────

func TestNormaliseURL_Relative(t *testing.T) {
	got := normaliseURL("/api/users", "https://example.com/app")
	if got != "https://example.com/api/users" {
		t.Errorf("expected https://example.com/api/users, got %q", got)
	}
}

func TestNormaliseURL_Absolute(t *testing.T) {
	got := normaliseURL("https://api.example.com/v1", "https://example.com")
	if got != "https://api.example.com/v1" {
		t.Errorf("expected https://api.example.com/v1, got %q", got)
	}
}

func TestNormaliseURL_ProtocolRelative(t *testing.T) {
	got := normaliseURL("//cdn.example.com/js/app.js", "https://example.com")
	if got != "https://cdn.example.com/js/app.js" {
		t.Errorf("expected https://cdn.example.com/js/app.js, got %q", got)
	}
}

func TestNormaliseURL_JavaScript(t *testing.T) {
	got := normaliseURL("javascript:void(0)", "https://example.com")
	if got != "" {
		t.Errorf("expected empty string for javascript: URL, got %q", got)
	}
}

func TestNormaliseURL_HashOnly(t *testing.T) {
	got := normaliseURL("#section", "https://example.com")
	if got != "" {
		t.Fatalf("fragment-only reference must be discarded, got %q", got)
	}
}

func TestNormaliseURL_RejectsTemplateArtifacts(t *testing.T) {
	for _, raw := range []string{"/api/{id}", "/assets/[name].js", `\webpack\chunk`} {
		if got := normaliseURL(raw, "https://example.com/app.js"); got != "" {
			t.Errorf("expected template artifact %q to be rejected, got %q", raw, got)
		}
	}
}

func TestIsValidURL(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"https://example.com/api", true},
		{"http://localhost/test", true},
		{"ftp://example.com", false},
		{"/relative/path", false},
		{"", false},
	}
	for _, c := range cases {
		got := isValidURL(c.s)
		if got != c.want {
			t.Errorf("isValidURL(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestInScope(t *testing.T) {
	scope := []string{"example.com"}
	cases := []struct {
		u    string
		want bool
	}{
		{"https://example.com/api", true},
		{"https://api.example.com/v1", true},
		{"https://sub.api.example.com/", true},
		{"https://other.com/api", false},
		{"https://notexample.com/", false},
	}
	for _, c := range cases {
		got := inScope(c.u, scope)
		if got != c.want {
			t.Errorf("inScope(%q, %v) = %v, want %v", c.u, scope, got, c.want)
		}
	}
}

func TestExtractAll_AbsoluteURLs(t *testing.T) {
	content := `
var x = "https://api.example.com/users";
fetch("https://api.example.com/posts");
`
	urls := extractAll(content, "https://example.com", nil, true)
	found := false
	for _, u := range urls {
		if strings.Contains(u, "api.example.com") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected api.example.com URL to be extracted")
	}
}

func TestExtractAll_NoFalsePositivesOnShortStrings(t *testing.T) {
	// Very short strings should not be extracted.
	content := `var x = "ok"; var y = "ab";`
	urls := extractAll(content, "https://example.com", nil, true)
	// Short strings < 5 chars should not become URLs.
	for _, u := range urls {
		if u == "ok" || u == "ab" {
			t.Errorf("short string %q should not be extracted as URL", u)
		}
	}
}

func TestExtractAll_WebpackChunk(t *testing.T) {
	content := `__webpack_require__("./src/pages/home.chunk.js")`
	urls := extractAll(content, "https://example.com/", nil, true)
	found := false
	for _, u := range urls {
		if strings.Contains(u, "home.chunk.js") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected webpack chunk URL to be extracted")
	}
}

func TestFindingType(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<a href="/api/test">link</a>`))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runFetch(t, m, []string{srv.URL})
	for _, f := range findings {
		if f.Type != "web_location_candidate" {
			t.Errorf("expected type 'web_location_candidate', got %q", f.Type)
		}
		if f.Extra["validated"] != "false" ||
			f.Extra["validation_state"] != "content_extraction_candidate" ||
			f.Extra["promote_to_context"] != "false" ||
			f.Extra["source_validated"] != "true" {
			t.Errorf("candidate evidence contract is incomplete: %+v", f.Extra)
		}
	}
}
