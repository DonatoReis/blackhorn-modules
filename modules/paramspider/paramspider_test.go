package paramspider_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/paramspider"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// cdxServer returns a mock CDX API with the given URL lines.
func cdxServer(lines []string) *httptest.Server {
	body := strings.Join(lines, "\n") + "\n"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
}

// rewriteTransport redirects all requests to the given host (for test servers).
type rewriteTransport struct{ host string }

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = t.host
	return http.DefaultTransport.RoundTrip(clone)
}

func clientFor(srv *httptest.Server) *http.Client {
	host := strings.TrimPrefix(srv.URL, "http://")
	return &http.Client{Transport: &rewriteTransport{host: host}}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if paramspider.New().Name() != "paramspider" {
		t.Error("expected name 'paramspider'")
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = paramspider.New()
}

// TestReturnsParamURLs: CDX returns URLs with params → findings produced.
func TestReturnsParamURLs(t *testing.T) {
	srv := cdxServer([]string{
		"https://example.com/search?q=foo&page=1",
		"https://example.com/api/users?id=123",
	})
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected param URL findings, got none")
	}
	for _, f := range findings {
		if f.Type != "historical_parameter_url_candidate" {
			t.Errorf("unexpected finding type %q", f.Type)
		}
		if !strings.Contains(f.URL, "FUZZ") {
			t.Errorf("expected FUZZ placeholder in URL, got %q", f.URL)
		}
		if f.Extra["validated"] != "false" ||
			f.Extra["validation_state"] != "public_archive_reference" ||
			f.Extra["promote_to_context"] != "false" ||
			f.Extra["source_validated"] != "true" {
			t.Errorf("historical candidate has unsafe evidence metadata: %+v", f.Extra)
		}
	}
}

// TestDropsStaticExtensions: CSS/PNG/JS URLs with params are dropped.
func TestDropsStaticExtensions(t *testing.T) {
	srv := cdxServer([]string{
		"https://example.com/style.css?v=1",
		"https://example.com/image.png?size=large",
		"https://example.com/bundle.js?v=2",
		"https://example.com/api?action=list", // should keep
	})
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.URL, ".css") || strings.Contains(f.URL, ".png") ||
			strings.Contains(f.URL, ".js?") {
			t.Errorf("static extension URL should have been dropped: %q", f.URL)
		}
	}
	if len(findings) == 0 {
		t.Error("expected at least one non-static URL to survive")
	}
}

// TestCustomPlaceholder: placeholder option replaces FUZZ with custom value.
func TestCustomPlaceholder(t *testing.T) {
	srv := cdxServer([]string{"https://example.com/api?key=value"})
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"placeholder": "INJECT"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.URL, "INJECT") {
			t.Errorf("expected INJECT placeholder, got %q", f.URL)
		}
		if strings.Contains(f.URL, "FUZZ") {
			t.Errorf("default FUZZ should not appear when custom placeholder set")
		}
	}
}

// TestDropsURLsWithoutParams: parameterless URLs are not returned.
func TestDropsURLsWithoutParams(t *testing.T) {
	srv := cdxServer([]string{
		"https://example.com/about",     // no params
		"https://example.com/contact",   // no params
		"https://example.com/?q=search", // has params → keep
	})
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.URL, "?") {
			t.Errorf("URL without params should have been dropped: %q", f.URL)
		}
	}
}

// TestEmptyTarget: no target → error.
func TestEmptyTarget(t *testing.T) {
	m := paramspider.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestURLsFromURLs: uses input.URLs[0] as domain fallback.
func TestURLsFromURLs(t *testing.T) {
	srv := cdxServer([]string{"https://example.com/search?q=test"})
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings when domain provided via URLs")
	}
}

// TestDeduplication: same URL not returned twice.
func TestDeduplication(t *testing.T) {
	srv := cdxServer([]string{
		"https://example.com/search?q=foo",
		"https://example.com/search?q=bar", // same params, different values → same after FUZZ
		"https://example.com/api?id=1",
		"https://example.com/api?id=2", // same
	})
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		seen[f.URL]++
	}
	for u, count := range seen {
		if count > 1 {
			t.Errorf("URL %q returned %d times (should be deduplicated)", u, count)
		}
	}
}

// TestFindingFields: all required fields populated.
func TestFindingFields(t *testing.T) {
	srv := cdxServer([]string{"https://example.com/page?id=1&action=view"})
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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
	if f.Extra["domain"] == "" {
		t.Error("Extra.domain empty")
	}
	if f.Extra["placeholder"] == "" {
		t.Error("Extra.placeholder empty")
	}
	if f.Extra["source"] == "" {
		t.Error("Extra.source empty")
	}
}

// TestHTTPSchemeNormalized: scheme in target is stripped.
func TestHTTPSchemeNormalized(t *testing.T) {
	srv := cdxServer([]string{"https://example.com/api?key=test"})
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	// Target with https:// prefix should work.
	findings, err := m.Run(context.Background(), module.Input{
		Target: "https://example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings with https:// scheme in target")
	}
}

// TestRedundantPortStripped: :80 on HTTP and :443 on HTTPS are stripped.
func TestRedundantPortStripped(t *testing.T) {
	srv := cdxServer([]string{
		"http://example.com:80/page?q=1",
		"https://example.com:443/api?id=2",
	})
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.URL, ":80/") || strings.Contains(f.URL, ":443/") {
			t.Errorf("redundant port should be stripped, got: %q", f.URL)
		}
	}
}

// TestCustomExtensions: user-supplied extensions are also dropped.
func TestCustomExtensions(t *testing.T) {
	srv := cdxServer([]string{
		"https://example.com/file.xml?version=1",   // custom extension
		"https://example.com/data.csv?format=json", // custom extension
		"https://example.com/api?action=test",      // should keep
	})
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"extensions": ".xml,.csv"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.URL, ".xml") || strings.Contains(f.URL, ".csv") {
			t.Errorf("custom extension should be dropped, got: %q", f.URL)
		}
	}
	if len(findings) == 0 {
		t.Error("expected non-dropped URL to survive")
	}
}

// TestContextCancellation: cancelled context → no panic.
func TestContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := paramspider.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{Target: "example.com"})
	_ = err // error expected, no panic
}

// TestNewWithClient: does not panic.
func TestNewWithClient(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := paramspider.NewWithClient(c)
	if m == nil || m.Name() != "paramspider" {
		t.Fatal("NewWithClient failed")
	}
}

// TestCDXError: CDX returns error → error propagated.
func TestCDXError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, "internal server error")
	}))
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err == nil {
		t.Fatal("expected an error for a non-success CDX response")
	}
}

// TestEmptyCDXResponse: CDX returns empty body → no findings, no error.
func TestEmptyCDXResponse(t *testing.T) {
	srv := cdxServer([]string{})
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for empty CDX response, got %d", len(findings))
	}
}

// TestFindingType: all findings are explicitly historical candidates.
func TestFindingType(t *testing.T) {
	srv := cdxServer([]string{
		"https://example.com/a?x=1",
		"https://example.com/b?y=2",
		"https://example.com/c?z=3",
	})
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type != "historical_parameter_url_candidate" {
			t.Errorf("expected historical candidate type, got %q", f.Type)
		}
	}
}

func TestOutOfScopeArchiveURLsAreDiscarded(t *testing.T) {
	srv := cdxServer([]string{
		"https://example.com/search?q=ok",
		"https://attacker.example/search?q=outside",
	})
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0].URL, "example.com/search") {
		t.Fatalf("out-of-scope archive URL was not discarded: %+v", findings)
	}
}

func TestMaxResults(t *testing.T) {
	srv := cdxServer([]string{
		"https://example.com/a?x=1",
		"https://example.com/b?x=1",
		"https://example.com/c?x=1",
	})
	defer srv.Close()

	m := paramspider.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"max_results": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected max 2 findings, got %d", len(findings))
	}
}
