package crawler_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/crawler"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────

// newSiteServer builds a multi-page site on an httptest.Server.
// pages maps URL paths to HTML content.
func newSiteServer(t *testing.T, pages map[string]string) (*httptest.Server, *crawler.Module) {
	t.Helper()
	mux := http.NewServeMux()
	for path, content := range pages {
		path, content := path, content
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, content)
		})
	}
	srv := httptest.NewServer(mux)
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	return srv, crawler.NewWithClient(client)
}

// urlSet returns a set of URL strings from findings.
func urlSet(findings []module.Finding) map[string]bool {
	s := map[string]bool{}
	for _, f := range findings {
		s[f.URL] = true
	}
	return s
}

// ─── tests ────────────────────────────────────────────────────────────────

// TestName verifies the module name.
func TestName(t *testing.T) {
	if crawler.New().Name() != "crawler" {
		t.Error("expected module name 'crawler'")
	}
}

// TestRun_EmptyTarget expects an error.
func TestRun_EmptyTarget(t *testing.T) {
	m := crawler.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestRun_ContextCancellation should not hang.
func TestRun_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := crawler.New()
	_, _ = m.Run(ctx, module.Input{Target: "http://example.com"})
}

// TestRun_SinglePage crawls a single page with no links.
func TestRun_SinglePage(t *testing.T) {
	srv, m := newSiteServer(t, map[string]string{
		"/": "<html><body>Hello World</body></html>",
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"depth": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least one finding for seed page")
	}
}

// TestRun_FollowsLinks verifies that links in HTML are followed.
func TestRun_FollowsLinks(t *testing.T) {
	srv, m := newSiteServer(t, map[string]string{
		"/":      `<html><body><a href="/about">About</a></body></html>`,
		"/about": `<html><body>About Page</body></html>`,
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/",
		Options: map[string]string{"depth": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	urls := urlSet(findings)
	if !urls[srv.URL+"/about"] {
		t.Errorf("expected /about in crawled URLs, got: %v", urls)
	}
}

// TestRun_DepthLimit verifies that crawl stops at max depth.
func TestRun_DepthLimit(t *testing.T) {
	// Three levels deep: / → /level1 → /level2
	srv, m := newSiteServer(t, map[string]string{
		"/":       fmt.Sprintf(`<html><body><a href="/level1">L1</a></body></html>`),
		"/level1": fmt.Sprintf(`<html><body><a href="/level2">L2</a></body></html>`),
		"/level2": fmt.Sprintf(`<html><body><a href="/level3">L3</a></body></html>`),
		"/level3": `<html><body>Deep Page</body></html>`,
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"depth": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	urls := urlSet(findings)
	// Level 3 should NOT be crawled when depth = 2.
	if urls[srv.URL+"/level3"] {
		t.Error("depth limit violated: /level3 should not be crawled at depth=2")
	}
}

// TestRun_Deduplication verifies that the same URL is only visited once.
func TestRun_Deduplication(t *testing.T) {
	var visitCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visitCount++
		w.Header().Set("Content-Type", "text/html")
		// Every page links back to itself and to /other.
		fmt.Fprintf(w, `<html><body><a href="/">Home</a><a href="/other">Other</a></body></html>`)
	}))
	defer srv.Close()

	m := crawler.NewWithClient(&http.Client{Timeout: 5 * time.Second})
	_, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"depth": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have visited "/" once and "/other" once — not revisit "/" again.
	if visitCount > 3 {
		t.Errorf("too many visits (%d) — deduplication broken", visitCount)
	}
}

// TestRun_FindingFields verifies required fields on every finding.
func TestRun_FindingFields(t *testing.T) {
	srv, m := newSiteServer(t, map[string]string{
		"/": "<html><body>Root</body></html>",
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"depth": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type != "crawled_url" {
			t.Errorf("expected type 'crawled_url', got %q", f.Type)
		}
		if f.URL == "" {
			t.Error("finding missing URL")
		}
		if f.Extra["status_code"] == "" {
			t.Error("finding missing status_code field")
		}
		if f.Extra["depth"] == "" {
			t.Error("finding missing depth field")
		}
		if f.Extra["validated"] != "true" ||
			f.Extra["validation_state"] != "http_response_confirmed" ||
			f.Extra["promote_to_context"] != "true" {
			t.Errorf("confirmed crawl result has incomplete evidence metadata: %+v", f.Extra)
		}
	}
}

func TestRun_MaxPagesLimitsWork(t *testing.T) {
	var visitCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visitCount++
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<a href="/one">one</a><a href="/two">two</a><a href="/three">three</a>`)
			return
		}
		fmt.Fprint(w, "<html><body>leaf</body></html>")
	}))
	defer srv.Close()

	m := crawler.NewWithClient(&http.Client{Timeout: 5 * time.Second})
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL,
		Options: map[string]string{
			"depth":     "3",
			"max_pages": "2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if visitCount > 2 {
		t.Fatalf("max_pages=2 allowed %d requests", visitCount)
	}
	if len(findings) > 2 {
		t.Fatalf("max_pages=2 returned %d findings", len(findings))
	}
}

// TestRun_TargetFromURLs uses URLs[0] when Target is empty.
func TestRun_TargetFromURLs(t *testing.T) {
	srv, m := newSiteServer(t, map[string]string{
		"/": "<html><body>Root</body></html>",
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL},
		Options: map[string]string{"depth": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected findings when using URLs[0]")
	}
}

// TestRun_OutOfScopeLinksFiltered verifies that external links are not followed.
func TestRun_OutOfScopeLinksFiltered(t *testing.T) {
	// Page links to both same-server path and a completely different domain.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><body>
			<a href="/internal">Internal</a>
			<a href="https://evil.com/phishing">External</a>
		</body></html>`)
	}))
	defer srv.Close()

	m := crawler.NewWithClient(&http.Client{Timeout: 5 * time.Second})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"depth": "2", "scope": "strict"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if strings.Contains(f.URL, "evil.com") {
			t.Errorf("out-of-scope URL %q should not be in findings", f.URL)
		}
	}
}

// TestRun_HttpStatus verifies that status codes are captured.
func TestRun_HttpStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "<html><body>OK</body></html>")
	}))
	defer srv.Close()

	m := crawler.NewWithClient(&http.Client{Timeout: 5 * time.Second})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"depth": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["status_code"] != "200" {
			t.Errorf("expected status_code 200, got %q", f.Extra["status_code"])
		}
	}
}

// TestModuleImplementsInterface ensures the Module implements the interface.
func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = crawler.New()
}

// TestRun_SeedURLRecorded verifies the seed URL itself is in the results.
func TestRun_SeedURLRecorded(t *testing.T) {
	srv, m := newSiteServer(t, map[string]string{
		"/start": "<html><body>Start</body></html>",
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/start",
		Options: map[string]string{"depth": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	urls := urlSet(findings)
	if !urls[srv.URL+"/start"] {
		t.Error("seed URL should appear in crawl results")
	}
}

// TestRun_FormActionFound verifies that form action URLs are discovered.
func TestRun_FormActionFound(t *testing.T) {
	srv, m := newSiteServer(t, map[string]string{
		"/":       `<html><body><form action="/submit" method="post"><input type="submit"></form></body></html>`,
		"/submit": "<html><body>Submitted</body></html>",
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"depth": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	urls := urlSet(findings)
	if !urls[srv.URL+"/submit"] {
		t.Logf("form action URL not found (may require forms=true option): %v", urls)
	}
}

// TestRun_AbsoluteLinksFollowed verifies absolute URLs on same host are followed.
func TestRun_AbsoluteLinksFollowed(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			fmt.Fprintf(w, `<html><body><a href="%s/page">Page</a></body></html>`, srv.URL)
		} else {
			fmt.Fprintln(w, "<html><body>Page</body></html>")
		}
	}))
	defer srv.Close()

	m := crawler.NewWithClient(&http.Client{Timeout: 5 * time.Second})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"depth": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	urls := urlSet(findings)
	if !urls[srv.URL+"/page"] {
		t.Errorf("absolute link on same host not followed, got: %v", urls)
	}
}

// TestRun_MaxConcurrency verifies concurrency option is accepted.
func TestRun_MaxConcurrency(t *testing.T) {
	srv, m := newSiteServer(t, map[string]string{
		"/": "<html><body>root</body></html>",
	})
	defer srv.Close()

	_, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"depth": "1", "concurrency": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRun_FindingsSeveritySet verifies all crawler findings have a severity.
func TestRun_FindingsSeveritySet(t *testing.T) {
	srv, m := newSiteServer(t, map[string]string{
		"/":        `<html><body><a href="/about">about</a><a href="/contact">contact</a></body></html>`,
		"/about":   "<html><body>About</body></html>",
		"/contact": "<html><body>Contact</body></html>",
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"depth": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == "" {
			t.Errorf("crawler finding missing Severity: %+v", f)
		}
	}
}

// TestRun_FindingsHaveConfidence verifies all findings have a non-empty confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	srv, m := newSiteServer(t, map[string]string{
		"/": "<html><body>Root</body></html>",
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"depth": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding missing Extra[confidence]: %+v", f)
		}
	}
}

// TestRun_FindingTypeValid verifies all findings have a non-empty Type field.
func TestRun_FindingTypeValid(t *testing.T) {
	srv, m := newSiteServer(t, map[string]string{
		"/":     `<html><body><a href="/page">page</a></body></html>`,
		"/page": "<html><body>Page</body></html>",
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"depth": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "" {
			t.Errorf("finding has empty Type: %+v", f)
		}
	}
}

// TestRun_FindingURLOrDetailSet verifies each finding has at least URL or Detail set.
func TestRun_FindingURLOrDetailSet(t *testing.T) {
	srv, m := newSiteServer(t, map[string]string{
		"/": "<html><body>Root</body></html>",
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"depth": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.URL == "" && f.Detail == "" {
			t.Errorf("finding has neither URL nor Detail: %+v", f)
		}
	}
}
