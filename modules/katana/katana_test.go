package katana

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func hasType(findings []module.Finding, t string) bool {
	for _, f := range findings {
		if f.Type == t {
			return true
		}
	}
	return false
}

func hasURL(findings []module.Finding, u string) bool {
	for _, f := range findings {
		if f.URL == u || strings.HasSuffix(f.URL, u) {
			return true
		}
	}
	return false
}

func countType(findings []module.Finding, t string) int {
	n := 0
	for _, f := range findings {
		if f.Type == t {
			n++
		}
	}
	return n
}

func htmlSrv(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, body)
	}))
}

func routedSrv(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := routes[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, body)
		} else {
			http.NotFound(w, r)
		}
	}))
}

// ─── basic ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "katana" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoTarget(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

// ─── basic crawl ─────────────────────────────────────────────────────────────

func TestCrawl_Single(t *testing.T) {
	srv := htmlSrv(t, `<html><body><a href="/about">About</a></body></html>`)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.MaxDepth = 1

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, TypeCrawled) {
		t.Fatal("expected crawled_url finding")
	}
	if !hasURL(findings, srv.URL) {
		t.Fatal("expected seed URL in findings")
	}
	for _, finding := range findings {
		if finding.Type != TypeCrawled {
			continue
		}
		if finding.Extra["validated"] != "true" ||
			finding.Extra["validation_state"] != "http_response_confirmed" ||
			finding.Extra["promote_to_context"] != "true" {
			t.Fatalf("crawled URL lacks confirmation metadata: %+v", finding.Extra)
		}
	}
}

func TestCrawl_FollowsLinks(t *testing.T) {
	srv := routedSrv(t, map[string]string{
		"/":      `<html><body><a href="/page1">p1</a><a href="/page2">p2</a></body></html>`,
		"/page1": `<html><body>Page 1</body></html>`,
		"/page2": `<html><body>Page 2</body></html>`,
	})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.MaxDepth = 2
	m.Scope = ScopeSameHost

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasURL(findings, "/page1") {
		t.Fatal("expected /page1 to be crawled")
	}
	if !hasURL(findings, "/page2") {
		t.Fatal("expected /page2 to be crawled")
	}
}

func TestCrawl_DepthLimit(t *testing.T) {
	// /a links to /b, /b links to /c. With depth=1 only /a should be visited.
	srv := routedSrv(t, map[string]string{
		"/a": `<a href="/b">b</a>`,
		"/b": `<a href="/c">c</a>`,
		"/c": `<p>deep</p>`,
	})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.MaxDepth = 1

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "/a"})
	if err != nil {
		t.Fatal(err)
	}
	if hasURL(findings, "/c") {
		t.Fatal("/c should not be crawled at depth=1")
	}
}

// ─── form extraction ─────────────────────────────────────────────────────────

func TestForms_LoginForm(t *testing.T) {
	html := `<html><body>
<form method="POST" action="/login">
  <input name="username" type="text">
  <input name="password" type="password">
  <input type="submit" value="Login">
</form>
</body></html>`

	srv := htmlSrv(t, html)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.ExtractForms = true
	m.MaxDepth = 0

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, TypeForm) {
		t.Fatal("expected form_field findings")
	}
	// Check username field.
	found := false
	for _, f := range findings {
		if f.Type == TypeForm && f.Extra["field_name"] == "username" && f.Extra["field_type"] == "text" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected username text field finding")
	}
	// Check password field.
	foundPwd := false
	for _, f := range findings {
		if f.Type == TypeForm && f.Extra["field_name"] == "password" && f.Extra["field_type"] == "password" {
			foundPwd = true
		}
	}
	if !foundPwd {
		t.Fatal("expected password field finding")
	}
	// submit inputs with no name should be skipped.
	for _, f := range findings {
		if f.Type == TypeForm && f.Extra["field_type"] == "submit" {
			t.Fatal("submit input with no name should not create a finding")
		}
	}
}

func TestForms_TextareaAndSelect(t *testing.T) {
	html := `<html><body>
<form method="POST" action="/submit">
  <textarea name="comment"></textarea>
  <select name="category"><option>A</option></select>
</form>
</body></html>`

	srv := htmlSrv(t, html)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.ExtractForms = true
	m.MaxDepth = 0

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	foundTextarea := false
	foundSelect := false
	for _, f := range findings {
		if f.Type == TypeForm && f.Extra["field_name"] == "comment" && f.Extra["field_type"] == "textarea" {
			foundTextarea = true
		}
		if f.Type == TypeForm && f.Extra["field_name"] == "category" && f.Extra["field_type"] == "select" {
			foundSelect = true
		}
	}
	if !foundTextarea {
		t.Fatal("expected textarea finding")
	}
	if !foundSelect {
		t.Fatal("expected select finding")
	}
}

func TestForms_FormMethod_Default_GET(t *testing.T) {
	html := `<form action="/search"><input name="q" type="text"></form>`
	srv := htmlSrv(t, html)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.ExtractForms = true
	m.MaxDepth = 0

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Type == TypeForm && f.Extra["field_name"] == "q" {
			if f.Extra["form_method"] != "GET" {
				t.Errorf("expected form_method=GET, got %q", f.Extra["form_method"])
			}
			return
		}
	}
	t.Fatal("expected form field q")
}

func TestForms_Disabled_NoFormFindings(t *testing.T) {
	html := `<form method="POST" action="/login"><input name="user" type="text"></form>`
	srv := htmlSrv(t, html)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.ExtractForms = false
	m.MaxDepth = 0

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if hasType(findings, TypeForm) {
		t.Fatal("expected no form findings when ExtractForms=false")
	}
}

// ─── JS endpoint extraction ───────────────────────────────────────────────────

func TestJSEndpoints_Fetch(t *testing.T) {
	html := `<script>
fetch('/api/users').then(r => r.json());
fetch("/api/posts");
</script>`
	srv := htmlSrv(t, html)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.ExtractJS = true
	m.MaxDepth = 0

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, TypeJSEndpoint) {
		t.Fatal("expected js_endpoint findings")
	}
	foundAPI := false
	for _, f := range findings {
		if f.Type == TypeJSEndpoint && strings.Contains(f.URL, "/api/") {
			foundAPI = true
		}
	}
	if !foundAPI {
		t.Fatal("expected /api/* JS endpoint")
	}
	for _, finding := range findings {
		if finding.Type != TypeJSEndpoint {
			continue
		}
		if finding.Extra["validated"] != "false" ||
			finding.Extra["validation_state"] != "javascript_endpoint_candidate" ||
			finding.Extra["promote_to_context"] != "false" ||
			finding.Extra["source_validated"] != "true" {
			t.Fatalf("JS endpoint candidate has unsafe evidence metadata: %+v", finding.Extra)
		}
	}
}

func TestJSEndpoints_Axios(t *testing.T) {
	html := `<script>axios.get('/api/v2/items')</script>`
	srv := htmlSrv(t, html)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.ExtractJS = true
	m.MaxDepth = 0

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, TypeJSEndpoint) {
		t.Fatal("expected js_endpoint from axios.get")
	}
}

func TestJSEndpoints_XHR(t *testing.T) {
	html := `<script>xhr.open('GET', '/api/data')</script>`
	srv := htmlSrv(t, html)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.ExtractJS = true
	m.MaxDepth = 0

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Type == TypeJSEndpoint && strings.Contains(f.URL, "/api/data") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected /api/data from XHR.open")
	}
}

func TestJSEndpoints_Disabled(t *testing.T) {
	html := `<script>fetch('/api/secret')</script>`
	srv := htmlSrv(t, html)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.ExtractJS = false
	m.MaxDepth = 0

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if hasType(findings, TypeJSEndpoint) {
		t.Fatal("expected no JS endpoints when ExtractJS=false")
	}
}

func TestRunOptionsDoNotMutateModule(t *testing.T) {
	html := `<script>fetch('/api/secret')</script>`
	srv := htmlSrv(t, html)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.ExtractJS = true
	m.MaxDepth = 0

	disabled, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"js": "false"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasType(disabled, TypeJSEndpoint) {
		t.Fatal("js=false should disable endpoint extraction for this run")
	}

	enabled, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(enabled, TypeJSEndpoint) {
		t.Fatal("run options mutated the reusable module instance")
	}
}

// ─── robots.txt ───────────────────────────────────────────────────────────────

func TestRobots_DisallowPaths(t *testing.T) {
	srv := routedSrv(t, map[string]string{
		"/robots.txt": "User-agent: *\nDisallow: /admin\nDisallow: /private\n",
		"/":           "<html></html>",
	})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = true
	m.SeedSitemap = false
	m.MaxDepth = 0

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, TypeRobots) {
		t.Fatal("expected robots_disallow findings")
	}
	found := false
	for _, f := range findings {
		if f.Type == TypeRobots && strings.Contains(f.URL, "/admin") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected /admin in robots_disallow findings")
	}
	for _, finding := range findings {
		if finding.Type != TypeRobots {
			continue
		}
		if finding.Extra["validated"] != "false" ||
			finding.Extra["promote_to_context"] != "false" ||
			finding.Extra["source_validated"] != "true" {
			t.Fatalf("robots path must remain a non-promoting candidate: %+v", finding.Extra)
		}
	}
}

func TestRobots_404_SoftFail(t *testing.T) {
	srv := htmlSrv(t, "<html></html>")
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = true
	m.SeedSitemap = false
	m.MaxDepth = 0

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	// No robots.txt — should soft fail, not error.
	for _, f := range findings {
		if f.Type == TypeRobots {
			t.Fatal("expected no robots findings when robots.txt is 404")
		}
	}
}

// ─── sitemap.xml ─────────────────────────────────────────────────────────────

func TestSitemap_URLSet(t *testing.T) {
	urlset := sitemapURLSet{
		URLs: []sitemapLoc{
			{Loc: "https://example.com/page1"},
			{Loc: "https://example.com/page2"},
		},
	}
	xmlBytes, _ := xml.Marshal(urlset)

	srv := routedSrv(t, map[string]string{
		"/sitemap.xml": string(xmlBytes),
		"/":            "<html></html>",
	})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = true
	m.MaxDepth = 0

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, TypeSitemap) {
		t.Fatal("expected sitemap_url findings")
	}
}

func TestSitemap_404_SoftFail(t *testing.T) {
	srv := htmlSrv(t, "<html></html>")
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = true
	m.MaxDepth = 0

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Type == TypeSitemap {
			t.Fatal("expected no sitemap findings when sitemap.xml is 404")
		}
	}
}

// ─── scope ────────────────────────────────────────────────────────────────────

func TestScope_SameHost_RejectsExternal(t *testing.T) {
	// Page links to an external domain.
	html := `<a href="https://evil.com/malware">evil</a><a href="/safe">safe</a>`
	srv := htmlSrv(t, html)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.Scope = ScopeSameHost
	m.MaxDepth = 1

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.URL == "https://evil.com/malware" {
			t.Fatal("external link should be out of scope with ScopeSameHost")
		}
	}
}

func TestScope_Option_Domain(t *testing.T) {
	srv := htmlSrv(t, `<a href="/internal">int</a>`)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.MaxDepth = 1

	// scope=domain via options.
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"scope": "domain"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, TypeCrawled) {
		t.Fatal("expected crawled findings with domain scope")
	}
}

// ─── asset extraction ─────────────────────────────────────────────────────────

func TestAssets_ExtractEnabled(t *testing.T) {
	html := `<img src="/logo.png"><script src="/app.js"></script><link href="/style.css">`
	srv := htmlSrv(t, html)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.ExtractAssets = true
	m.MaxDepth = 0

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, TypeAsset) {
		t.Fatal("expected asset_url findings when ExtractAssets=true")
	}
}

func TestAssets_Disabled(t *testing.T) {
	html := `<img src="/logo.png"><script src="/app.js"></script>`
	srv := htmlSrv(t, html)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.ExtractAssets = false
	m.MaxDepth = 0

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if hasType(findings, TypeAsset) {
		t.Fatal("expected no asset findings when ExtractAssets=false")
	}
}

// ─── dedup ────────────────────────────────────────────────────────────────────

func TestDedup_SamePage(t *testing.T) {
	// Multiple links to the same page.
	html := `<a href="/same">1</a><a href="/same">2</a><a href="/same">3</a>`
	srv := routedSrv(t, map[string]string{
		"/":     html,
		"/same": "<html></html>",
	})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.MaxDepth = 2

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, f := range findings {
		if f.Type == TypeCrawled && strings.HasSuffix(f.URL, "/same") {
			count++
		}
	}
	if count > 1 {
		t.Fatalf("expected /same crawled once, got %d times", count)
	}
}

func TestCrawl_MaxPagesLimitsRequests(t *testing.T) {
	var visitCount int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visitCount++
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<a href="/one">one</a><a href="/two">two</a><a href="/three">three</a>`)
			return
		}
		fmt.Fprint(w, "<html><body>leaf</body></html>")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.MaxDepth = 3
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL,
		Options: map[string]string{
			"max_pages": "2",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if visitCount > 2 {
		t.Fatalf("max_pages=2 allowed %d requests", visitCount)
	}
	if countType(findings, TypeCrawled) > 2 {
		t.Fatalf("max_pages=2 returned too many confirmed pages: %d", countType(findings, TypeCrawled))
	}
}

// ─── multi-seed ───────────────────────────────────────────────────────────────

func TestMultiSeed_URLsField(t *testing.T) {
	page1 := htmlSrv(t, `<html><title>Page1</title></html>`)
	defer page1.Close()
	page2 := htmlSrv(t, `<html><title>Page2</title></html>`)
	defer page2.Close()

	// Use page1's client for both (both use srv.Client() with InsecureSkipVerify).
	m := NewWithClient(page1.Client())
	m.SeedRobots = false
	m.SeedSitemap = false
	m.MaxDepth = 0
	m.Scope = ScopeAll

	findings, err := m.Run(context.Background(), module.Input{
		Target: page1.URL,
		URLs:   []string{page2.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasURL(findings, page1.URL) {
		t.Fatal("expected page1 in findings")
	}
}

// ─── helpers unit tests ───────────────────────────────────────────────────────

func TestExtractForms_InputFields(t *testing.T) {
	html := `<form method="POST" action="/login">
<input name="user" type="text" value="admin">
<input name="pass" type="password">
</form>`
	fields := extractForms(html, "https://example.com/")
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(fields))
	}
	if fields[0].Name != "user" || fields[0].Type != "text" {
		t.Errorf("field[0] mismatch: %+v", fields[0])
	}
	if fields[1].Name != "pass" || fields[1].Type != "password" {
		t.Errorf("field[1] mismatch: %+v", fields[1])
	}
}

func TestExtractJSEndpoints_APIPatterns(t *testing.T) {
	body := `
fetch('/api/users')
axios.get('/api/items')
xhr.open('GET', '/v2/data')
`
	endpoints := extractJSEndpoints(body, "https://example.com")
	if len(endpoints) < 3 {
		t.Fatalf("expected at least 3 JS endpoints, got %d: %v", len(endpoints), endpoints)
	}
}

func TestAbsoluteURL(t *testing.T) {
	base, _ := url.Parse("https://example.com/app/")
	cases := []struct{ in, want string }{
		{"/api/v1", "https://example.com/api/v1"},
		{"https://other.com/x", "https://other.com/x"},
		{"#anchor", ""},
		{"javascript:void(0)", ""},
	}
	for _, c := range cases {
		got := absoluteURL(base, c.in)
		if got != c.want {
			t.Errorf("absoluteURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSameDomain(t *testing.T) {
	if !sameDomain("sub.example.com", "example.com") {
		t.Fatal("expected same domain for sub.example.com / example.com")
	}
	if sameDomain("example.com", "other.com") {
		t.Fatal("expected different domain for example.com / other.com")
	}
}

func TestETLDPlus1(t *testing.T) {
	if got := eTLDPlus1("sub.example.com"); got != "example.com" {
		t.Fatalf("expected example.com, got %q", got)
	}
	if got := eTLDPlus1("example.com"); got != "example.com" {
		t.Fatalf("expected example.com, got %q", got)
	}
}
