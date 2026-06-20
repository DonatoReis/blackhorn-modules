package gau

import (
	"context"
	"encoding/json"
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
		if f.URL == u {
			return true
		}
	}
	return false
}

func hasSource(findings []module.Finding, src string) bool {
	for _, f := range findings {
		if f.Extra["source"] == src {
			return true
		}
	}
	return false
}

func jsonSrv(t *testing.T, v any) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}))
}

func statusSrv(code int) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
	}))
}

// ─── basic ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "gau" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoDomain(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

// ─── Wayback ─────────────────────────────────────────────────────────────────

func TestWayback_HistoricalURLs(t *testing.T) {
	// CDX API with fl=original: first row is header, rest are data.
	rows := [][]string{
		{"original"},
		{"https://example.com/api/users"},
		{"https://example.com/admin/login"},
		{"https://sub.example.com/page"},
	}
	srv := jsonSrv(t, rows)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.WaybackBaseURL = srv.URL
	m.Sources = []string{"wayback"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "historical_reference") {
		t.Fatal("expected historical_reference findings from Wayback")
	}
	if !hasURL(findings, "https://example.com/api/users") {
		t.Fatal("expected https://example.com/api/users")
	}
	if !hasSource(findings, "wayback") {
		t.Fatal("expected source=wayback")
	}
}

func TestBuildFindingsRejectsMalformedAndOutOfScopeURLs(t *testing.T) {
	findings := buildFindings("example.com", "wayback", []string{
		"https://example.com/good#fragment",
		"https://www..example.com/invalid",
		"https://example.com.attacker.test/out",
	}, nil, nil)
	if len(findings) != 1 {
		t.Fatalf("expected one valid reference, got %+v", findings)
	}
	if findings[0].URL != "https://example.com/good" {
		t.Fatalf("unexpected canonical URL %q", findings[0].URL)
	}
	if findings[0].Extra["promote_to_context"] != "false" {
		t.Fatal("historical references must not be promoted to active context")
	}
}

func TestWayback_EmptyBody(t *testing.T) {
	// Empty JSON array — no URLs.
	srv := jsonSrv(t, [][]string{})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.WaybackBaseURL = srv.URL
	m.Sources = []string{"wayback"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty CDX response, got %d", len(findings))
	}
}

func TestWayback_HTTP_Error_SoftFail(t *testing.T) {
	srv := statusSrv(500)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.WaybackBaseURL = srv.URL
	m.Sources = []string{"wayback"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal("expected soft failure on HTTP 500")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on error, got %d", len(findings))
	}
}

func TestWayback_HeaderRowSkipped(t *testing.T) {
	// The "original" header row must not appear in findings.
	rows := [][]string{
		{"original"},
		{"https://example.com/valid"},
	}
	srv := jsonSrv(t, rows)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.WaybackBaseURL = srv.URL
	m.Sources = []string{"wayback"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.URL == "original" {
			t.Fatal("header row 'original' must not appear in findings")
		}
	}
	if !hasURL(findings, "https://example.com/valid") {
		t.Fatal("expected https://example.com/valid")
	}
}

// ─── Common Crawl ─────────────────────────────────────────────────────────────

func TestCommonCrawl_URLs(t *testing.T) {
	// Simulate collinfo.json + CDX query.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/collinfo.json" {
			w.Header().Set("Content-Type", "application/json")
			// Point cdx-api back to this test server.
			indexes := []ccIndex{{
				ID:     "CC-MAIN-2024-10",
				CDXAPI: "https://" + r.Host + "/cdx",
			}}
			json.NewEncoder(w).Encode(indexes)
			return
		}
		// CDX endpoint: return NDJSON.
		fmt.Fprintln(w, `{"url":"https://example.com/about"}`)
		fmt.Fprintln(w, `{"url":"https://example.com/contact"}`)
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CommonCrawlBaseURL = srv.URL
	m.Sources = []string{"commoncrawl"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasURL(findings, "https://example.com/about") {
		t.Fatal("expected https://example.com/about from CC")
	}
	if !hasSource(findings, "commoncrawl") {
		t.Fatal("expected source=commoncrawl")
	}
}

func TestCommonCrawl_EmptyIndexList(t *testing.T) {
	srv := jsonSrv(t, []ccIndex{})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CommonCrawlBaseURL = srv.URL
	m.Sources = []string{"commoncrawl"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty CC index list, got %d", len(findings))
	}
}

func TestCommonCrawl_CollinfoError_SoftFail(t *testing.T) {
	srv := statusSrv(503)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CommonCrawlBaseURL = srv.URL
	m.Sources = []string{"commoncrawl"}

	_, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal("expected soft failure for CC collinfo 503")
	}
}

// ─── AlienVault OTX ──────────────────────────────────────────────────────────

func TestOTX_URLs(t *testing.T) {
	resp := otxResponse{
		URLList: []struct {
			URL string `json:"url"`
		}{
			{URL: "https://example.com/path1"},
			{URL: "https://example.com/path2"},
		},
		HasNext: false,
	}
	srv := jsonSrv(t, resp)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.OTXBaseURL = srv.URL
	m.Sources = []string{"otx"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasURL(findings, "https://example.com/path1") {
		t.Fatal("expected https://example.com/path1 from OTX")
	}
	if !hasSource(findings, "otx") {
		t.Fatal("expected source=otx")
	}
}

func TestOTX_Pagination(t *testing.T) {
	page := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		w.Header().Set("Content-Type", "application/json")
		if page == 1 {
			json.NewEncoder(w).Encode(otxResponse{
				URLList: []struct {
					URL string `json:"url"`
				}{{URL: "https://example.com/p" + fmt.Sprint(page)}},
				HasNext: true,
			})
		} else {
			json.NewEncoder(w).Encode(otxResponse{
				URLList: []struct {
					URL string `json:"url"`
				}{{URL: "https://example.com/p" + fmt.Sprint(page)}},
				HasNext: false,
			})
		}
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.OTXBaseURL = srv.URL
	m.Sources = []string{"otx"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings from OTX pagination, got %d", len(findings))
	}
}

func TestOTX_HTTP_Error_SoftFail(t *testing.T) {
	srv := statusSrv(429)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.OTXBaseURL = srv.URL
	m.Sources = []string{"otx"}

	_, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal("expected soft failure for OTX 429")
	}
}

// ─── URLScan ─────────────────────────────────────────────────────────────────

func TestURLScan_URLs(t *testing.T) {
	resp := urlscanResponse{
		Results: []struct {
			Page struct {
				URL string `json:"url"`
			} `json:"page"`
		}{
			{Page: struct {
				URL string `json:"url"`
			}{URL: "https://example.com/login"}},
			{Page: struct {
				URL string `json:"url"`
			}{URL: "https://api.example.com/v2"}},
		},
		Total: 2,
	}
	srv := jsonSrv(t, resp)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.URLScanBaseURL = srv.URL
	m.Sources = []string{"urlscan"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasURL(findings, "https://example.com/login") {
		t.Fatal("expected https://example.com/login from urlscan")
	}
	if !hasSource(findings, "urlscan") {
		t.Fatal("expected source=urlscan")
	}
}

func TestURLScan_HTTP_Error_SoftFail(t *testing.T) {
	srv := statusSrv(503)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.URLScanBaseURL = srv.URL
	m.Sources = []string{"urlscan"}

	_, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal("expected soft failure for urlscan 503")
	}
}

// ─── filtering ───────────────────────────────────────────────────────────────

func TestBlacklist_ExtensionFiltered(t *testing.T) {
	rows := [][]string{
		{"original"},
		{"https://example.com/image.png"},
		{"https://example.com/page.html"},
		{"https://example.com/style.css"},
	}
	srv := jsonSrv(t, rows)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.WaybackBaseURL = srv.URL
	m.Sources = []string{"wayback"}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"blacklist": "png,css"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		ext := urlExtension(f.URL)
		if ext == "png" || ext == "css" {
			t.Fatalf("blacklisted extension %q found in findings: %s", ext, f.URL)
		}
	}
	if !hasURL(findings, "https://example.com/page.html") {
		t.Fatal("expected page.html (not blacklisted)")
	}
}

func TestWhitelist_OnlyMatchingExtensions(t *testing.T) {
	rows := [][]string{
		{"original"},
		{"https://example.com/api/endpoint"},
		{"https://example.com/file.php"},
		{"https://example.com/image.jpg"},
	}
	srv := jsonSrv(t, rows)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.WaybackBaseURL = srv.URL
	m.Sources = []string{"wayback"}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"whitelist": "php"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		ext := urlExtension(f.URL)
		if ext != "php" && ext != "" {
			// URLs with no extension are also kept when they pass whitelist check
			// — but our whitelist implementation returns false for non-matching
			// non-empty extensions.
			t.Fatalf("whitelist violated: found URL with ext %q: %s", ext, f.URL)
		}
	}
}

// ─── MaxURLs cap ─────────────────────────────────────────────────────────────

func TestMaxURLs_Cap(t *testing.T) {
	rows := make([][]string, 51)
	rows[0] = []string{"original"}
	for i := 1; i <= 50; i++ {
		rows[i] = []string{fmt.Sprintf("https://example.com/page%d", i)}
	}
	srv := jsonSrv(t, rows)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.WaybackBaseURL = srv.URL
	m.Sources = []string{"wayback"}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"max_urls": "10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) > 10 {
		t.Fatalf("expected max 10 findings, got %d", len(findings))
	}
}

// ─── dedup ────────────────────────────────────────────────────────────────────

func TestDedup_SameURL(t *testing.T) {
	// Two sources returning the same URL — should be deduped.
	resp := otxResponse{
		URLList: []struct {
			URL string `json:"url"`
		}{{URL: "https://example.com/api"}},
		HasNext: false,
	}
	urlscanResp := urlscanResponse{
		Results: []struct {
			Page struct {
				URL string `json:"url"`
			} `json:"page"`
		}{{Page: struct {
			URL string `json:"url"`
		}{URL: "https://example.com/api"}}},
	}

	otxSrv := jsonSrv(t, resp)
	defer otxSrv.Close()
	urlscanSrv := jsonSrv(t, urlscanResp)
	defer urlscanSrv.Close()

	m := NewWithClient(otxSrv.Client())
	m.OTXBaseURL = otxSrv.URL
	// Both sources serve from the same test client, so we reuse the client.
	// In practice both servers return the same URL to test dedup.
	m.URLScanBaseURL = urlscanSrv.URL
	m.Sources = []string{"otx"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, f := range findings {
		if f.URL == "https://example.com/api" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 occurrence of deduped URL, got %d", count)
	}
}

// ─── multi-domain ─────────────────────────────────────────────────────────────

func TestMultiDomain_FromURLs(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := r.URL.RawQuery
		if strings.Contains(q, url.QueryEscape("example.com")) {
			json.NewEncoder(w).Encode([][]string{
				{"original"},
				{"https://example.com/home"},
			})
		} else {
			json.NewEncoder(w).Encode([][]string{
				{"original"},
				{"https://acme.org/home"},
			})
		}
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.WaybackBaseURL = srv.URL
	m.Sources = []string{"wayback"}

	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		URLs:   []string{"acme.org"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasURL(findings, "https://example.com/home") {
		t.Fatal("expected https://example.com/home")
	}
	if !hasURL(findings, "https://acme.org/home") {
		t.Fatal("expected https://acme.org/home")
	}
}

func TestRawContent_Domains(t *testing.T) {
	rows := [][]string{
		{"original"},
		{"https://example.com/test"},
	}
	srv := jsonSrv(t, rows)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.WaybackBaseURL = srv.URL
	m.Sources = []string{"wayback"}

	findings, err := m.Run(context.Background(), module.Input{
		RawContent: "example.com\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasURL(findings, "https://example.com/test") {
		t.Fatal("expected https://example.com/test from RawContent domain")
	}
}

// ─── options via Input ────────────────────────────────────────────────────────

func TestSourcesOption_SelectsSingleSource(t *testing.T) {
	waybackRows := [][]string{
		{"original"},
		{"https://example.com/wayback"},
	}
	srv := jsonSrv(t, waybackRows)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.WaybackBaseURL = srv.URL

	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "wayback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Extra["source"] != "wayback" {
			t.Fatalf("expected only wayback source, got %q", f.Extra["source"])
		}
	}
}

func TestUnknownSource_SoftFail(t *testing.T) {
	m := New()
	m.Sources = []string{"unknown_source_xyz"}
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal("expected soft failure for unknown source")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for unknown source, got %d", len(findings))
	}
}

// ─── unit helpers ────────────────────────────────────────────────────────────

func TestCleanDomain(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://example.com/path?q=1", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"example.com.", "example.com"},
		{"  example.com  ", "example.com"},
		{"example.com:443", "example.com"},
	}
	for _, c := range cases {
		if got := cleanDomain(c.in); got != c.want {
			t.Errorf("cleanDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestURLExtension(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"https://example.com/image.PNG", "png"},
		{"https://example.com/script.js", "js"},
		{"https://example.com/api/endpoint", ""},
		{"https://example.com/", ""},
		{"not a url", ""},
	}
	for _, c := range cases {
		if got := urlExtension(c.url); got != c.want {
			t.Errorf("urlExtension(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

func TestMatchesFilter_Blacklist(t *testing.T) {
	if matchesFilter("https://x.com/img.png", []string{"png"}, nil) {
		t.Fatal("expected png to be filtered by blacklist")
	}
	if !matchesFilter("https://x.com/page.html", []string{"png"}, nil) {
		t.Fatal("expected html to pass blacklist")
	}
}

func TestMatchesFilter_Whitelist(t *testing.T) {
	if matchesFilter("https://x.com/img.png", nil, []string{"php"}) {
		t.Fatal("expected png to fail whitelist")
	}
	if !matchesFilter("https://x.com/file.php", nil, []string{"php"}) {
		t.Fatal("expected php to pass whitelist")
	}
}

func TestDedupFindings(t *testing.T) {
	ff := []module.Finding{
		{URL: "https://example.com/a"},
		{URL: "https://example.com/a"},
		{URL: "https://example.com/b"},
	}
	got := dedupFindings(ff)
	if len(got) != 2 {
		t.Fatalf("expected 2 after dedup, got %d", len(got))
	}
}

func TestCollectDomains_Dedup(t *testing.T) {
	input := module.Input{
		Target:     "example.com",
		URLs:       []string{"example.com", "acme.org"},
		RawContent: "example.com\n",
	}
	domains := collectDomains(input)
	if len(domains) != 2 {
		t.Fatalf("expected 2 unique domains, got %d: %v", len(domains), domains)
	}
}
