package recon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func hasSource(findings []module.Finding, src string) bool {
	for _, f := range findings {
		if f.Extra["source"] == src {
			return true
		}
	}
	return false
}

func hasHost(findings []module.Finding, host string) bool {
	for _, f := range findings {
		if f.URL == host || f.Extra["host"] == host {
			return true
		}
	}
	return false
}

func jsonSrv(t *testing.T, v any) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(v)
	}))
}

func textSrv(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(body))
	}))
}

func errorSrv(code int) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
	}))
}

// ─── basic ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "recon" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoDomain(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

// ─── CT Log ──────────────────────────────────────────────────────────────────

func TestCTLog_Subdomains(t *testing.T) {
	entries := []crtshEntry{
		{NameValue: "api.example.com\nwww.example.com\ndev.example.com"},
	}
	srv := jsonSrv(t, entries)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CRTSHBaseURL = srv.URL
	m.Sources = []string{"ct_log"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "passive_name_candidate") {
		t.Fatal("expected passive name candidates from CT log")
	}
	if !hasSource(findings, "ct_log") {
		t.Fatal("expected source=ct_log")
	}
	if !hasHost(findings, "api.example.com") {
		t.Fatal("expected api.example.com")
	}
}

func TestCTLog_OutOfScopeFiltered(t *testing.T) {
	entries := []crtshEntry{
		{NameValue: "evil.other.com\napi.example.com"},
	}
	srv := jsonSrv(t, entries)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CRTSHBaseURL = srv.URL
	m.Sources = []string{"ct_log"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.URL == "evil.other.com" {
			t.Fatal("out-of-scope domain should be filtered")
		}
	}
}

func TestCTLog_HTTP_Error_SoftFail(t *testing.T) {
	srv := errorSrv(503)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CRTSHBaseURL = srv.URL
	m.Sources = []string{"ct_log"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal("expected soft failure for HTTP 503")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on error, got %d", len(findings))
	}
}

// ─── Wayback ─────────────────────────────────────────────────────────────────

func TestWayback_URLsAndSubdomains(t *testing.T) {
	// CDX API with fl=original returns only the URL column.
	rows := [][]string{
		{"original"},                         // header row
		{"https://api.example.com/v1/users"}, // data rows
		{"https://dev.example.com/app"},
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
	if !hasType(findings, "passive_name_candidate") {
		t.Fatal("expected passive name candidates from Wayback")
	}
	if !hasType(findings, "historical_reference") {
		t.Fatal("expected historical_reference findings from Wayback")
	}
}

func TestWayback_HTTP_Error_SoftFail(t *testing.T) {
	srv := errorSrv(429)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.WaybackBaseURL = srv.URL
	m.Sources = []string{"wayback"}

	_, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal("expected soft failure for rate limit")
	}
}

// ─── HackerTarget ────────────────────────────────────────────────────────────

func TestHackerTarget_Subdomains(t *testing.T) {
	body := "api.example.com,1.2.3.4\nwww.example.com,5.6.7.8\nmailbox.example.com,9.10.11.12\n"
	srv := textSrv(t, body)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.HackerTargetBaseURL = srv.URL
	m.Sources = []string{"hackertarget"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasHost(findings, "api.example.com") {
		t.Fatal("expected api.example.com from hackertarget")
	}
	// Check that IP is captured.
	found := false
	for _, f := range findings {
		if f.Extra["host"] == "api.example.com" && f.Extra["ip"] == "1.2.3.4" {
			if f.Type != "subdomain_resolved" || f.Extra["validated"] != "true" {
				t.Fatalf("valid source IP must produce a confirmed subdomain: %+v", f)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("expected ip=1.2.3.4 in hackertarget finding for api.example.com")
	}
}

func TestHackerTarget_InvalidIPRemainsCandidate(t *testing.T) {
	srv := textSrv(t, "api.example.com,not-an-ip\n")
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.HackerTargetBaseURL = srv.URL
	m.Sources = []string{"hackertarget"}
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Type != "passive_name_candidate" {
		t.Fatalf("invalid source IP must not promote the candidate: %+v", findings)
	}
}

func TestHackerTarget_ErrorLine_Skipped(t *testing.T) {
	body := "error check your API usage\n"
	srv := textSrv(t, body)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.HackerTargetBaseURL = srv.URL
	m.Sources = []string{"hackertarget"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when HackerTarget returns error message, got %d", len(findings))
	}
}

// ─── RapidDNS ────────────────────────────────────────────────────────────────

func TestRapidDNS_Subdomains(t *testing.T) {
	body := "staging.example.com\nportal.example.com\n"
	srv := textSrv(t, body)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.RapidDNSBaseURL = srv.URL
	m.Sources = []string{"rapiddns"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasHost(findings, "staging.example.com") {
		t.Fatal("expected staging.example.com from rapiddns")
	}
	if !hasSource(findings, "rapiddns") {
		t.Fatal("expected source=rapiddns")
	}
}

func TestRapidDNS_OutOfScope_Filtered(t *testing.T) {
	body := "evil.other.com\nstaging.example.com\n"
	srv := textSrv(t, body)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.RapidDNSBaseURL = srv.URL
	m.Sources = []string{"rapiddns"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.URL == "evil.other.com" {
			t.Fatal("out-of-scope domain should be filtered")
		}
	}
}

// ─── urlscan ─────────────────────────────────────────────────────────────────

func TestURLScan_Results(t *testing.T) {
	resp := urlscanResponse{
		Results: []struct {
			Page struct {
				Domain string `json:"domain"`
				URL    string `json:"url"`
			} `json:"page"`
		}{
			{Page: struct {
				Domain string `json:"domain"`
				URL    string `json:"url"`
			}{Domain: "mail.example.com", URL: "https://mail.example.com/login"}},
		},
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
	if !hasHost(findings, "mail.example.com") {
		t.Fatal("expected mail.example.com from urlscan")
	}
	if !hasType(findings, "scan_reference") {
		t.Fatal("expected scan_reference finding from urlscan")
	}
}

// ─── multi-source ────────────────────────────────────────────────────────────

func TestMultiSource_Options(t *testing.T) {
	srv := jsonSrv(t, []crtshEntry{{NameValue: "sub.example.com"}})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CRTSHBaseURL = srv.URL

	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "ct_log"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasSource(findings, "ct_log") {
		t.Fatal("expected source=ct_log when only ct_log configured via Options")
	}
}

func TestMultiDomain(t *testing.T) {
	// Different responses based on URL path.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "example.com") {
			json.NewEncoder(w).Encode([]crtshEntry{{NameValue: "api.example.com"}})
		} else {
			json.NewEncoder(w).Encode([]crtshEntry{{NameValue: "www.acme.org"}})
		}
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CRTSHBaseURL = srv.URL
	m.Sources = []string{"ct_log"}

	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		URLs:   []string{"acme.org"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasHost(findings, "api.example.com") {
		t.Fatal("expected api.example.com")
	}
	if !hasHost(findings, "www.acme.org") {
		t.Fatal("expected www.acme.org")
	}
}

func TestRawContent_Domains(t *testing.T) {
	srv := jsonSrv(t, []crtshEntry{{NameValue: "dev.example.com"}})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CRTSHBaseURL = srv.URL
	m.Sources = []string{"ct_log"}

	findings, err := m.Run(context.Background(), module.Input{
		RawContent: "example.com\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasHost(findings, "dev.example.com") {
		t.Fatal("expected dev.example.com from RawContent")
	}
}

// ─── MaxSubdomains cap ────────────────────────────────────────────────────────

func TestMaxSubdomains_Cap(t *testing.T) {
	// Return 50 subdomains from CT log.
	var entries []crtshEntry
	var names []string
	for i := 0; i < 50; i++ {
		names = append(names, "sub"+string(rune('a'+i%26))+".example.com")
	}
	entries = append(entries, crtshEntry{NameValue: strings.Join(names, "\n")})
	srv := jsonSrv(t, entries)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CRTSHBaseURL = srv.URL
	m.Sources = []string{"ct_log"}
	m.MaxSubdomains = 10

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) > 10 {
		t.Fatalf("expected max 10 findings (MaxSubdomains), got %d", len(findings))
	}
}

// ─── unknown source ───────────────────────────────────────────────────────────

func TestUnknownSource_SoftFail(t *testing.T) {
	m := New()
	m.Sources = []string{"unknown_osint_source"}
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal("expected soft failure for unknown source")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for unknown source, got %d", len(findings))
	}
}

// ─── helpers unit tests ───────────────────────────────────────────────────────

func TestCleanDomain(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://example.com/path", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"example.com.", "example.com"},
		{"  example.com  ", "example.com"},
	}
	for _, c := range cases {
		got := cleanDomain(c.in)
		if got != c.want {
			t.Errorf("cleanDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseURLHost(t *testing.T) {
	got, err := parseURLHost("https://api.example.com/v1/users")
	if err != nil {
		t.Fatal(err)
	}
	if got != "api.example.com" {
		t.Errorf("expected api.example.com, got %q", got)
	}
}

func TestIsRFC1918(t *testing.T) {
	cases := []struct {
		addr    string
		private bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"172.16.5.5", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}
	for _, c := range cases {
		if isRFC1918(c.addr) != c.private {
			t.Errorf("isRFC1918(%q) = %v, want %v", c.addr, !c.private, c.private)
		}
	}
}

func TestDedupFindings(t *testing.T) {
	ff := []module.Finding{
		{Type: "subdomain", URL: "api.example.com"},
		{Type: "subdomain", URL: "api.example.com"},
		{Type: "subdomain", URL: "www.example.com"},
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
		RawContent: "example.com\nacme.org\n",
	}
	domains := collectDomains(input)
	if len(domains) != 2 {
		t.Fatalf("expected 2 unique domains, got %d: %v", len(domains), domains)
	}
}
