package tlsfinder

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

func hasHost(findings []module.Finding, host string) bool {
	for _, f := range findings {
		if f.URL == host || f.Extra["host"] == host {
			return true
		}
	}
	return false
}

func hasSource(findings []module.Finding, source string) bool {
	for _, f := range findings {
		if f.Extra["source"] == source {
			return true
		}
	}
	return false
}

// crtshServer returns a TLS test server that simulates crt.sh responses.
func crtshServer(entries []crtshEntry) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}))
}

// certspotterServer returns a TLS test server that simulates Certspotter responses.
func certspotterServer(entries []certspotterEntry) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}))
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "tlsfinder" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoInput(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

// ─── parseCRTSHResponse ───────────────────────────────────────────────────────

func TestParseCRTSH_SingleEntry(t *testing.T) {
	entries := []crtshEntry{
		{NameValue: "api.example.com", NotAfter: "2027-01-01"},
	}
	body, _ := json.Marshal(entries)
	subs, err := parseCRTSHResponse(body, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 || subs[0] != "api.example.com" {
		t.Fatalf("expected [api.example.com], got %v", subs)
	}
}

func TestParseCRTSH_WildcardStripped(t *testing.T) {
	entries := []crtshEntry{
		{NameValue: "*.example.com"},
	}
	body, _ := json.Marshal(entries)
	subs, err := parseCRTSHResponse(body, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	// After stripping *. the name equals the apex — should be filtered.
	if len(subs) != 0 {
		t.Fatalf("expected wildcard apex to be filtered, got %v", subs)
	}
}

func TestParseCRTSH_MultilineNameValue(t *testing.T) {
	entries := []crtshEntry{
		{NameValue: "api.example.com\nwww.example.com\ndev.example.com"},
	}
	body, _ := json.Marshal(entries)
	subs, err := parseCRTSHResponse(body, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 3 {
		t.Fatalf("expected 3 subdomains from multiline name_value, got %d: %v", len(subs), subs)
	}
}

func TestParseCRTSH_OutOfScopeFiltered(t *testing.T) {
	entries := []crtshEntry{
		{NameValue: "evil.other.com"},
	}
	body, _ := json.Marshal(entries)
	subs, err := parseCRTSHResponse(body, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 0 {
		t.Fatalf("expected out-of-scope domain to be filtered, got %v", subs)
	}
}

func TestParseCRTSH_Dedup(t *testing.T) {
	entries := []crtshEntry{
		{NameValue: "api.example.com\napi.example.com"},
	}
	body, _ := json.Marshal(entries)
	subs, err := parseCRTSHResponse(body, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 {
		t.Fatalf("expected 1 unique subdomain after dedup, got %d", len(subs))
	}
}

func TestParseCRTSH_InvalidJSON(t *testing.T) {
	_, err := parseCRTSHResponse([]byte("not-json"), "example.com")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ─── parseCertspotterResponse ─────────────────────────────────────────────────

func TestParseCertspotter_SingleEntry(t *testing.T) {
	entries := []certspotterEntry{
		{DNSNames: []string{"api.example.com", "www.example.com"}},
	}
	body, _ := json.Marshal(entries)
	subs, err := parseCertspotterResponse(body, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 2 {
		t.Fatalf("expected 2 subdomains, got %v", subs)
	}
}

func TestParseCertspotter_WildcardStripped(t *testing.T) {
	entries := []certspotterEntry{
		{DNSNames: []string{"*.api.example.com"}},
	}
	body, _ := json.Marshal(entries)
	subs, err := parseCertspotterResponse(body, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	// *.api.example.com → api.example.com (wildcard prefix stripped).
	if len(subs) != 1 || subs[0] != "api.example.com" {
		t.Fatalf("expected [api.example.com] after stripping wildcard, got %v", subs)
	}
}

func TestParseCertspotter_OutOfScopeFiltered(t *testing.T) {
	entries := []certspotterEntry{
		{DNSNames: []string{"api.other.com"}},
	}
	body, _ := json.Marshal(entries)
	subs, err := parseCertspotterResponse(body, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 0 {
		t.Fatalf("expected out-of-scope domain to be filtered, got %v", subs)
	}
}

func TestParseCertspotter_InvalidJSON(t *testing.T) {
	_, err := parseCertspotterResponse([]byte("{bad"), "example.com")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ─── queryCRTSH via test server ───────────────────────────────────────────────

func TestQueryCRTSH_FindingsBuilt(t *testing.T) {
	srv := crtshServer([]crtshEntry{
		{NameValue: "staging.example.com\napi.example.com"},
	})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	// Override the URL to point to test server.
	subs, err := m.queryCRTSHFromURL(context.Background(), "example.com", srv.URL+"/?q=%25.example.com&output=json")
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 2 {
		t.Fatalf("expected 2 subs, got %d: %v", len(subs), subs)
	}
}

func TestQueryCRTSH_Non200Error(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	_, err := m.queryCRTSHFromURL(context.Background(), "example.com", srv.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 503")
	}
}

// ─── queryCertspotter via test server ────────────────────────────────────────

func TestQueryCertspotter_FindingsBuilt(t *testing.T) {
	srv := certspotterServer([]certspotterEntry{
		{DNSNames: []string{"mail.example.com", "smtp.example.com"}},
	})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	subs, err := m.queryCertspotterFromURL(context.Background(), "example.com", srv.URL+"/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names")
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 2 {
		t.Fatalf("expected 2 subs, got %d: %v", len(subs), subs)
	}
}

func TestQueryCertspotter_Non200Error(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(429)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	_, err := m.queryCertspotterFromURL(context.Background(), "example.com", srv.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 429")
	}
}

// ─── Run integration ──────────────────────────────────────────────────────────

func TestRun_FindingsHaveCorrectType(t *testing.T) {
	srv := crtshServer([]crtshEntry{
		{NameValue: "sub.example.com"},
	})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CRTSHBaseURL = srv.URL
	m.CertspotterBaseURL = srv.URL
	m.Sources = []string{"crtsh"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Type != "ct_name_reference" {
			t.Errorf("expected type ct_name_reference, got %q", f.Type)
		}
		if f.Severity != module.SeverityInfo {
			t.Errorf("expected SeverityInfo, got %v", f.Severity)
		}
		if f.Extra["promote_to_context"] != "false" {
			t.Errorf("CT reference must not be promoted: %+v", f)
		}
	}
}

func TestRun_DedupAcrossSources(t *testing.T) {
	// Both sources return the same subdomain — should deduplicate.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "output=json") {
			json.NewEncoder(w).Encode([]crtshEntry{{NameValue: "api.example.com"}})
		} else {
			json.NewEncoder(w).Encode([]certspotterEntry{{DNSNames: []string{"api.example.com"}}})
		}
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CRTSHBaseURL = srv.URL
	m.CertspotterBaseURL = srv.URL
	m.Sources = []string{"crtsh", "certspotter"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, f := range findings {
		if f.URL == "api.example.com" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected 1 finding for api.example.com after dedup, got %d", count)
	}
}

func TestRun_MultiDomain(t *testing.T) {
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
	m.CertspotterBaseURL = srv.URL
	m.Sources = []string{"crtsh"}

	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		URLs:   []string{"acme.org"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasHost(findings, "api.example.com") {
		t.Fatal("expected api.example.com in findings")
	}
	if !hasHost(findings, "www.acme.org") {
		t.Fatal("expected www.acme.org in findings")
	}
}

func TestRun_RawContentDomains(t *testing.T) {
	srv := crtshServer([]crtshEntry{
		{NameValue: "dev.example.com"},
	})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CRTSHBaseURL = srv.URL
	m.CertspotterBaseURL = srv.URL
	m.Sources = []string{"crtsh"}

	findings, err := m.Run(context.Background(), module.Input{
		RawContent: "example.com\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasHost(findings, "dev.example.com") {
		t.Fatal("expected dev.example.com from RawContent domain")
	}
}

func TestRun_ExtraFields(t *testing.T) {
	srv := crtshServer([]crtshEntry{
		{NameValue: "portal.example.com"},
	})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CRTSHBaseURL = srv.URL
	m.CertspotterBaseURL = srv.URL
	m.Sources = []string{"crtsh"}

	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Extra["apex"] != "example.com" {
		t.Errorf("expected apex=example.com, got %q", f.Extra["apex"])
	}
	if f.Extra["source"] != "crtsh" {
		t.Errorf("expected source=crtsh, got %q", f.Extra["source"])
	}
}

// ─── helpers unit tests ───────────────────────────────────────────────────────

func TestCleanDomain_URL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://example.com/path", "example.com"},
		{"http://API.Example.COM", "api.example.com"},
		{"example.com.", "example.com"},
		{"  example.com  ", "example.com"},
		{"example.com:8080", "example.com"},
	}
	for _, c := range cases {
		got := cleanDomain(c.in)
		if got != c.want {
			t.Errorf("cleanDomain(%q) = %q, want %q", c.in, got, c.want)
		}
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

func TestDedupFindings_RemovesDuplicates(t *testing.T) {
	findings := []module.Finding{
		{URL: "api.example.com", Type: "ct_name_reference"},
		{URL: "api.example.com", Type: "ct_name_reference"},
		{URL: "www.example.com", Type: "ct_name_reference"},
	}
	got := dedupFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected 2 after dedup, got %d", len(got))
	}
}

func TestBuildFindings_WildcardExcluded(t *testing.T) {
	m := New()
	m.IncludeWildcard = false
	findings := m.buildFindings("example.com", "crtsh", []string{"*.example.com", "api.example.com"})
	// *.example.com should be filtered out.
	for _, f := range findings {
		if strings.HasPrefix(f.URL, "*") {
			t.Errorf("wildcard finding should be excluded when IncludeWildcard=false, got %q", f.URL)
		}
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding with wildcard excluded, got %d", len(findings))
	}
}
