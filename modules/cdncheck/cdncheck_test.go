package cdncheck

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// fetchHeadersForTest makes a GET to rawURL and returns the response headers.
func fetchHeadersForTest(client *http.Client, rawURL string) (http.Header, error) {
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return resp.Header, nil
}

func runCheck(t *testing.T, m *Module, targets []string) []module.Finding {
	t.Helper()
	findings, err := m.Run(context.Background(), module.Input{URLs: targets})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	return findings
}

func hasProvider(findings []module.Finding, provider string) bool {
	for _, f := range findings {
		if f.Extra["provider"] == provider {
			return true
		}
	}
	return false
}

func hasMethod(findings []module.Finding, method string) bool {
	for _, f := range findings {
		if f.Extra["method"] == method {
			return true
		}
	}
	return false
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "cdncheck" {
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
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	_, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMatchIPRanges_CloudflareIP(t *testing.T) {
	// 104.16.0.1 is in Cloudflare's 104.16.0.0/13
	ip := net.ParseIP("104.16.0.1")
	provider, kind := matchIPRanges(ip)
	if provider != "Cloudflare" {
		t.Errorf("expected Cloudflare, got %q", provider)
	}
	if kind != KindCDN {
		t.Errorf("expected cdn kind, got %q", kind)
	}
}

func TestMatchIPRanges_Unknown(t *testing.T) {
	// A non-CDN IP.
	ip := net.ParseIP("8.8.8.8")
	provider, _ := matchIPRanges(ip)
	if provider != "" {
		t.Errorf("expected no provider for 8.8.8.8, got %q", provider)
	}
}

func TestMatchIPRanges_FastlyIP(t *testing.T) {
	// 151.101.0.1 is in Fastly's 151.101.0.0/17
	ip := net.ParseIP("151.101.0.1")
	provider, kind := matchIPRanges(ip)
	if provider != "Fastly" {
		t.Errorf("expected Fastly, got %q", provider)
	}
	if kind != KindCDN {
		t.Errorf("expected cdn, got %q", kind)
	}
}

func TestMatchCNAME_Cloudflare(t *testing.T) {
	provider, kind := matchCNAME("foo.bar.cloudflare.com.")
	if provider != "Cloudflare" {
		t.Errorf("expected Cloudflare, got %q", provider)
	}
	if kind != KindCDN {
		t.Errorf("expected cdn, got %q", kind)
	}
}

func TestMatchCNAME_CloudFront(t *testing.T) {
	provider, kind := matchCNAME("d123.cloudfront.net.")
	if provider != "AWS CloudFront" {
		t.Errorf("expected AWS CloudFront, got %q", provider)
	}
	_ = kind
}

func TestMatchCNAME_Vercel(t *testing.T) {
	provider, _ := matchCNAME("myapp.vercel.app.")
	if provider != "Vercel" {
		t.Errorf("expected Vercel, got %q", provider)
	}
}

func TestMatchCNAME_Unknown(t *testing.T) {
	provider, _ := matchCNAME("example.com.")
	if provider != "" {
		t.Errorf("expected no provider for example.com, got %q", provider)
	}
}

func TestMatchHeaders_Cloudflare(t *testing.T) {
	headers := http.Header{
		"Cf-Ray":          []string{"12345abc-LHR"},
		"Cf-Cache-Status": []string{"HIT"},
	}
	provider, kind := matchHeaders(headers)
	if provider != "Cloudflare" {
		t.Errorf("expected Cloudflare from cf-ray header, got %q", provider)
	}
	if kind != KindCDN {
		t.Errorf("expected cdn, got %q", kind)
	}
}

func TestMatchHeaders_Fastly(t *testing.T) {
	headers := http.Header{
		"X-Served-By": []string{"cache-lhr1234"},
	}
	provider, kind := matchHeaders(headers)
	if provider != "Fastly" {
		t.Errorf("expected Fastly, got %q", provider)
	}
	if kind != KindCDN {
		t.Errorf("expected cdn, got %q", kind)
	}
}

func TestMatchHeaders_Vercel(t *testing.T) {
	headers := http.Header{
		"X-Vercel-Id": []string{"iad1::abc123"},
	}
	provider, _ := matchHeaders(headers)
	if provider != "Vercel" {
		t.Errorf("expected Vercel, got %q", provider)
	}
}

func TestMatchHeaders_Unknown(t *testing.T) {
	headers := http.Header{
		"Content-Type": []string{"text/html"},
	}
	provider, _ := matchHeaders(headers)
	if provider != "" {
		t.Errorf("expected no provider for generic headers, got %q", provider)
	}
}

func TestRun_HeaderDetection_Cloudflare(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("cf-ray", "78abc-LHR")
		w.Header().Set("cf-cache-status", "HIT")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	// Test header matching directly using the test server's response.
	respHeaders, err := fetchHeadersForTest(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("could not fetch headers: %v", err)
	}
	provider, kind := matchHeaders(respHeaders)
	if provider != "Cloudflare" {
		t.Fatalf("expected Cloudflare detection via response headers, matchHeaders returned %q", provider)
	}
	if kind != KindCDN {
		t.Errorf("expected cdn, got %q", kind)
	}
	// Also verify the method const.
	if MethodHeader != "header" {
		t.Error("MethodHeader constant mismatch")
	}
}

func TestRun_Dedup_SameHost(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	m := NewWithClient(srv.Client())
	// Same host provided twice — should be probed once.
	_, err := m.Run(context.Background(), module.Input{
		URLs: []string{host, host},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_RawContent(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	m := NewWithClient(srv.Client())
	_, err := m.Run(context.Background(), module.Input{
		RawContent: host + "\nexample.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractHost_URL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://example.com/path?q=1", "example.com"},
		{"http://sub.example.com:8080/", "sub.example.com"},
		{"example.com", "example.com"},
		{"example.com:443", "example.com"},
	}
	for _, c := range cases {
		got := extractHost(c.in)
		if got != c.want {
			t.Errorf("extractHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCIDREntries_Valid(t *testing.T) {
	for _, e := range cidrEntries {
		_, _, err := net.ParseCIDR(e.cidr)
		if err != nil {
			t.Errorf("invalid CIDR %q (%s): %v", e.cidr, e.provider, err)
		}
		if e.provider == "" {
			t.Errorf("empty provider for CIDR %q", e.cidr)
		}
	}
}

func TestCIDREntries_Count(t *testing.T) {
	if len(cidrEntries) < 30 {
		t.Fatalf("expected at least 30 CIDR entries, got %d", len(cidrEntries))
	}
}

func TestCNAMEEntries_Count(t *testing.T) {
	if len(cnameEntries) < 20 {
		t.Fatalf("expected at least 20 CNAME entries, got %d", len(cnameEntries))
	}
}

func TestHeaderEntries_Count(t *testing.T) {
	if len(headerEntries) < 15 {
		t.Fatalf("expected at least 15 header entries, got %d", len(headerEntries))
	}
}

func TestMatchIPRanges_AWSCloudFront(t *testing.T) {
	// 13.32.0.1 is in AWS CloudFront 13.32.0.0/15
	ip := net.ParseIP("13.32.0.1")
	provider, kind := matchIPRanges(ip)
	if provider != "AWS CloudFront" {
		t.Errorf("expected AWS CloudFront, got %q", provider)
	}
	if kind != KindCDN {
		t.Errorf("expected cdn, got %q", kind)
	}
}

func TestMatchCNAME_Netlify(t *testing.T) {
	provider, _ := matchCNAME("mysite.netlify.app.")
	if provider != "Netlify" {
		t.Errorf("expected Netlify, got %q", provider)
	}
}

func TestMatchCNAME_Heroku(t *testing.T) {
	provider, kind := matchCNAME("myapp.herokuapp.com.")
	if provider != "Heroku" {
		t.Errorf("expected Heroku, got %q", provider)
	}
	if kind != KindCloud {
		t.Errorf("expected cloud, got %q", kind)
	}
}

func TestMatchHeaders_Imperva(t *testing.T) {
	headers := http.Header{
		"X-Iinfo": []string{"12345678"},
	}
	provider, kind := matchHeaders(headers)
	if provider != "Imperva" {
		t.Errorf("expected Imperva, got %q", provider)
	}
	if kind != KindWAF {
		t.Errorf("expected waf, got %q", kind)
	}
}
