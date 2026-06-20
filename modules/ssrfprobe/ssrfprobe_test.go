package ssrfprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func run(t *testing.T, m *Module, urls []string) []module.Finding {
	t.Helper()
	findings, err := m.Run(context.Background(), module.Input{URLs: urls})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	return findings
}

func hasCheck(findings []module.Finding, check string) bool {
	for _, f := range findings {
		if f.Extra["check"] == check {
			return true
		}
	}
	return false
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "ssrfprobe" {
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

func TestRun_CloudMetadata_Critical(t *testing.T) {
	// Server echoes back the 'url' param value in the body (simulates SSRF fetch-and-reflect).
	// When the param contains a cloud metadata URL, we inject "ami-id" into the response.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if strings.Contains(urlParam, "169.254.169.254") {
			w.WriteHeader(200)
			// Simulate: server fetched the metadata endpoint and returned the response.
			w.Write([]byte("ami-id\ninstance-id\nhostname"))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("normal response"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := run(t, m, []string{srv.URL + "/?url=https://example.com"})
	if !hasCheck(findings, "cloud-metadata") {
		t.Fatal("expected cloud-metadata finding when server reflects IMDS content")
	}
	for _, f := range findings {
		if f.Extra["check"] == "cloud-metadata" {
			if f.Severity != module.SeverityCritical {
				t.Errorf("expected Critical severity for cloud metadata SSRF, got %q", f.Severity)
			}
			break
		}
	}
}

func TestRun_NoSSRF_NoFindings(t *testing.T) {
	// Normal app: returns a regular HTML page regardless of params.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html><body><h1>Welcome to our app</h1><p>Browse our products here.</p></body></html>"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	// CloudOnly=true limits probes to in-band cloud metadata only — faster for test.
	m.CloudOnly = true
	findings := run(t, m, []string{srv.URL + "/?redirect=https://example.com"})
	if hasCheck(findings, "cloud-metadata") {
		t.Fatal("normal app should not trigger cloud-metadata finding")
	}
}

func TestRun_HeaderInjection_High(t *testing.T) {
	// Server reads X-Forwarded-Host header and uses it to make a backend request,
	// reflecting the response body. Simulates header-based SSRF.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		if strings.Contains(xfh, "169.254.169.254") {
			// Simulate: server made a request to the injected host.
			w.WriteHeader(200)
			w.Write([]byte("ami-id\nlatest/meta-data"))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("normal"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.CloudOnly = false
	findings := run(t, m, []string{srv.URL + "/"})
	if !hasCheck(findings, "header-injection") {
		t.Fatal("expected header-injection finding")
	}
	for _, f := range findings {
		if f.Extra["check"] == "header-injection" {
			if f.Severity != module.SeverityHigh {
				t.Errorf("expected High severity for header injection, got %q", f.Severity)
			}
			break
		}
	}
}

func TestRun_OpenRedirectSSRF_High(t *testing.T) {
	// Server redirects to 169.254.169.254 — SSRF via open redirect.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectParam := r.URL.Query().Get("redirect")
		if redirectParam != "" {
			http.Redirect(w, r, redirectParam, http.StatusFound)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	// We must NOT follow redirects to detect the redirect target.
	noRedirectClient := &http.Client{
		Transport: srv.Client().Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	m := NewWithClient(noRedirectClient)
	m.CloudOnly = false
	findings := run(t, m, []string{srv.URL + "/?redirect=https://example.com"})
	if !hasCheck(findings, "open-redirect-ssrf") {
		t.Fatal("expected open-redirect-ssrf finding when server redirects to 169.254.x.x")
	}
}

func TestRun_RawContent_Input(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	_, err := m.Run(context.Background(), module.Input{
		RawContent: srv.URL + "/?url=x\n" + srv.URL + "/?redirect=y",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCollectURLs_Dedup(t *testing.T) {
	input := module.Input{
		Target: "https://a.com/?x=1",
		URLs:   []string{"https://a.com/?x=1", "https://b.com/?y=2"},
	}
	urls := collectURLs(input)
	if len(urls) != 2 {
		t.Fatalf("expected 2 unique URLs, got %d", len(urls))
	}
}

func TestInjectURL_AddsParam(t *testing.T) {
	out, err := injectURL("https://example.com/page?existing=1", "url", "http://evil.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "url=http") {
		t.Errorf("expected injected param in URL, got: %s", out)
	}
}

func TestInjectURL_PreservesExistingParams(t *testing.T) {
	out, err := injectURL("https://example.com/?a=1&b=2", "a", "injected")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "b=2") {
		t.Errorf("expected original params preserved, got: %s", out)
	}
}

func TestIsInternalURL_Loopback(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://169.254.169.254/latest/", true},
		{"http://127.0.0.1/admin", true},
		{"http://localhost/", true},
		{"http://192.168.1.1/", true},
		{"http://10.0.0.1/", true},
		{"https://example.com/", false},
		{"https://api.github.com/", false},
	}
	for _, c := range cases {
		got := isInternalURL(c.url)
		if got != c.want {
			t.Errorf("isInternalURL(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestCloudMetadataPayloads_NotEmpty(t *testing.T) {
	if len(cloudMetadataPayloads) < 10 {
		t.Fatalf("expected at least 10 cloud metadata payloads, got %d", len(cloudMetadataPayloads))
	}
}

func TestCloudResponseMarkers_NotEmpty(t *testing.T) {
	if len(cloudResponseMarkers) < 5 {
		t.Fatalf("expected at least 5 response markers, got %d", len(cloudResponseMarkers))
	}
}

func TestSSRFHeaderTargets_Count(t *testing.T) {
	if len(ssrfHeaderInjectionTargets) < 10 {
		t.Fatalf("expected at least 10 header injection targets, got %d", len(ssrfHeaderInjectionTargets))
	}
}

func TestQueryParamNames(t *testing.T) {
	u, _ := parseTestURL("https://example.com/?a=1&b=2&c=3")
	names := queryParamNames(u)
	if len(names) != 3 {
		t.Fatalf("expected 3 params, got %d", len(names))
	}
}

func TestRandomHex(t *testing.T) {
	h1, _ := randomHex(8)
	h2, _ := randomHex(8)
	if h1 == h2 {
		t.Fatal("randomHex should produce unique values")
	}
	if len(h1) != 16 {
		t.Fatalf("expected 16 hex chars, got %d", len(h1))
	}
}

func TestBuildWorkItems_NilForInvalidURL(t *testing.T) {
	items := buildWorkItems("not-a-url://\x00invalid", "nonce", "", false)
	// Should not panic, may be empty.
	_ = items
}

func TestOOBProbe_NotRecordedAsLocalFinding(t *testing.T) {
	// With OOB host set and a normal server, OOB probes should NOT produce local findings.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.OOBHost = "test.oast.me"
	findings := run(t, m, []string{srv.URL + "/?url=x"})
	// OOB findings are external — should not appear as local cloud-metadata findings.
	for _, f := range findings {
		if f.Extra["kind"] == "oob" {
			t.Fatal("OOB probes should not produce local findings")
		}
	}
}

func TestRun_MultipleURLs_Dedup(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.CloudOnly = true
	// Same URL twice should not panic.
	_, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/?a=1", srv.URL + "/?a=1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func parseTestURL(s string) (*url.URL, error) {
	return url.Parse(s)
}
