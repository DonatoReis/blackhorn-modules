package httpxpro

import (
	"context"
	"crypto/tls"
	"fmt"
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

func getExtra(findings []module.Finding, key string) string {
	for _, f := range findings {
		if v, ok := f.Extra[key]; ok {
			return v
		}
	}
	return ""
}

func tlsSrv(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(handler)
}

// ─── basic ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "httpxpro" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoTarget(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

// ─── basic probe ─────────────────────────────────────────────────────────────

func TestProbe_StatusCode(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "<html><title>Test Page</title></html>")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "http_probe") {
		t.Fatal("expected http_probe finding")
	}
	if getExtra(findings, "status_code") != "200" {
		t.Fatalf("expected status_code=200, got %q", getExtra(findings, "status_code"))
	}
}

func TestProbe_TitleExtracted(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<html><title>My App</title><body>Hello</body></html>")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if getExtra(findings, "title") != "My App" {
		t.Fatalf("expected title=My App, got %q", getExtra(findings, "title"))
	}
}

func TestProbe_ContentLength(t *testing.T) {
	body := strings.Repeat("a", 500)
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	cl := getExtra(findings, "content_length")
	if cl == "" || cl == "0" {
		t.Fatalf("expected non-zero content_length, got %q", cl)
	}
}

// ─── TLS metadata ────────────────────────────────────────────────────────────

func TestTLS_Version(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tls ok")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	m.ExtractTLS = true
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if tlsV := getExtra(findings, "tls_version"); tlsV == "" {
		t.Fatal("expected tls_version to be populated")
	}
}

func TestTLS_Disabled(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	m.ExtractTLS = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if getExtra(findings, "tls_version") != "" {
		t.Fatal("expected no tls_version when ExtractTLS=false")
	}
}

// ─── security headers ────────────────────────────────────────────────────────

func TestSecurityHeaders_HSTS(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if getExtra(findings, "hsts") != "true" {
		t.Fatal("expected hsts=true")
	}
}

func TestSecurityHeaders_CSP(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if getExtra(findings, "csp") != "true" {
		t.Fatal("expected csp=true")
	}
}

func TestSecurityHeaders_XFrame(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if getExtra(findings, "x_frame") != "true" {
		t.Fatal("expected x_frame=true")
	}
}

func TestSecurityHeaders_NoHSTS(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if getExtra(findings, "hsts") != "false" {
		t.Fatalf("expected hsts=false when header absent, got %q", getExtra(findings, "hsts"))
	}
}

// ─── CDN detection ───────────────────────────────────────────────────────────

func TestCDN_Cloudflare(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("CF-Ray", "abc123-LHR")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if getExtra(findings, "cdn") != "Cloudflare" {
		t.Fatalf("expected cdn=Cloudflare, got %q", getExtra(findings, "cdn"))
	}
}

func TestCDN_Netlify(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-NF-Request-ID", "abc123")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if getExtra(findings, "cdn") != "Netlify" {
		t.Fatalf("expected cdn=Netlify, got %q", getExtra(findings, "cdn"))
	}
}

// ─── WAF detection ────────────────────────────────────────────────────────────

func TestWAF_Sucuri(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Sucuri-ID", "123456")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if getExtra(findings, "waf") != "Sucuri" {
		t.Fatalf("expected waf=Sucuri, got %q", getExtra(findings, "waf"))
	}
}

// ─── technology detection ────────────────────────────────────────────────────

func TestTech_PHP(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.1")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	techs := getExtra(findings, "technologies")
	if !strings.Contains(techs, "PHP") {
		t.Fatalf("expected PHP in technologies, got %q", techs)
	}
}

func TestTech_WordPress(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `<html><link href="/wp-content/themes/test/style.css"></html>`)
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	techs := getExtra(findings, "technologies")
	if !strings.Contains(techs, "WordPress") {
		t.Fatalf("expected WordPress in technologies, got %q", techs)
	}
}

func TestTech_Nginx(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.25.0")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	techs := getExtra(findings, "technologies")
	if !strings.Contains(techs, "Nginx") {
		t.Fatalf("expected Nginx in technologies, got %q", techs)
	}
}

// ─── favicon hash ─────────────────────────────────────────────────────────────

func TestFavicon_Hash(t *testing.T) {
	faviconData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A} // PNG header

	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Header().Set("Content-Type", "image/x-icon")
			w.Write(faviconData)
			return
		}
		fmt.Fprint(w, "<html><head></head><body>ok</body></html>")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = true
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if hash := getExtra(findings, "favicon_hash"); hash == "" {
		t.Fatal("expected favicon_hash in findings")
	}
}

func TestFavicon_Disabled(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<html></html>")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if getExtra(findings, "favicon_hash") != "" {
		t.Fatal("expected no favicon_hash when FetchFavicon=false")
	}
}

func TestFavicon_CustomLink(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/custom-icon.ico" {
			w.Write([]byte("icon"))
			return
		}
		fmt.Fprintf(w, `<html><head><link rel="icon" href="/custom-icon.ico"></head></html>`)
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = true
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if hash := getExtra(findings, "favicon_hash"); hash == "" {
		t.Fatal("expected favicon_hash from custom link")
	}
}

// ─── multi-target ─────────────────────────────────────────────────────────────

func TestMultiTarget_URLs(t *testing.T) {
	srv1 := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<title>Site1</title>")
	}))
	defer srv1.Close()
	srv2 := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<title>Site2</title>")
	}))
	defer srv2.Close()

	m := NewWithClient(srv1.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv1.URL,
		URLs:   []string{srv2.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings for 2 targets, got %d", len(findings))
	}
}

func TestRawContent_Targets(t *testing.T) {
	srv := tlsSrv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{
		RawContent: srv.URL + "\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from RawContent target")
	}
}

// ─── error handling ───────────────────────────────────────────────────────────

func TestProbe_ConnectionError_SoftFail(t *testing.T) {
	// Unreachable URL — transport error (StatusCode=0) should produce no findings.
	// A connection failure is not a vulnerability — silently discarding is correct.
	m := NewWithClient(&http.Client{
		Timeout: 100,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	})
	m.FetchFavicon = false
	findings, err := m.Run(context.Background(), module.Input{Target: "https://127.0.0.1:1"})
	if err != nil {
		t.Fatal("expected soft failure, not error return")
	}
	// Zero findings is the correct behaviour for a transport error.
	for _, f := range findings {
		if f.Severity == module.SeverityLow && f.Extra["status_code"] == "0" {
			t.Error("transport error (status_code=0) should not produce a Low finding")
		}
	}
}

// ─── MurmurHash3 ─────────────────────────────────────────────────────────────

func TestMurmurHash3_Deterministic(t *testing.T) {
	a := murmurHash3_32([]byte("hello world"), 0)
	b := murmurHash3_32([]byte("hello world"), 0)
	if a != b {
		t.Fatal("murmurHash3_32 must be deterministic")
	}
}

func TestMurmurHash3_DifferentInputs(t *testing.T) {
	a := murmurHash3_32([]byte("hello"), 0)
	b := murmurHash3_32([]byte("world"), 0)
	if a == b {
		t.Fatal("murmurHash3_32 should differ for different inputs")
	}
}

func TestMurmurHash3_EmptyInput(t *testing.T) {
	// Should not panic.
	_ = murmurHash3_32([]byte{}, 0)
}

// ─── helper unit tests ────────────────────────────────────────────────────────

func TestExtractTitle_Simple(t *testing.T) {
	title := extractTitle([]byte("<html><head><title>Hello World</title></head></html>"))
	if title != "Hello World" {
		t.Fatalf("expected 'Hello World', got %q", title)
	}
}

func TestExtractTitle_Empty(t *testing.T) {
	title := extractTitle([]byte("<html><head></head></html>"))
	if title != "" {
		t.Fatalf("expected empty title, got %q", title)
	}
}

func TestSHA256Hex(t *testing.T) {
	h1 := sha256Hex([]byte("data"))
	h2 := sha256Hex([]byte("data"))
	h3 := sha256Hex([]byte("other"))
	if h1 != h2 {
		t.Fatal("sha256Hex must be deterministic")
	}
	if h1 == h3 {
		t.Fatal("sha256Hex should differ for different inputs")
	}
	if len(h1) != 16 {
		t.Fatalf("expected 16 hex chars, got %d", len(h1))
	}
}

func TestCollectTargets_Dedup(t *testing.T) {
	targets := collectTargets(module.Input{
		Target: "https://example.com",
		URLs:   []string{"https://example.com", "https://other.com"},
	})
	if len(targets) != 2 {
		t.Fatalf("expected 2 unique targets, got %d", len(targets))
	}
}

func TestFaviconURL_Fallback(t *testing.T) {
	u := faviconURLFromPage("https://example.com/page", "<html></html>")
	if u != "https://example.com/favicon.ico" {
		t.Fatalf("expected fallback favicon URL, got %q", u)
	}
}

func TestFaviconURL_FromLink(t *testing.T) {
	body := `<html><head><link rel="shortcut icon" href="/img/icon.png"></head></html>`
	u := faviconURLFromPage("https://example.com/", body)
	if !strings.HasSuffix(u, "/img/icon.png") {
		t.Fatalf("expected /img/icon.png from link, got %q", u)
	}
}
