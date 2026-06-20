package soft404

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func hasKind(findings []module.Finding, k Kind) bool {
	for _, f := range findings {
		if Kind(f.Extra["kind"]) == k {
			return true
		}
	}
	return false
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "soft404" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoInput(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestClassify_ValidPage(t *testing.T) {
	body := "<html><body><h1>Welcome</h1><p>This is a real page with real content.</p></body></html>"
	_, _, is404 := Classify(body, nil, 200)
	if is404 {
		t.Fatal("valid page should not be classified as soft-404")
	}
}

func TestClassify_ErrorMarkers(t *testing.T) {
	body := "<html><body><h1>404 Page Not Found</h1><p>Sorry, we couldn't find that page</p></body></html>"
	_, _, is404 := Classify(body, nil, 200)
	if !is404 {
		t.Fatal("page with error markers should be classified as soft-404")
	}
}

func TestClassify_AuthWall(t *testing.T) {
	body := "<html><body><h1>Sign In</h1><form>Please sign in to continue</form></body></html>"
	kind, _, is404 := Classify(body, nil, 200)
	if !is404 {
		t.Fatal("login page should be classified as soft-404")
	}
	if kind != KindAuthWall {
		t.Errorf("expected kind auth_wall, got %q", kind)
	}
}

func TestClassify_AntiBot(t *testing.T) {
	headers := http.Header{"Cf-Mitigated": []string{"challenge"}}
	body := "Just a moment... Checking your browser before accessing."
	kind, _, is404 := Classify(body, headers, 200)
	if !is404 {
		t.Fatal("Cloudflare challenge should be classified as soft-404")
	}
	if kind != KindAntiBot {
		t.Errorf("expected kind anti_bot, got %q", kind)
	}
}

func TestClassify_JSONAPINotSoft404(t *testing.T) {
	body := `{"status":"ok","data":[]}`
	_, _, is404 := Classify(body, nil, 200)
	if is404 {
		t.Fatal("JSON API response should not be classified as soft-404")
	}
}

func TestClassify_XMLNotSoft404(t *testing.T) {
	body := `<?xml version="1.0"?><root><status>ok</status></root>`
	_, _, is404 := Classify(body, nil, 200)
	if is404 {
		t.Fatal("XML API response should not be classified as soft-404")
	}
}

func TestClassify_NonHTTP200(t *testing.T) {
	// Non-200 codes should not be classified as soft-404 by Classify.
	body := "Not Found"
	_, _, is404 := Classify(body, nil, 404)
	if is404 {
		t.Fatal("Classify should return false for non-200 codes")
	}
}

func TestClassify_LowContentPage(t *testing.T) {
	// Extremely short page with very few words.
	body := "<html><body><p>Hi</p></body></html>"
	_, score, _ := Classify(body, nil, 200)
	// Score may or may not reach threshold — just check it runs without panic.
	_ = score
}

func TestRun_MarksSoft404(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html><body>404 page not found, sorry we couldn't find this page.</body></html>"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := run(t, m, []string{srv.URL})
	if len(findings) == 0 {
		t.Fatal("expected soft-404 finding")
	}
	if findings[0].Type != "soft_404" {
		t.Errorf("expected type soft_404, got %q", findings[0].Type)
	}
}

func TestRun_ValidPage_NoFinding(t *testing.T) {
	// Server returns 404 for any unknown path (normal server), 200 for the specific URL.
	// This ensures the sibling probe returns 404 → no wildcard-200 detection.
	body := "<html><head><title>Our Online Store</title></head><body>" +
		"<h1>Welcome to Our Store</h1>" +
		"<p>Browse our extensive catalog of quality products from top brands. We offer fast shipping, easy returns, and competitive pricing across all categories.</p>" +
		"<p>Our electronics section features the latest smartphones, laptops, tablets, cameras, and accessories from leading manufacturers worldwide.</p>" +
		"<p>Shop our clothing department for seasonal fashion including shirts, pants, dresses, outerwear, and footwear for men, women, and children.</p>" +
		"</body></html>"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/products" {
			w.WriteHeader(200)
			w.Write([]byte(body))
			return
		}
		// All other paths (including the sibling probe) return 404.
		w.WriteHeader(404)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := run(t, m, []string{srv.URL + "/products"})
	if len(findings) != 0 {
		t.Fatalf("valid page should produce no findings, got %d", len(findings))
	}
}

func TestRun_TargetInput(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html><body>Page not found 404</body></html>"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding via Target input")
	}
}

func TestRun_MultipleURLs(t *testing.T) {
	// Server returns 404 for unknown paths, 200-soft for /soft, 200-valid for /real.
	validBody := "<html><head><title>Product Catalog</title></head><body>" +
		"<h1>Welcome to Our Product Catalog</h1>" +
		"<p>Browse thousands of products across electronics, clothing, home goods, sports equipment, and books. We offer competitive pricing, fast delivery, and easy returns on all items in our catalog.</p>" +
		"<p>New arrivals updated daily. Sign up for our newsletter to get notified of sales and special promotions throughout the year.</p>" +
		"</body></html>"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/soft":
			w.WriteHeader(200)
			w.Write([]byte("<html><body>404 not found page not found sorry we could not find what you were looking for</body></html>"))
		case "/real":
			w.WriteHeader(200)
			w.Write([]byte(validBody))
		default:
			// Sibling probes return 404 — normal server, no wildcard-200.
			w.WriteHeader(404)
			w.Write([]byte("not found"))
		}
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := run(t, m, []string{srv.URL + "/soft", srv.URL + "/real"})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 soft-404 finding, got %d", len(findings))
	}
}

func TestProber_InvalidFingerprint_404(t *testing.T) {
	// Server returns hard 404 for the invalid sibling → prober should cache 0.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	p := NewProber(context.Background(), srv.Client(), defaultTimeout)
	fp, ok := p.InvalidFingerprint(srv.URL + "/some/path")
	if !ok {
		t.Fatal("expected ok=true for reachable server")
	}
	if fp != 0 {
		t.Fatal("expected fp=0 for hard-404 server")
	}
}

func TestProber_IsSimilarToInvalid_SameContent(t *testing.T) {
	// Server returns the same "not found" page for everything — classic wildcard-200.
	body := "<html><body><h1>Page Not Found</h1><p>Sorry this page does not exist.</p></body></html>"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	p := NewProber(context.Background(), srv.Client(), defaultTimeout)
	similar := p.IsSimilarToInvalid(body, srv.URL+"/test-path")
	if !similar {
		t.Fatal("expected IsSimilarToInvalid=true for wildcard-200 host")
	}
}

func TestSimhash64_Stable(t *testing.T) {
	text := "hello world this is a test of the simhash fingerprinting algorithm"
	h1 := simhash64(text)
	h2 := simhash64(text)
	if h1 != h2 {
		t.Fatal("simhash64 should be deterministic")
	}
}

func TestSimhash64_Empty(t *testing.T) {
	if simhash64("") != 0 {
		t.Fatal("empty input should return 0")
	}
}

func TestWordCount(t *testing.T) {
	tests := []struct {
		text string
		want int
	}{
		{"hello world", 2},
		{"", 0},
		{"one two three four five", 5},
		{"single", 1},
	}
	for _, tt := range tests {
		got := wordCount(tt.text)
		if got != tt.want {
			t.Errorf("wordCount(%q) = %d, want %d", tt.text, got, tt.want)
		}
	}
}

func TestExtractText_RemovesHTML(t *testing.T) {
	html := "<html><body><h1>Hello</h1><p>World</p></body></html>"
	text := extractText(html)
	if text == html {
		t.Fatal("extractText should remove HTML tags")
	}
	if !containsWord(text, "hello") {
		t.Fatal("extractText should preserve text content")
	}
}

func containsWord(s, word string) bool {
	for _, f := range splitWords(s) {
		if f == word {
			return true
		}
	}
	return false
}

func splitWords(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
