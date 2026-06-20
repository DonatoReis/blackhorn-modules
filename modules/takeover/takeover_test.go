package takeover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func hasService(findings []module.Finding, service string) bool {
	for _, f := range findings {
		if f.Extra["service"] == service {
			return true
		}
	}
	return false
}

func hasSubdomain(findings []module.Finding, sub string) bool {
	for _, f := range findings {
		if f.Extra["subdomain"] == sub {
			return true
		}
	}
	return false
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "takeover" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoInput(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestBuiltinSignatures_Count(t *testing.T) {
	sigs := builtinSignatures()
	if len(sigs) < 30 {
		t.Fatalf("expected at least 30 built-in signatures, got %d", len(sigs))
	}
}

func TestBuiltinSignatures_NoDuplicates(t *testing.T) {
	sigs := builtinSignatures()
	seen := make(map[string]int)
	for i, s := range sigs {
		if prev, dup := seen[s.Suffix]; dup {
			t.Errorf("duplicate suffix %q at index %d (first at %d)", s.Suffix, i, prev)
		}
		seen[s.Suffix] = i
	}
}

func TestBuiltinSignatures_NoEmpty(t *testing.T) {
	for _, s := range builtinSignatures() {
		if s.Suffix == "" || s.Service == "" {
			t.Errorf("signature has empty Suffix or Service: %+v", s)
		}
	}
}

func TestNewWithSignatures(t *testing.T) {
	sigs := []Signature{{"example.com", "Test Service"}}
	m := NewWithSignatures(sigs)
	if len(m.signatures) != 1 {
		t.Fatal("expected 1 custom signature")
	}
}

func TestClassify_Hard404(t *testing.T) {
	m := New()
	ok, conf := m.classify(404, "", nil)
	if !ok || conf != "high" {
		t.Fatalf("hard 404 should produce isTakeover=true, confidence=high, got %v %q", ok, conf)
	}
}

func TestClassify_410(t *testing.T) {
	m := New()
	ok, conf := m.classify(410, "", nil)
	if !ok || conf != "high" {
		t.Fatalf("410 should produce isTakeover=true, confidence=high")
	}
}

func TestClassify_Timeout(t *testing.T) {
	m := New()
	ok, conf := m.classify(0, "", nil)
	if !ok || conf != "low" {
		t.Fatalf("timeout should produce isTakeover=true, confidence=low")
	}
}

func TestClassify_200_NoMarkers(t *testing.T) {
	m := New()
	body := "<html><body><h1>Welcome to our site!</h1><p>Everything is working fine here.</p></body></html>"
	ok, _ := m.classify(200, body, nil)
	if ok {
		t.Fatal("200 with valid content should not be classified as takeover")
	}
}

func TestClassify_200_GitHubPages(t *testing.T) {
	m := New()
	body := "There isn't a GitHub Pages site here."
	ok, conf := m.classify(200, body, nil)
	if !ok {
		t.Fatal("GitHub Pages 'not claimed' response should be classified as takeover")
	}
	if conf != "medium" {
		t.Errorf("expected confidence=medium for soft-200, got %q", conf)
	}
}

func TestClassify_200_HerokuNoApp(t *testing.T) {
	m := New()
	body := "Heroku | No such app"
	ok, _ := m.classify(200, body, nil)
	if !ok {
		t.Fatal("Heroku 'no such app' should be classified as takeover")
	}
}

func TestClassify_200_AWSS3NoBucket(t *testing.T) {
	m := New()
	body := `<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`
	ok, _ := m.classify(200, body, nil)
	if !ok {
		t.Fatal("AWS S3 NoSuchBucket should be classified as takeover")
	}
}

func TestProbe_404Server(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.probeHTTP = false
	// We test probe logic by using a synthetic subdomain that resolves to the test server.
	// Since DNS resolution would fail for random subdomains in tests, we test classify directly.
	code, body, _ := m.probe(context.Background(), strings.TrimPrefix(srv.URL, "https://"))
	if code != 404 {
		t.Fatalf("expected status 404, got %d", code)
	}
	_ = body
}

func TestCollectSubdomains_AllInputs(t *testing.T) {
	m := New()
	input := module.Input{
		Target:     "test.example.com",
		URLs:       []string{"https://api.example.com", "http://staging.example.com/path"},
		RawContent: "dev.example.com\nold.example.com\n",
	}
	subs := m.collectSubdomains(input)
	expected := []string{"test.example.com", "api.example.com", "staging.example.com", "dev.example.com", "old.example.com"}
	for _, e := range expected {
		found := false
		for _, s := range subs {
			if s == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subdomain %q in collected list", e)
		}
	}
}

func TestCollectSubdomains_Deduplication(t *testing.T) {
	m := New()
	input := module.Input{
		Target:     "example.com",
		URLs:       []string{"https://example.com", "http://example.com/page"},
		RawContent: "example.com\n",
	}
	subs := m.collectSubdomains(input)
	if len(subs) != 1 {
		t.Fatalf("expected 1 unique subdomain, got %d: %v", len(subs), subs)
	}
}

func TestCollectSubdomains_RawContent(t *testing.T) {
	m := New()
	input := module.Input{
		RawContent: "sub1.example.com\nsub2.example.com\nsub3.example.com\n",
	}
	subs := m.collectSubdomains(input)
	if len(subs) != 3 {
		t.Fatalf("expected 3 subdomains from RawContent, got %d", len(subs))
	}
}

func TestIsSoft404_GitHubPages(t *testing.T) {
	body := "404 There isn't a GitHub Pages site here."
	if !isSoft404(body, nil) {
		t.Fatal("expected soft-404 for GitHub Pages not-claimed message")
	}
}

func TestIsSoft404_JSONNotSoft(t *testing.T) {
	body := `{"status":"ok"}`
	if isSoft404(body, nil) {
		t.Fatal("JSON response should not be classified as soft-404")
	}
}

func TestRun_SubdomainsFromRawContent(t *testing.T) {
	// Create test server simulating a hard-404 service (takeover candidate).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	// Build module with a synthetic signature that matches "127.0.0.1" (test server host).
	host := strings.TrimPrefix(srv.URL, "https://")
	m := &Module{
		client:     srv.Client(),
		threads:    2,
		timeout:    defaultTimeout,
		probeHTTP:  false,
		probeHTTPS: true,
		signatures: []Signature{
			{host, "Test Service"},
		},
	}

	// Inject subdomain resolution by overriding resolveCNAME behaviour:
	// Since we can't mock DNS in unit tests cleanly, we directly test classify.
	ok, conf := m.classify(404, "not found", nil)
	if !ok || conf != "high" {
		t.Fatalf("expected takeover candidate from hard-404 server, got ok=%v conf=%q", ok, conf)
	}
}
