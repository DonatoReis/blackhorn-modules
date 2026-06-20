package fingerprint_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/fingerprint"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// newServer creates a test server that returns the given body and headers.
func newServer(t *testing.T, body string, extraHeaders map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range extraHeaders {
			w.Header().Set(k, v)
		}
		fmt.Fprint(w, body)
	}))
}

// moduleWithClient returns a fingerprint.Module with a short-timeout client.
func moduleWithClient(t *testing.T) *fingerprint.Module {
	t.Helper()
	return fingerprint.NewWithClient(&http.Client{Timeout: 5 * time.Second})
}

// hasTech checks if a technology was detected in the findings.
func hasTech(findings []module.Finding, tech string) bool {
	for _, f := range findings {
		if strings.EqualFold(f.Extra["technology"], tech) {
			return true
		}
	}
	return false
}

// ─── tests ────────────────────────────────────────────────────────────────────

// TestName verifies the module name.
func TestName(t *testing.T) {
	if fingerprint.New().Name() != "fingerprint" {
		t.Error("expected module name 'fingerprint'")
	}
}

// TestRun_EmptyTarget expects an error.
func TestRun_EmptyTarget(t *testing.T) {
	m := fingerprint.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestRun_ContextCancellation should not hang.
func TestRun_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := fingerprint.New()
	_, _ = m.Run(ctx, module.Input{Target: "http://localhost:1"})
}

// TestRun_DetectsWordPress verifies WordPress detection via body patterns.
func TestRun_DetectsWordPress(t *testing.T) {
	body := `<html><head><link rel="stylesheet" href="/wp-content/themes/main.css">
	<meta name="generator" content="WordPress 6.4.2"></head><body></body></html>`

	srv := newServer(t, body, map[string]string{"Server": "Apache/2.4.51"})
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasTech(findings, "WordPress") {
		t.Error("expected WordPress to be detected")
	}
}

// TestRun_DetectsApache verifies Apache detection via Server header.
func TestRun_DetectsApache(t *testing.T) {
	srv := newServer(t, "<html></html>", map[string]string{"Server": "Apache/2.4.51 (Ubuntu)"})
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasTech(findings, "Apache HTTP Server") {
		t.Error("expected Apache HTTP Server to be detected")
	}
}

// TestRun_DetectsNginx verifies Nginx detection via Server header.
func TestRun_DetectsNginx(t *testing.T) {
	srv := newServer(t, "<html></html>", map[string]string{"Server": "nginx/1.24.0"})
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasTech(findings, "Nginx") {
		t.Error("expected Nginx to be detected")
	}
}

// TestRun_DetectsPHP verifies PHP detection via X-Powered-By header.
func TestRun_DetectsPHP(t *testing.T) {
	srv := newServer(t, "<html></html>", map[string]string{"X-Powered-By": "PHP/8.2.0"})
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasTech(findings, "PHP") {
		t.Error("expected PHP to be detected")
	}
}

// TestRun_VersionExtraction verifies that version numbers are extracted correctly.
func TestRun_VersionExtraction(t *testing.T) {
	srv := newServer(t, "<html></html>", map[string]string{"Server": "nginx/1.24.0"})
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Extra["technology"] == "Nginx" {
			if f.Extra["version"] != "1.24.0" {
				t.Errorf("expected version '1.24.0', got %q", f.Extra["version"])
			}
			return
		}
	}
	t.Error("Nginx finding not found")
}

// TestRun_FindingFields verifies all required fields on every finding.
func TestRun_FindingFields(t *testing.T) {
	srv := newServer(t, "<html></html>", map[string]string{"Server": "Apache/2.4.51"})
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range findings {
		if f.Type != "technology" {
			t.Errorf("expected type 'technology', got %q", f.Type)
		}
		if f.Extra["technology"] == "" {
			t.Error("finding missing 'technology' field")
		}
		if f.Extra["category"] == "" {
			t.Error("finding missing 'category' field")
		}
		if f.Extra["confidence"] == "" {
			t.Error("finding missing 'confidence' field")
		}
		if f.Extra["source"] == "" {
			t.Error("finding missing 'source' field")
		}
		if f.URL == "" {
			t.Error("finding missing URL")
		}
		if f.Severity == "" {
			t.Error("finding missing severity")
		}
		if f.Detail == "" {
			t.Error("finding missing detail")
		}
	}
}

// TestRun_CategoryFilter verifies that only matching categories are returned.
func TestRun_CategoryFilter(t *testing.T) {
	srv := newServer(t, `<html><link href="/wp-content/main.css"></html>`,
		map[string]string{"Server": "Apache/2.4.51", "X-Powered-By": "PHP/8.2"})
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"categories": "web-server"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Extra["category"] != "web-server" && f.Extra["source"] != "implies" {
			t.Errorf("unexpected category %q with source %q (expected web-server)", f.Extra["category"], f.Extra["source"])
		}
	}
}

// TestRun_Deduplication verifies that each technology appears at most once per URL.
func TestRun_Deduplication(t *testing.T) {
	// Multiple Apache-matching patterns in body + header → only one finding.
	srv := newServer(t, "Apache is great", map[string]string{"Server": "Apache/2.4.51"})
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := 0
	for _, f := range findings {
		if f.Extra["technology"] == "Apache HTTP Server" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected at most 1 Apache finding, got %d", count)
	}
}

// TestRun_ImpliesChain verifies that implied technologies are added.
func TestRun_ImpliesChain(t *testing.T) {
	// WordPress implies PHP and MySQL.
	body := `<html><link href="/wp-content/themes/x.css"><meta name="generator" content="WordPress 6.4"></html>`
	srv := newServer(t, body, nil)
	defer srv.Close()

	// Use a custom sig set where WordPress implies PHP.
	sigs := []fingerprint.Signature{
		{
			Name:     "WordPress",
			Category: "cms",
			Website:  "https://wordpress.org",
			HTML:     fingerprint.MustParsePatterns([]string{`/wp-content/`}),
			Implies:  []string{"PHP"},
		},
		{
			Name:     "PHP",
			Category: "programming-language",
			Website:  "https://php.net",
		},
	}

	m := fingerprint.NewWithSignatures(sigs)
	m2 := fingerprint.NewWithClientAndSignatures(&http.Client{Timeout: 5 * time.Second}, sigs)

	for _, mod := range []*fingerprint.Module{m, m2} {
		findings, err := mod.Run(context.Background(), module.Input{Target: srv.URL})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !hasTech(findings, "PHP") {
			t.Error("expected PHP to be detected via implies chain from WordPress")
		}
	}
}

// TestRun_ScriptDetection verifies detection from script src attributes.
func TestRun_ScriptDetection(t *testing.T) {
	body := `<html><head>
	<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.0/jquery.min.js"></script>
	</head><body></body></html>`
	srv := newServer(t, body, nil)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasTech(findings, "jQuery") {
		t.Error("expected jQuery to be detected via script src")
	}
}

// TestRun_MetaDetection verifies detection from meta generator tags.
func TestRun_MetaDetection(t *testing.T) {
	body := `<html><head><meta name="generator" content="Drupal 10 (https://www.drupal.org)"></head><body></body></html>`
	srv := newServer(t, body, nil)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasTech(findings, "Drupal") {
		t.Error("expected Drupal to be detected via meta generator")
	}
}

// TestRun_MultipleURLs verifies that multiple URLs in input are all probed.
func TestRun_MultipleURLs(t *testing.T) {
	srv1 := newServer(t, "<html></html>", map[string]string{"Server": "nginx/1.24.0"})
	defer srv1.Close()
	srv2 := newServer(t, "<html></html>", map[string]string{"Server": "Apache/2.4.51"})
	defer srv2.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv1.URL, srv2.URL},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasNginx := hasTech(findings, "Nginx")
	hasApache := hasTech(findings, "Apache HTTP Server")
	if !hasNginx || !hasApache {
		t.Errorf("expected both Nginx and Apache, nginx=%v apache=%v", hasNginx, hasApache)
	}
}

// TestRun_TargetFromURLs uses URLs[0] when Target is empty.
func TestRun_TargetFromURLs(t *testing.T) {
	srv := newServer(t, "<html></html>", map[string]string{"Server": "nginx/1.24.0"})
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasTech(findings, "Nginx") {
		t.Error("expected Nginx to be detected when using URLs field")
	}
}

// TestRun_NoMatch verifies that no findings are returned for an empty page.
func TestRun_NoMatch(t *testing.T) {
	srv := newServer(t, "<html><body>Hello World</body></html>", nil)
	defer srv.Close()

	// Use a minimal signature set that won't match.
	sigs := []fingerprint.Signature{
		{
			Name:     "NonExistent",
			Category: "cms",
			HTML:     fingerprint.MustParsePatterns([]string{`this-string-never-appears-12345`}),
		},
	}
	m := fingerprint.NewWithSignatures(sigs)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

// TestRun_CloudflareDetection verifies CDN detection from headers.
func TestRun_CloudflareDetection(t *testing.T) {
	srv := newServer(t, "<html></html>", map[string]string{
		"CF-Ray":          "abc123-SFO",
		"CF-Cache-Status": "HIT",
	})
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasTech(findings, "Cloudflare") {
		t.Error("expected Cloudflare to be detected")
	}
}

// TestRun_CustomSignatures verifies that NewWithSignatures uses only the provided set.
func TestRun_CustomSignatures(t *testing.T) {
	sigs := []fingerprint.Signature{
		{
			Name:     "CustomApp",
			Category: "framework",
			HTML:     fingerprint.MustParsePatterns([]string{`X-CustomApp-Token`}),
		},
	}

	body := `<html><body>X-CustomApp-Token: abc123</body></html>`
	srv := newServer(t, body, nil)
	defer srv.Close()

	m := fingerprint.NewWithSignatures(sigs)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasTech(findings, "CustomApp") {
		t.Error("expected CustomApp to be detected with custom signatures")
	}
}
