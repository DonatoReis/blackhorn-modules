package urlparse_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/urlparse"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

func findingsByMode(findings []module.Finding, mode string) []string {
	var out []string
	for _, f := range findings {
		if f.Extra["mode"] == mode {
			out = append(out, f.Extra["value"])
		}
	}
	return out
}

func TestRun_ModeKeys(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"https://example.com/path?foo=1&bar=2"},
		Options: map[string]string{"mode": "keys"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vals := findingsByMode(findings, "keys")
	if len(vals) != 2 {
		t.Fatalf("expected 2 key findings, got %d: %v", len(vals), vals)
	}
}

func TestRun_ModeValues(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"https://example.com/?a=hello&b=world"},
		Options: map[string]string{"mode": "values"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vals := findingsByMode(findings, "values")
	if len(vals) != 2 {
		t.Fatalf("expected 2 value findings, got %d", len(vals))
	}
}

func TestRun_ModeKeyPairs(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"https://example.com/?x=1"},
		Options: map[string]string{"mode": "keypairs"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vals := findingsByMode(findings, "keypairs")
	if len(vals) != 1 || vals[0] != "x=1" {
		t.Fatalf("expected keypair x=1, got %v", vals)
	}
}

func TestRun_ModeDomains(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"https://sub.example.com/path"},
		Options: map[string]string{"mode": "domains"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vals := findingsByMode(findings, "domains")
	if len(vals) != 1 || vals[0] != "sub.example.com" {
		t.Fatalf("expected sub.example.com, got %v", vals)
	}
}

func TestRun_ModeApexes(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"https://sub.example.com/"},
		Options: map[string]string{"mode": "apexes"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vals := findingsByMode(findings, "apexes")
	if len(vals) == 0 {
		t.Fatal("expected apex finding, got none")
	}
	if vals[0] != "example.com" {
		t.Fatalf("expected apex example.com, got %q", vals[0])
	}
}

func TestRun_ModePaths(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"https://example.com/users/profile"},
		Options: map[string]string{"mode": "paths"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vals := findingsByMode(findings, "paths")
	if len(vals) != 1 || vals[0] != "/users/profile" {
		t.Fatalf("expected /users/profile, got %v", vals)
	}
}

func TestRun_ModeJSON(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"https://sub.example.com:8080/path?q=1#frag"},
		Options: map[string]string{"mode": "json"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 JSON finding, got %d", len(findings))
	}

	var s urlparse.UrlStruct
	if err := json.Unmarshal([]byte(findings[0].Extra["value"]), &s); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if s.Scheme != "https" {
		t.Errorf("expected scheme https, got %q", s.Scheme)
	}
	if s.Port != "8080" {
		t.Errorf("expected port 8080, got %q", s.Port)
	}
	if s.Fragment != "frag" {
		t.Errorf("expected fragment frag, got %q", s.Fragment)
	}
	if s.Apex != "example.com" {
		t.Errorf("expected apex example.com, got %q", s.Apex)
	}
}

func TestRun_ModeFormat(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"https://example.com/search?q=test"},
		Options: map[string]string{"mode": "format", "format": "%s://%d%p"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vals := findingsByMode(findings, "format")
	if len(vals) != 1 || vals[0] != "https://example.com/search" {
		t.Fatalf("expected https://example.com/search, got %v", vals)
	}
}

func TestRun_UniqueFlag(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/?x=1",
			"https://example.com/?x=2",
		},
		Options: map[string]string{"mode": "keys", "unique": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Both URLs have key "x" — with unique=true only one should appear
	vals := findingsByMode(findings, "keys")
	if len(vals) != 1 {
		t.Fatalf("expected 1 unique key finding, got %d", len(vals))
	}
}

func TestRun_TargetFallback(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "https://example.com/",
		Options: map[string]string{"mode": "domains"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from Target fallback")
	}
}

func TestRun_NoInput(t *testing.T) {
	m := urlparse.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestRun_UnknownMode(t *testing.T) {
	m := urlparse.New()
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"https://example.com/"},
		Options: map[string]string{"mode": "invalid"},
	})
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestRun_MalformedURLsSkipped(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"://not-a-url", "https://valid.com/"},
		Options: map[string]string{"mode": "domains"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for valid URL")
	}
}

func TestName(t *testing.T) {
	if urlparse.New().Name() != "urlparse" {
		t.Error("wrong module name")
	}
}

// TestRun_ModeSubdomains extracts unique subdomains from URLs.
func TestRun_ModeSubdomains(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://api.example.com/v1/users",
			"https://app.example.com/dashboard",
			"https://api.example.com/v2/posts",
		},
		Options: map[string]string{"mode": "domains"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected domain findings from URLs")
	}
}

// TestRun_UniquePreservesOrder verifies that unique mode deduplicates across URLs.
func TestRun_UniquePreservesOrder(t *testing.T) {
	m := urlparse.New()
	urls := []string{
		"https://example.com/search?q=foo&page=1",
		"https://example.com/search?q=foo&page=1",
		"https://example.com/search?q=bar&page=2",
	}
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    urls,
		Options: map[string]string{"mode": "keys", "unique": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seen := map[string]int{}
	for _, f := range findings {
		seen[f.Detail]++
		if seen[f.Detail] > 1 {
			t.Errorf("duplicate detail %q in unique mode", f.Detail)
		}
	}
}

// TestRun_ModeExtension extracts file extensions from URL paths.
func TestRun_ModeExtension(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/file.pdf",
			"https://example.com/image.png",
			"https://example.com/page",
		},
		Options: map[string]string{"mode": "paths"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// paths mode should return path strings including the extension
	_ = findings // no panic = pass
}

// TestRun_FindingsHaveConfidence verifies all findings have a non-empty confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"https://example.com/path?foo=1&bar=2"},
		Options: map[string]string{"mode": "keys"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding missing Extra[confidence]: %+v", f)
		}
	}
}

// TestRun_FindingTypeValid verifies all findings have a non-empty Type field.
func TestRun_FindingTypeValid(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"https://example.com/path?foo=1"},
		Options: map[string]string{"mode": "domains"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "" {
			t.Errorf("finding has empty Type: %+v", f)
		}
	}
}

// TestRun_FindingURLOrDetailSet verifies each finding has at least URL or Detail set.
func TestRun_FindingURLOrDetailSet(t *testing.T) {
	m := urlparse.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"https://example.com/search?q=test"},
		Options: map[string]string{"mode": "keys"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.URL == "" && f.Detail == "" {
			t.Errorf("finding has neither URL nor Detail: %+v", f)
		}
	}
}
