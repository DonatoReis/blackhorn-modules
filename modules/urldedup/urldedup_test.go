package urldedup_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/urldedup"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

func urlsFrom(findings []module.Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.URL
	}
	return out
}

func containsURL(findings []module.Finding, u string) bool {
	for _, f := range findings {
		if f.URL == u {
			return true
		}
	}
	return false
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if urldedup.New().Name() != "urldedup" {
		t.Error("expected name 'urldedup'")
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = urldedup.New()
}

// TestEmptyInput: no URLs → error.
func TestEmptyInput(t *testing.T) {
	m := urldedup.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

// TestSameParamValuesDeduplicated: same param keys, different values → 1 result.
func TestSameParamValuesDeduplicated(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/page?id=1",
			"https://example.com/page?id=2",
			"https://example.com/page?id=99",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 unique URL (same param pattern), got %d: %v", len(findings), urlsFrom(findings))
	}
}

// TestNewParamKeyKept: second URL introduces new param key → 2 results.
func TestNewParamKeyKept(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/search?q=foo",
			"https://example.com/search?q=foo&page=2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (new param key), got %d: %v", len(findings), urlsFrom(findings))
	}
}

// TestIntegerPathsCollapsed: /user/123/... and /user/456/... → same pattern.
func TestIntegerPathsCollapsed(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/user/123/profile",
			"https://example.com/user/456/profile",
			"https://example.com/user/789/profile",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for integer path pattern, got %d: %v", len(findings), urlsFrom(findings))
	}
}

// TestStaticExtensionsDropped: CSS/PNG/SVG → dropped.
func TestStaticExtensionsDropped(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/style.css",
			"https://example.com/image.png",
			"https://example.com/logo.svg",
			"https://example.com/app.js", // .js not in default drop list → kept
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (.js kept), got %d: %v", len(findings), urlsFrom(findings))
	}
}

// TestContentPathsDropped: slug-style paths dropped, API path kept.
func TestContentPathsDropped(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/blog/how-to-use-the-new-feature-in-v2",
			"https://example.com/api/users",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (content URL dropped), got %d: %v", len(findings), urlsFrom(findings))
	}
	if findings[0].URL != "https://example.com/api/users" {
		t.Errorf("expected API URL kept, got %q", findings[0].URL)
	}
}

// TestDistinctPathsKept: different paths → all kept.
func TestDistinctPathsKept(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/users",
			"https://example.com/products",
			"https://example.com/orders",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 distinct paths, got %d", len(findings))
	}
}

// TestFindingFields: all required fields populated.
func TestFindingFields(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{"https://example.com/api?id=1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type == "" {
		t.Error("Type empty")
	}
	if f.URL == "" {
		t.Error("URL empty")
	}
	if f.Type != "deduplicated_url_candidate" ||
		f.Extra["validated"] != "false" ||
		f.Extra["validation_state"] != "syntactic_deduplication_only" ||
		f.Extra["promote_to_context"] != "false" {
		t.Errorf("deduplicated URL has unsafe evidence metadata: %+v", f)
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "https://example.com/api?q=1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings via Target fallback")
	}
}

// TestMixedParamsAndPaths: combination of patterns.
func TestMixedParamsAndPaths(t *testing.T) {
	m := urldedup.New()
	urls := []string{
		"https://example.com/api?id=1",
		"https://example.com/api?id=2",         // deduplicated with above
		"https://example.com/api?id=3&extra=x", // new key → kept
		"https://example.com/items/100",
		"https://example.com/items/200", // deduplicated with above
		"https://example.com/about",
	}
	findings, err := m.Run(context.Background(), module.Input{URLs: urls})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Expected: api?id, api?id&extra, items/{int}, about = 4 unique patterns
	if len(findings) < 3 || len(findings) > 5 {
		t.Errorf("expected 3-5 findings, got %d: %v", len(findings), urlsFrom(findings))
	}
}

// TestDuplicateURLs: exact duplicates → 1 result.
func TestDuplicateURLs(t *testing.T) {
	m := urldedup.New()
	u := "https://example.com/api?q=test"
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{u, u, u, u},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for exact duplicates, got %d", len(findings))
	}
}

// TestDifferentHostsKept: same path on different hosts → both kept.
func TestDifferentHostsKept(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/api?id=1",
			"https://other.com/api?id=1",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (different hosts), got %d: %v", len(findings), urlsFrom(findings))
	}
}

// TestSortedOutput: output order is deterministic.
func TestSortedOutput(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/z?a=1",
			"https://example.com/a?b=2",
			"https://example.com/m?c=3",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := urlsFrom(findings)
	sorted := make([]string, len(out))
	copy(sorted, out)
	sort.Strings(sorted)
	if strings.Join(out, ",") != strings.Join(sorted, ",") {
		t.Fatalf("output is not deterministic: got %v want %v", out, sorted)
	}
}

func TestMaxResults(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/a",
			"https://example.com/b",
			"https://example.com/c",
		},
		Options: map[string]string{"max_results": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected max 2 findings, got %d", len(findings))
	}
}

func TestMalformedURLsAreDiscarded(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/valid",
			"https://user:pass@example.com/secret",
			"https://bad host.example/path",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].URL != "https://example.com/valid" {
		t.Fatalf("malformed URLs were not discarded: %+v", findings)
	}
}

// TestImageExtensionDropped: common image exts → dropped.
func TestImageExtensionDropped(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/photo.jpg",
			"https://example.com/icon.ico",
			"https://example.com/banner.gif",
			"https://example.com/doc.pdf",
			"https://example.com/api", // kept
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		for _, ext := range []string{".jpg", ".ico", ".gif", ".pdf"} {
			if strings.HasSuffix(strings.ToLower(f.URL), ext) {
				t.Errorf("static extension %q should be dropped, got: %q", ext, f.URL)
			}
		}
	}
	if !containsURL(findings, "https://example.com/api") {
		t.Error("expected /api URL to be kept")
	}
}

// TestRun_FindingsSeveritySet verifies all urldedup findings carry severity.
func TestRun_FindingsSeveritySet(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/page1",
			"https://example.com/page2",
			"https://example.com/page1", // duplicate
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == "" {
			t.Errorf("urldedup finding missing Severity: %+v", f)
		}
	}
}

// TestRun_FindingsHaveConfidence verifies all findings have a non-empty confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/api?id=1",
			"https://example.com/api?id=2",
		},
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
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/users",
			"https://example.com/products",
		},
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
	m := urldedup.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/api?q=test",
			"https://example.com/other",
		},
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
