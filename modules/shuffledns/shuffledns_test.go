package shuffledns

import (
	"context"
	"net"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func hasHost(findings []module.Finding, host string) bool {
	for _, f := range findings {
		if f.Extra["host"] == host {
			return true
		}
	}
	return false
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "shuffledns" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoTarget_Error(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error when no target provided")
	}
}

func TestRun_InvalidDomain_Error(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{Target: "www..example.com"})
	if err == nil {
		t.Fatal("expected error for malformed domain")
	}
}

func TestResolvedFindingPromotesOnlyDNSConfirmedHost(t *testing.T) {
	finding := resolvedFinding("example.com", "api.example.com", []string{"2001:db8::1", "192.0.2.1"})
	if finding.Type != "subdomain_resolved" {
		t.Fatalf("unexpected type %q", finding.Type)
	}
	if finding.Extra["validated"] != "true" ||
		finding.Extra["validation_state"] != "dns_confirmed_non_wildcard" ||
		finding.Extra["promote_to_context"] != "true" {
		t.Fatalf("resolved host metadata is incomplete: %+v", finding.Extra)
	}
	if finding.Extra["ips"] != "192.0.2.1,2001:db8::1" {
		t.Fatalf("IPs should be deterministic, got %q", finding.Extra["ips"])
	}
}

func TestRun_OnlyWords_LimitedWordlist(t *testing.T) {
	m := New()
	m.OnlyWords = []string{"nonexistentlabel12345xyz"}
	m.concurrency = 2
	// With a single non-existent label, we expect zero resolutions.
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	// No real DNS query should succeed for a random label on example.com.
	_ = findings
}

func TestRun_ExtraWords(t *testing.T) {
	m := New()
	m.ExtraWords = []string{"uniquecustomword"}
	m.OnlyWords = []string{"uniquecustomword"} // restrict to only our word
	candidates := m.buildCandidates("example.com", module.Input{})
	found := false
	for _, c := range candidates {
		if c == "uniquecustomword.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected extra word in candidate list")
	}
}

func TestBuildCandidates_FromURLs(t *testing.T) {
	m := New()
	m.OnlyWords = []string{"placeholder"} // don't use full wordlist
	input := module.Input{
		URLs: []string{
			"https://api.example.com/v1",
			"https://dev.example.com",
			"https://other.com", // different apex — should be excluded
		},
	}
	candidates := m.buildCandidates("example.com", input)
	hasAPI := false
	hasDev := false
	for _, c := range candidates {
		if c == "api.example.com" {
			hasAPI = true
		}
		if c == "dev.example.com" {
			hasDev = true
		}
	}
	if !hasAPI {
		t.Fatal("expected api.example.com from URLs")
	}
	if !hasDev {
		t.Fatal("expected dev.example.com from URLs")
	}
}

func TestBuildCandidates_FromRawContent(t *testing.T) {
	m := New()
	m.OnlyWords = []string{"placeholder"}
	input := module.Input{
		RawContent: "staging.example.com\napi.example.com\nextraword",
	}
	candidates := m.buildCandidates("example.com", input)
	hasStaging := false
	hasExtra := false
	for _, c := range candidates {
		if c == "staging.example.com" {
			hasStaging = true
		}
		if c == "extraword.example.com" {
			hasExtra = true
		}
	}
	if !hasStaging {
		t.Fatal("expected staging.example.com from RawContent")
	}
	if !hasExtra {
		t.Fatal("expected extraword.example.com from RawContent word")
	}
}

func TestBuildCandidates_Dedup(t *testing.T) {
	m := New()
	m.OnlyWords = []string{"api", "api", "dev"} // duplicates
	candidates := m.buildCandidates("example.com", module.Input{})
	seen := make(map[string]int)
	for _, c := range candidates {
		seen[c]++
	}
	for c, n := range seen {
		if n > 1 {
			t.Errorf("duplicate candidate %q (seen %d times)", c, n)
		}
	}
}

func TestBuiltinWordlist_Count(t *testing.T) {
	if len(builtinWordlist) < 200 {
		t.Fatalf("expected at least 200 words in built-in wordlist, got %d", len(builtinWordlist))
	}
}

func TestBuiltinWordlist_NoEmptyWords(t *testing.T) {
	for _, w := range builtinWordlist {
		if w == "" {
			t.Fatal("found empty word in builtinWordlist")
		}
	}
}

func TestBuiltinWordlist_AllLowercase(t *testing.T) {
	for _, w := range builtinWordlist {
		for _, c := range w {
			if c >= 'A' && c <= 'Z' {
				t.Errorf("word %q has uppercase character", w)
				break
			}
		}
	}
}

func TestIsWildcardResult_Empty(t *testing.T) {
	// Empty wildcard set → never a wildcard.
	if isWildcardResult([]string{"1.2.3.4"}, map[string]struct{}{}) {
		t.Fatal("expected false for empty wildcard set")
	}
}

func TestIsWildcardResult_Match(t *testing.T) {
	wildcards := map[string]struct{}{"1.2.3.4": {}}
	if !isWildcardResult([]string{"1.2.3.4"}, wildcards) {
		t.Fatal("expected true when IP is in wildcard set")
	}
}

func TestIsWildcardResult_PartialMatch(t *testing.T) {
	// One IP matches wildcard, one doesn't → not filtered (real record may exist).
	wildcards := map[string]struct{}{"1.2.3.4": {}}
	if isWildcardResult([]string{"1.2.3.4", "5.6.7.8"}, wildcards) {
		t.Fatal("expected false when at least one non-wildcard IP exists")
	}
}

func TestExtractApex(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"example.com", "example.com"},
		{"https://example.com/path", "example.com"},
		{"http://sub.example.com:8080/", "sub.example.com"},
		{"example.com.", "example.com"},
		{" example.com ", "example.com"},
		{"", ""},
	}
	for _, c := range cases {
		got := extractApex(c.in)
		if got != c.want {
			t.Errorf("extractApex(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildResolver_Default(t *testing.T) {
	m := New()
	r := m.buildResolver()
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
}

func TestBuildResolver_Custom(t *testing.T) {
	m := New()
	m.Resolvers = []string{"8.8.8.8"}
	r := m.buildResolver()
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
	// Ensure it doesn't panic when building.
	_ = r
}

func TestRandomHex_Length(t *testing.T) {
	h, err := randomHex(8)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 16 {
		t.Fatalf("expected 16 hex chars, got %d", len(h))
	}
}

func TestRandomHex_Unique(t *testing.T) {
	h1, _ := randomHex(8)
	h2, _ := randomHex(8)
	if h1 == h2 {
		t.Fatal("randomHex should produce unique values")
	}
}

func TestRun_RealDNS_Skipped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real DNS test in short mode")
	}
	// Test that real resolution works for a known hostname.
	m := New()
	m.OnlyWords = []string{"www"}
	m.concurrency = 1
	findings, err := m.Run(context.Background(), module.Input{Target: "google.com"})
	if err != nil {
		t.Fatal(err)
	}
	// www.google.com should resolve.
	if !hasHost(findings, "www.google.com") {
		t.Error("expected www.google.com to resolve")
	}
}

func TestBuildWordlist_OnlyWordsOverrides(t *testing.T) {
	m := New()
	m.OnlyWords = []string{"onlythis"}
	wl := m.buildWordlist(module.Input{})
	if len(wl) != 1 {
		t.Fatalf("expected 1 word with OnlyWords, got %d", len(wl))
	}
	if wl[0] != "onlythis" {
		t.Errorf("expected 'onlythis', got %q", wl[0])
	}
}

func TestResolveHost_InvalidHost(t *testing.T) {
	// Resolving an invalid hostname should return an error, not panic.
	ctx := context.Background()
	_, err := resolveHost(ctx, net.DefaultResolver, "this-does-not-exist-12345.invalid.")
	if err == nil {
		t.Fatal("expected error for non-existent hostname")
	}
}
