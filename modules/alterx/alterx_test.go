package alterx

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func run(t *testing.T, input module.Input) []module.Finding {
	t.Helper()
	findings, err := New().Run(context.Background(), input)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	return findings
}

func hasCandidatePrefix(findings []module.Finding, prefix string) bool {
	for _, f := range findings {
		if strings.HasPrefix(f.URL, prefix) {
			return true
		}
	}
	return false
}

func allHaveApex(findings []module.Finding, apex string) bool {
	for _, f := range findings {
		if !strings.HasSuffix(f.URL, "."+apex) && f.URL != apex {
			return false
		}
	}
	return true
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "alterx" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoTarget_Error(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error when no target is provided")
	}
}

func TestRun_BasicGeneration(t *testing.T) {
	findings := run(t, module.Input{Target: "example.com"})
	if len(findings) == 0 {
		t.Fatal("expected at least one candidate")
	}
}

func TestRun_AllCandidatesEndWithApex(t *testing.T) {
	findings := run(t, module.Input{Target: "example.com"})
	if !allHaveApex(findings, "example.com") {
		for _, f := range findings {
			if !strings.HasSuffix(f.URL, ".example.com") {
				t.Errorf("candidate %q does not end with .example.com", f.URL)
				break
			}
		}
	}
}

func TestRun_ContainsCommonWords(t *testing.T) {
	findings := run(t, module.Input{Target: "example.com"})
	// "api.example.com" and "dev.example.com" should always be generated.
	wantCandidates := []string{"api.example.com", "dev.example.com", "staging.example.com"}
	for _, want := range wantCandidates {
		found := false
		for _, f := range findings {
			if f.URL == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected candidate %q in output", want)
		}
	}
}

func TestRun_MaxResults_Respected(t *testing.T) {
	m := New()
	m.MaxResults = 50
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) > 50 {
		t.Errorf("expected at most 50 results, got %d", len(findings))
	}
}

func TestRun_Dedup(t *testing.T) {
	findings := run(t, module.Input{Target: "example.com"})
	seen := make(map[string]struct{})
	for _, f := range findings {
		if _, ok := seen[f.URL]; ok {
			t.Fatalf("duplicate candidate: %q", f.URL)
		}
		seen[f.URL] = struct{}{}
	}
}

func TestRun_FindingType(t *testing.T) {
	findings := run(t, module.Input{Target: "example.com"})
	for _, f := range findings[:min(5, len(findings))] {
		if f.Type != "dns_permutation_candidate" {
			t.Errorf("expected type 'dns_permutation_candidate', got %q", f.Type)
		}
		if f.Severity != module.SeverityInfo {
			t.Errorf("expected SeverityInfo, got %q", f.Severity)
		}
		if f.Extra["validated"] != "false" ||
			f.Extra["validation_state"] != "generated_dns_permutation" ||
			f.Extra["promote_to_context"] != "false" {
			t.Errorf("candidate has unsafe evidence metadata: %+v", f.Extra)
		}
	}
}

type stubHostResolver struct {
	records map[string][]string
}

func (r stubHostResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if addresses := r.records[host]; len(addresses) > 0 {
		return addresses, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestRun_ResolveOnlyReturnsConfirmedNames(t *testing.T) {
	m := New()
	m.OnlyPatterns = []string{"{{.Word}}.{{.Suffix}}"}
	m.ExtraWords = []string{"confirmed"}
	m.MaxResults = 1
	m.resolver = stubHostResolver{
		records: map[string][]string{"confirmed.example.com": {"203.0.113.10"}},
	}

	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"resolve":             "true",
			"parallelism":         "1",
			"max_runtime_seconds": "1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one confirmed result, got %d", len(findings))
	}
	if findings[0].Type != "subdomain_resolved" ||
		findings[0].Extra["validated"] != "true" ||
		findings[0].Extra["validation_state"] != "dns_confirmed_non_wildcard" ||
		findings[0].Extra["promote_to_context"] != "true" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

type wildcardHostResolver struct{}

func (wildcardHostResolver) LookupHost(_ context.Context, _ string) ([]string, error) {
	return []string{"203.0.113.20"}, nil
}

func TestRun_ResolveFiltersWildcardDNS(t *testing.T) {
	m := New()
	m.OnlyPatterns = []string{"{{.Word}}.{{.Suffix}}"}
	m.ExtraWords = []string{"candidate"}
	m.MaxResults = 3
	m.resolver = wildcardHostResolver{}

	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"resolve":             "true",
			"parallelism":         "1",
			"max_runtime_seconds": "1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("wildcard DNS must not confirm generated names: %+v", findings)
	}
}

func TestRun_Enrichment_FromURLs(t *testing.T) {
	// Provide existing subdomains — words should be extracted and used.
	findings, err := New().Run(context.Background(), module.Input{
		Target: "example.com",
		URLs:   []string{"api-v2.example.com", "internal-staging.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The extracted words "api", "v2", "internal", "staging" should be used in patterns.
	// So "v2.example.com" or "api-internal.example.com" etc. should appear.
	hasEnriched := false
	for _, f := range findings {
		if strings.Contains(f.URL, "v2") || strings.Contains(f.URL, "internal") {
			hasEnriched = true
			break
		}
	}
	if !hasEnriched {
		t.Fatal("expected enriched words (v2, internal) to appear in candidates")
	}
}

func TestRun_Enrichment_FromRawContent(t *testing.T) {
	findings, err := New().Run(context.Background(), module.Input{
		Target:     "example.com",
		RawContent: "payments.example.com\ncustomer-portal.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	// "payments" and "portal" should appear in candidates.
	hasPayments := false
	for _, f := range findings {
		if strings.Contains(f.URL, "payments") || strings.Contains(f.URL, "portal") {
			hasPayments = true
			break
		}
	}
	if !hasPayments {
		t.Fatal("expected enriched words from RawContent")
	}
}

func TestRun_ExtraWords(t *testing.T) {
	m := New()
	m.ExtraWords = []string{"mycustomword"}
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if strings.Contains(f.URL, "mycustomword") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected extra word 'mycustomword' to appear in candidates")
	}
}

func TestRun_ExtraPatterns(t *testing.T) {
	m := New()
	m.ExtraPatterns = []string{"superprefix-{{.Word}}.{{.Suffix}}"}
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if strings.HasPrefix(f.URL, "superprefix-") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected extra pattern 'superprefix-*' to appear in candidates")
	}
}

func TestRun_OnlyPatterns(t *testing.T) {
	m := New()
	// Use a completely custom word that we control so we can verify the pattern shape.
	m.OnlyPatterns = []string{"{{.Word}}.{{.Suffix}}"}
	m.ExtraWords = []string{"uniqueword"}
	m.MaxResults = 50
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	// "uniqueword.example.com" must appear (pattern {{.Word}}.{{.Suffix}} applied).
	found := false
	for _, f := range findings {
		if f.URL == "uniqueword.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected uniqueword.example.com from custom OnlyPattern")
	}
}

func TestRun_InvalidPattern_Error(t *testing.T) {
	m := New()
	m.OnlyPatterns = []string{"{{.InvalidUnclosed"}
	_, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err == nil {
		t.Fatal("expected error for invalid template pattern")
	}
}

func TestRun_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	findings, err := New().Run(ctx, module.Input{Target: "example.com"})
	// Should not hang. May return 0 findings or partial results — no error expected.
	_ = err
	_ = findings
}

func TestBuiltinWordlist_Count(t *testing.T) {
	if len(builtinWordlist) < 200 {
		t.Fatalf("expected at least 200 built-in words, got %d", len(builtinWordlist))
	}
}

func TestBuiltinPatterns_Count(t *testing.T) {
	if len(builtinPatterns) < 8 {
		t.Fatalf("expected at least 8 built-in patterns, got %d", len(builtinPatterns))
	}
}

func TestExtractWords_SplitsOnHyphen(t *testing.T) {
	words := extractWords([]string{"api-v2", "internal-staging"}, "example.com")
	want := map[string]bool{"api": true, "v2": true, "internal": true, "staging": true}
	for w := range want {
		found := false
		for _, word := range words {
			if word == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected extracted word %q", w)
		}
	}
}

func TestExtractApex(t *testing.T) {
	cases := []struct {
		input module.Input
		want  string
	}{
		{module.Input{Target: "example.com"}, "example.com"},
		{module.Input{Target: "https://example.com/path"}, "example.com"},
		{module.Input{Target: " example.com "}, "example.com"},
	}
	for _, c := range cases {
		got := extractApex(c.input)
		if got != c.want {
			t.Errorf("extractApex(%v) = %q, want %q", c.input.Target, got, c.want)
		}
	}
}

func TestIsValidHostname(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"api.example.com", true},
		{"dev-staging.example.com", true},
		{"v2.api.example.com", true},
		{"-bad.example.com", false},
		{"nodot", false},
		{"", false},
		{"has space.example.com", false},
	}
	for _, c := range cases {
		got := isValidHostname(c.s)
		if got != c.want {
			t.Errorf("isValidHostname(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestCleanDomain(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://example.com/path", "example.com"},
		{"http://sub.example.com:8080/", "sub.example.com"},
		{"example.com.", "example.com"},
		{" example.com ", "example.com"},
	}
	for _, c := range cases {
		got := cleanDomain(c.in)
		if got != c.want {
			t.Errorf("cleanDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
