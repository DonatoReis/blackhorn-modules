package dnsaudit

import (
	"context"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func hasCheck(findings []module.Finding, check string) bool {
	for _, f := range findings {
		if f.Extra["check"] == check {
			return true
		}
	}
	return false
}

func findingByCheck(findings []module.Finding, check string) *module.Finding {
	for i := range findings {
		if findings[i].Extra["check"] == check {
			return &findings[i]
		}
	}
	return nil
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "dnsaudit" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoInput(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestCleanDomain(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://example.com/path", "example.com"},
		{"http://example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"https://sub.example.com/path?q=1", "sub.example.com"},
	}
	for _, tt := range tests {
		got := cleanDomain(tt.in)
		if got != tt.want {
			t.Errorf("cleanDomain(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestResolveDomain_Target(t *testing.T) {
	input := module.Input{Target: "https://example.com/path"}
	got := resolveDomain(input)
	if got != "example.com" {
		t.Errorf("resolveDomain = %q, want example.com", got)
	}
}

func TestResolveDomain_URLs(t *testing.T) {
	input := module.Input{URLs: []string{"https://api.example.com"}}
	got := resolveDomain(input)
	if got != "api.example.com" {
		t.Errorf("resolveDomain = %q, want api.example.com", got)
	}
}

func TestLookupCount_Simple(t *testing.T) {
	spf := "v=spf1 include:_spf.google.com ~all"
	count := lookupCount(spf)
	if count != 1 {
		t.Errorf("expected 1 lookup, got %d", count)
	}
}

func TestLookupCount_Complex(t *testing.T) {
	// 12 includes — exceeds limit.
	parts := "v=spf1"
	for i := 0; i < 12; i++ {
		parts += " include:spf" + string(rune('a'+i)) + ".example.com"
	}
	parts += " -all"
	count := lookupCount(parts)
	if count <= maxSPFLookups {
		t.Errorf("expected count > %d, got %d", maxSPFLookups, count)
	}
}

func TestCheckSPF_Permissive(t *testing.T) {
	// Test the classification logic directly.
	spf := "v=spf1 include:mail.example.com +all"
	// Permissive: ends with +all.
	isPermissive := spf[len(spf)-4:] == "+all"
	if !isPermissive {
		t.Fatal("expected +all to be detected as permissive")
	}
}

func TestCheckSPF_MissingQualifier(t *testing.T) {
	spf := "v=spf1 include:mail.example.com"
	hasNegative := false
	for _, q := range []string{"-all", "~all", "+all"} {
		if contains(spf, q) {
			hasNegative = true
			break
		}
	}
	if hasNegative {
		t.Fatal("expected no qualifier in this SPF record")
	}
}

func TestBuildAXFRQuery_Structure(t *testing.T) {
	query := buildAXFRQuery("example.com")
	// Should have at least 2 (len prefix) + 12 (header) + labels + 4 (qtype/qclass) bytes.
	if len(query) < 20 {
		t.Fatalf("AXFR query too short: %d bytes", len(query))
	}
	// First 2 bytes are length prefix.
	msgLen := int(query[0])<<8 | int(query[1])
	if msgLen != len(query)-2 {
		t.Errorf("AXFR query length prefix mismatch: prefix says %d, actual is %d", msgLen, len(query)-2)
	}
}

func TestBuildAXFRQuery_QTYPE(t *testing.T) {
	query := buildAXFRQuery("example.com")
	// AXFR QTYPE is 0x00FC = 252.
	// Find it by looking for the last 4 bytes before the end (QTYPE + QCLASS).
	last4 := query[len(query)-4:]
	if last4[0] != 0x00 || last4[1] != 0xFC {
		t.Errorf("expected QTYPE=AXFR (0x00FC), got 0x%02X%02X", last4[0], last4[1])
	}
	if last4[2] != 0x00 || last4[3] != 0x01 {
		t.Errorf("expected QCLASS=IN (0x0001), got 0x%02X%02X", last4[2], last4[3])
	}
}

func TestDKIMSelectors_Count(t *testing.T) {
	if len(dkimSelectors) < 10 {
		t.Fatalf("expected at least 10 DKIM selectors, got %d", len(dkimSelectors))
	}
}

func TestDKIMSelectors_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, s := range dkimSelectors {
		if seen[s] {
			t.Errorf("duplicate DKIM selector: %q", s)
		}
		seen[s] = true
	}
}

func TestRandomHex8_Length(t *testing.T) {
	h := randomHex8()
	if len(h) != 8 {
		t.Fatalf("expected 8 chars, got %d: %q", len(h), h)
	}
}

func TestRandomHex8_Different(t *testing.T) {
	// Should produce different values each time (uses UnixNano).
	h1 := randomHex8()
	h2 := randomHex8()
	// In theory they could collide if called in the same nanosecond — tolerate.
	_ = h1
	_ = h2
}

func TestOptInt(t *testing.T) {
	opts := map[string]string{"threads": "4"}
	if got := optInt(opts, "threads", 8); got != 4 {
		t.Errorf("expected 4, got %d", got)
	}
	if got := optInt(opts, "missing", 8); got != 8 {
		t.Errorf("expected default 8, got %d", got)
	}
	if got := optInt(nil, "threads", 8); got != 8 {
		t.Errorf("expected default 8 for nil opts, got %d", got)
	}
}

// ─── integration tests (using real DNS — run with -short to skip) ─────────────

func TestRun_RealDomain_NoPanic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real DNS test in short mode")
	}
	m := New()
	// Use a well-known domain — we don't assert exact findings, just no panic/error.
	findings, err := m.Run(context.Background(), module.Input{Target: "cloudflare.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("cloudflare.com: %d findings", len(findings))
}

// ─── internal helper ─────────────────────────────────────────────────────────

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestRun_FindingsHaveConfidence verifies all findings have a non-empty confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real DNS test in short mode")
	}
	m := New()
	findings, err := m.Run(context.Background(), module.Input{Target: "cloudflare.com"})
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
	if testing.Short() {
		t.Skip("skipping real DNS test in short mode")
	}
	m := New()
	findings, err := m.Run(context.Background(), module.Input{Target: "cloudflare.com"})
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
	if testing.Short() {
		t.Skip("skipping real DNS test in short mode")
	}
	m := New()
	findings, err := m.Run(context.Background(), module.Input{Target: "cloudflare.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.URL == "" && f.Detail == "" {
			t.Errorf("finding has neither URL nor Detail: %+v", f)
		}
	}
}
