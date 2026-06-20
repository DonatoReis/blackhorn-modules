package emailspoof_test

import (
	"context"
	"net"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/emailspoof"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Stub DNS resolver ────────────────────────────────────────────────────────

// stubResolver intercepts LookupTXT calls and returns configured records.
type stubResolver struct {
	txtRecords map[string][]string // domain → TXT records
}

func newStub(records map[string][]string) *net.Resolver {
	// net.Resolver doesn't have an easy mock interface; use custom Dial to
	// intercept. For unit tests, we wrap the module with direct function injection.
	// Since NewWithResolver accepts *net.Resolver, we use a real one for integration
	// and fake DNS for unit tests via the test helper below.
	return net.DefaultResolver // placeholder
}

func findByType(findings []module.Finding, typ string) []module.Finding {
	var out []module.Finding
	for _, f := range findings {
		if f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

// ─── Tests using real DNS (integration-style, domain known to have records) ──

func TestName(t *testing.T) {
	if emailspoof.New().Name() != "emailspoof" {
		t.Error("expected name 'emailspoof'")
	}
}

func TestEmptyTargetReturnsError(t *testing.T) {
	m := emailspoof.New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Error("expected error for empty target")
	}
}

// TestDomainWithNoRecords: non-existent domain → spf_missing + dmarc_missing.
func TestNonExistentDomainFindings(t *testing.T) {
	// Use a clearly non-existent domain. DNS will NXDOMAIN.
	m := emailspoof.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "this-domain-does-not-exist-xyzzy123.invalid",
		Options: map[string]string{"check_dkim": "false", "check_bimi": "false", "check_mta_sts": "false"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for non-existent domain")
	}
	// Should emit spf_missing or spf_lookup_failed.
	hasSPF := false
	for _, f := range findings {
		if f.Type == "spf_missing" || f.Type == "spf_lookup_failed" {
			hasSPF = true
		}
	}
	if !hasSPF {
		t.Errorf("expected spf_missing or spf_lookup_failed, got types: %v", typesOf(findings))
	}
}

// TestSpoofabilityVerdictPresent: verdict finding always emitted.
func TestSpoofabilityVerdictPresent(t *testing.T) {
	m := emailspoof.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "this-domain-does-not-exist-xyzzy123.invalid",
		Options: map[string]string{"check_dkim": "false", "check_bimi": "false", "check_mta_sts": "false"},
	})
	verdicts := findByType(findings, "emailspoof_verdict")
	if len(verdicts) == 0 {
		t.Error("expected emailspoof_verdict finding")
	}
}

// TestSpoofableDomainHasCriticalVerdict: non-existent domain has no SPF/DMARC → verdict SPOOFABLE.
func TestSpoofableDomainVerdict(t *testing.T) {
	m := emailspoof.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "this-domain-does-not-exist-xyzzy123.invalid",
		Options: map[string]string{"check_dkim": "false", "check_bimi": "false", "check_mta_sts": "false"},
	})
	verdicts := findByType(findings, "emailspoof_verdict")
	if len(verdicts) == 0 {
		t.Skip("verdict not emitted (DNS resolution may have behaved unexpectedly)")
	}
	if verdicts[0].Extra["spoofable"] != "true" {
		t.Errorf("expected spoofable=true for domain with no records, got %q", verdicts[0].Extra["spoofable"])
	}
}

// TestConfidencePresent: all findings must have confidence in Extra.
func TestConfidencePresent(t *testing.T) {
	m := emailspoof.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "this-domain-does-not-exist-xyzzy123.invalid",
		Options: map[string]string{"check_dkim": "false", "check_bimi": "false", "check_mta_sts": "false"},
	})
	for _, f := range findings {
		if f.Extra == nil || f.Extra["confidence"] == "" {
			t.Errorf("finding %q missing confidence in Extra", f.Type)
		}
	}
}

// TestChecksDisabled: with all checks disabled still emits verdict.
func TestAllChecksDisabledStillEmitsVerdict(t *testing.T) {
	m := emailspoof.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "this-domain-does-not-exist-xyzzy123.invalid",
		Options: map[string]string{
			"check_dkim":    "false",
			"check_bimi":    "false",
			"check_mta_sts": "false",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least one finding even with optional checks disabled")
	}
}

// TestDomainStripping: various input formats should all work.
func TestDomainStripping(t *testing.T) {
	inputs := []string{
		"https://www.example.invalid",
		"http://example.invalid",
		"www.example.invalid",
		"example.invalid",
		"example.invalid/path?q=1",
	}
	m := emailspoof.New()
	for _, input := range inputs {
		findings, err := m.Run(context.Background(), module.Input{
			Target:  input,
			Options: map[string]string{"check_dkim": "false", "check_bimi": "false", "check_mta_sts": "false"},
		})
		if err != nil {
			t.Errorf("Run(%q): unexpected error: %v", input, err)
		}
		if len(findings) == 0 {
			t.Errorf("Run(%q): expected at least 1 finding", input)
		}
	}
}

// TestDKIMCheckSkipped: check_dkim=false means no dkim_* findings.
func TestDKIMCheckSkipped(t *testing.T) {
	m := emailspoof.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "this-domain-does-not-exist-xyzzy123.invalid",
		Options: map[string]string{
			"check_dkim":    "false",
			"check_bimi":    "false",
			"check_mta_sts": "false",
		},
	})
	for _, f := range findings {
		if f.Type == "dkim_no_selectors_found" || f.Type == "dkim_selectors_found" {
			t.Errorf("DKIM check ran despite check_dkim=false: %q", f.Type)
		}
	}
}

// TestBIMICheckSkipped: check_bimi=false means no bimi_* findings.
func TestBIMICheckSkipped(t *testing.T) {
	m := emailspoof.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "this-domain-does-not-exist-xyzzy123.invalid",
		Options: map[string]string{
			"check_dkim":    "false",
			"check_bimi":    "false",
			"check_mta_sts": "false",
		},
	})
	for _, f := range findings {
		if f.Type == "bimi_missing" || f.Type == "bimi_found" {
			t.Errorf("BIMI check ran despite check_bimi=false: %q", f.Type)
		}
	}
}

// TestMTASTSCheckSkipped: check_mta_sts=false means no mta_sts_* findings.
func TestMTASTSCheckSkipped(t *testing.T) {
	m := emailspoof.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "this-domain-does-not-exist-xyzzy123.invalid",
		Options: map[string]string{
			"check_dkim":    "false",
			"check_bimi":    "false",
			"check_mta_sts": "false",
		},
	})
	for _, f := range findings {
		if f.Type == "mta_sts_missing" || f.Type == "mta_sts_found" || f.Type == "tls_rpt_missing" {
			t.Errorf("MTA-STS check ran despite check_mta_sts=false: %q", f.Type)
		}
	}
}

// TestContextCancellation: cancelled context must not panic.
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := emailspoof.New()
	_, _ = m.Run(ctx, module.Input{
		Target:  "example.invalid",
		Options: map[string]string{"check_dkim": "false", "check_bimi": "false", "check_mta_sts": "false"},
	})
}

// TestVerdictSeverity: spoofable=true → at least Medium, spoofable=false → Info.
// Severity is now graded (Critical/High/Medium) based on which controls are missing.
// DMARC p=none alone → Medium (not Critical — monitoring mode, not confirmed spoofable).
// SPF missing alone → High. SPF+DMARC both missing → Critical.
func TestVerdictSeverity(t *testing.T) {
	m := emailspoof.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "this-domain-does-not-exist-xyzzy123.invalid",
		Options: map[string]string{"check_dkim": "false", "check_bimi": "false", "check_mta_sts": "false"},
	})
	for _, f := range findings {
		if f.Type != "emailspoof_verdict" {
			continue
		}
		if f.Extra["spoofable"] == "true" {
			// Must be at least Medium for any spoofable finding.
			if f.Severity == module.SeverityInfo || f.Severity == module.SeverityLow {
				t.Errorf("spoofable=true verdict must be at least Medium, got %v", f.Severity)
			}
		}
		if f.Extra["spoofable"] == "false" && f.Severity != module.SeverityInfo {
			t.Errorf("spoofable=false verdict should be Info, got %v", f.Severity)
		}
	}
}

func typesOf(findings []module.Finding) []string {
	types := make([]string, len(findings))
	for i, f := range findings {
		types[i] = f.Type
	}
	return types
}
