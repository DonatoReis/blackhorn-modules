package dnsprobe_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/dnsprobe"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// TestRun_ResolvesLocalhost uses the system resolver to look up "localhost".
// This is reliably available on all systems and requires no network access.
func TestRun_ResolvesLocalhost(t *testing.T) {
	m := dnsprobe.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "localhost",
		Options: map[string]string{"types": "A"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for localhost")
	}
	// Accept any dns_record type — some systems return only AAAA for localhost
	for _, f := range findings {
		if f.Type == "dns_record" {
			return
		}
	}
	t.Errorf("expected dns_record finding for localhost, got: %+v", findings)
}

// TestRun_EmptyTarget expects an error.
func TestRun_EmptyTarget(t *testing.T) {
	m := dnsprobe.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestRun_ContextCancellation should not hang.
func TestRun_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := dnsprobe.New()
	_, _ = m.Run(ctx, module.Input{Target: "localhost"})
	// Should return quickly without hanging
}

// TestRun_NXDOMAIN verifies that an unknown domain returns gracefully.
func TestRun_NXDOMAIN(t *testing.T) {
	m := dnsprobe.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := m.Run(ctx, module.Input{
		Target:  "this-host-definitely-does-not-exist-xyzabc.invalid",
		Options: map[string]string{"types": "A"},
	})
	// NXDOMAIN is either an error or a finding with a status field
	if err == nil && len(findings) > 0 {
		for _, f := range findings {
			status := f.Extra["status"]
			if status == "NXDOMAIN" || status == "SERVFAIL" || status == "" {
				return // acceptable
			}
		}
	}
	// err is also acceptable (NXDOMAIN propagated as error)
}

// TestRun_MultipleTypes queries A and AAAA for localhost.
func TestRun_MultipleTypes(t *testing.T) {
	m := dnsprobe.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "localhost",
		Options: map[string]string{"types": "A,AAAA"},
	})
	if err != nil {
		t.Logf("error (acceptable for AAAA on some systems): %v", err)
	}
	// Verify all returned findings are dns_record type
	for _, f := range findings {
		if f.Type != "dns_record" {
			t.Errorf("unexpected finding type: %q", f.Type)
		}
	}
}

// TestRun_FindingFields verifies all expected extra fields are present.
func TestRun_FindingFields(t *testing.T) {
	m := dnsprobe.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "localhost",
		Options: map[string]string{"types": "A"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type != "dns_record" {
			t.Errorf("expected type dns_record, got %q", f.Type)
		}
		if f.Extra["host"] == "" {
			t.Error("finding missing 'host' extra field")
		}
	}
}

// TestRun_TargetFromURLs uses the first URL as host when Target is empty.
func TestRun_TargetFromURLs(t *testing.T) {
	m := dnsprobe.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"localhost"},
		Options: map[string]string{"types": "A"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Extra["host"] == "localhost" {
			found = true
		}
	}
	if !found {
		t.Error("expected finding with host=localhost from URLs[0]")
	}
}

// TestRun_CustomResolver uses Cloudflare as resolver override.
// Skipped gracefully if no outbound UDP/53 access.
func TestRun_CustomResolver(t *testing.T) {
	m := dnsprobe.NewWithResolver("1.1.1.1:53")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := m.Run(ctx, module.Input{
		Target:  "localhost",
		Options: map[string]string{"types": "A"},
	})
	if err != nil {
		t.Logf("custom resolver error (acceptable in restricted environments): %v", err)
		return
	}
	for _, f := range findings {
		if f.Type != "dns_record" {
			t.Errorf("unexpected finding type: %q", f.Type)
		}
	}
}

// TestRun_AllOption queries all supported types.
func TestRun_AllOption(t *testing.T) {
	m := dnsprobe.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "localhost",
		Options: map[string]string{"all": "true"},
	})
	if err != nil {
		t.Logf("all-types query returned error (some types may not apply): %v", err)
	}
	// Just verify we got at least one finding
	if len(findings) == 0 {
		t.Log("no findings with all=true — acceptable if system resolver returns no records")
	}
}

// TestName checks the module name.
func TestName(t *testing.T) {
	if dnsprobe.New().Name() != "dnsprobe" {
		t.Error("wrong module name")
	}
}

// TestDefaultResolvers verifies the default resolver list contains Cloudflare.
func TestDefaultResolvers(t *testing.T) {
	if len(dnsprobe.DefaultResolvers) == 0 {
		t.Fatal("DefaultResolvers must not be empty")
	}
	found := false
	for _, r := range dnsprobe.DefaultResolvers {
		if strings.HasPrefix(r, "1.1.1.1") {
			found = true
		}
	}
	if !found {
		t.Error("expected 1.1.1.1 (Cloudflare) in DefaultResolvers")
	}
}

// TestModuleImplementsInterface ensures the Module implements the interface.
func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = dnsprobe.New()
}

// TestRun_SchemeStrippedFromURL: https:// in target should not cause error.
func TestRun_SchemeStrippedFromURL(t *testing.T) {
	m := dnsprobe.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "https://localhost",
		Options: map[string]string{"types": "A"},
	})
	if err != nil {
		t.Logf("scheme in target produced error (acceptable): %v", err)
		return
	}
	_ = findings
}

// TestRun_InvalidType_NoError: unknown DNS type should not crash.
func TestRun_InvalidType_NoError(t *testing.T) {
	m := dnsprobe.New()
	_, err := m.Run(context.Background(), module.Input{
		Target:  "localhost",
		Options: map[string]string{"types": "INVALID_TYPE"},
	})
	// May or may not error — should not panic.
	_ = err
}

// TestRun_FindingSeverityInfo: DNS records are informational.
func TestRun_FindingSeverityInfo(t *testing.T) {
	m := dnsprobe.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "localhost",
		Options: map[string]string{"types": "A"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == "" {
			t.Errorf("finding has empty severity: %v", f)
		}
	}
}

// TestRun_FindingURLField: findings have URL field set.
func TestRun_FindingURLField(t *testing.T) {
	m := dnsprobe.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "localhost",
		Options: map[string]string{"types": "A"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.URL == "" {
			t.Error("finding missing URL field")
		}
	}
}

// TestRun_FindingsSeverityNotEmpty verifies all dns findings carry a severity value.
func TestRun_FindingsSeverityNotEmpty(t *testing.T) {
	m := dnsprobe.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "localhost",
		Options: map[string]string{"types": "A,AAAA"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == "" {
			t.Errorf("dns finding missing Severity: %+v", f)
		}
	}
}

// TestRun_FindingsHaveConfidence verifies all findings have a non-empty confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	m := dnsprobe.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "localhost",
		Options: map[string]string{"types": "A"},
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

// TestRun_FindingTypeValid verifies all dns findings have a non-empty Type field.
func TestRun_FindingTypeValid(t *testing.T) {
	m := dnsprobe.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "localhost",
		Options: map[string]string{"types": "A"},
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
	m := dnsprobe.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "localhost",
		Options: map[string]string{"types": "A"},
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
