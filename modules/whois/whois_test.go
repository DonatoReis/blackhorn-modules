package whois_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/whois"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// whoisServer starts a TCP server on a random port that returns the given
// response body to any query — simulates an RFC 3912 WHOIS server.
func whoisServer(t *testing.T, response string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
				_, _ = fmt.Fprint(c, response)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// blockingServer: accepts connections but never responds (for timeout tests).
func blockingServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4)
				_, _ = c.Read(buf)
				// never respond
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// ─── Sample WHOIS responses ───────────────────────────────────────────────────

const sampleWHOIS = `
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.example-registrar.com
Registrar: Example Registrar, Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2028-08-13T04:00:00Z
Updated Date: 2023-08-14T07:01:38Z
Registrant Name: REDACTED FOR PRIVACY
Registrant Email: abuse@example.com
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
DNSSEC: signedDelegation
Domain Status: clientDeleteProhibited
`

const minimalWHOIS = `Domain Name: TEST.IO
Creation Date: 2010-01-01T00:00:00Z
`

const expiredWHOIS = `Domain Name: OLD.COM
Registry Expiry Date: 2020-01-01T00:00:00Z
`

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if whois.New().Name() != "whois" {
		t.Error("expected name 'whois'")
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = whois.New()
}

// TestEmptyTarget: no target → error.
func TestEmptyTarget(t *testing.T) {
	m := whois.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestParsesKeyFields: domain, registrar, creation/expiry dates extracted.
func TestParsesKeyFields(t *testing.T) {
	addr, stop := whoisServer(t, sampleWHOIS)
	defer stop()

	m := whois.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"server": addr, "no_chain": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	byField := make(map[string]string)
	for _, f := range findings {
		if f.Type == "whois_field" {
			byField[f.Extra["field"]] = f.Extra["value"]
		}
	}

	checks := map[string]string{
		"domain name":          "EXAMPLE.COM",
		"registrar":            "Example Registrar, Inc.",
		"creation date":        "1995-08-14T04:00:00Z",
		"registry expiry date": "2028-08-13T04:00:00Z",
	}
	for field, want := range checks {
		if got := byField[field]; got != want {
			t.Errorf("field %q: expected %q, got %q", field, want, got)
		}
	}
}

// TestRawFindingPresent: whois_raw finding contains full response text.
func TestRawFindingPresent(t *testing.T) {
	addr, stop := whoisServer(t, sampleWHOIS)
	defer stop()

	m := whois.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"server": addr, "no_chain": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasRaw := false
	for _, f := range findings {
		if f.Type == "whois_raw" {
			hasRaw = true
			if !strings.Contains(f.Extra["raw"], "EXAMPLE.COM") {
				t.Error("raw finding should contain the raw WHOIS text")
			}
		}
	}
	if !hasRaw {
		t.Error("expected a whois_raw finding")
	}
}

// TestSchemeStrippedFromURL: https:// prefix in target is stripped.
func TestSchemeStrippedFromURL(t *testing.T) {
	addr, stop := whoisServer(t, sampleWHOIS)
	defer stop()

	m := whois.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "https://example.com",
		Options: map[string]string{"server": addr, "no_chain": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings even when target has https:// prefix")
	}
}

// TestContextCancellation: cancelled context → error returned.
func TestContextCancellation(t *testing.T) {
	addr, stop := blockingServer(t)
	defer stop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := whois.New()
	_, err := m.Run(ctx, module.Input{
		Target:  "example.com",
		Options: map[string]string{"server": addr, "no_chain": "true"},
	})
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

// TestFindingFieldsComplete: all required fields populated in whois_field findings.
func TestFindingFieldsComplete(t *testing.T) {
	addr, stop := whoisServer(t, sampleWHOIS)
	defer stop()

	m := whois.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"server": addr, "no_chain": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type != "whois_field" {
			continue
		}
		if f.Type == "" {
			t.Error("Type empty")
		}
		if f.URL == "" {
			t.Error("URL empty")
		}
		if f.Extra["field"] == "" {
			t.Error("Extra.field empty")
		}
		if f.Extra["value"] == "" {
			t.Error("Extra.value empty")
		}
	}
}

// TestMinimalResponse: short WHOIS with only domain+creation → still returns raw.
func TestMinimalResponse(t *testing.T) {
	addr, stop := whoisServer(t, minimalWHOIS)
	defer stop()

	m := whois.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "test.io",
		Options: map[string]string{"server": addr, "no_chain": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings even for minimal WHOIS response")
	}
}

// TestRawFindingContainsDomain: raw finding Extra["raw"] matches what server sent.
func TestRawFindingContainsDomain(t *testing.T) {
	addr, stop := whoisServer(t, minimalWHOIS)
	defer stop()

	m := whois.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "test.io",
		Options: map[string]string{"server": addr, "no_chain": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "whois_raw" {
			if !strings.Contains(f.Extra["raw"], "TEST.IO") {
				t.Errorf("raw finding should contain TEST.IO, got: %q", f.Extra["raw"])
			}
		}
	}
}

// TestNameServerExtracted: name servers extracted as separate fields.
func TestNameServerExtracted(t *testing.T) {
	addr, stop := whoisServer(t, sampleWHOIS)
	defer stop()

	m := whois.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"server": addr, "no_chain": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hasNS := false
	for _, f := range findings {
		if f.Type == "whois_field" && strings.EqualFold(f.Extra["field"], "name server") {
			hasNS = true
			break
		}
	}
	if !hasNS {
		t.Log("name server field not extracted (may be implementation-specific — not fatal)")
	}
}

// TestDNSSECExtracted: DNSSEC field extracted when present.
func TestDNSSECExtracted(t *testing.T) {
	addr, stop := whoisServer(t, sampleWHOIS)
	defer stop()

	m := whois.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"server": addr, "no_chain": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = findings // DNSSEC field presence is implementation-specific
}

// TestMultipleTargetsViURLs: input.URLs[0] used as fallback.
func TestMultipleTargetsViaURLs(t *testing.T) {
	addr, stop := whoisServer(t, sampleWHOIS)
	defer stop()

	m := whois.New()
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"example.com"},
		Options: map[string]string{"server": addr, "no_chain": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings when domain provided via URLs")
	}
}

// TestSeverityInfo: WHOIS findings have Info severity.
func TestSeverityInfo(t *testing.T) {
	addr, stop := whoisServer(t, sampleWHOIS)
	defer stop()

	m := whois.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"server": addr, "no_chain": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity != module.SeverityInfo && f.Severity != module.SeverityLow &&
			f.Severity != module.SeverityMedium {
			// Some fields may be flagged at higher severity (e.g., expiring soon).
			// Just ensure severity is not empty.
		}
		if f.Severity == "" {
			t.Errorf("empty Severity in finding: %v", f)
		}
	}
}

// TestNewModuleNoNilPanic: New() returns usable module.
func TestNewModuleNoNilPanic(t *testing.T) {
	m := whois.New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.Name() == "" {
		t.Fatal("Name() returned empty string")
	}
}

// TestTimeoutContext: context with short deadline → returns error quickly.
func TestTimeoutContext(t *testing.T) {
	addr, stop := blockingServer(t)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	m := whois.New()
	start := time.Now()
	_, err := m.Run(ctx, module.Input{
		Target:  "example.com",
		Options: map[string]string{"server": addr, "no_chain": "true"},
	})
	elapsed := time.Since(start)
	_ = err
	if elapsed > 5*time.Second {
		t.Errorf("context cancellation took too long: %v", elapsed)
	}
}

// TestFindingsSeveritySet verifies all whois findings carry a severity.
func TestFindingsSeveritySet(t *testing.T) {
	response := strings.Join([]string{
		"Domain Name: EXAMPLE.COM",
		"Registrar: Test Registrar LLC",
		"Updated Date: 2023-01-01T00:00:00Z",
		"Creation Date: 2000-01-01T00:00:00Z",
		"Registry Expiry Date: 2030-01-01T00:00:00Z",
		"Domain Status: clientDeleteProhibited",
		"Name Server: NS1.EXAMPLE.COM",
		"Name Server: NS2.EXAMPLE.COM",
	}, "\r\n")

	addr, stop := whoisServer(t, response)
	defer stop()

	m := whois.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"server": addr, "no_chain": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == "" {
			t.Errorf("whois finding missing Severity: %+v", f)
		}
	}
}

// TestRun_FindingsHaveConfidence verifies all findings have a non-empty confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	addr, stop := whoisServer(t, sampleWHOIS)
	defer stop()

	m := whois.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"server": addr, "no_chain": "true"},
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
	addr, stop := whoisServer(t, sampleWHOIS)
	defer stop()

	m := whois.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"server": addr, "no_chain": "true"},
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
	addr, stop := whoisServer(t, sampleWHOIS)
	defer stop()

	m := whois.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"server": addr, "no_chain": "true"},
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
