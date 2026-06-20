package interactsh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func hasType(findings []module.Finding, t string) bool {
	for _, f := range findings {
		if f.Type == t {
			return true
		}
	}
	return false
}

func hasKind(findings []module.Finding, kind string) bool {
	for _, f := range findings {
		if f.Extra["payload_kind"] == kind || f.Extra["kind"] == kind {
			return true
		}
	}
	return false
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// ─── basic ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New("example.com").Name() != "interactsh" {
		t.Fatal("wrong name")
	}
}

func TestCorrelationID_Generated(t *testing.T) {
	m1 := New("x.com")
	m2 := New("x.com")
	if m1.CorrelationID == m2.CorrelationID {
		t.Fatal("expected unique correlation IDs per instance")
	}
	if len(m1.CorrelationID) != correlationIDLen*2 {
		t.Fatalf("expected %d hex chars, got %d", correlationIDLen*2, len(m1.CorrelationID))
	}
}

// ─── payload generation ───────────────────────────────────────────────────────

func TestRun_PayloadFindings(t *testing.T) {
	m := New("oob.example.com")
	findings, err := m.Run(context.Background(), module.Input{Target: "victim.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "oob_payload") {
		t.Fatal("expected oob_payload findings")
	}
	// Check correlation ID is embedded.
	for _, f := range findings {
		if f.Type == "oob_payload" {
			if f.Extra["correlation_id"] != m.CorrelationID {
				t.Errorf("expected correlation_id=%s in payload, got %q", m.CorrelationID, f.Extra["correlation_id"])
			}
			if !strings.Contains(f.URL, m.CorrelationID) {
				t.Errorf("expected correlation ID in payload URL %q", f.URL)
			}
		}
	}
}

func TestRun_PayloadKinds(t *testing.T) {
	m := New("oob.example.com")
	findings, err := m.Run(context.Background(), module.Input{Target: "test.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasKind(findings, string(KindHTTP)) {
		t.Fatal("expected http payload")
	}
	if !hasKind(findings, string(KindDNS)) {
		t.Fatal("expected dns payload")
	}
	if !hasKind(findings, string(KindSMTP)) {
		t.Fatal("expected smtp payload")
	}
	if !hasKind(findings, string(KindLDAP)) {
		t.Fatal("expected ldap payload")
	}
}

func TestGeneratePayloads_ContainsBase(t *testing.T) {
	m := New("my-oob.example.com")
	payloads := m.generatePayloads("victim.com")
	for _, p := range payloads {
		if !strings.Contains(p.URL, "my-oob.example.com") {
			t.Errorf("expected base domain in payload URL %q", p.URL)
		}
	}
}

func TestGeneratePayloads_NoTarget(t *testing.T) {
	m := New("x.com")
	payloads := m.generatePayloads("")
	// Should still generate HTTP and DNS payloads without target.
	if len(payloads) == 0 {
		t.Fatal("expected at least one payload even without target")
	}
}

func TestGeneratePayloads_LDAPPayload(t *testing.T) {
	m := New("x.com")
	m.CorrelationID = "deadbeefcafebabe" // controlled value for test
	payloads := m.generatePayloads("victim.com")
	found := false
	for _, p := range payloads {
		if p.Kind == KindLDAP && strings.HasPrefix(p.URL, "ldap://") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected LDAP payload")
	}
}

func TestPayloadDomain_Fallback(t *testing.T) {
	m := New("")
	m.ServerURL = "https://interact.sh"
	domain := m.payloadDomain()
	if domain != "interact.sh" {
		t.Errorf("expected interact.sh, got %q", domain)
	}
}

// ─── interaction store ────────────────────────────────────────────────────────

func TestRecordInteraction(t *testing.T) {
	m := New("x.com")
	m.RecordInteraction(Interaction{
		CorrelationID: "testcid",
		Kind:          KindHTTP,
		RemoteAddr:    "1.2.3.4:12345",
		Timestamp:     time.Now(),
		UniqueID:      "uid1",
	})
	if !m.HasInteraction("testcid") {
		t.Fatal("expected stored interaction to be found")
	}
}

func TestClearInteractions(t *testing.T) {
	m := New("x.com")
	m.RecordInteraction(Interaction{CorrelationID: "cid1"})
	m.ClearInteractions()
	if len(m.Interactions()) != 0 {
		t.Fatal("expected empty interactions after Clear")
	}
}

func TestInteractions_ReturnsCopy(t *testing.T) {
	m := New("x.com")
	m.RecordInteraction(Interaction{CorrelationID: "cid1"})
	copy1 := m.Interactions()
	copy1[0].CorrelationID = "mutated"
	copy2 := m.Interactions()
	if copy2[0].CorrelationID == "mutated" {
		t.Fatal("Interactions() should return a copy, not a reference")
	}
}

func TestRun_InteractionFindings(t *testing.T) {
	m := New("x.com")
	m.RecordInteraction(Interaction{
		CorrelationID: m.CorrelationID,
		Kind:          KindHTTP,
		RemoteAddr:    "10.0.0.1:80",
		Timestamp:     time.Now(),
		UniqueID:      "uid",
	})

	findings, err := m.Run(context.Background(), module.Input{Target: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "oob_interaction") {
		t.Fatal("expected oob_interaction finding")
	}
	for _, f := range findings {
		if f.Type == "oob_interaction" {
			if f.Severity != module.SeverityHigh {
				t.Errorf("expected High severity for HTTP interaction, got %q", f.Severity)
			}
		}
	}
}

func TestRun_DNSInteraction_LowSeverity(t *testing.T) {
	m := New("x.com")
	m.RecordInteraction(Interaction{
		CorrelationID: m.CorrelationID,
		Kind:          KindDNS,
		RemoteAddr:    "8.8.8.8:53",
		Timestamp:     time.Now(),
	})

	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Type == "oob_interaction" && f.Extra["kind"] == string(KindDNS) {
			if f.Severity != module.SeverityLow {
				t.Errorf("expected Low severity for DNS interaction, got %q", f.Severity)
			}
		}
	}
}

// ─── HTTP listener (self-hosted) ─────────────────────────────────────────────

func TestListen_ReceivesHTTPInteraction(t *testing.T) {
	addr := freePort(t)
	m := New("x.com")
	if err := m.Listen(addr); err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	defer m.Stop()

	// Send HTTP request to the listener.
	resp, err := http.Get("http://" + addr + "/test?q=1")
	if err != nil {
		t.Fatalf("HTTP request to interactsh listener: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	time.Sleep(50 * time.Millisecond)
	if len(m.Interactions()) == 0 {
		t.Fatal("expected at least one interaction after HTTP request")
	}
	interaction := m.Interactions()[0]
	if interaction.Kind != KindHTTP {
		t.Errorf("expected KindHTTP, got %v", interaction.Kind)
	}
}

func TestListen_RecordsFindingOnPoll(t *testing.T) {
	addr := freePort(t)
	m := New("x.com")
	if err := m.Listen(addr); err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	defer m.Stop()

	// Trigger an interaction.
	go func() {
		time.Sleep(20 * time.Millisecond)
		http.Get("http://" + addr + "/callback")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Run with 1 second poll but short context.
	findings, _ := m.Run(ctx, module.Input{
		Options: map[string]string{"poll_seconds": "1"},
	})
	// Should contain oob_payload findings at minimum.
	if !hasType(findings, "oob_payload") {
		t.Fatal("expected oob_payload findings")
	}
}

// ─── DNS listener ────────────────────────────────────────────────────────────

func TestListenDNS_ReceivesDNSInteraction(t *testing.T) {
	// Find a free UDP port.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsAddr := pc.LocalAddr().String()
	pc.Close()

	m := New("x.com")
	if err := m.ListenDNS(dnsAddr); err != nil {
		t.Fatalf("ListenDNS error: %v", err)
	}
	defer m.Stop()

	// Send a fake UDP DNS packet.
	conn, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte{0x00, 0x01, 0x00, 0x00}) // minimal DNS-like bytes

	time.Sleep(50 * time.Millisecond)
	if len(m.Interactions()) == 0 {
		t.Fatal("expected DNS interaction to be recorded")
	}
	if m.Interactions()[0].Kind != KindDNS {
		t.Errorf("expected KindDNS, got %v", m.Interactions()[0].Kind)
	}
}

// ─── remote poll ──────────────────────────────────────────────────────────────

func TestPollRemote_StoresInteractions(t *testing.T) {
	// Mock interact.sh-compatible poll endpoint.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(interactshPollResponse{
			Data: []string{"eyJkYXRhIjoidGVzdCJ9", "eyJkYXRhIjoidGVzdDIifQ=="},
		})
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client(), "")
	m.ServerURL = srv.URL
	m.CorrelationID = "abcdef1234567890"

	if err := m.pollRemote(context.Background()); err != nil {
		t.Fatalf("pollRemote error: %v", err)
	}
	if len(m.Interactions()) != 2 {
		t.Fatalf("expected 2 interactions from poll, got %d", len(m.Interactions()))
	}
}

func TestPollRemote_HTTP500_Error(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client(), "")
	m.ServerURL = srv.URL
	err := m.pollRemote(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 500 poll response")
	}
}

// ─── correlation ID extraction ────────────────────────────────────────────────

func TestExtractCorrelationID_FromHost(t *testing.T) {
	// 8 bytes = 16 hex chars.
	cid := "deadbeefcafebabe"
	host := fmt.Sprintf("%s.oob.example.com", cid)
	got := extractCorrelationID(host, "fallback")
	if got != cid {
		t.Errorf("expected %q, got %q", cid, got)
	}
}

func TestExtractCorrelationID_Fallback(t *testing.T) {
	got := extractCorrelationID("unknown.host.example.com", "fallback")
	if got != "fallback" {
		t.Errorf("expected fallback, got %q", got)
	}
}

func TestExtractCorrelationID_WithPort(t *testing.T) {
	cid := "deadbeefcafebabe"
	host := fmt.Sprintf("%s.oob.example.com:8080", cid)
	got := extractCorrelationID(host, "fallback")
	if got != cid {
		t.Errorf("expected %q, got %q", cid, got)
	}
}

// ─── Options override ────────────────────────────────────────────────────────

func TestRun_ServerURLOverride(t *testing.T) {
	m := New("original.com")
	m.Run(context.Background(), module.Input{
		Options: map[string]string{"server_url": "https://custom.interact.sh"},
	})
	if m.ServerURL != "https://custom.interact.sh" {
		t.Errorf("expected ServerURL to be overridden, got %q", m.ServerURL)
	}
}

func TestRun_CorrelationIDOverride(t *testing.T) {
	m := New("x.com")
	m.Run(context.Background(), module.Input{
		Options: map[string]string{"correlation_id": "customcid1234567"},
	})
	if m.CorrelationID != "customcid1234567" {
		t.Errorf("expected CorrelationID=customcid1234567, got %q", m.CorrelationID)
	}
}
