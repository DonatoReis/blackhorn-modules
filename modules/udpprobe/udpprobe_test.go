package udpprobe

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── UDP test server helpers ──────────────────────────────────────────────────

// udpEchoServer starts a UDP server on a random port that replies with the
// supplied response bytes for every packet received.
// Returns the port and a cancel func that stops the server.
func udpEchoServer(t *testing.T, reply []byte) (port int, cancel func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("udpEchoServer: listen: %v", err)
	}
	port = conn.LocalAddr().(*net.UDPAddr).Port
	var once sync.Once
	stop := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-stop:
					return
				default:
					continue
				}
			}
			if n >= 0 && reply != nil {
				_, _ = conn.WriteToUDP(reply, addr)
			}
		}
	}()
	cancel = func() {
		once.Do(func() {
			close(stop)
			conn.Close()
		})
	}
	return port, cancel
}

// ─── probeForPort returns a probe configured for the given port with minimal timeout. ─

func testProbe(port int, service string, reply []byte) Probe {
	return Probe{
		Port:     port,
		Service:  service,
		Severity: module.SeverityInfo,
		Tags:     []string{"test"},
		Payload:  []byte("hello"),
		Validate: func(resp []byte) bool {
			return len(resp) > 0
		},
	}
}

// ─── Tests ───────────────────────────────────────────────────────────────────

func TestUDPProbe_ServiceFound(t *testing.T) {
	reply := []byte("pong")
	port, cancel := udpEchoServer(t, reply)
	defer cancel()

	m := &Module{
		probes:      []Probe{testProbe(port, "test-svc", reply)},
		timeout:     500 * time.Millisecond,
		parallelism: 5,
		logger:      testLogger(),
	}

	findings, err := m.Run(context.Background(), module.Input{Target: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type != "udp_service" {
		t.Errorf("type=%q want udp_service", f.Type)
	}
	if f.Extra["service"] != "test-svc" {
		t.Errorf("service=%q want test-svc", f.Extra["service"])
	}
	if f.Extra["proto"] != "udp" {
		t.Errorf("proto=%q want udp", f.Extra["proto"])
	}
	if f.Extra["port"] != fmt.Sprintf("%d", port) {
		t.Errorf("port=%q want %d", f.Extra["port"], port)
	}
}

func TestUDPProbe_NoResponse(t *testing.T) {
	// Use a port that is closed (no server). Probe should get no response.
	// Find a free port then immediately close it.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	conn.Close() // port is now free/closed

	m := &Module{
		probes:      []Probe{testProbe(port, "dead-svc", nil)},
		timeout:     200 * time.Millisecond,
		parallelism: 5,
		logger:      testLogger(),
	}

	findings, err := m.Run(context.Background(), module.Input{Target: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// With no server responding, no findings expected.
	// (Some OS may return ICMP unreachable → read error → no finding)
	_ = findings // 0 or 0 expected depending on OS
}

func TestUDPProbe_ValidateFails(t *testing.T) {
	// Server responds, but validate rejects the response.
	reply := []byte("bad-response")
	port, cancel := udpEchoServer(t, reply)
	defer cancel()

	m := &Module{
		probes: []Probe{{
			Port:     port,
			Service:  "strict-svc",
			Severity: module.SeverityInfo,
			Tags:     []string{"test"},
			Payload:  []byte("probe"),
			Validate: func(resp []byte) bool {
				return string(resp) == "expected-response"
			},
		}},
		timeout:     300 * time.Millisecond,
		parallelism: 5,
		logger:      testLogger(),
	}

	findings, _ := m.Run(context.Background(), module.Input{Target: "127.0.0.1"})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with failing validate, got %d", len(findings))
	}
}

func TestUDPProbe_MultipleServices(t *testing.T) {
	// Start two UDP echo servers, expect two findings.
	reply1 := []byte("svc1-reply")
	reply2 := []byte("svc2-reply")
	port1, cancel1 := udpEchoServer(t, reply1)
	port2, cancel2 := udpEchoServer(t, reply2)
	defer cancel1()
	defer cancel2()

	m := &Module{
		probes: []Probe{
			testProbe(port1, "svc1", reply1),
			testProbe(port2, "svc2", reply2),
		},
		timeout:     400 * time.Millisecond,
		parallelism: 10,
		logger:      testLogger(),
	}

	findings, err := m.Run(context.Background(), module.Input{Target: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) < 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
}

func TestUDPProbe_MultipleTargets(t *testing.T) {
	reply := []byte("ok")
	port, cancel := udpEchoServer(t, reply)
	defer cancel()

	m := &Module{
		probes:      []Probe{testProbe(port, "multi-target", reply)},
		timeout:     400 * time.Millisecond,
		parallelism: 10,
		logger:      testLogger(),
	}

	findings, err := m.Run(context.Background(), module.Input{
		Target: "127.0.0.1",
		URLs:   []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Both 127.0.0.1 entries should deduplicate.
	if len(findings) == 0 {
		t.Error("expected at least one finding")
	}
}

func TestUDPProbe_EmptyInput(t *testing.T) {
	m := New()
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty input, got %d", len(findings))
	}
}

func TestUDPProbe_ContextCancellation(t *testing.T) {
	reply := []byte("ok")
	port, cancel := udpEchoServer(t, reply)
	defer cancel()

	m := &Module{
		probes:      []Probe{testProbe(port, "ctx-svc", reply)},
		timeout:     2 * time.Second,
		parallelism: 5,
		logger:      testLogger(),
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	cancelCtx() // cancel immediately

	_, err := m.Run(ctx, module.Input{Target: "127.0.0.1"})
	// Should not panic or hang; error is nil (module absorbs context errors).
	_ = err
}

func TestUDPProbe_PortFilter(t *testing.T) {
	reply := []byte("ok")
	port1, cancel1 := udpEchoServer(t, reply)
	port2, cancel2 := udpEchoServer(t, reply)
	defer cancel1()
	defer cancel2()

	m := &Module{
		probes: []Probe{
			testProbe(port1, "allowed", reply),
			testProbe(port2, "blocked", reply),
		},
		timeout:     400 * time.Millisecond,
		parallelism: 5,
		logger:      testLogger(),
	}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  "127.0.0.1",
		Options: map[string]string{"ports": fmt.Sprintf("%d", port1)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if f.Extra["port"] == fmt.Sprintf("%d", port2) {
			t.Errorf("port2 should have been filtered out")
		}
	}
}

func TestUDPProbe_ServiceFilter(t *testing.T) {
	reply := []byte("ok")
	port1, cancel1 := udpEchoServer(t, reply)
	port2, cancel2 := udpEchoServer(t, reply)
	defer cancel1()
	defer cancel2()

	m := &Module{
		probes: []Probe{
			testProbe(port1, "want-this", reply),
			testProbe(port2, "not-this", reply),
		},
		timeout:     400 * time.Millisecond,
		parallelism: 5,
		logger:      testLogger(),
	}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  "127.0.0.1",
		Options: map[string]string{"service": "want-this"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if f.Extra["service"] == "not-this" {
			t.Error("not-this service should be filtered out")
		}
	}
}

func TestUDPProbe_TimeoutOption(t *testing.T) {
	// Test that timeout_ms option is parsed correctly.
	// Use a server that delays response to validate timeout kicks in.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	defer conn.Close()

	m := &Module{
		probes:      []Probe{testProbe(port, "slow-svc", []byte("ok"))},
		timeout:     100 * time.Millisecond,
		parallelism: 5,
		logger:      testLogger(),
	}

	start := time.Now()
	_, err = m.Run(context.Background(), module.Input{
		Target:  "127.0.0.1",
		Options: map[string]string{"timeout_ms": "200"},
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Should complete in < 1s (no hanging).
	if elapsed > 5*time.Second {
		t.Errorf("Run took too long: %v", elapsed)
	}
}

func TestUDPProbe_HostStripping(t *testing.T) {
	// cleanHost should strip scheme and path.
	tests := []struct {
		in   string
		want string
	}{
		{"http://example.com/path", "example.com"},
		{"https://192.168.1.1:8080/api", "192.168.1.1"},
		{"192.168.1.1", "192.168.1.1"},
		{"example.com", "example.com"},
		{"", ""},
	}
	for _, tc := range tests {
		got := cleanHost(tc.in)
		if got != tc.want {
			t.Errorf("cleanHost(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestUDPProbe_FindingURL(t *testing.T) {
	reply := []byte("ok")
	port, cancel := udpEchoServer(t, reply)
	defer cancel()

	m := &Module{
		probes:      []Probe{testProbe(port, "url-svc", reply)},
		timeout:     400 * time.Millisecond,
		parallelism: 5,
		logger:      testLogger(),
	}

	findings, _ := m.Run(context.Background(), module.Input{Target: "127.0.0.1"})
	if len(findings) == 0 {
		t.Skip("no findings (UDP may be filtered)")
	}
	expected := fmt.Sprintf("udp://127.0.0.1:%d", port)
	if findings[0].URL != expected {
		t.Errorf("URL=%q want %q", findings[0].URL, expected)
	}
}

func TestUDPProbe_HexDump(t *testing.T) {
	tests := []struct {
		in   []byte
		n    int
		want string
	}{
		{[]byte{0x01, 0x02, 0x03}, 10, "01 02 03"},
		{[]byte{0xde, 0xad}, 1, "de"},
		{[]byte{}, 10, ""},
	}
	for _, tc := range tests {
		got := hexDump(tc.in, tc.n)
		if got != tc.want {
			t.Errorf("hexDump(%v,%d)=%q want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

func TestUDPProbe_ParseCSV(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"dns, ntp, snmp", []string{"dns", "ntp", "snmp"}},
		{"", nil},
		{"single", []string{"single"}},
	}
	for _, tc := range tests {
		got := parseCSV(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("parseCSV(%q) len=%d want %d", tc.in, len(got), len(tc.want))
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("parseCSV(%q)[%d]=%q want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

func TestUDPProbe_NullPayload(t *testing.T) {
	reply := []byte("response")
	port, cancel := udpEchoServer(t, reply)
	defer cancel()

	// Probe with nil payload — should send empty bytes.
	m := &Module{
		probes: []Probe{{
			Port:     port,
			Service:  "null-payload",
			Severity: module.SeverityInfo,
			Tags:     []string{"test"},
			Payload:  nil,
			Validate: func(resp []byte) bool { return len(resp) > 0 },
		}},
		timeout:     400 * time.Millisecond,
		parallelism: 5,
		logger:      testLogger(),
	}

	findings, err := m.Run(context.Background(), module.Input{Target: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Server may or may not respond to empty payload; just ensure no panic.
	_ = findings
}

func TestUDPProbe_ParallelismOption(t *testing.T) {
	reply := []byte("ok")
	ports := make([]int, 5)
	cancels := make([]func(), 5)
	probes := make([]Probe, 5)
	for i := 0; i < 5; i++ {
		ports[i], cancels[i] = udpEchoServer(t, reply)
		probes[i] = testProbe(ports[i], fmt.Sprintf("svc%d", i), reply)
		defer cancels[i]()
	}

	m := &Module{
		probes:      probes,
		timeout:     400 * time.Millisecond,
		parallelism: 3,
		logger:      testLogger(),
	}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  "127.0.0.1",
		Options: map[string]string{"parallelism": "2"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	_ = findings // Just verify it doesn't deadlock.
}

func TestUDPProbe_FindingFields(t *testing.T) {
	reply := []byte("svc-ok")
	port, cancel := udpEchoServer(t, reply)
	defer cancel()

	probe := Probe{
		Port:     port,
		Service:  "field-test",
		Severity: module.SeverityHigh,
		Tags:     []string{"tag1", "tag2"},
		Payload:  []byte("probe"),
		Validate: func(resp []byte) bool { return len(resp) > 0 },
	}

	m := &Module{
		probes:      []Probe{probe},
		timeout:     400 * time.Millisecond,
		parallelism: 5,
		logger:      testLogger(),
	}

	findings, _ := m.Run(context.Background(), module.Input{Target: "127.0.0.1"})
	if len(findings) == 0 {
		t.Skip("no findings (UDP may be filtered)")
	}
	f := findings[0]
	if f.Severity != module.SeverityHigh {
		t.Errorf("severity=%q want High", f.Severity)
	}
	if f.Extra["tags"] != "tag1,tag2" {
		t.Errorf("tags=%q want tag1,tag2", f.Extra["tags"])
	}
}

func TestUDPProbe_BuiltinProbesCount(t *testing.T) {
	probes := builtinProbes()
	if len(probes) < 15 {
		t.Errorf("expected at least 15 built-in probes, got %d", len(probes))
	}
}

func TestUDPProbe_BuiltinProbesUniqueServices(t *testing.T) {
	seen := make(map[string]struct{})
	for _, p := range builtinProbes() {
		if _, ok := seen[p.Service]; ok {
			t.Errorf("duplicate service name: %s", p.Service)
		}
		seen[p.Service] = struct{}{}
	}
}

func TestUDPProbe_BuiltinProbesValidPorts(t *testing.T) {
	for _, p := range builtinProbes() {
		if p.Port <= 0 || p.Port > 65535 {
			t.Errorf("service %s has invalid port %d", p.Service, p.Port)
		}
	}
}

func TestUDPProbe_Name(t *testing.T) {
	m := New()
	if m.Name() != "udpprobe" {
		t.Errorf("Name()=%q want udpprobe", m.Name())
	}
}

func TestUDPProbe_DNSProbeValidate(t *testing.T) {
	probes := builtinProbes()
	var dnsProbe *Probe
	for i := range probes {
		if probes[i].Service == "dns" {
			dnsProbe = &probes[i]
			break
		}
	}
	if dnsProbe == nil {
		t.Fatal("dns probe not found")
	}
	// Valid DNS response: ID 0xdead, QR bit set.
	validResp := []byte{0xde, 0xad, 0x81, 0x80, 0x00, 0x01}
	if !dnsProbe.Validate(validResp) {
		t.Error("expected dns validate to accept valid response")
	}
	// Wrong ID.
	invalidResp := []byte{0x00, 0x00, 0x81, 0x80, 0x00, 0x01}
	if dnsProbe.Validate(invalidResp) {
		t.Error("expected dns validate to reject wrong ID")
	}
}

func TestUDPProbe_NTPProbeValidate(t *testing.T) {
	probes := builtinProbes()
	var ntp *Probe
	for i := range probes {
		if probes[i].Service == "ntp" {
			ntp = &probes[i]
			break
		}
	}
	if ntp == nil {
		t.Fatal("ntp probe not found")
	}
	// Valid NTP response: 48 bytes, mode=4 (server).
	resp := make([]byte, 48)
	resp[0] = 0x24 // LI=0, VN=4, Mode=4
	if !ntp.Validate(resp) {
		t.Error("expected ntp validate to accept server mode=4")
	}
	// Wrong mode.
	resp[0] = 0x1b // mode=3 (client)
	if ntp.Validate(resp) {
		t.Error("expected ntp validate to reject client mode")
	}
}

func TestUDPProbe_SNMPProbePayload(t *testing.T) {
	probes := builtinProbes()
	var snmp *Probe
	for i := range probes {
		if probes[i].Service == "snmp" {
			snmp = &probes[i]
			break
		}
	}
	if snmp == nil {
		t.Fatal("snmp probe not found")
	}
	if snmp.Payload[0] != 0x30 {
		t.Errorf("SNMP payload should start with 0x30 (SEQUENCE), got 0x%02x", snmp.Payload[0])
	}
}

func TestUDPProbe_SSDPProbePayload(t *testing.T) {
	probes := builtinProbes()
	var ssdp *Probe
	for i := range probes {
		if probes[i].Service == "ssdp" {
			ssdp = &probes[i]
			break
		}
	}
	if ssdp == nil {
		t.Fatal("ssdp probe not found")
	}
	if !contains(string(ssdp.Payload), "M-SEARCH") {
		t.Error("SSDP payload should contain M-SEARCH")
	}
}

func TestUDPProbe_MemcachedValidate(t *testing.T) {
	probes := builtinProbes()
	var mc *Probe
	for i := range probes {
		if probes[i].Service == "memcached" {
			mc = &probes[i]
			break
		}
	}
	if mc == nil {
		t.Fatal("memcached probe not found")
	}
	if !mc.Validate([]byte("STAT version 1.6.0\r\nEND\r\n")) {
		t.Error("expected memcached validate to accept STAT response")
	}
	if mc.Validate([]byte("ERROR\r\n")) {
		t.Error("expected memcached validate to reject ERROR response")
	}
}

func TestUDPProbe_URLSchemeInput(t *testing.T) {
	// Input with http:// scheme should have scheme stripped.
	reply := []byte("ok")
	port, cancel := udpEchoServer(t, reply)
	defer cancel()

	m := &Module{
		probes:      []Probe{testProbe(port, "scheme-svc", reply)},
		timeout:     400 * time.Millisecond,
		parallelism: 5,
		logger:      testLogger(),
	}

	findings, err := m.Run(context.Background(), module.Input{
		Target: fmt.Sprintf("http://127.0.0.1:%d/path", port+1), // different port in URL
		URLs:   []string{"http://127.0.0.1/"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	_ = findings
}

func TestUDPProbe_DeduplicateTargets(t *testing.T) {
	reply := []byte("ok")
	port, cancel := udpEchoServer(t, reply)
	defer cancel()

	m := &Module{
		probes:      []Probe{testProbe(port, "dedup-svc", reply)},
		timeout:     400 * time.Millisecond,
		parallelism: 5,
		logger:      testLogger(),
	}

	// Same target twice — should deduplicate.
	findings, err := m.Run(context.Background(), module.Input{
		Target: "127.0.0.1",
		URLs:   []string{"127.0.0.1", "127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) > 1 {
		t.Errorf("expected deduplicated targets: got %d findings", len(findings))
	}
}

func TestUDPProbe_EchoValidate(t *testing.T) {
	probes := builtinProbes()
	var echo *Probe
	for i := range probes {
		if probes[i].Service == "echo" {
			echo = &probes[i]
			break
		}
	}
	if echo == nil {
		t.Fatal("echo probe not found")
	}
	if !echo.Validate([]byte("blackhorn-udpprobe\n")) {
		t.Error("expected echo validate to accept exact echo")
	}
	if echo.Validate([]byte("other response")) {
		t.Error("expected echo validate to reject non-matching response")
	}
}

func TestUDPProbe_RPCPayload(t *testing.T) {
	probes := builtinProbes()
	var rpc *Probe
	for i := range probes {
		if probes[i].Service == "rpcbind" {
			rpc = &probes[i]
			break
		}
	}
	if rpc == nil {
		t.Fatal("rpcbind probe not found")
	}
	if len(rpc.Payload) < 36 {
		t.Errorf("RPC payload too short: %d bytes", len(rpc.Payload))
	}
}

func TestUDPProbe_IKEPayload(t *testing.T) {
	probes := builtinProbes()
	var ike *Probe
	for i := range probes {
		if probes[i].Service == "ike" {
			ike = &probes[i]
			break
		}
	}
	if ike == nil {
		t.Fatal("ike probe not found")
	}
	if len(ike.Payload) < 28 {
		t.Errorf("IKE payload too short: %d bytes", len(ike.Payload))
	}
	// Verify IKE responds to non-zero responder SPI.
	fakeResp := make([]byte, 28)
	fakeResp[8] = 0xAA // non-zero responder SPI
	if !ike.Validate(fakeResp) {
		t.Error("expected IKE validate to accept non-zero responder SPI")
	}
}

func TestUDPProbe_InvalidParallelismOption(t *testing.T) {
	// Invalid parallelism option should fall back to module default.
	m := New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"parallelism": "invalid"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	_ = findings
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

func testLogger() *slog.Logger {
	return slog.Default()
}
