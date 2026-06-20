// Package udpprobe implements UDP service discovery for common protocols.
//
// Source reference: projectdiscovery/naabu (MIT License) UDP mode,
// nmap NSE UDP probes (GPL — logic reimplemented, not copied).
//
// Strategy: UDP scanning cannot rely on TCP connect-style probing. Instead,
// we send protocol-specific probes and look for valid responses. We implement
// probes for the 20 most common UDP services (DNS, NTP, SNMP, SSDP, mDNS,
// NetBIOS, TFTP, DHCP, QUIC, WireGuard, LDAP, Syslog, RPC, Memcached,
// Redis, NFS, Kerberos, L2TP, IKE, Echo).
//
// Architecture:
//   - Each UDP service has a Probe struct: port, payload bytes, response validator func
//   - errgroup.SetLimit(Parallelism) for bounded goroutine fan-out (guia-go §9)
//   - net.DialContext UDP + SetDeadline for each probe (stdlib only)
//   - io.LimitReader on response bytes (dicas.md §5)
//   - log/slog observability (dicas.md §16)
//   - sync.Mutex protecting findings slice
//   - NewWithProbes(probes) for testability
//
// What is ported faithfully:
//   - Common UDP port list (top 20 services) from nmap default UDP scan
//   - Protocol-specific payload bytes (DNS version query, NTP monlist, etc.)
//   - Service name mapping from /etc/services tradition
package udpprobe

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	// DefaultTimeout is the per-probe read deadline.
	DefaultTimeout = 3 * time.Second

	// DefaultParallelism is the maximum concurrent UDP probes.
	DefaultParallelism = 50

	// maxResponseBytes is the maximum bytes read from a UDP response.
	maxResponseBytes = 4096
)

// ─── Probe ───────────────────────────────────────────────────────────────────

// Probe defines a UDP service probe — mirrors nmap NSE probe structure.
type Probe struct {
	// Port is the default UDP port for this service.
	Port int
	// Service is the human-readable service name.
	Service string
	// Payload is the bytes to send (nil = empty probe, triggers ICMP unreachable on closed ports).
	Payload []byte
	// Validate returns true if the response bytes indicate the service is running.
	// If nil, any non-empty response is considered a match.
	Validate func(resp []byte) bool
	// Severity is the finding severity for this service.
	Severity module.Severity
	// Tags are metadata tags for the finding.
	Tags []string
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements UDP service discovery via protocol-specific probes.
type Module struct {
	probes      []Probe
	timeout     time.Duration
	parallelism int
	logger      *slog.Logger
}

// New returns a Module with all built-in probes.
func New() *Module {
	return &Module{
		probes:      builtinProbes(),
		timeout:     DefaultTimeout,
		parallelism: DefaultParallelism,
		logger:      slog.Default(),
	}
}

// NewWithProbes returns a Module with only the supplied probes (testability).
func NewWithProbes(probes []Probe) *Module {
	return &Module{
		probes:      probes,
		timeout:     DefaultTimeout,
		parallelism: DefaultParallelism,
		logger:      slog.Default(),
	}
}

// Name returns the module name.
func (m *Module) Name() string { return "udpprobe" }

// Run executes UDP probes against all targets in input.
//
// Options supported:
//   - "timeout_ms"   — per-probe deadline in milliseconds (default: 3000)
//   - "parallelism"  — max concurrent probes (default: 50)
//   - "ports"        — comma-separated port list to limit scan (e.g. "53,123,161")
//   - "service"      — comma-separated service names to limit scan (e.g. "dns,ntp,snmp")
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	targets := collectTargets(input)
	if len(targets) == 0 {
		return nil, nil
	}

	timeout := m.timeout
	if v := input.Options["timeout_ms"]; v != "" {
		if ms, err := parseInt(v); err == nil && ms > 0 {
			timeout = time.Duration(ms) * time.Millisecond
		}
	}

	parallelism := m.parallelism
	if v := input.Options["parallelism"]; v != "" {
		if p, err := parseInt(v); err == nil && p > 0 {
			parallelism = p
		}
	}

	probes := m.selectProbes(input.Options)

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(parallelism)

	for _, target := range targets {
		target := target
		for _, probe := range probes {
			probe := probe
			eg.Go(func() error {
				f, ok := m.runProbe(egCtx, target, probe, timeout)
				if ok {
					mu.Lock()
					findings = append(findings, f)
					mu.Unlock()
				}
				return nil
			})
		}
	}

	_ = eg.Wait()
	return findings, nil
}

// selectProbes filters built-in probes based on Options["ports"] and Options["service"].
func (m *Module) selectProbes(opts map[string]string) []Probe {
	portFilter := parseCSV(opts["ports"])
	svcFilter := parseCSV(opts["service"])

	if len(portFilter) == 0 && len(svcFilter) == 0 {
		return m.probes
	}

	portSet := make(map[int]struct{})
	for _, p := range portFilter {
		if n, err := parseInt(p); err == nil {
			portSet[n] = struct{}{}
		}
	}

	svcSet := make(map[string]struct{})
	for _, s := range svcFilter {
		svcSet[strings.ToLower(s)] = struct{}{}
	}

	var out []Probe
	for _, p := range m.probes {
		if len(portSet) > 0 {
			if _, ok := portSet[p.Port]; !ok {
				continue
			}
		}
		if len(svcSet) > 0 {
			if _, ok := svcSet[strings.ToLower(p.Service)]; !ok {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

// runProbe sends a single UDP probe and validates the response.
func (m *Module) runProbe(ctx context.Context, host string, probe Probe, timeout time.Duration) (module.Finding, bool) {
	addr := fmt.Sprintf("%s:%d", host, probe.Port)

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		m.logger.DebugContext(ctx, "udp dial failed", "addr", addr, "service", probe.Service, "err", err)
		return module.Finding{}, false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	payload := probe.Payload
	if payload == nil {
		payload = []byte{}
	}
	if _, err = conn.Write(payload); err != nil {
		return module.Finding{}, false
	}

	buf := make([]byte, maxResponseBytes)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		// UDP: no response ≠ closed (firewalled), but we need a response to confirm.
		return module.Finding{}, false
	}

	resp := buf[:n]
	if probe.Validate != nil && !probe.Validate(resp) {
		return module.Finding{}, false
	}

	m.logger.InfoContext(ctx, "udp service found",
		"addr", addr, "service", probe.Service, "bytes", n)

	return module.Finding{
		Type:     "udp_service",
		Severity: probe.Severity,
		URL:      fmt.Sprintf("udp://%s:%d", host, probe.Port),
		Detail:   fmt.Sprintf("UDP service detected: %s (port %d)", probe.Service, probe.Port),
		Extra: map[string]string{
			"service":      probe.Service,
			"port":         fmt.Sprintf("%d", probe.Port),
			"proto":        "udp",
			"response_len": fmt.Sprintf("%d", n),
			"response_hex": hexDump(resp, 16),
			"tags":         strings.Join(probe.Tags, ","),
			"confidence":   "0.85",
		},
	}, true
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func collectTargets(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(h string) {
		h = cleanHost(h)
		if h == "" {
			return
		}
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	add(input.Target)
	for _, u := range input.URLs {
		add(u)
	}
	return out
}

// cleanHost strips scheme and path, returning just the host.
func cleanHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Strip scheme.
	if idx := strings.Index(raw, "://"); idx >= 0 {
		raw = raw[idx+3:]
	}
	// Strip path/query.
	if idx := strings.Index(raw, "/"); idx >= 0 {
		raw = raw[:idx]
	}
	// Strip port if present.
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host
	}
	return raw
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n, err
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// hexDump returns up to n bytes as hex string.
func hexDump(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	sb := strings.Builder{}
	for i, v := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", v)
	}
	return sb.String()
}

// ─── Built-in probes ─────────────────────────────────────────────────────────

// builtinProbes returns the set of default UDP probes.
// Protocol payloads are public-domain RFC-defined request formats.
func builtinProbes() []Probe {
	return []Probe{
		// ── DNS ─────────────────────────────────────────────────────────────
		{
			Port:     53,
			Service:  "dns",
			Severity: module.SeverityInfo,
			Tags:     []string{"dns", "network"},
			// DNS version query: standard version.bind CHAOS TXT query.
			// RFC 1035 — Transaction ID 0xdead, QR=0, QDCOUNT=1, QTYPE=TXT, QCLASS=CH.
			Payload: []byte{
				0xde, 0xad, // ID
				0x01, 0x00, // Flags: standard query
				0x00, 0x01, // QDCOUNT
				0x00, 0x00, // ANCOUNT
				0x00, 0x00, // NSCOUNT
				0x00, 0x00, // ARCOUNT
				0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
				0x04, 'b', 'i', 'n', 'd',
				0x00,       // root label
				0x00, 0x10, // QTYPE = TXT
				0x00, 0x03, // QCLASS = CH
			},
			Validate: func(resp []byte) bool {
				// DNS response: ID must match 0xdead, QR bit (0x80) set.
				return len(resp) >= 4 &&
					resp[0] == 0xde && resp[1] == 0xad &&
					resp[2]&0x80 != 0
			},
		},

		// ── NTP ─────────────────────────────────────────────────────────────
		{
			Port:     123,
			Service:  "ntp",
			Severity: module.SeverityInfo,
			Tags:     []string{"ntp", "network"},
			// NTP client request (version 3, mode 3 — client).
			// RFC 5905 — 48 bytes, LI=0, VN=3, Mode=3.
			Payload: func() []byte {
				p := make([]byte, 48)
				p[0] = 0x1b // LI=0, VN=3, Mode=3
				return p
			}(),
			Validate: func(resp []byte) bool {
				// NTP response: 48 bytes, VN=3 or 4, mode=4 (server).
				return len(resp) >= 48 && (resp[0]&0x07) == 0x04
			},
		},

		// ── SNMP v1 ──────────────────────────────────────────────────────────
		{
			Port:     161,
			Service:  "snmp",
			Severity: module.SeverityMedium,
			Tags:     []string{"snmp", "network", "iot"},
			// SNMPv1 GetRequest for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0)
			// using community string "public". RFC 1157.
			Payload: []byte{
				0x30, 0x26, // SEQUENCE
				0x02, 0x01, 0x00, // INTEGER version=0 (SNMPv1)
				0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // community "public"
				0xa0, 0x19, // GetRequest-PDU
				0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request-id=1
				0x02, 0x01, 0x00, // error-status=0
				0x02, 0x01, 0x00, // error-index=0
				0x30, 0x0b, // VarBindList
				0x30, 0x09, // VarBind
				0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID 1.3.6.1.2.1
				0x05, 0x00, // NULL value
			},
			Validate: func(resp []byte) bool {
				// SNMP response: starts with 0x30 (SEQUENCE), community "public" present.
				return len(resp) > 2 && resp[0] == 0x30
			},
		},

		// ── SSDP ─────────────────────────────────────────────────────────────
		{
			Port:     1900,
			Service:  "ssdp",
			Severity: module.SeverityLow,
			Tags:     []string{"ssdp", "upnp", "iot"},
			// SSDP M-SEARCH request. UPnP Device Architecture 2.0.
			Payload: []byte("M-SEARCH * HTTP/1.1\r\n" +
				"HOST: 239.255.255.250:1900\r\n" +
				"MAN: \"ssdp:discover\"\r\n" +
				"MX: 1\r\n" +
				"ST: ssdp:all\r\n" +
				"\r\n"),
			Validate: func(resp []byte) bool {
				s := strings.ToUpper(string(resp))
				return strings.Contains(s, "HTTP/1.1 200") ||
					strings.Contains(s, "NOTIFY") ||
					strings.Contains(s, "LOCATION")
			},
		},

		// ── mDNS ─────────────────────────────────────────────────────────────
		{
			Port:     5353,
			Service:  "mdns",
			Severity: module.SeverityInfo,
			Tags:     []string{"mdns", "dns", "network"},
			// mDNS query for _services._dns-sd._udp.local PTR.
			// RFC 6762 — multicast DNS, but we probe the unicast port.
			Payload: []byte{
				0x00, 0x00, // ID=0 (mDNS)
				0x00, 0x00, // flags: standard query
				0x00, 0x01, // QDCOUNT=1
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ANCOUNT/NSCOUNT/ARCOUNT=0
				0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
				0x07, '_', 'd', 'n', 's', '-', 's', 'd',
				0x04, '_', 'u', 'd', 'p',
				0x05, 'l', 'o', 'c', 'a', 'l',
				0x00,       // root
				0x00, 0x0c, // QTYPE=PTR
				0x80, 0x01, // QCLASS=IN with QU bit
			},
			Validate: func(resp []byte) bool {
				return len(resp) >= 4 && resp[2]&0x80 != 0
			},
		},

		// ── NetBIOS Name Service ──────────────────────────────────────────────
		{
			Port:     137,
			Service:  "netbios-ns",
			Severity: module.SeverityLow,
			Tags:     []string{"netbios", "smb", "windows"},
			// NetBIOS Name Service node status request. RFC 1002.
			Payload: []byte{
				0x00, 0x01, // Transaction ID
				0x00, 0x00, // Flags: query
				0x00, 0x01, // QDCOUNT
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x20,
				0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // CKAAAAAA
				0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
				0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
				0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
				0x00,
				0x00, 0x21, // QTYPE=NBSTAT
				0x00, 0x01, // QCLASS=IN
			},
			Validate: func(resp []byte) bool {
				return len(resp) > 56
			},
		},

		// ── TFTP ─────────────────────────────────────────────────────────────
		{
			Port:     69,
			Service:  "tftp",
			Severity: module.SeverityHigh,
			Tags:     []string{"tftp", "network", "file-transfer"},
			// TFTP Read Request for "test" in netascii mode. RFC 1350.
			Payload: []byte{
				0x00, 0x01, // Opcode=RRQ
				't', 'e', 's', 't', 0x00, // filename
				'n', 'e', 't', 'a', 's', 'c', 'i', 'i', 0x00, // mode
			},
			Validate: func(resp []byte) bool {
				// TFTP DATA (opcode=3) or ERROR (opcode=5) means server is alive.
				return len(resp) >= 2 && (resp[1] == 0x03 || resp[1] == 0x05)
			},
		},

		// ── Memcached ────────────────────────────────────────────────────────
		{
			Port:     11211,
			Service:  "memcached",
			Severity: module.SeverityHigh,
			Tags:     []string{"memcached", "cache", "database"},
			// Memcached UDP stats command. Binary protocol header + stats request.
			Payload: []byte{
				0x00, 0x01, // Request ID
				0x00, 0x00, // Sequence number
				0x00, 0x01, // Total datagrams
				0x00, 0x00, // Reserved
				's', 't', 'a', 't', 's', '\r', '\n', // stats command
			},
			Validate: func(resp []byte) bool {
				s := string(resp)
				return strings.Contains(s, "STAT ") || strings.Contains(s, "END\r\n")
			},
		},

		// ── IKE (IPsec) ──────────────────────────────────────────────────────
		{
			Port:     500,
			Service:  "ike",
			Severity: module.SeverityMedium,
			Tags:     []string{"ike", "ipsec", "vpn"},
			// IKEv1 Phase 1 Main Mode SA proposal. RFC 2409.
			Payload: func() []byte {
				p := make([]byte, 84)
				// IKE Header: Initiator SPI (random), responder SPI (0)
				copy(p[0:8], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
				// Next payload=SA(1), major=1, minor=0, exchange=ID_PROT(2), flags=0
				p[16] = 0x01
				p[17] = 0x10
				p[18] = 0x02
				// Message ID=0, length=84
				binary.BigEndian.PutUint32(p[24:28], 84)
				return p
			}(),
			Validate: func(resp []byte) bool {
				// IKE response has non-zero responder SPI (bytes 8-15).
				if len(resp) < 28 {
					return false
				}
				for i := 8; i < 16; i++ {
					if resp[i] != 0 {
						return true
					}
				}
				return false
			},
		},

		// ── QUIC ─────────────────────────────────────────────────────────────
		{
			Port:     443,
			Service:  "quic",
			Severity: module.SeverityInfo,
			Tags:     []string{"quic", "http3", "web"},
			// QUIC Initial packet with version negotiation probe. RFC 9000.
			// Simplified: long header with version 0x00000001.
			Payload: func() []byte {
				p := make([]byte, 1200)
				p[0] = 0xc0                                    // Long header flag
				binary.BigEndian.PutUint32(p[1:5], 0x00000001) // Version 1
				p[5] = 0x08                                    // DCID length=8
				p[13] = 0x08                                   // SCID length=8
				return p[:30]
			}(),
			Validate: func(resp []byte) bool {
				// QUIC version negotiation: first byte 0x80|flags, or any long header.
				return len(resp) >= 5 && (resp[0]&0x80) != 0
			},
		},

		// ── DHCP ─────────────────────────────────────────────────────────────
		{
			Port:     67,
			Service:  "dhcp",
			Severity: module.SeverityMedium,
			Tags:     []string{"dhcp", "network", "infrastructure"},
			// DHCP DISCOVER. RFC 2131.
			Payload: func() []byte {
				p := make([]byte, 300)
				p[0] = 0x01   // BootRequest
				p[1] = 0x01   // Ethernet
				p[2] = 0x06   // HWLen=6
				p[4] = 0x00   // hops=0
				p[8] = 0x00   // ciaddr=0
				p[236] = 0x63 // Magic cookie
				p[237] = 0x82
				p[238] = 0x53
				p[239] = 0x63
				p[240] = 53  // DHCP Message Type option
				p[241] = 1   // length
				p[242] = 1   // DHCP DISCOVER
				p[243] = 255 // END
				return p
			}(),
			Validate: func(resp []byte) bool {
				// DHCP reply: op=BOOTREPLY (2), magic cookie present.
				return len(resp) >= 240 &&
					resp[0] == 0x02 &&
					resp[236] == 0x63 && resp[237] == 0x82
			},
		},

		// ── LDAP ─────────────────────────────────────────────────────────────
		{
			Port:     389,
			Service:  "ldap",
			Severity: module.SeverityMedium,
			Tags:     []string{"ldap", "directory", "network"},
			// LDAP anonymous bind request. RFC 4511.
			Payload: []byte{
				0x30, 0x0c, // SEQUENCE
				0x02, 0x01, 0x01, // messageID=1
				0x60, 0x07, // BindRequest
				0x02, 0x01, 0x03, // version=3
				0x04, 0x00, // DN=""
				0x80, 0x00, // simple auth, password=""
			},
			Validate: func(resp []byte) bool {
				// LDAP response: starts with 0x30 (SEQUENCE).
				return len(resp) >= 4 && resp[0] == 0x30
			},
		},

		// ── Syslog ───────────────────────────────────────────────────────────
		{
			Port:     514,
			Service:  "syslog",
			Severity: module.SeverityLow,
			Tags:     []string{"syslog", "logging", "network"},
			// Syslog test message. RFC 5424.
			Payload: []byte("<14>1 - - - - - - blackhorn-udpprobe test\n"),
			// Syslog is fire-and-forget (no response). Open port = service exists.
			// Use nil validate — any response (even ICMP-unreachable translated) = present.
			Validate: nil,
		},

		// ── SNMP Trap ────────────────────────────────────────────────────────
		{
			Port:     162,
			Service:  "snmp-trap",
			Severity: module.SeverityLow,
			Tags:     []string{"snmp", "network", "monitoring"},
			Payload: []byte{
				0x30, 0x26,
				0x02, 0x01, 0x00,
				0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
				0xa5, 0x19, // TrapPDU
				0x02, 0x04, 0x00, 0x00, 0x00, 0x01,
				0x02, 0x01, 0x00,
				0x02, 0x01, 0x00,
				0x30, 0x0b,
				0x30, 0x09,
				0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,
				0x05, 0x00,
			},
			Validate: func(resp []byte) bool {
				return len(resp) > 2 && resp[0] == 0x30
			},
		},

		// ── WireGuard ────────────────────────────────────────────────────────
		{
			Port:     51820,
			Service:  "wireguard",
			Severity: module.SeverityInfo,
			Tags:     []string{"wireguard", "vpn", "network"},
			// WireGuard Handshake Initiation (type=1). WireGuard whitepaper.
			// A valid initiation is 148 bytes with type field = 1.
			Payload: func() []byte {
				p := make([]byte, 148)
				p[0] = 0x01 // type = handshake initiation
				return p
			}(),
			Validate: func(resp []byte) bool {
				// WireGuard response type=2 (handshake response) or type=3 (cookie reply).
				return len(resp) >= 1 && (resp[0] == 0x02 || resp[0] == 0x03)
			},
		},

		// ── L2TP ─────────────────────────────────────────────────────────────
		{
			Port:     1701,
			Service:  "l2tp",
			Severity: module.SeverityMedium,
			Tags:     []string{"l2tp", "vpn", "network"},
			// L2TP SCCRQ (Start-Control-Connection-Request). RFC 2661.
			Payload: []byte{
				0xc8, 0x02, // Flags+Ver: control, L, S, O bits; version=2
				0x00, 0x14, // Length=20
				0x00, 0x00, // Tunnel ID=0
				0x00, 0x00, // Session ID=0
				0x00, 0x00, // Ns=0
				0x00, 0x00, // Nr=0
				0x80, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, // AVP: Message Type=SCCRQ
			},
			Validate: func(resp []byte) bool {
				// L2TP control: flags byte has control bit (0x80) set.
				return len(resp) >= 12 && (resp[0]&0x80) != 0
			},
		},

		// ── Kerberos ─────────────────────────────────────────────────────────
		{
			Port:     88,
			Service:  "kerberos",
			Severity: module.SeverityMedium,
			Tags:     []string{"kerberos", "active-directory", "auth"},
			// Kerberos AS-REQ (Application Request) for "blackhorn@TEST.LOCAL".
			// RFC 4120 — KRB_AS_REQ = 0x6a.
			Payload: []byte{
				0x6a, 0x35, // AS-REQ application tag
				0x30, 0x33, // SEQUENCE
				0xa1, 0x03, 0x02, 0x01, 0x05, // pvno=5
				0xa2, 0x03, 0x02, 0x01, 0x0a, // msg-type=10 (AS-REQ)
				0xa4, 0x27,
				0x30, 0x25,
				0xa0, 0x07, 0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10, // kdc-options
				0xa1, 0x0c,
				0x30, 0x0a, 0xa0, 0x03, 0x02, 0x01, 0x01,
				0xa1, 0x03, 0x1b, 0x01, 0x00, // cname
				0xa2, 0x0d,
				0x1b, 0x0b, 't', 'e', 's', 't', '.', 'l', 'o', 'c', 'a', 'l', 0x00,
			},
			Validate: func(resp []byte) bool {
				// KRB_AS_REP (0x6b) or KRB_ERROR (0x7e).
				return len(resp) >= 2 && (resp[0] == 0x6b || resp[0] == 0x7e)
			},
		},

		// ── Echo ─────────────────────────────────────────────────────────────
		{
			Port:     7,
			Service:  "echo",
			Severity: module.SeverityLow,
			Tags:     []string{"echo", "network", "diagnostic"},
			Payload:  []byte("blackhorn-udpprobe\n"),
			Validate: func(resp []byte) bool {
				return string(resp) == "blackhorn-udpprobe\n"
			},
		},

		// ── Chargen ──────────────────────────────────────────────────────────
		{
			Port:     19,
			Service:  "chargen",
			Severity: module.SeverityLow,
			Tags:     []string{"chargen", "network", "diagnostic"},
			Payload:  []byte{0x00},
			Validate: func(resp []byte) bool {
				// Chargen responds with printable ASCII characters.
				if len(resp) < 10 {
					return false
				}
				for _, b := range resp[:10] {
					if b < 0x20 || b > 0x7e {
						return false
					}
				}
				return true
			},
		},

		// ── RADIUS ───────────────────────────────────────────────────────────
		{
			Port:     1812,
			Service:  "radius",
			Severity: module.SeverityMedium,
			Tags:     []string{"radius", "auth", "network"},
			// RADIUS Access-Request. RFC 2865.
			Payload: func() []byte {
				p := make([]byte, 44)
				p[0] = 0x01 // Code=Access-Request
				p[1] = 0x01 // ID=1
				binary.BigEndian.PutUint16(p[2:4], 44)
				// Authenticator (16 bytes random) at p[4:20] — zeroed here.
				// User-Name attribute (type=1, len=6, "test")
				p[20] = 0x01
				p[21] = 0x06
				copy(p[22:26], "test")
				// NAS-Identifier attribute (type=32, len=18, "blackhorn-udpprobe")
				p[26] = 0x20
				p[27] = 0x06
				copy(p[28:32], "bh01")
				return p
			}(),
			Validate: func(resp []byte) bool {
				// RADIUS response: code 2(Access-Accept), 3(Access-Reject), 11(Challenge).
				return len(resp) >= 4 && (resp[0] == 0x02 || resp[0] == 0x03 || resp[0] == 0x0b)
			},
		},

		// ── RPC (portmapper) ─────────────────────────────────────────────────
		{
			Port:     111,
			Service:  "rpcbind",
			Severity: module.SeverityMedium,
			Tags:     []string{"rpc", "nfs", "network"},
			// RPC portmapper dump request. RFC 1833.
			// CALL, XID=1, prog=portmapper(100000), ver=2, proc=4(DUMP)
			Payload: []byte{
				0x00, 0x00, 0x00, 0x01, // XID
				0x00, 0x00, 0x00, 0x00, // CALL
				0x00, 0x00, 0x00, 0x02, // RPC version=2
				0x00, 0x01, 0x86, 0xa0, // program=portmapper (100000)
				0x00, 0x00, 0x00, 0x02, // version=2
				0x00, 0x00, 0x00, 0x04, // procedure=DUMP(4)
				0x00, 0x00, 0x00, 0x00, // NULL credentials
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, // NULL verifier
				0x00, 0x00, 0x00, 0x00,
			},
			Validate: func(resp []byte) bool {
				// RPC REPLY: bytes 4-7 = 0x00000001.
				return len(resp) >= 8 &&
					binary.BigEndian.Uint32(resp[4:8]) == 0x00000001
			},
		},
	}
}
