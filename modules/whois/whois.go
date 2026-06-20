// Package whois performs WHOIS lookups via direct TCP connection to WHOIS
// servers (RFC 3912), with referral chaining (follow the "Registrar WHOIS
// Server" or "whois:" pointer in the response for authoritative results).
//
// Native Go replacement for the system `whois` CLI binary.
// No external library — pure stdlib: net.Dial + bufio.Scanner.
//
// Observability (dicas.md §16): every decision (server selected, referral
// followed, field extracted) is logged via log/slog.
package whois

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const moduleName = "whois"

// defaultPort is the IANA-assigned WHOIS port.
const defaultPort = "43"

// dialTimeout for each WHOIS TCP connection.
const dialTimeout = 15 * time.Second

// maxResponseSize — 512 KB ceiling (WHOIS responses are plain text, never huge).
const maxResponseSize = 512 << 10

// maxReferrals limits referral chain depth to prevent loops.
const maxReferrals = 3

// ianaServer is the IANA root WHOIS server — used when no TLD-specific server
// is known. It returns a referral to the authoritative registrar server.
const ianaServer = "whois.iana.org"

// tldServers maps common TLDs to their authoritative WHOIS servers.
// Mirrors the lookup table that the system whois binary ships with.
var tldServers = map[string]string{
	"com":  "whois.verisign-grs.com",
	"net":  "whois.verisign-grs.com",
	"org":  "whois.pir.org",
	"io":   "whois.nic.io",
	"dev":  "whois.nic.google",
	"app":  "whois.nic.google",
	"co":   "whois.nic.co",
	"uk":   "whois.nic.uk",
	"de":   "whois.denic.de",
	"nl":   "whois.domain-registry.nl",
	"fr":   "whois.nic.fr",
	"eu":   "whois.eu",
	"ca":   "whois.cira.ca",
	"au":   "whois.auda.org.au",
	"br":   "whois.registro.br",
	"ru":   "whois.tcinet.ru",
	"cn":   "whois.cnnic.cn",
	"jp":   "whois.jprs.jp",
	"in":   "whois.registry.in",
	"mx":   "whois.mx",
	"it":   "whois.nic.it",
	"es":   "whois.nic.es",
	"info": "whois.afilias.net",
	"biz":  "whois.biz",
	"edu":  "whois.educause.edu",
	"gov":  "whois.dotgov.gov",
	"mil":  "whois.nic.mil",
	"int":  "whois.iana.org",
	"ac":   "whois.nic.ac",
	"sh":   "whois.nic.sh",
	"ai":   "whois.nic.ai",
}

// reReferral matches the WHOIS referral pointer lines.
var reReferral = regexp.MustCompile(`(?i)(?:registrar whois server|whois server|refer)\s*:\s*(\S+)`)

// reField matches structured WHOIS field lines (e.g. "Domain Name: example.com").
var reField = regexp.MustCompile(`^([^:]+):\s+(.+)$`)

// Module implements module.Module for WHOIS lookups.
type Module struct {
	logger *slog.Logger
}

func New() *Module { return &Module{logger: slog.Default()} }

func (m *Module) Name() string { return moduleName }

// Run performs a WHOIS lookup for input.Target (domain or IP).
// Returns structured Findings for key WHOIS fields (registrar, registrant,
// creation/expiry dates, nameservers, status) plus a raw-text Finding.
//
// Supported options:
//   - "server":   override the WHOIS server (default: auto-detect by TLD)
//   - "no_chain": "true" to disable referral following (default "false")
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := input.Target
	if target == "" && len(input.URLs) > 0 {
		target = input.URLs[0]
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("whois: target required")
	}

	// Strip scheme/path if a full URL was passed
	target = stripScheme(target)

	server := optStr(input.Options, "server", m.selectServer(target))
	noChain := optBool(input.Options, "no_chain", false)

	m.logger.Info("whois: querying", "target", target, "server", server)

	raw, finalServer, err := m.query(ctx, target, server, noChain, 0)
	if err != nil {
		return nil, fmt.Errorf("whois: query failed: %w", err)
	}

	m.logger.Info("whois: response received", "target", target, "server", finalServer, "bytes", len(raw))

	findings := m.parseFindings(target, raw, finalServer)
	return findings, nil
}

// query sends a WHOIS request via TCP and optionally follows referrals.
func (m *Module) query(ctx context.Context, target, server string, noChain bool, depth int) (string, string, error) {
	if depth > maxReferrals {
		return "", server, fmt.Errorf("whois: referral depth exceeded (%d)", maxReferrals)
	}

	raw, err := m.dial(ctx, target, server)
	if err != nil {
		return "", server, err
	}

	if noChain {
		return raw, server, nil
	}

	// Follow referral if present
	if ref := extractReferral(raw); ref != "" && ref != server {
		m.logger.Info("whois: following referral", "from", server, "to", ref)
		refRaw, refServer, refErr := m.query(ctx, target, ref, noChain, depth+1)
		if refErr == nil && len(refRaw) > len(raw) {
			return refRaw, refServer, nil
		}
	}
	return raw, server, nil
}

// dial opens a TCP connection to the WHOIS server, sends the query, and
// reads the response — direct implementation of RFC 3912.
func (m *Module) dial(ctx context.Context, target, server string) (string, error) {
	addr := server
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(server, defaultPort)
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	// RFC 3912: send "<query>\r\n"
	if _, err := fmt.Fprintf(conn, "%s\r\n", target); err != nil {
		return "", err
	}

	// Read response with size limit
	limited := io.LimitReader(conn, maxResponseSize)
	var sb strings.Builder
	sc := bufio.NewScanner(limited)
	for sc.Scan() {
		sb.WriteString(sc.Text())
		sb.WriteRune('\n')
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// selectServer returns the best WHOIS server for the given query target.
func (m *Module) selectServer(target string) string {
	// IP address → ARIN by default
	if net.ParseIP(target) != nil {
		return "whois.arin.net"
	}
	// Extract TLD
	parts := strings.Split(strings.ToLower(target), ".")
	if len(parts) >= 2 {
		tld := parts[len(parts)-1]
		if srv, ok := tldServers[tld]; ok {
			return srv
		}
	}
	return ianaServer
}

// parseFindings extracts structured fields from a raw WHOIS response
// and returns one Finding per meaningful field plus a raw-text Finding.
func (m *Module) parseFindings(target, raw, server string) []module.Finding {
	// Fields of interest — mirrors what `whois` CLI highlights
	interestingFields := map[string]bool{
		// Standard IANA/ICANN format (e.g. Verisign, ARIN)
		"domain name":            true,
		"registrar":              true,
		"registrar whois server": true,
		"creation date":          true,
		"updated date":           true,
		"registry expiry date":   true,
		"expiry date":            true,
		"registrant name":        true,
		"registrant email":       true,
		"registrant country":     true,
		"name server":            true,
		"dnssec":                 true,
		"domain status":          true,
		"admin email":            true,
		"tech email":             true,
		// registro.br format (ccTLD .br — short lowercase keys)
		"domain":  true,
		"owner":   true,
		"country": true,
		"created": true,
		"changed": true,
		"status":  true,
		"nserver": true,
		"e-mail":  true,
		// RIPE NCC / APNIC format
		"netname":      true,
		"org":          true,
		"inetnum":      true,
		"inet6num":     true,
		"descr":        true,
		"tech-c":       true,
		"admin-c":      true,
		"mnt-by":       true,
		"organisation": true,
	}

	var findings []module.Finding
	seen := make(map[string]bool)

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		m := reField.FindStringSubmatch(line)
		if len(m) < 3 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(m[1]))
		val := strings.TrimSpace(m[2])
		if !interestingFields[key] || val == "" {
			continue
		}
		dedup := key + "=" + val
		if seen[dedup] {
			continue
		}
		seen[dedup] = true

		sev := module.SeverityInfo
		// Flag privacy-revealing fields
		if strings.Contains(key, "email") || strings.Contains(key, "registrant") {
			sev = module.SeverityLow
		}

		findings = append(findings, module.Finding{
			Type:     "whois_field",
			URL:      target,
			Detail:   fmt.Sprintf("%s: %s", strings.Title(key), val),
			Severity: sev,
			Extra: map[string]string{
				"field":      key,
				"value":      val,
				"server":     server,
				"confidence": "0.90", // WHOIS record field from authoritative server
			},
		})
	}

	// Raw text Finding — useful for the decision log (dicas.md §17)
	findings = append(findings, module.Finding{
		Type:     "whois_raw",
		URL:      target,
		Detail:   fmt.Sprintf("Raw WHOIS response from %s (%d bytes)", server, len(raw)),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"server":     server,
			"raw":        raw,
			"confidence": "0.90", // raw WHOIS text from authoritative server
		},
	})

	return findings
}

// extractReferral returns the referral server from a WHOIS response, or "".
func extractReferral(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		m := reReferral.FindStringSubmatch(line)
		if len(m) > 1 {
			return strings.ToLower(strings.TrimSpace(m[1]))
		}
	}
	return ""
}

// stripScheme removes scheme and path from a URL, returning only the host.
func stripScheme(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func optStr(opts map[string]string, key, def string) string {
	if opts == nil {
		return def
	}
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

func optBool(opts map[string]string, key string, def bool) bool {
	if opts == nil {
		return def
	}
	v, ok := opts[key]
	if !ok {
		return def
	}
	return strings.ToLower(v) != "false"
}
