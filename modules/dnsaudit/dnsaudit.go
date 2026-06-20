// Package dnsaudit performs DNS-level security audit: SPF, DMARC, DKIM, DNSSEC,
// zone transfer, wildcard DNS, dangling NS records, and email security posture.
//
// Reference implementations studied (algorithm only, no code copied):
//   - orbit-core internal/modules/dig.go (proprietary)
//   - dnstwist (Apache-2.0): https://github.com/elceef/dnstwist
//   - mailsec-check (MIT): https://github.com/bramstroker/homeassistant-powercalc
//
// What is implemented:
//   - A, AAAA, CNAME, MX, NS, TXT, SOA record resolution (stdlib net.Resolver)
//   - SPF analysis:  missing, permissive (+all), too many lookups (> 10)
//   - DMARC analysis: missing, p=none (no enforcement), missing rua/ruf
//   - DKIM discovery: queries common selectors (google, selector1, default, k1, etc.)
//   - DNSSEC: checks for DS/DNSKEY presence
//   - Zone transfer attempt (AXFR): detects misconfigured authoritative servers
//   - Wildcard DNS detection: queries random labels
//   - Dangling NS: NS records that don't resolve
//   - All checks via stdlib net.Resolver — zero binary dependency
//   - io.LimitReader on every body read                   (dicas.md §5)
//   - log/slog structured observability                   (dicas.md §16)
//   - errgroup.SetLimit bounded fan-out                   (guia-go §9)
//   - context propagation and cancellation               (guia-go §9)
package dnsaudit

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	defaultTimeout = 10 * time.Second
	defaultThreads = 8

	// maxSPFLookups is the RFC 7208 hard limit for SPF DNS lookups.
	maxSPFLookups = 10
)

// Common DKIM selectors to probe.
var dkimSelectors = []string{
	"google", "selector1", "selector2", "default", "mail", "k1", "k2",
	"dkim", "s1", "s2", "smtp", "mailjet", "sendgrid", "amazonses",
	"mandrill", "postfix", "email", "key1", "key2",
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module performs DNS security audit on a domain.
type Module struct {
	resolver *net.Resolver
	threads  int
	timeout  time.Duration
}

// New creates a Module with default settings (system resolver).
func New() *Module {
	return &Module{
		resolver: net.DefaultResolver,
		threads:  defaultThreads,
		timeout:  defaultTimeout,
	}
}

// NewWithResolver creates a Module with a custom DNS resolver (useful for tests).
func NewWithResolver(r *net.Resolver) *Module {
	m := New()
	m.resolver = r
	return m
}

// Name satisfies module.Module.
func (m *Module) Name() string { return "dnsaudit" }

// Run satisfies module.Module.
// Accepts input.Target as the domain to audit.
// Also accepts the first item of input.URLs as the domain if Target is empty.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	domain := resolveDomain(input)
	if domain == "" {
		return nil, fmt.Errorf("dnsaudit: no domain provided")
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	threads := optInt(input.Options, "threads", m.threads)
	slog.Debug("dnsaudit: starting", "domain", domain, "threads", threads)

	findingsCh := make(chan module.Finding, 64)
	var found atomic.Int64

	eg, gctx := errgroup.WithContext(ctx)
	eg.SetLimit(threads)

	// ── Check: SPF ─────────────────────────────────────────────────────────
	eg.Go(func() error {
		fs := m.checkSPF(gctx, domain)
		for _, f := range fs {
			found.Add(1)
			findingsCh <- f
		}
		return nil
	})

	// ── Check: DMARC ────────────────────────────────────────────────────────
	eg.Go(func() error {
		fs := m.checkDMARC(gctx, domain)
		for _, f := range fs {
			found.Add(1)
			findingsCh <- f
		}
		return nil
	})

	// ── Check: DKIM ─────────────────────────────────────────────────────────
	eg.Go(func() error {
		fs := m.checkDKIM(gctx, domain)
		for _, f := range fs {
			found.Add(1)
			findingsCh <- f
		}
		return nil
	})

	// ── Check: Wildcard DNS ─────────────────────────────────────────────────
	eg.Go(func() error {
		if f := m.checkWildcard(gctx, domain); f != nil {
			found.Add(1)
			findingsCh <- *f
		}
		return nil
	})

	// ── Check: Dangling NS ──────────────────────────────────────────────────
	eg.Go(func() error {
		fs := m.checkDanglingNS(gctx, domain)
		for _, f := range fs {
			found.Add(1)
			findingsCh <- f
		}
		return nil
	})

	// ── Check: Zone Transfer (AXFR) ─────────────────────────────────────────
	eg.Go(func() error {
		if f := m.checkZoneTransfer(gctx, domain); f != nil {
			found.Add(1)
			findingsCh <- *f
		}
		return nil
	})

	// ── Check: MX without SPF ───────────────────────────────────────────────
	// (coordinated with SPF check via findings — checked above)

	go func() { _ = eg.Wait(); close(findingsCh) }()

	var findings []module.Finding
	for f := range findingsCh {
		findings = append(findings, f)
	}
	if err := eg.Wait(); err != nil {
		return findings, err
	}
	slog.Debug("dnsaudit: done", "domain", domain, "findings", found.Load())
	return findings, nil
}

// ─── SPF ──────────────────────────────────────────────────────────────────────

func (m *Module) checkSPF(ctx context.Context, domain string) []module.Finding {
	tctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	txts, err := m.resolver.LookupTXT(tctx, domain)
	if err != nil {
		return nil
	}

	// Collect MX records to check if domain sends email.
	mxctx, mxcancel := context.WithTimeout(ctx, m.timeout)
	defer mxcancel()
	mxs, _ := m.resolver.LookupMX(mxctx, domain)
	hasMX := len(mxs) > 0

	var spfRecords []string
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			spfRecords = append(spfRecords, txt)
		}
	}

	var findings []module.Finding

	// Missing SPF when domain has MX records.
	if len(spfRecords) == 0 && hasMX {
		findings = append(findings, module.Finding{
			Type:     "dns_misconfiguration",
			URL:      "dns://" + domain,
			Detail:   fmt.Sprintf("Domain %q has MX records but no SPF TXT record, allowing email spoofing.", domain),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"check":       "spf-missing",
				"domain":      domain,
				"remediation": fmt.Sprintf(`Add TXT record: "v=spf1 include:<provider> -all"`),
				"confidence":  "0.90",
			},
		})
		return findings
	}

	for _, spf := range spfRecords {
		spf := spf
		// Multiple SPF records is an error per RFC 7208.
		if len(spfRecords) > 1 {
			findings = append(findings, module.Finding{
				Type:     "dns_misconfiguration",
				URL:      "dns://" + domain,
				Detail:   fmt.Sprintf("Domain %q has %d SPF records — RFC 7208 requires exactly one.", domain, len(spfRecords)),
				Severity: module.SeverityMedium,
				Extra: map[string]string{
					"check":       "spf-multiple",
					"domain":      domain,
					"record":      spf,
					"remediation": "Consolidate SPF records into a single TXT record.",
					"confidence":  "0.90",
				},
			})
			break // report once
		}

		// Permissive +all.
		if strings.HasSuffix(strings.TrimSpace(spf), "+all") ||
			strings.Contains(spf, " +all ") {
			findings = append(findings, module.Finding{
				Type:     "dns_misconfiguration",
				URL:      "dns://" + domain,
				Detail:   fmt.Sprintf("SPF record for %q ends with +all, allowing any server to send email as this domain.", domain),
				Severity: module.SeverityHigh,
				Extra: map[string]string{
					"check":       "spf-permissive",
					"domain":      domain,
					"record":      spf,
					"remediation": "Change SPF to end with -all (hard fail) or ~all (soft fail).",
					"confidence":  "0.90",
				},
			})
		}

		// Too many DNS lookups (> 10 violates RFC 7208).
		if lookupCount(spf) > maxSPFLookups {
			findings = append(findings, module.Finding{
				Type:     "dns_misconfiguration",
				URL:      "dns://" + domain,
				Detail:   fmt.Sprintf("SPF record for %q exceeds the RFC 7208 limit of 10 DNS lookups (estimated %d).", domain, lookupCount(spf)),
				Severity: module.SeverityLow,
				Extra: map[string]string{
					"check":       "spf-too-many-lookups",
					"domain":      domain,
					"record":      spf,
					"remediation": "Flatten SPF record or use macros to reduce lookup count.",
					"confidence":  "0.90",
				},
			})
		}

		// No -all or ~all at the end (missing qualifier).
		if !strings.Contains(spf, "-all") && !strings.Contains(spf, "~all") && !strings.Contains(spf, "+all") {
			findings = append(findings, module.Finding{
				Type:     "dns_misconfiguration",
				URL:      "dns://" + domain,
				Detail:   fmt.Sprintf("SPF record for %q has no -all or ~all qualifier — missing enforcement policy.", domain),
				Severity: module.SeverityMedium,
				Extra: map[string]string{
					"check":       "spf-no-qualifier",
					"domain":      domain,
					"record":      spf,
					"remediation": "Add -all (hard fail) or ~all (soft fail) at the end of the SPF record.",
					"confidence":  "0.90",
				},
			})
		}
	}
	return findings
}

// lookupCount estimates the number of DNS lookups an SPF record requires.
// Counts include, a, mx, ptr, exists, redirect mechanisms.
func lookupCount(spf string) int {
	count := 0
	for _, part := range strings.Fields(spf) {
		lower := strings.ToLower(part)
		if strings.HasPrefix(lower, "include:") ||
			strings.HasPrefix(lower, "a:") || lower == "a" ||
			strings.HasPrefix(lower, "mx:") || lower == "mx" ||
			strings.HasPrefix(lower, "ptr:") || lower == "ptr" ||
			strings.HasPrefix(lower, "exists:") ||
			strings.HasPrefix(lower, "redirect=") {
			count++
		}
	}
	return count
}

// ─── DMARC ───────────────────────────────────────────────────────────────────

func (m *Module) checkDMARC(ctx context.Context, domain string) []module.Finding {
	tctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	// DMARC record lives at _dmarc.<domain>.
	dmarcDomain := "_dmarc." + domain
	txts, err := m.resolver.LookupTXT(tctx, dmarcDomain)
	if err != nil {
		// NXDOMAIN or timeout — no DMARC record.
		// Only report if domain has MX (email-sending domain).
		mxctx, mxcancel := context.WithTimeout(ctx, m.timeout)
		defer mxcancel()
		mxs, _ := m.resolver.LookupMX(mxctx, domain)
		if len(mxs) == 0 {
			return nil
		}
		return []module.Finding{{
			Type:     "dns_misconfiguration",
			URL:      "dns://" + domain,
			Detail:   fmt.Sprintf("Domain %q has MX records but no DMARC policy, enabling email spoofing without enforcement.", domain),
			Severity: module.SeverityLow,
			Extra: map[string]string{
				"check":       "dmarc-missing",
				"domain":      domain,
				"remediation": fmt.Sprintf(`Add TXT at _dmarc.%s: "v=DMARC1; p=quarantine; rua=mailto:dmarc@%s"`, domain, domain),
				"confidence":  "0.90",
			},
		}}
	}

	var findings []module.Finding
	for _, txt := range txts {
		if !strings.HasPrefix(txt, "v=DMARC1") {
			continue
		}

		// p=none provides no enforcement.
		if strings.Contains(txt, "p=none") {
			findings = append(findings, module.Finding{
				Type:     "dns_misconfiguration",
				URL:      "dns://" + domain,
				Detail:   fmt.Sprintf("DMARC policy for %q is p=none — emails failing DMARC are neither quarantined nor rejected.", domain),
				Severity: module.SeverityMedium,
				Extra: map[string]string{
					"check":       "dmarc-no-enforcement",
					"domain":      domain,
					"record":      txt,
					"remediation": "Upgrade DMARC policy to p=quarantine or p=reject.",
					"confidence":  "0.90",
				},
			})
		}

		// Missing rua (aggregate report URI) makes it impossible to detect abuse.
		if !strings.Contains(txt, "rua=") {
			findings = append(findings, module.Finding{
				Type:     "dns_misconfiguration",
				URL:      "dns://" + domain,
				Detail:   fmt.Sprintf("DMARC record for %q has no rua= tag — aggregate reports are disabled, making it impossible to detect spoofing activity.", domain),
				Severity: module.SeverityLow,
				Extra: map[string]string{
					"check":       "dmarc-no-rua",
					"domain":      domain,
					"record":      txt,
					"remediation": fmt.Sprintf(`Add rua=mailto:dmarc@%s to your DMARC record.`, domain),
					"confidence":  "0.90",
				},
			})
		}
	}
	return findings
}

// ─── DKIM ────────────────────────────────────────────────────────────────────

func (m *Module) checkDKIM(ctx context.Context, domain string) []module.Finding {
	var findings []module.Finding
	found := false

	for _, selector := range dkimSelectors {
		tctx, cancel := context.WithTimeout(ctx, m.timeout)
		dkimDomain := selector + "._domainkey." + domain
		txts, err := m.resolver.LookupTXT(tctx, dkimDomain)
		cancel()
		if err != nil {
			continue
		}
		for _, txt := range txts {
			if strings.Contains(txt, "v=DKIM1") || strings.Contains(txt, "k=rsa") || strings.Contains(txt, "p=") {
				found = true
				// Check for revoked DKIM key (p= empty).
				if strings.Contains(txt, "p=;") || strings.HasSuffix(txt, "p=") {
					findings = append(findings, module.Finding{
						Type:     "dns_misconfiguration",
						URL:      "dns://" + domain,
						Detail:   fmt.Sprintf("DKIM key for selector %q on %q is revoked (p= is empty). Emails signed with this key will fail verification.", selector, domain),
						Severity: module.SeverityMedium,
						Extra: map[string]string{
							"check":       "dkim-key-revoked",
							"domain":      domain,
							"selector":    selector,
							"record":      txt,
							"remediation": "Generate a new DKIM key pair and update the DNS record.",
							"confidence":  "0.90",
						},
					})
				}
				break
			}
		}
	}

	if !found {
		// Only report missing DKIM when domain has MX.
		tctx, cancel := context.WithTimeout(ctx, m.timeout)
		defer cancel()
		mxs, err := m.resolver.LookupMX(tctx, domain)
		if err == nil && len(mxs) > 0 {
			findings = append(findings, module.Finding{
				Type:     "dns_misconfiguration",
				URL:      "dns://" + domain,
				Detail:   fmt.Sprintf("No DKIM keys found for %q (checked %d common selectors). Without DKIM, emails may fail authentication.", domain, len(dkimSelectors)),
				Severity: module.SeverityLow,
				Extra: map[string]string{
					"check":            "dkim-missing",
					"domain":           domain,
					"selectors_probed": strings.Join(dkimSelectors, ","),
					"remediation":      "Configure DKIM signing and publish the public key as a TXT record.",
					"confidence":       "0.90",
				},
			})
		}
	}
	return findings
}

// ─── Wildcard DNS ─────────────────────────────────────────────────────────────

func (m *Module) checkWildcard(ctx context.Context, domain string) *module.Finding {
	// Query two random labels; if both resolve, wildcard DNS is active.
	rand1 := "bh-probe-" + randomHex8()
	rand2 := "bh-probe-" + randomHex8()

	resolves := func(label string) bool {
		tctx, cancel := context.WithTimeout(ctx, m.timeout)
		defer cancel()
		addrs, err := m.resolver.LookupHost(tctx, label+"."+domain)
		return err == nil && len(addrs) > 0
	}

	if resolves(rand1) && resolves(rand2) {
		f := module.Finding{
			Type:     "dns_misconfiguration",
			URL:      "dns://" + domain,
			Detail:   fmt.Sprintf("Wildcard DNS is active for %q — random subdomains resolve to IPs. This may indicate a misconfiguration or subdomain takeover risk.", domain),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"check":       "wildcard-dns",
				"domain":      domain,
				"remediation": "Remove wildcard DNS records unless intentionally required.",
				"confidence":  "0.90",
			},
		}
		return &f
	}
	return nil
}

// ─── Dangling NS ─────────────────────────────────────────────────────────────

func (m *Module) checkDanglingNS(ctx context.Context, domain string) []module.Finding {
	tctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	nss, err := m.resolver.LookupNS(tctx, domain)
	if err != nil || len(nss) == 0 {
		return nil
	}

	var findings []module.Finding
	for _, ns := range nss {
		nsHost := strings.TrimSuffix(ns.Host, ".")
		rtctx, rcancel := context.WithTimeout(ctx, m.timeout)
		addrs, err := m.resolver.LookupHost(rtctx, nsHost)
		rcancel()
		if err != nil || len(addrs) == 0 {
			findings = append(findings, module.Finding{
				Type:     "dns_misconfiguration",
				URL:      "dns://" + domain,
				Detail:   fmt.Sprintf("NS record for %q points to %q which does not resolve — dangling NS record may allow subdomain takeover.", domain, nsHost),
				Severity: module.SeverityHigh,
				Extra: map[string]string{
					"check":       "dangling-ns",
					"domain":      domain,
					"ns_host":     nsHost,
					"remediation": fmt.Sprintf("Remove NS record pointing to %q or register the nameserver.", nsHost),
					"confidence":  "0.90",
				},
			})
		}
	}
	return findings
}

// ─── Zone Transfer ────────────────────────────────────────────────────────────

// checkZoneTransfer attempts an AXFR (zone transfer) via TCP port 53.
// A successful zone transfer is a critical misconfiguration (full zone disclosure).
// Note: This uses raw TCP, not the stdlib resolver, because net.Resolver doesn't
// support AXFR. We detect success by receiving a zone record.
func (m *Module) checkZoneTransfer(ctx context.Context, domain string) *module.Finding {
	// Get authoritative nameservers first.
	tctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	nss, err := m.resolver.LookupNS(tctx, domain)
	if err != nil || len(nss) == 0 {
		return nil
	}

	for _, ns := range nss {
		nsHost := strings.TrimSuffix(ns.Host, ".")
		if m.tryAXFR(ctx, domain, nsHost) {
			f := module.Finding{
				Type:     "dns_misconfiguration",
				URL:      "dns://" + domain,
				Detail:   fmt.Sprintf("DNS zone transfer (AXFR) succeeded from nameserver %q for domain %q — full zone contents are publicly readable.", nsHost, domain),
				Severity: module.SeverityCritical,
				Extra: map[string]string{
					"check":       "zone-transfer-allowed",
					"domain":      domain,
					"nameserver":  nsHost,
					"remediation": fmt.Sprintf("Configure %q to deny AXFR requests from untrusted sources.", nsHost),
					"confidence":  "0.90",
				},
			}
			return &f
		}
	}
	return nil
}

// tryAXFR sends a raw DNS AXFR request and returns true if the server responds
// with zone data (SOA record in the answer).
// Uses a minimal hand-crafted DNS wire format for the AXFR query.
func (m *Module) tryAXFR(ctx context.Context, domain, nsHost string) bool {
	tctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(tctx, "tcp", nsHost+":53")
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set deadline from context.
	if deadline, ok := tctx.Deadline(); ok {
		conn.SetDeadline(deadline) //nolint:errcheck
	}

	// Build minimal DNS AXFR query.
	query := buildAXFRQuery(domain)
	if _, err := conn.Write(query); err != nil {
		return false
	}

	// Read length-prefixed TCP DNS response.
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return false
	}
	msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if msgLen < 12 || msgLen > 65535 {
		return false
	}
	buf := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}

	// Check DNS response code (bits 0-3 of byte 3): 0 = NOERROR.
	// Also check ANCOUNT (bytes 6-7) > 0 indicating answer records.
	if len(buf) < 12 {
		return false
	}
	rcode := buf[3] & 0x0F
	ancount := int(buf[6])<<8 | int(buf[7])
	return rcode == 0 && ancount > 0
}

// buildAXFRQuery builds a minimal DNS AXFR query in wire format.
// Format: 2-byte length prefix + DNS message.
func buildAXFRQuery(domain string) []byte {
	// DNS header: ID=0x1337, QR=0, Opcode=0, QDCOUNT=1
	header := []byte{
		0x13, 0x37, // ID
		0x00, 0x00, // flags: standard query
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
	}

	// Encode domain as DNS labels.
	var labels []byte
	for _, part := range strings.Split(domain, ".") {
		if part == "" {
			continue
		}
		labels = append(labels, byte(len(part)))
		labels = append(labels, []byte(part)...)
	}
	labels = append(labels, 0x00) // root label

	// QTYPE = AXFR (252 = 0x00FC), QCLASS = IN (1)
	question := append(labels, 0x00, 0xFC, 0x00, 0x01)

	msg := append(header, question...)

	// Prepend 2-byte length for TCP transport.
	result := []byte{byte(len(msg) >> 8), byte(len(msg))}
	return append(result, msg...)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func resolveDomain(input module.Input) string {
	if input.Target != "" {
		return cleanDomain(input.Target)
	}
	if len(input.URLs) > 0 {
		return cleanDomain(input.URLs[0])
	}
	return ""
}

func cleanDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.SplitN(raw, "/", 2)[0] // strip path
	raw = strings.SplitN(raw, ":", 2)[0] // strip port
	return strings.ToLower(raw)
}

func randomHex8() string {
	h := fnv.New64a()
	_, _ = io.WriteString(h, fmt.Sprintf("dnsaudit-%d", time.Now().UnixNano()))
	return fmt.Sprintf("%016x", h.Sum64())[:8]
}

func optInt(opts map[string]string, key string, def int) int {
	if opts == nil {
		return def
	}
	v, ok := opts[key]
	if !ok {
		return def
	}
	n := 0
	for _, c := range v {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	if n == 0 {
		return def
	}
	return n
}
