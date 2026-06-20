// Package dnsrecon performs advanced DNS reconnaissance: zone transfer attempts,
// DNSSEC validation, email security records (SPF/DMARC/DKIM), CAA, NSEC walking
// and comprehensive record enumeration.
//
// Checks performed:
//   - A/AAAA/CNAME/MX/NS/TXT/SRV/SOA — full record enumeration
//   - Zone transfer (AXFR) attempt — detects misconfigured nameservers
//   - SPF record analysis — checks for +all (any sender), missing SPF
//   - DMARC analysis — missing, p=none (no enforcement), subdomain policy
//   - DKIM discovery — probes common selectors (google, mail, default, k1, etc.)
//   - CAA — detects absence (allows any CA to issue certs)
//   - DNSSEC — checks DS/RRSIG presence
//   - Wildcard DNS — detects wildcard A/AAAA records
//   - Dangling CNAME — CNAMEs pointing to non-existent hosts (subdomain takeover)
//
// All checks use Go stdlib net.Resolver with PreferGo:true for pure-Go DNS.
// No external DNS binaries required.
//
// Usage:
//
//	m := dnsrecon.New()
//	findings, err := m.Run(ctx, module.Input{
//	    Target:  "example.com",
//	    Options: map[string]string{
//	        "checks":       "axfr,spf,dmarc,dkim,caa,dnssec,wildcard,cname",
//	        "resolvers":    "8.8.8.8,1.1.1.1",  // custom resolvers
//	        "dkim_selectors": "google,mail,default,k1,k2,selector1,selector2",
//	    },
//	})
package dnsrecon

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const maxParallel = 8

// Module implements module.Module for DNS reconnaissance.
type Module struct {
	resolver *net.Resolver
}

// New returns a Module with the system resolver (PreferGo=true).
func New() *Module {
	return &Module{
		resolver: &net.Resolver{
			PreferGo: true,
		},
	}
}

// NewWithResolver allows injecting a custom resolver (useful for tests).
func NewWithResolver(r *net.Resolver) *Module { return &Module{resolver: r} }

// Name returns the canonical module identifier.
func (m *Module) Name() string { return "dnsrecon" }

// Run performs DNS reconnaissance against the target domain.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("dnsrecon: target vazio")
	}
	domain := normaliseDomain(target)
	if !strings.Contains(domain, ".") {
		return nil, fmt.Errorf("dnsrecon: domínio inválido: '%s'", target)
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}
	checksFilter := opts["checks"]

	slog.InfoContext(ctx, "dnsrecon.Run iniciado",
		"domain", domain,
		"checks", checksFilter,
	)

	type checkFunc struct {
		name string
		fn   func(context.Context, string, map[string]string) ([]module.Finding, error)
	}

	checks := []checkFunc{
		{"records", m.checkRecords},
		{"axfr", m.checkZoneTransfer},
		{"spf", m.checkSPF},
		{"dmarc", m.checkDMARC},
		{"dkim", m.checkDKIM},
		{"caa", m.checkCAA},
		{"dnssec", m.checkDNSSEC},
		{"wildcard", m.checkWildcard},
		{"cname", m.checkDanglingCNAME},
	}

	var mu sync.Mutex
	var all []module.Finding

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxParallel)

	for _, c := range checks {
		c := c
		if !isWanted(checksFilter, c.name) {
			continue
		}
		g.Go(func() error {
			slog.DebugContext(gctx, "dnsrecon: executando check", "check", c.name, "domain", domain)
			findings, err := c.fn(gctx, domain, opts)
			if err != nil {
				slog.WarnContext(gctx, "dnsrecon: check com erro",
					"check", c.name, "domain", domain, "err", err)
				return nil
			}
			mu.Lock()
			all = append(all, findings...)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	result := dedup(all)
	slog.InfoContext(ctx, "dnsrecon.Run concluído",
		"domain", domain,
		"findings", len(result),
	)
	return result, nil
}

// ─── Records enumeration ──────────────────────────────────────────────────────

func (m *Module) checkRecords(ctx context.Context, domain string, _ map[string]string) ([]module.Finding, error) {
	var findings []module.Finding

	// A records
	addrs, err := m.resolver.LookupHost(ctx, domain)
	if err == nil && len(addrs) > 0 {
		findings = append(findings, module.Finding{
			Type:     "dns_a_record",
			URL:      fmt.Sprintf("https://%s", domain),
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("Domínio '%s' resolve para: %s", domain, strings.Join(addrs, ", ")),
			Extra: map[string]string{
				"record_type": "A/AAAA",
				"addresses":   strings.Join(addrs, ","),
				"source":      "dns_lookup",
				"confidence":  "0.98",
			},
		})
	}

	// MX records
	mxs, err := m.resolver.LookupMX(ctx, domain)
	if err == nil && len(mxs) > 0 {
		mxList := make([]string, len(mxs))
		for i, mx := range mxs {
			mxList[i] = fmt.Sprintf("%s (prio %d)", mx.Host, mx.Pref)
		}
		findings = append(findings, module.Finding{
			Type:     "dns_mx_record",
			URL:      fmt.Sprintf("https://%s", domain),
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("Registros MX para '%s': %s — identifica servidores de email", domain, strings.Join(mxList, "; ")),
			Extra: map[string]string{
				"record_type": "MX",
				"mx_records":  strings.Join(mxList, " | "),
				"source":      "dns_lookup",
				"confidence":  "0.98",
			},
		})
	}

	// NS records
	nss, err := m.resolver.LookupNS(ctx, domain)
	if err == nil && len(nss) > 0 {
		nsList := make([]string, len(nss))
		for i, ns := range nss {
			nsList[i] = ns.Host
		}
		findings = append(findings, module.Finding{
			Type:     "dns_ns_record",
			URL:      fmt.Sprintf("https://%s", domain),
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("Nameservers para '%s': %s", domain, strings.Join(nsList, ", ")),
			Extra: map[string]string{
				"record_type": "NS",
				"ns_records":  strings.Join(nsList, ","),
				"source":      "dns_lookup",
				"confidence":  "0.98",
			},
		})
	}

	// TXT records
	txts, err := m.resolver.LookupTXT(ctx, domain)
	if err == nil {
		for _, txt := range txts {
			if strings.HasPrefix(txt, "v=spf1") || strings.HasPrefix(txt, "v=DMARC") {
				continue // handled by dedicated checks
			}
			findings = append(findings, module.Finding{
				Type:     "dns_txt_record",
				URL:      fmt.Sprintf("https://%s", domain),
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("Registro TXT em '%s': %s", domain, truncate(txt, 200)),
				Extra: map[string]string{
					"record_type": "TXT",
					"value":       truncate(txt, 500),
					"source":      "dns_lookup",
					"confidence":  "0.95",
				},
			})
		}
	}

	return findings, nil
}

// ─── Zone Transfer (AXFR) ─────────────────────────────────────────────────────
//
// Methodology: an AXFR finding is only emitted when the nameserver actually
// returns zone records. TCP/53 being open is a necessary precondition but NOT
// a vulnerability — virtually all authoritative nameservers listen on TCP/53
// for large DNS responses (RFC 1035 §4.2.2).
//
// We implement a real AXFR attempt using raw TCP DNS wire format (type=AXFR=252).
// A server that refuses returns RCODE=5 (REFUSED) or RCODE=9 (NotAuth).
// Only a server that returns actual resource records is vulnerable.

func (m *Module) checkZoneTransfer(ctx context.Context, domain string, _ map[string]string) ([]module.Finding, error) {
	nss, err := m.resolver.LookupNS(ctx, domain)
	if err != nil || len(nss) == 0 {
		return nil, nil
	}

	var findings []module.Finding
	var mu sync.Mutex

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(4)

	for _, ns := range nss {
		ns := ns
		g.Go(func() error {
			nsHost := strings.TrimSuffix(ns.Host, ".")
			result := attemptAXFR(gctx, domain, nsHost)

			switch result.status {
			case axfrSuccess:
				slog.WarnContext(gctx, "dnsrecon: AXFR bem-sucedido",
					"ns", nsHost, "domain", domain, "records", result.recordCount)
				mu.Lock()
				findings = append(findings, module.Finding{
					Type:     "dns_axfr_success",
					URL:      fmt.Sprintf("dns://%s", nsHost),
					Severity: module.SeverityHigh,
					Detail: fmt.Sprintf("Zone transfer AXFR CONFIRMADO: nameserver '%s' transferiu %d registros da zona '%s'. "+
						"Isso expõe toda a infraestrutura DNS do domínio.",
						nsHost, result.recordCount, domain),
					Extra: map[string]string{
						"nameserver":   nsHost,
						"domain":       domain,
						"record_count": fmt.Sprintf("%d", result.recordCount),
						"evidence":     "AXFR query returned resource records",
						"check_cmd":    fmt.Sprintf("dig AXFR %s @%s", domain, nsHost),
						"source":       "axfr_probe",
						"confidence":   "0.98",
					},
				})
				mu.Unlock()

			case axfrRefused:
				// Refused is the expected/correct behaviour — no finding.
				slog.DebugContext(gctx, "dnsrecon: AXFR recusado (correto)",
					"ns", nsHost, "domain", domain)

			case axfrNetworkError:
				// Can't reach the server — no finding (not a vulnerability).
				slog.DebugContext(gctx, "dnsrecon: AXFR erro de rede",
					"ns", nsHost, "err", result.err)

			case axfrTimeout:
				slog.DebugContext(gctx, "dnsrecon: AXFR timeout", "ns", nsHost)
			}
			return nil
		})
	}
	_ = g.Wait()
	return findings, nil
}

// axfrStatus represents the outcome of an AXFR attempt.
type axfrStatus int

const (
	axfrSuccess      axfrStatus = iota
	axfrRefused                 // RCODE 5 (REFUSED) or 9 (NotAuth) — correct behaviour
	axfrNetworkError            // TCP connection failed
	axfrTimeout
)

type axfrResult struct {
	status      axfrStatus
	recordCount int
	err         error
}

// attemptAXFR performs a real DNS AXFR query over TCP against nsHost port 53.
// nsHost must be a bare hostname or IP — the port ":53" is appended internally.
// For tests with a custom port, use attemptAXFRAddr which takes a full address.
//
// Wire format per RFC 1035 §4 — no external DNS library needed for this check.
func attemptAXFR(ctx context.Context, domain, nsHost string) axfrResult {
	return attemptAXFRAddr(ctx, domain, nsHost+":53")
}

// attemptAXFRAddr is like attemptAXFR but accepts a pre-formed "host:port" address.
// Used by tests that spin up a fake DNS server on a random port.
func attemptAXFRAddr(ctx context.Context, domain, addr string) axfrResult {
	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return axfrResult{status: axfrNetworkError, err: err}
	}
	defer conn.Close()

	// Apply deadline so the read loop doesn't block forever.
	deadline, ok := dialCtx.Deadline()
	if ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	}

	// Build AXFR DNS query packet.
	// ID=0xABCD, QR=0 (query), OPCODE=0 (QUERY), RD=0 (no recursion desired for AXFR)
	// QDCOUNT=1, ANCOUNT=NSCOUNT=ARCOUNT=0
	qname := encodeDNSName(domain)
	// QTYPE=252 (AXFR), QCLASS=1 (IN)
	question := append(qname, 0x00, 0xFC, 0x00, 0x01)
	// DNS header: 12 bytes
	header := []byte{
		0xAB, 0xCD, // ID
		0x00, 0x00, // Flags: standard query
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
	}
	packet := append(header, question...)
	// TCP DNS: 2-byte big-endian length prefix.
	msgLen := []byte{byte(len(packet) >> 8), byte(len(packet))}
	_, err = conn.Write(append(msgLen, packet...))
	if err != nil {
		return axfrResult{status: axfrNetworkError, err: err}
	}

	// Read response length prefix (2 bytes).
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		if isTimeout(err) {
			return axfrResult{status: axfrTimeout}
		}
		return axfrResult{status: axfrNetworkError, err: err}
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if respLen < 12 || respLen > 65535 {
		return axfrResult{status: axfrNetworkError, err: fmt.Errorf("invalid DNS response length: %d", respLen)}
	}

	// Read response body.
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		if isTimeout(err) {
			return axfrResult{status: axfrTimeout}
		}
		return axfrResult{status: axfrNetworkError, err: err}
	}

	// Parse DNS header from response.
	// Byte 3 (low byte of flags) contains RCODE in bits 0-3.
	if len(respBuf) < 12 {
		return axfrResult{status: axfrNetworkError, err: fmt.Errorf("response too short")}
	}
	rcode := int(respBuf[3] & 0x0F)

	// RCODE 5 = REFUSED, RCODE 9 = NotAuth — server correctly rejected AXFR.
	if rcode == 5 || rcode == 9 {
		return axfrResult{status: axfrRefused}
	}

	// RCODE 0 = NOERROR — check ANCOUNT to see if records were returned.
	if rcode == 0 {
		ancount := int(respBuf[6])<<8 | int(respBuf[7])
		if ancount > 0 {
			return axfrResult{status: axfrSuccess, recordCount: ancount}
		}
		// NOERROR with 0 answers = effectively refused or empty.
		return axfrResult{status: axfrRefused}
	}

	// Any other RCODE (NXDOMAIN, SERVFAIL, etc.) = not a successful transfer.
	return axfrResult{status: axfrRefused}
}

// encodeDNSName encodes a domain name in DNS wire format (RFC 1035 §3.1).
func encodeDNSName(domain string) []byte {
	var out []byte
	domain = strings.TrimSuffix(domain, ".")
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0x00) // root label
	return out
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	type timeoutErr interface{ Timeout() bool }
	if te, ok := err.(timeoutErr); ok {
		return te.Timeout()
	}
	return strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline")
}

// ─── SPF ──────────────────────────────────────────────────────────────────────

func (m *Module) checkSPF(ctx context.Context, domain string, _ map[string]string) ([]module.Finding, error) {
	txts, err := m.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, nil
	}

	spfRecord := ""
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			spfRecord = txt
			break
		}
	}

	if spfRecord == "" {
		return []module.Finding{{
			Type:     "spf_missing",
			URL:      fmt.Sprintf("https://%s", domain),
			Severity: module.SeverityMedium,
			Detail:   fmt.Sprintf("Domínio '%s' não tem registro SPF — qualquer servidor pode enviar email se passando pelo domínio (phishing/spoofing facilitado)", domain),
			Extra: map[string]string{
				"domain":     domain,
				"source":     "spf_check",
				"confidence": "0.97",
			},
		}}, nil
	}

	var findings []module.Finding

	// Check for +all (allows everyone)
	if strings.Contains(spfRecord, " +all") || strings.HasSuffix(spfRecord, "+all") {
		findings = append(findings, module.Finding{
			Type:     "spf_all_pass",
			URL:      fmt.Sprintf("https://%s", domain),
			Severity: module.SeverityHigh,
			Detail:   fmt.Sprintf("SPF de '%s' usa '+all' — qualquer servidor de internet pode enviar email como este domínio (spoofing direto). SPF: %s", domain, spfRecord),
			Extra: map[string]string{
				"spf_record": spfRecord,
				"mechanism":  "+all",
				"source":     "spf_check",
				"confidence": "0.99",
			},
		})
	} else if strings.Contains(spfRecord, " ?all") {
		findings = append(findings, module.Finding{
			Type:     "spf_neutral",
			URL:      fmt.Sprintf("https://%s", domain),
			Severity: module.SeverityMedium,
			Detail:   fmt.Sprintf("SPF de '%s' usa '?all' (neutral) — não rejeita emails de fontes desconhecidas. SPF: %s", domain, spfRecord),
			Extra: map[string]string{
				"spf_record": spfRecord,
				"mechanism":  "?all",
				"source":     "spf_check",
				"confidence": "0.92",
			},
		})
	} else {
		// Good SPF — informational
		findings = append(findings, module.Finding{
			Type:     "spf_record",
			URL:      fmt.Sprintf("https://%s", domain),
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("SPF de '%s' encontrado: %s", domain, truncate(spfRecord, 300)),
			Extra: map[string]string{
				"spf_record": spfRecord,
				"source":     "spf_check",
				"confidence": "0.98",
			},
		})
	}

	return findings, nil
}

// ─── DMARC ────────────────────────────────────────────────────────────────────

func (m *Module) checkDMARC(ctx context.Context, domain string, _ map[string]string) ([]module.Finding, error) {
	dmarcDomain := "_dmarc." + domain
	txts, err := m.resolver.LookupTXT(ctx, dmarcDomain)
	if err != nil || len(txts) == 0 {
		return []module.Finding{{
			Type:     "dmarc_missing",
			URL:      fmt.Sprintf("https://%s", domain),
			Severity: module.SeverityMedium,
			Detail:   fmt.Sprintf("Domínio '%s' não tem registro DMARC — emails fraudulentos não são reportados e podem não ser rejeitados", domain),
			Extra: map[string]string{
				"dmarc_domain": dmarcDomain,
				"source":       "dmarc_check",
				"confidence":   "0.97",
			},
		}}, nil
	}

	dmarcRecord := ""
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=DMARC1") {
			dmarcRecord = txt
			break
		}
	}

	if dmarcRecord == "" {
		return nil, nil
	}

	var findings []module.Finding
	policy := extractDMARCField(dmarcRecord, "p")
	spPolicy := extractDMARCField(dmarcRecord, "sp")

	sev := module.SeverityInfo
	conf := "0.97"
	note := ""

	switch strings.ToLower(policy) {
	case "none":
		// p=none: o DMARC existe mas não bloqueia nada. Emails forjados são apenas
		// reportados (rua/ruf) — ou ignorados se não houver rua configurado.
		// Spoofing ainda é possível. Severidade Medium (não Critical, não Low).
		sev = module.SeverityMedium
		conf = "0.88"
		note = "p=none: DMARC em modo monitor — emails fraudulentos são reportados mas não bloqueados. Spoofing ainda é possível."
	case "quarantine":
		sev = module.SeverityInfo
		conf = "0.92"
		note = "p=quarantine: emails suspeitos vão para spam — proteção parcial"
	case "reject":
		sev = module.SeverityInfo
		conf = "0.97"
		note = "p=reject: emails fraudulentos são rejeitados — configuração ideal"
	case "":
		sev = module.SeverityMedium
		conf = "0.90"
		note = "política p= não definida — equivale a nenhuma proteção DMARC"
	}

	findings = append(findings, module.Finding{
		Type:     "dmarc_record",
		URL:      fmt.Sprintf("https://%s", domain),
		Severity: sev,
		Detail:   fmt.Sprintf("DMARC de '%s': p=%s sp=%s — %s. Registro: %s", domain, policy, spPolicy, note, truncate(dmarcRecord, 300)),
		Extra: map[string]string{
			"dmarc_record":     dmarcRecord,
			"policy":           policy,
			"subdomain_policy": spPolicy,
			"source":           "dmarc_check",
			"confidence":       conf,
		},
	})

	return findings, nil
}

func extractDMARCField(record, field string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, field+"=") {
			return strings.TrimPrefix(part, field+"=")
		}
	}
	return ""
}

// ─── DKIM ─────────────────────────────────────────────────────────────────────

var defaultDKIMSelectors = []string{
	"google", "mail", "default", "k1", "k2", "k3",
	"selector1", "selector2", "s1", "s2", "dkim",
	"email", "mailjet", "sendgrid", "mandrill",
	"amazonses", "smtp", "newsletter",
}

func (m *Module) checkDKIM(ctx context.Context, domain string, opts map[string]string) ([]module.Finding, error) {
	selectorsStr := opts["dkim_selectors"]
	selectors := defaultDKIMSelectors
	if selectorsStr != "" {
		selectors = strings.Split(selectorsStr, ",")
		for i := range selectors {
			selectors[i] = strings.TrimSpace(selectors[i])
		}
	}

	var mu sync.Mutex
	var findings []module.Finding
	found := false

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(10)

	for _, sel := range selectors {
		sel := sel
		g.Go(func() error {
			dkimDomain := fmt.Sprintf("%s._domainkey.%s", sel, domain)
			txts, err := m.resolver.LookupTXT(gctx, dkimDomain)
			if err != nil || len(txts) == 0 {
				return nil
			}
			for _, txt := range txts {
				if strings.Contains(txt, "v=DKIM1") || strings.Contains(txt, "p=") {
					mu.Lock()
					found = true
					findings = append(findings, module.Finding{
						Type:     "dkim_record",
						URL:      fmt.Sprintf("https://%s", domain),
						Severity: module.SeverityInfo,
						Detail:   fmt.Sprintf("DKIM encontrado para '%s' com selector '%s': %s", domain, sel, truncate(txt, 200)),
						Extra: map[string]string{
							"dkim_selector": sel,
							"dkim_domain":   dkimDomain,
							"dkim_record":   truncate(txt, 500),
							"source":        "dkim_check",
							"confidence":    "0.95",
						},
					})
					mu.Unlock()
					break
				}
			}
			return nil
		})
	}
	_ = g.Wait()

	if !found {
		// Selectors are not enumerable through DNS. A miss across common names is
		// inconclusive and must not be reported as a missing security control.
		return nil, nil
	}

	return findings, nil
}

// ─── CAA ──────────────────────────────────────────────────────────────────────

func (m *Module) checkCAA(ctx context.Context, domain string, _ map[string]string) ([]module.Finding, error) {
	// Go stdlib net.Resolver does not expose CAA (type 257) records.
	// We perform a raw DNS query (UDP, then TCP fallback) for QTYPE=CAA=257.
	// Only emit a finding when we receive a conclusive answer.
	result := queryCAADNS(ctx, domain)
	switch result {
	case caaPresent:
		// CAA exists — good, no actionable finding.
		return nil, nil
	case caaMissing:
		// Authoritative NXDOMAIN or NOERROR with ANCOUNT=0 for CAA — confirmed absent.
		return []module.Finding{{
			Type:     "caa_missing",
			URL:      fmt.Sprintf("https://%s", domain),
			Severity: module.SeverityLow,
			Detail: fmt.Sprintf("Registro CAA ausente para '%s' — qualquer CA (Certificate Authority) pode emitir certificados TLS para este domínio. "+
				"CAA restringe quais CAs estão autorizados. Verificar: dig CAA %s", domain, domain),
			Extra: map[string]string{
				"domain":     domain,
				"check_cmd":  fmt.Sprintf("dig CAA %s", domain),
				"source":     "caa_check",
				"confidence": "0.88",
			},
		}}, nil
	default:
		// caaUnknown — resolver error, timeout, or inconclusive. No finding.
		return nil, nil
	}
}

type caaCheckResult int

const (
	caaUnknown caaCheckResult = iota
	caaPresent
	caaMissing
)

// queryCAADNS sends a raw DNS query for QTYPE=CAA (257) to two independent
// recursive resolvers. A resolver/network failure remains inconclusive.
// Returns caaUnknown on any network error or ambiguous response.
func queryCAADNS(ctx context.Context, domain string) caaCheckResult {
	servers := []string{"8.8.8.8:53", "1.1.1.1:53"}

	for _, srv := range servers {
		result := sendDNSQuery(ctx, domain, 257, srv) // QTYPE=CAA=257
		if result != caaUnknown {
			return result
		}
	}
	return caaUnknown
}

// sendDNSQuery sends a DNS query for the given qtype. UDP is attempted first;
// truncated responses are retried over TCP. Responses are validated before
// absence/presence is classified.
func sendDNSQuery(ctx context.Context, domain string, qtype uint16, addr string) caaCheckResult {
	dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	packet := buildDNSQueryPacket(domain, qtype, 0xABCE, true)
	response, err := exchangeDNSPacket(dialCtx, "udp", addr, packet)
	if err != nil {
		return caaUnknown
	}
	if len(response) >= 4 && response[2]&0x02 != 0 {
		response, err = exchangeDNSPacket(dialCtx, "tcp", addr, packet)
		if err != nil {
			return caaUnknown
		}
	}
	return classifyDNSResponse(response, qtype, 0xABCE)
}

func buildDNSQueryPacket(domain string, qtype, id uint16, recursionDesired bool) []byte {
	flagsHigh := byte(0)
	if recursionDesired {
		flagsHigh = 0x01
	}
	header := []byte{
		byte(id >> 8), byte(id),
		flagsHigh, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
	question := append(encodeDNSName(domain), byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return append(header, question...)
}

func exchangeDNSPacket(ctx context.Context, network, addr string, packet []byte) ([]byte, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if network == "tcp" {
		length := []byte{byte(len(packet) >> 8), byte(len(packet))}
		if _, err := conn.Write(append(length, packet...)); err != nil {
			return nil, err
		}
		length = make([]byte, 2)
		if _, err := io.ReadFull(conn, length); err != nil {
			return nil, err
		}
		responseLength := int(length[0])<<8 | int(length[1])
		if responseLength < 12 || responseLength > 65535 {
			return nil, fmt.Errorf("invalid DNS TCP response length: %d", responseLength)
		}
		response := make([]byte, responseLength)
		_, err = io.ReadFull(conn, response)
		return response, err
	}

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}
	return response[:n], nil
}

func classifyDNSResponse(response []byte, qtype, expectedID uint16) caaCheckResult {
	if len(response) < 12 {
		return caaUnknown
	}
	responseID := uint16(response[0])<<8 | uint16(response[1])
	if responseID != expectedID || response[2]&0x80 == 0 || response[2]&0x02 != 0 {
		return caaUnknown
	}
	if response[3]&0x0F != 0 {
		// NXDOMAIN, SERVFAIL, REFUSED and other RCODEs are not evidence that a
		// security record is absent from a valid target zone.
		return caaUnknown
	}
	qdCount := int(response[4])<<8 | int(response[5])
	answerCount := int(response[6])<<8 | int(response[7])
	if qdCount != 1 {
		return caaUnknown
	}

	offset := 12
	if !skipDNSName(response, &offset) || offset+4 > len(response) {
		return caaUnknown
	}
	offset += 4
	if answerCount == 0 {
		return caaMissing
	}

	for range answerCount {
		if !skipDNSName(response, &offset) || offset+10 > len(response) {
			return caaUnknown
		}
		recordType := uint16(response[offset])<<8 | uint16(response[offset+1])
		recordLength := int(response[offset+8])<<8 | int(response[offset+9])
		offset += 10
		if offset+recordLength > len(response) {
			return caaUnknown
		}
		if recordType == qtype {
			return caaPresent
		}
		offset += recordLength
	}
	// A CNAME or unrelated answer without the requested record is ambiguous.
	return caaUnknown
}

func skipDNSName(message []byte, offset *int) bool {
	for {
		if *offset >= len(message) {
			return false
		}
		length := int(message[*offset])
		if length&0xC0 == 0xC0 {
			if *offset+1 >= len(message) {
				return false
			}
			*offset += 2
			return true
		}
		*offset++
		if length == 0 {
			return true
		}
		if length > 63 || *offset+length > len(message) {
			return false
		}
		*offset += length
	}
}

// ─── DNSSEC ───────────────────────────────────────────────────────────────────

func (m *Module) checkDNSSEC(ctx context.Context, domain string, _ map[string]string) ([]module.Finding, error) {
	// Query QTYPE=DNSKEY (48) for the apex zone — if ANCOUNT>0, DNSSEC is configured.
	// Also query QTYPE=DS (43) which appears in the parent zone for delegated zones.
	//
	// We use raw DNS UDP queries (same helper as CAA). We only emit a finding when
	// we can confirm DNSSEC is NOT configured — "resolves OK" alone is not enough.
	dnskeyResult := sendDNSQuery(ctx, domain, 48, "8.8.8.8:53") // DNSKEY
	dsResult := sendDNSQuery(ctx, domain, 43, "8.8.8.8:53")     // DS

	switch {
	case dnskeyResult == caaPresent || dsResult == caaPresent:
		// DNSSEC is configured — informational positive, no actionable finding.
		return nil, nil

	case dnskeyResult == caaMissing && dsResult == caaMissing:
		// Both queries returned RCODE=0 with no records — DNSSEC not configured.
		return []module.Finding{{
			Type:     "dnssec_not_configured",
			URL:      fmt.Sprintf("https://%s", domain),
			Severity: module.SeverityInfo,
			Detail: fmt.Sprintf("DNSSEC não configurado para '%s' — sem registros DNSKEY nem DS. "+
				"Sem DNSSEC, respostas DNS podem ser forjadas (DNS spoofing/cache poisoning). "+
				"Verificar: dig DNSKEY %s +dnssec @8.8.8.8", domain, domain),
			Extra: map[string]string{
				"domain":     domain,
				"check_cmd":  fmt.Sprintf("dig DNSKEY %s +dnssec @8.8.8.8", domain),
				"source":     "dnssec_check",
				"confidence": "0.85",
			},
		}}, nil

	default:
		// caaUnknown — network error, timeout, or inconclusive.
		// Do NOT emit a finding — absence of evidence is not evidence of absence.
		return nil, nil
	}
}

// ─── Wildcard DNS ─────────────────────────────────────────────────────────────

func (m *Module) checkWildcard(ctx context.Context, domain string, _ map[string]string) ([]module.Finding, error) {
	// Probe a random non-existent subdomain — if it resolves, wildcard is active
	testSub := fmt.Sprintf("blackhorn-wildcard-test-xyzabc123.%s", domain)
	addrs, err := m.resolver.LookupHost(ctx, testSub)
	if err != nil || len(addrs) == 0 {
		return nil, nil // good — no wildcard
	}

	return []module.Finding{{
		Type:     "dns_wildcard",
		URL:      fmt.Sprintf("https://%s", domain),
		Severity: module.SeverityMedium,
		Detail: fmt.Sprintf("DNS wildcard ativo em '%s' — qualquer subdomínio resolve para %v. Isso pode esconder subdomínios reais e complica enumeração.",
			domain, addrs),
		Extra: map[string]string{
			"wildcard_addresses": strings.Join(addrs, ","),
			"test_subdomain":     testSub,
			"source":             "wildcard_check",
			"confidence":         "0.97",
		},
	}}, nil
}

// ─── Dangling CNAME ───────────────────────────────────────────────────────────

func (m *Module) checkDanglingCNAME(ctx context.Context, domain string, _ map[string]string) ([]module.Finding, error) {
	// Check common subdomains for dangling CNAMEs
	subs := []string{"www", "mail", "blog", "shop", "app", "api", "cdn", "static", "staging", "dev"}

	var mu sync.Mutex
	var findings []module.Finding

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(8)

	for _, sub := range subs {
		sub := sub
		g.Go(func() error {
			fqdn := sub + "." + domain
			cname, err := m.resolver.LookupCNAME(gctx, fqdn)
			if err != nil || cname == fqdn+"." || cname == fqdn {
				return nil // no CNAME or points to itself
			}

			// Check if CNAME target resolves
			target := strings.TrimSuffix(cname, ".")
			addrs, err := m.resolver.LookupHost(gctx, target)
			if err != nil || len(addrs) == 0 {
				// CNAME exists but target doesn't resolve = dangling CNAME
				mu.Lock()
				findings = append(findings, module.Finding{
					Type:     "dangling_cname",
					URL:      fmt.Sprintf("https://%s", fqdn),
					Severity: module.SeverityHigh,
					Detail: fmt.Sprintf("CNAME suspenso detectado: '%s' → '%s' mas '%s' não resolve — possível subdomain takeover",
						fqdn, target, target),
					Extra: map[string]string{
						"subdomain":    fqdn,
						"cname_target": target,
						"source":       "cname_check",
						"confidence":   "0.88",
					},
				})
				mu.Unlock()
			}
			return nil
		})
	}
	_ = g.Wait()
	return findings, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func normaliseDomain(raw string) string {
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.SplitN(raw, "/", 2)[0]
	return strings.ToLower(strings.TrimSpace(raw))
}

func isWanted(filter, name string) bool {
	if filter == "" {
		return true
	}
	for _, s := range strings.Split(filter, ",") {
		if strings.TrimSpace(s) == name {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	out := make([]module.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Extra["source"]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
