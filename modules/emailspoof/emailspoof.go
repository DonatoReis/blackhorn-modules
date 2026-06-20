// Package emailspoof audits a domain's email authentication posture to determine
// whether it can be spoofed. It checks:
//   - SPF record presence, ~all vs -all strictness, redirect/include chain depth
//   - DMARC presence, policy (none/quarantine/reject), pct, rua/ruf
//   - DKIM selector enumeration via common selectors
//   - BIMI record (brand indicator for message identification)
//   - MTA-STS record and policy file
//   - SMTP TLS reporting (TLS-RPT)
//   - Combination scoring: domain that has no DMARC or DMARC p=none is spoofable
//
// Source references (algorithm/analysis design, no code copied):
//   - IETF RFC 7208 (SPF), RFC 7489 (DMARC), RFC 6376 (DKIM)
//   - PortSwigger Web Security Academy — Email spoofing
//   - emailspooftest.com methodology
//   - checkdmarc (MIT, domainaware/checkdmarc) — DMARC analysis approach
//
// Architecture:
//   - errgroup.SetLimit for parallel DNS lookups          (guia-go §9)
//   - net.Resolver with context                           (guia-go §9)
//   - log/slog structured observability                   (dicas.md §16)
//   - confidence scoring per dicas.md §4
package emailspoof

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

// Common DKIM selectors to enumerate.
var dkimSelectors = []string{
	"default", "google", "mail", "k1", "k2", "selector1", "selector2",
	"dkim", "dkim1", "dkim2", "s1", "s2", "email", "smtp",
	"mxvault", "pm", "postmaster", "sendgrid", "mailchimp", "mandrill",
	"amazonses", "ses", "key1", "key2", "em", "em1", "em2",
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements the emailspoof module.
type Module struct {
	resolver *net.Resolver
	logger   *slog.Logger
}

// New creates an emailspoof module with the default system resolver.
func New() *Module {
	return &Module{
		resolver: net.DefaultResolver,
		logger:   slog.Default(),
	}
}

// NewWithResolver creates an emailspoof module with a custom resolver (for tests).
func NewWithResolver(r *net.Resolver) *Module {
	return &Module{resolver: r, logger: slog.Default()}
}

func (m *Module) Name() string { return "emailspoof" }

// Run audits domain's email authentication for spoofability.
//
// Options:
//   - dkim_selectors: comma-separated extra selectors to test (added to builtins)
//   - check_dkim:     "false" to skip DKIM selector enumeration (default: true)
//   - check_bimi:     "false" to skip BIMI check (default: true)
//   - check_mta_sts:  "false" to skip MTA-STS check (default: true)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	domain := strings.TrimSpace(input.Target)
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "www.")
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	if domain == "" {
		return nil, fmt.Errorf("emailspoof: target domain is required")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}
	checkDKIM := optBool(opts, "check_dkim", true)
	checkBIMI := optBool(opts, "check_bimi", true)
	checkMTASTS := optBool(opts, "check_mta_sts", true)
	extraSelectors := parseCSV(optStr(opts, "dkim_selectors", ""))

	m.logger.InfoContext(ctx, "emailspoof: starting", "domain", domain)

	var (
		mu       sync.Mutex
		findings []module.Finding
	)
	add := func(ff ...module.Finding) {
		mu.Lock()
		findings = append(findings, ff...)
		mu.Unlock()
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(8)

	// ── SPF ──────────────────────────────────────────────────────────────────
	eg.Go(func() error {
		add(m.checkSPF(egCtx, domain)...)
		return nil
	})

	// ── DMARC ────────────────────────────────────────────────────────────────
	eg.Go(func() error {
		add(m.checkDMARC(egCtx, domain)...)
		return nil
	})

	// ── DKIM selectors ────────────────────────────────────────────────────────
	if checkDKIM {
		selectors := append(dkimSelectors, sliceFromMap(extraSelectors)...)
		eg.Go(func() error {
			add(m.checkDKIM(egCtx, domain, selectors)...)
			return nil
		})
	}

	// ── BIMI ─────────────────────────────────────────────────────────────────
	if checkBIMI {
		eg.Go(func() error {
			add(m.checkBIMI(egCtx, domain)...)
			return nil
		})
	}

	// ── MTA-STS + TLS-RPT ────────────────────────────────────────────────────
	if checkMTASTS {
		eg.Go(func() error {
			add(m.checkMTASTS(egCtx, domain)...)
			return nil
		})
		eg.Go(func() error {
			add(m.checkTLSRPT(egCtx, domain)...)
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return findings, err
	}

	// ── Spoofability summary ──────────────────────────────────────────────────
	add(m.spoofabilitySummary(domain, findings)...)

	return findings, nil
}

// ─── SPF ─────────────────────────────────────────────────────────────────────

func (m *Module) checkSPF(ctx context.Context, domain string) []module.Finding {
	txts, err := m.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return []module.Finding{{
			Type:     "spf_lookup_failed",
			URL:      "dns://" + domain,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("[emailspoof] SPF: DNS lookup failed for %s — %v", domain, err),
			Extra:    map[string]string{"confidence": "0.99", "fonte": "emailspoof"},
		}}
	}

	var spfRecord string
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			spfRecord = txt
			break
		}
	}

	if spfRecord == "" {
		return []module.Finding{{
			Type:     "spf_missing",
			URL:      "dns://" + domain,
			Severity: module.SeverityHigh,
			Detail:   fmt.Sprintf("[emailspoof] SPF record missing for %s — domain can be spoofed without SPF policy", domain),
			Extra:    map[string]string{"confidence": "0.99", "fonte": "emailspoof"},
		}}
	}

	var findings []module.Finding

	// Check for ~all (softfail) vs -all (fail)
	switch {
	case strings.Contains(spfRecord, "+all"):
		findings = append(findings, module.Finding{
			Type:     "spf_plus_all",
			URL:      "dns://" + domain,
			Severity: module.SeverityCritical,
			Detail:   fmt.Sprintf("[emailspoof] SPF uses +all — allows ANY server to send as %s (completely open)", domain),
			Extra:    map[string]string{"record": spfRecord, "confidence": "0.99", "fonte": "emailspoof"},
		})
	case strings.Contains(spfRecord, "?all"):
		findings = append(findings, module.Finding{
			Type:     "spf_neutral_all",
			URL:      "dns://" + domain,
			Severity: module.SeverityHigh,
			Detail:   fmt.Sprintf("[emailspoof] SPF uses ?all (neutral) — no enforcement, domain %s can be spoofed", domain),
			Extra:    map[string]string{"record": spfRecord, "confidence": "0.99", "fonte": "emailspoof"},
		})
	case strings.Contains(spfRecord, "~all"):
		findings = append(findings, module.Finding{
			Type:     "spf_softfail",
			URL:      "dns://" + domain,
			Severity: module.SeverityMedium,
			Detail:   fmt.Sprintf("[emailspoof] SPF uses ~all (softfail) for %s — unauthorized senders not rejected, only marked. Recommend -all", domain),
			Extra:    map[string]string{"record": spfRecord, "confidence": "0.99", "fonte": "emailspoof"},
		})
	case strings.Contains(spfRecord, "-all"):
		findings = append(findings, module.Finding{
			Type:     "spf_hardfail",
			URL:      "dns://" + domain,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("[emailspoof] SPF uses -all (hardfail) for %s — unauthorized senders rejected", domain),
			Extra:    map[string]string{"record": spfRecord, "confidence": "0.99", "fonte": "emailspoof"},
		})
	}

	// Check lookup depth (RFC 7208 §4.6.4 limits to 10 DNS lookups)
	depth := strings.Count(spfRecord, "include:") + strings.Count(spfRecord, "redirect=")
	if depth > 7 {
		findings = append(findings, module.Finding{
			Type:     "spf_lookup_depth",
			URL:      "dns://" + domain,
			Severity: module.SeverityMedium,
			Detail:   fmt.Sprintf("[emailspoof] SPF has %d include/redirect mechanisms — approaching RFC 7208 limit of 10 DNS lookups (risk of PermError)", depth),
			Extra:    map[string]string{"record": spfRecord, "depth": fmt.Sprintf("%d", depth), "confidence": "0.90", "fonte": "emailspoof"},
		})
	}

	return findings
}

// ─── DMARC ───────────────────────────────────────────────────────────────────

func (m *Module) checkDMARC(ctx context.Context, domain string) []module.Finding {
	dmarcDomain := "_dmarc." + domain
	txts, err := m.resolver.LookupTXT(ctx, dmarcDomain)
	if err != nil || len(txts) == 0 {
		return []module.Finding{{
			Type:     "dmarc_missing",
			URL:      "dns://" + dmarcDomain,
			Severity: module.SeverityHigh,
			Detail:   fmt.Sprintf("[emailspoof] DMARC record missing at %s — domain can be spoofed (no policy enforcement)", dmarcDomain),
			Extra:    map[string]string{"confidence": "0.99", "fonte": "emailspoof"},
		}}
	}

	var dmarcRecord string
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=DMARC1") {
			dmarcRecord = txt
			break
		}
	}
	if dmarcRecord == "" {
		return []module.Finding{{
			Type:     "dmarc_invalid",
			URL:      "dns://" + dmarcDomain,
			Severity: module.SeverityHigh,
			Detail:   fmt.Sprintf("[emailspoof] DMARC TXT record at %s does not start with v=DMARC1 — invalid record", dmarcDomain),
			Extra:    map[string]string{"record": strings.Join(txts, " "), "confidence": "0.95", "fonte": "emailspoof"},
		}}
	}

	var findings []module.Finding
	policy := extractTag(dmarcRecord, "p")
	subPolicy := extractTag(dmarcRecord, "sp")
	pct := extractTag(dmarcRecord, "pct")
	rua := extractTag(dmarcRecord, "rua")

	switch policy {
	case "none":
		findings = append(findings, module.Finding{
			Type:     "dmarc_policy_none",
			URL:      "dns://" + dmarcDomain,
			Severity: module.SeverityMedium,
			Detail: fmt.Sprintf("[emailspoof] DMARC p=none for %s — monitoring only; messages are not rejected by DMARC. "+
				"This increases spoofing risk but does not prove successful impersonation or delivery.", domain),
			Extra: map[string]string{"record": dmarcRecord, "policy": "none", "confidence": "0.99", "fonte": "emailspoof"},
		})
	case "quarantine":
		findings = append(findings, module.Finding{
			Type:     "dmarc_policy_quarantine",
			URL:      "dns://" + dmarcDomain,
			Severity: module.SeverityLow,
			Detail:   fmt.Sprintf("[emailspoof] DMARC p=quarantine for %s — spoofed emails go to spam (not rejected)", domain),
			Extra:    map[string]string{"record": dmarcRecord, "policy": "quarantine", "confidence": "0.99", "fonte": "emailspoof"},
		})
	case "reject":
		findings = append(findings, module.Finding{
			Type:     "dmarc_policy_reject",
			URL:      "dns://" + dmarcDomain,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("[emailspoof] DMARC p=reject for %s — strongest enforcement; spoofed emails are rejected", domain),
			Extra:    map[string]string{"record": dmarcRecord, "policy": "reject", "confidence": "0.99", "fonte": "emailspoof"},
		})
	default:
		findings = append(findings, module.Finding{
			Type:     "dmarc_policy_unknown",
			URL:      "dns://" + dmarcDomain,
			Severity: module.SeverityMedium,
			Detail:   fmt.Sprintf("[emailspoof] DMARC policy is %q (unknown) for %s — cannot determine enforcement level", policy, domain),
			Extra:    map[string]string{"record": dmarcRecord, "confidence": "0.85", "fonte": "emailspoof"},
		})
	}

	// Subdomain policy fallback
	if subPolicy == "" || subPolicy == "none" {
		findings = append(findings, module.Finding{
			Type:     "dmarc_subdomain_none",
			URL:      "dns://" + dmarcDomain,
			Severity: module.SeverityMedium,
			Detail:   fmt.Sprintf("[emailspoof] DMARC sp= not set or sp=none for %s — subdomains may be spoofable", domain),
			Extra:    map[string]string{"sp": subPolicy, "confidence": "0.90", "fonte": "emailspoof"},
		})
	}

	// pct < 100 = partial enforcement
	if pct != "" && pct != "100" {
		findings = append(findings, module.Finding{
			Type:     "dmarc_partial_pct",
			URL:      "dns://" + dmarcDomain,
			Severity: module.SeverityLow,
			Detail:   fmt.Sprintf("[emailspoof] DMARC pct=%s for %s — policy applies to only %s%% of messages", pct, domain, pct),
			Extra:    map[string]string{"pct": pct, "confidence": "0.99", "fonte": "emailspoof"},
		})
	}

	// No rua = no aggregate reports
	if rua == "" {
		findings = append(findings, module.Finding{
			Type:     "dmarc_no_reports",
			URL:      "dns://" + dmarcDomain,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("[emailspoof] DMARC rua= not set for %s — no aggregate reports, visibility into spoofing attempts is blind", domain),
			Extra:    map[string]string{"confidence": "0.95", "fonte": "emailspoof"},
		})
	}

	return findings
}

// ─── DKIM ────────────────────────────────────────────────────────────────────

func (m *Module) checkDKIM(ctx context.Context, domain string, selectors []string) []module.Finding {
	var (
		mu      sync.Mutex
		found   []string
		missing []string
	)

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(10)

	for _, sel := range selectors {
		sel := sel
		eg.Go(func() error {
			dkimDomain := sel + "._domainkey." + domain
			txts, err := m.resolver.LookupTXT(egCtx, dkimDomain)
			mu.Lock()
			defer mu.Unlock()
			if err == nil && len(txts) > 0 {
				for _, txt := range txts {
					if strings.Contains(txt, "v=DKIM1") || strings.Contains(txt, "p=") {
						found = append(found, sel)
						return nil
					}
				}
			}
			missing = append(missing, sel)
			return nil
		})
	}
	_ = eg.Wait()

	if len(found) == 0 {
		// DKIM selectors are administrator-defined. Failing to find a small list of
		// common selectors cannot establish that DKIM is absent.
		return nil
	}

	return []module.Finding{{
		Type:     "dkim_selectors_found",
		URL:      "dns://" + domain,
		Severity: module.SeverityInfo,
		Detail:   fmt.Sprintf("[emailspoof] DKIM active selectors for %s: %s", domain, strings.Join(found, ", ")),
		Extra: map[string]string{
			"selectors":       strings.Join(found, ","),
			"selectors_count": fmt.Sprintf("%d", len(found)),
			"confidence":      "0.95",
			"fonte":           "emailspoof",
		},
	}}
}

// ─── BIMI ────────────────────────────────────────────────────────────────────

func (m *Module) checkBIMI(ctx context.Context, domain string) []module.Finding {
	bimiDomain := "default._bimi." + domain
	txts, err := m.resolver.LookupTXT(ctx, bimiDomain)
	if err != nil || len(txts) == 0 {
		return []module.Finding{{
			Type:     "bimi_missing",
			URL:      "dns://" + bimiDomain,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("[emailspoof] BIMI record not found at %s — no brand indicator configured", bimiDomain),
			Extra:    map[string]string{"confidence": "0.99", "fonte": "emailspoof"},
		}}
	}

	return []module.Finding{{
		Type:     "bimi_found",
		URL:      "dns://" + bimiDomain,
		Severity: module.SeverityInfo,
		Detail:   fmt.Sprintf("[emailspoof] BIMI record found for %s", domain),
		Extra:    map[string]string{"record": txts[0], "confidence": "0.99", "fonte": "emailspoof"},
	}}
}

// ─── MTA-STS ─────────────────────────────────────────────────────────────────

func (m *Module) checkMTASTS(ctx context.Context, domain string) []module.Finding {
	mtaDomain := "_mta-sts." + domain
	txts, err := m.resolver.LookupTXT(ctx, mtaDomain)
	if err != nil || len(txts) == 0 {
		return []module.Finding{{
			Type:     "mta_sts_missing",
			URL:      "dns://" + mtaDomain,
			Severity: module.SeverityLow,
			Detail:   fmt.Sprintf("[emailspoof] MTA-STS record missing for %s — SMTP downgrade attacks not mitigated", domain),
			Extra:    map[string]string{"confidence": "0.99", "fonte": "emailspoof"},
		}}
	}

	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=STSv1") {
			return []module.Finding{{
				Type:     "mta_sts_found",
				URL:      "dns://" + mtaDomain,
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("[emailspoof] MTA-STS configured for %s — SMTP TLS enforcement active", domain),
				Extra:    map[string]string{"record": txt, "confidence": "0.99", "fonte": "emailspoof"},
			}}
		}
	}

	return nil
}

// ─── TLS-RPT ─────────────────────────────────────────────────────────────────

func (m *Module) checkTLSRPT(ctx context.Context, domain string) []module.Finding {
	tlsDomain := "_smtp._tls." + domain
	txts, err := m.resolver.LookupTXT(ctx, tlsDomain)
	if err != nil || len(txts) == 0 {
		return []module.Finding{{
			Type:     "tls_rpt_missing",
			URL:      "dns://" + tlsDomain,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("[emailspoof] TLS-RPT (RFC 8460) not configured for %s — no SMTP TLS failure reports", domain),
			Extra:    map[string]string{"confidence": "0.99", "fonte": "emailspoof"},
		}}
	}

	return []module.Finding{{
		Type:     "tls_rpt_found",
		URL:      "dns://" + tlsDomain,
		Severity: module.SeverityInfo,
		Detail:   fmt.Sprintf("[emailspoof] TLS-RPT configured for %s", domain),
		Extra:    map[string]string{"record": txts[0], "confidence": "0.99", "fonte": "emailspoof"},
	}}
}

// ─── Spoofability summary ─────────────────────────────────────────────────────

// spoofabilitySummary emits a high-level verdict after all checks complete.
//
// Severity grading:
//   - Critical: SPF +all (open relay — any server can send) OR both SPF and DMARC missing
//   - High:     SPF missing alone (DMARC could still partially protect), or DMARC missing alone
//   - Medium:   DMARC p=none (monitoring mode — spoofing is possible but not trivially confirmed)
//   - Info:     SPF + DMARC enforcement active
//
// IMPORTANT: p=none increases spoofing risk but does NOT prove successful delivery.
// It means the domain owner has not yet enabled enforcement — it is a configuration
// gap, not a confirmed vulnerability. Use High or Medium, never Critical for p=none alone.
func (m *Module) spoofabilitySummary(domain string, existing []module.Finding) []module.Finding {
	hasSPFMissing := containsType(existing, "spf_missing")
	hasSPFPlusAll := containsType(existing, "spf_plus_all")
	hasDMARCMissing := containsType(existing, "dmarc_missing")
	hasDMARCNone := containsType(existing, "dmarc_policy_none")

	var verdict, detail string
	var severity module.Severity
	var reasons []string
	spoofable := hasSPFMissing || hasSPFPlusAll || hasDMARCMissing || hasDMARCNone

	switch {
	case hasSPFPlusAll:
		// +all = any server can send — highest risk regardless of DMARC.
		severity = module.SeverityCritical
		verdict = "HIGHLY_SPOOFABLE"
		reasons = append(reasons, "SPF +all (open relay — any mail server can impersonate this domain)")
		if hasDMARCMissing {
			reasons = append(reasons, "DMARC missing")
		} else if hasDMARCNone {
			reasons = append(reasons, "DMARC p=none (no enforcement)")
		}

	case hasSPFMissing && hasDMARCMissing:
		// Both missing — maximum exposure.
		severity = module.SeverityCritical
		verdict = "HIGHLY_SPOOFABLE"
		reasons = append(reasons, "SPF missing", "DMARC missing")

	case hasSPFMissing && hasDMARCNone:
		// SPF missing + DMARC in monitor mode — high risk.
		severity = module.SeverityHigh
		verdict = "SPOOFABLE"
		reasons = append(reasons, "SPF missing", "DMARC p=none (no enforcement)")

	case hasSPFMissing:
		severity = module.SeverityHigh
		verdict = "SPOOFABLE"
		reasons = append(reasons, "SPF missing")

	case hasDMARCMissing:
		severity = module.SeverityHigh
		verdict = "SPOOFABLE"
		reasons = append(reasons, "DMARC missing")

	case hasDMARCNone:
		// DMARC exists but in monitor mode — increased risk but not confirmed spoofable.
		// SPF is present and syntactically correct, so MTA-level filtering may apply.
		severity = module.SeverityMedium
		verdict = "AT_RISK"
		reasons = append(reasons, "DMARC p=none (monitoring mode — emails are reported but not rejected)")

	default:
		severity = module.SeverityInfo
		verdict = "PROTECTED"
	}

	if len(reasons) > 0 {
		detail = fmt.Sprintf("[emailspoof] %s is %s — %s", domain, verdict, strings.Join(reasons, "; "))
	} else {
		detail = fmt.Sprintf("[emailspoof] %s is PROTECTED — SPF and DMARC enforcement active", domain)
	}

	return []module.Finding{{
		Type:     "emailspoof_verdict",
		URL:      "dns://" + domain,
		Severity: severity,
		Detail:   detail,
		Extra: map[string]string{
			"verdict":    verdict,
			"spoofable":  fmt.Sprintf("%v", spoofable),
			"confidence": "0.92",
			"fonte":      "emailspoof",
		},
	}}
}

// ─── Utility helpers ──────────────────────────────────────────────────────────

// extractTag extracts a DMARC/SPF tag value: e.g. p=reject → "reject".
func extractTag(record, tag string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, tag+"=") {
			return strings.TrimPrefix(part, tag+"=")
		}
	}
	return ""
}

func containsType(findings []module.Finding, typ string) bool {
	for _, f := range findings {
		if f.Type == typ {
			return true
		}
	}
	return false
}

func parseCSV(s string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		t := strings.TrimSpace(p)
		if t != "" {
			m[t] = true
		}
	}
	return m
}

func sliceFromMap(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func optStr(opts map[string]string, key, def string) string {
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

func optBool(opts map[string]string, key string, def bool) bool {
	if v, ok := opts[key]; ok {
		return v == "true" || v == "1"
	}
	return def
}
