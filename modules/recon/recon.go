// Package recon performs passive reconnaissance by aggregating multiple OSINT
// sources into a unified finding set. It combines subdomain enumeration,
// IP resolution, ASN lookup, WHOIS, certificate transparency, and historical
// URL data into a single pass.
//
// This module is designed to be the "first-pass" recon orchestrator — run it
// before active modules to build the attack surface inventory.
//
// Sources used (all passive/keyless by default):
//   - ct_log:     crt.sh certificate transparency subdomain discovery
//   - wayback:    Wayback Machine CDX historical URL enumeration
//   - hackertarget: HackerTarget host search (free tier)
//   - rapiddns:   RapidDNS public subdomain API
//   - urlscan:    urlscan.io public search API
//   - dns:        stdlib DNS resolution (A/AAAA/MX/NS/TXT)
//   - whois:      WHOIS registrar info via our whois module protocol
//
// Reference: OWASP Amass (Apache-2.0) + projectdiscovery passive sources.
// No source code copied. License: MIT (blackhorn-modules).
package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/urlutil"
	"golang.org/x/sync/errgroup"
)

const (
	defaultTimeout        = 20 * time.Second
	defaultRuntimeSeconds = 90
	maxConcurrentSources  = 8
	maxBodyBytes          = 4 * 1024 * 1024 // 4 MiB
)

// ─── module ──────────────────────────────────────────────────────────────────

// Module performs passive multi-source OSINT reconnaissance.
type Module struct {
	client *http.Client
	// Sources selects which OSINT sources to query.
	// Default: all available keyless sources.
	Sources []string
	// MaxSubdomains caps the total number of unique subdomains returned.
	MaxSubdomains int

	// Overridable base URLs for testing.
	CRTSHBaseURL        string
	WaybackBaseURL      string
	HackerTargetBaseURL string
	RapidDNSBaseURL     string
	URLScanBaseURL      string
}

var defaultSources = []string{
	"ct_log", "wayback", "hackertarget", "rapiddns", "urlscan", "dns",
}

// New returns a Module with all passive sources enabled.
func New() *Module {
	return &Module{
		client:        httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		Sources:       defaultSources,
		MaxSubdomains: 5000,
	}
}

// NewWithClient creates a Module using the provided HTTP client.
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client:        c,
		Sources:       defaultSources,
		MaxSubdomains: 5000,
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "recon" }

// Run implements module.Module.
// Input.Target: apex domain to recon (required).
// Input.URLs: additional domains.
// Input.Options:
//   - "sources": comma-separated source list
//   - "max_subs": max subdomains (default: 5000)
//   - "max_runtime_seconds": global execution budget (default: 90)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	domains := collectDomains(input)
	if len(domains) == 0 {
		return nil, fmt.Errorf("recon: no domains provided")
	}
	maxRuntime := optInt(input.Options, "max_runtime_seconds", defaultRuntimeSeconds)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntime)*time.Second)
	defer cancel()

	sources := m.Sources
	if input.Options != nil {
		if v := input.Options["sources"]; v != "" {
			sources = nil
			for _, s := range strings.Split(v, ",") {
				s = strings.TrimSpace(strings.ToLower(s))
				if s != "" {
					sources = append(sources, s)
				}
			}
		}
	}
	if len(sources) == 0 {
		sources = defaultSources
	}

	maxSubs := m.MaxSubdomains
	if maxSubs <= 0 {
		maxSubs = 5000
	}

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	// Fan out: one goroutine per (domain × source) pair.
	g, gctx := errgroup.WithContext(runCtx)
	g.SetLimit(maxConcurrentSources)

	for _, domain := range domains {
		for _, source := range sources {
			domain, source := domain, source
			g.Go(func() error {
				ff, err := m.querySource(gctx, source, domain)
				if err != nil {
					slog.Debug("recon: source failed", "source", source, "domain", domain, "err", err)
					return nil
				}
				if len(ff) > 0 {
					mu.Lock()
					findings = append(findings, ff...)
					mu.Unlock()
				}
				return nil
			})
		}
	}

	_ = g.Wait()

	deduped := dedupFindings(findings)
	if len(deduped) > maxSubs {
		deduped = deduped[:maxSubs]
	}
	return deduped, nil
}

// ─── source dispatcher ────────────────────────────────────────────────────────

func (m *Module) querySource(ctx context.Context, source, domain string) ([]module.Finding, error) {
	switch source {
	case "ct_log":
		return m.queryCTLog(ctx, domain)
	case "wayback":
		return m.queryWayback(ctx, domain)
	case "hackertarget":
		return m.queryHackerTarget(ctx, domain)
	case "rapiddns":
		return m.queryRapidDNS(ctx, domain)
	case "urlscan":
		return m.queryURLScan(ctx, domain)
	case "dns":
		return m.queryDNS(ctx, domain)
	default:
		return nil, fmt.Errorf("unknown source: %q", source)
	}
}

// ─── CT Log (crt.sh) ─────────────────────────────────────────────────────────

type crtshEntry struct {
	NameValue string `json:"name_value"`
}

func (m *Module) crtshBase() string {
	if m.CRTSHBaseURL != "" {
		return m.CRTSHBaseURL
	}
	return "https://crt.sh"
}

func (m *Module) queryCTLog(ctx context.Context, domain string) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("%s/?q=%%25.%s&output=json", m.crtshBase(), url.QueryEscape(domain))
	body, code, err := m.get(ctx, apiURL)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("crt.sh HTTP %d", code)
	}

	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh parse error: %w", err)
	}

	seen := make(map[string]struct{})
	var findings []module.Finding
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "*.")))
			if name == "" || name == domain {
				continue
			}
			if !strings.HasSuffix(name, "."+domain) {
				continue
			}
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				findings = append(findings, subdomainFinding(name, domain, "ct_log"))
			}
		}
	}
	return findings, nil
}

// ─── Wayback Machine ─────────────────────────────────────────────────────────

type waybackEntry [2]string // [timestamp, URL]

func (m *Module) waybackBase() string {
	if m.WaybackBaseURL != "" {
		return m.WaybackBaseURL
	}
	return "https://web.archive.org"
}

func (m *Module) queryWayback(ctx context.Context, domain string) ([]module.Finding, error) {
	apiURL := fmt.Sprintf(
		"%s/cdx/search/cdx?url=*.%s&output=json&fl=original&collapse=urlkey&limit=1000",
		m.waybackBase(), url.QueryEscape(domain),
	)
	body, code, err := m.get(ctx, apiURL)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("wayback HTTP %d", code)
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("wayback parse error: %w", err)
	}

	seen := make(map[string]struct{})
	var findings []module.Finding
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		canonical, ok := urlutil.CanonicalHTTP(row[0])
		if !ok || !urlutil.InDomainScope(canonical, domain) {
			continue
		}
		parsed, _ := url.Parse(canonical)
		host := strings.ToLower(parsed.Hostname())
		if _, ok := seen[host]; !ok {
			seen[host] = struct{}{}
			findings = append(findings, subdomainFinding(host, domain, "wayback"))
		}
		// Archive references are evidence, not confirmed live endpoints.
		findings = append(findings, module.Finding{
			Type:     "historical_reference",
			URL:      canonical,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("Historical URL found via Wayback Machine for %s", domain),
			Extra: map[string]string{
				"source":             "wayback",
				"domain":             domain,
				"confidence":         "0.85",
				"state":              "historical_unverified",
				"promote_to_context": "false",
			},
		})
	}
	return findings, nil
}

// ─── HackerTarget ─────────────────────────────────────────────────────────────

func (m *Module) hackerTargetBase() string {
	if m.HackerTargetBaseURL != "" {
		return m.HackerTargetBaseURL
	}
	return "https://api.hackertarget.com"
}

func (m *Module) queryHackerTarget(ctx context.Context, domain string) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("%s/hostsearch/?q=%s", m.hackerTargetBase(), url.QueryEscape(domain))
	body, code, err := m.get(ctx, apiURL)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("hackertarget HTTP %d", code)
	}

	seen := make(map[string]struct{})
	var findings []module.Finding
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "error") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		host := urlutil.NormalizeDomain(parts[0])
		if host == "" || host == domain || !strings.HasSuffix(host, "."+domain) {
			continue
		}
		ip := ""
		if len(parts) == 2 {
			ip = strings.TrimSpace(parts[1])
		}
		if _, ok := seen[host]; !ok {
			seen[host] = struct{}{}
			f := subdomainFinding(host, domain, "hackertarget")
			if net.ParseIP(ip) != nil {
				f.Type = "subdomain_resolved"
				f.Detail = fmt.Sprintf("DNS-confirmed subdomain %s resolves to %s via HackerTarget", host, ip)
				f.Extra["ip"] = ip
				f.Extra["addresses"] = ip
				f.Extra["validated"] = "true"
				f.Extra["validation_state"] = "dns_confirmed_by_source"
				f.Extra["confidence"] = "0.95"
				f.Extra["promote_to_context"] = "true"
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// ─── RapidDNS ─────────────────────────────────────────────────────────────────

type rapiddnsResponse struct {
	Subdomains []string `json:"subdomain"`
}

func (m *Module) rapiddnsBase() string {
	if m.RapidDNSBaseURL != "" {
		return m.RapidDNSBaseURL
	}
	return "https://rapiddns.io"
}

func (m *Module) queryRapidDNS(ctx context.Context, domain string) ([]module.Finding, error) {
	// RapidDNS returns JSON from their API endpoint.
	apiURL := fmt.Sprintf("%s/subdomain/%s?full=1&down=1", m.rapiddnsBase(), url.PathEscape(domain))
	body, code, err := m.get(ctx, apiURL)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("rapiddns HTTP %d", code)
	}

	// Parse plain-text response (one subdomain per line).
	seen := make(map[string]struct{})
	var findings []module.Finding
	for _, line := range strings.Split(string(body), "\n") {
		name := strings.ToLower(strings.TrimSpace(line))
		if name == "" || !strings.HasSuffix(name, "."+domain) {
			continue
		}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			findings = append(findings, subdomainFinding(name, domain, "rapiddns"))
		}
	}
	return findings, nil
}

// ─── urlscan.io ───────────────────────────────────────────────────────────────

type urlscanResponse struct {
	Results []struct {
		Page struct {
			Domain string `json:"domain"`
			URL    string `json:"url"`
		} `json:"page"`
	} `json:"results"`
}

func (m *Module) urlscanBase() string {
	if m.URLScanBaseURL != "" {
		return m.URLScanBaseURL
	}
	return "https://urlscan.io"
}

func (m *Module) queryURLScan(ctx context.Context, domain string) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("%s/api/v1/search/?q=domain:%s&size=200", m.urlscanBase(), url.QueryEscape(domain))
	body, code, err := m.get(ctx, apiURL)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("urlscan HTTP %d", code)
	}

	var resp urlscanResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("urlscan parse error: %w", err)
	}

	seen := make(map[string]struct{})
	var findings []module.Finding
	for _, result := range resp.Results {
		host := urlutil.NormalizeDomain(result.Page.Domain)
		if host == "" || (host != domain && !strings.HasSuffix(host, "."+domain)) {
			continue
		}
		if _, ok := seen[host]; !ok {
			seen[host] = struct{}{}
			findings = append(findings, subdomainFinding(host, domain, "urlscan"))
		}
		if result.Page.URL != "" {
			canonical, ok := urlutil.CanonicalHTTP(result.Page.URL)
			if !ok || !urlutil.InDomainScope(canonical, domain) {
				continue
			}
			findings = append(findings, module.Finding{
				Type:     "scan_reference",
				URL:      canonical,
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("URL previously scanned by urlscan.io for %s", domain),
				Extra: map[string]string{
					"source":             "urlscan",
					"domain":             domain,
					"host":               host,
					"confidence":         "0.85",
					"state":              "third_party_scan_unverified",
					"promote_to_context": "false",
				},
			})
		}
	}
	return findings, nil
}

// ─── DNS resolution ───────────────────────────────────────────────────────────

func (m *Module) queryDNS(ctx context.Context, domain string) ([]module.Finding, error) {
	resolver := net.DefaultResolver
	var findings []module.Finding

	// A records.
	addrs, err := resolver.LookupHost(ctx, domain)
	if err == nil {
		for _, addr := range addrs {
			sev := module.SeverityInfo
			if isRFC1918(addr) {
				sev = module.SeverityLow
			}
			findings = append(findings, module.Finding{
				Type:     "dns_record",
				URL:      addr,
				Severity: sev,
				Detail:   fmt.Sprintf("A/AAAA record: %s → %s", domain, addr),
				Extra: map[string]string{
					"source":     "dns",
					"domain":     domain,
					"type":       "A",
					"address":    addr,
					"confidence": "0.80",
				},
			})
		}
	}

	// MX records.
	mxs, err := resolver.LookupMX(ctx, domain)
	if err == nil {
		for _, mx := range mxs {
			findings = append(findings, module.Finding{
				Type:     "dns_record",
				URL:      strings.TrimSuffix(mx.Host, "."),
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("MX record: %s → %s (pref %d)", domain, mx.Host, mx.Pref),
				Extra: map[string]string{
					"source":     "dns",
					"domain":     domain,
					"type":       "MX",
					"host":       mx.Host,
					"pref":       fmt.Sprintf("%d", mx.Pref),
					"confidence": "0.80",
				},
			})
		}
	}

	// NS records.
	nss, err := resolver.LookupNS(ctx, domain)
	if err == nil {
		for _, ns := range nss {
			findings = append(findings, module.Finding{
				Type:     "dns_record",
				URL:      strings.TrimSuffix(ns.Host, "."),
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("NS record: %s → %s", domain, ns.Host),
				Extra: map[string]string{
					"source":     "dns",
					"domain":     domain,
					"type":       "NS",
					"host":       ns.Host,
					"confidence": "0.80",
				},
			})
		}
	}

	// TXT records.
	txts, err := resolver.LookupTXT(ctx, domain)
	if err == nil {
		for _, txt := range txts {
			findings = append(findings, module.Finding{
				Type:     "dns_record",
				URL:      domain,
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("TXT record: %s → %q", domain, txt),
				Extra: map[string]string{
					"source":     "dns",
					"domain":     domain,
					"type":       "TXT",
					"content":    txt,
					"confidence": "0.80",
				},
			})
		}
	}

	return findings, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func subdomainFinding(host, apex, source string) module.Finding {
	return module.Finding{
		Type:     "passive_name_candidate",
		URL:      host,
		Severity: module.SeverityInfo,
		Detail:   fmt.Sprintf("Unverified passive name %s discovered via %s for %s", host, source, apex),
		Extra: map[string]string{
			"source":             source,
			"apex":               apex,
			"host":               host,
			"subdomain":          host,
			"validated":          "false",
			"validation_state":   "passive_unverified",
			"confidence":         "0.55",
			"promote_to_context": "false",
		},
	}
}

func (m *Module) get(ctx context.Context, rawURL string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "blackhorn-recon/1.0")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return body, resp.StatusCode, err
}

func parseURLHost(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("empty URL")
	}
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

func isRFC1918(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	for _, cidr := range private {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func collectDomains(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = cleanDomain(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	if input.Target != "" {
		add(input.Target)
	}
	for _, u := range input.URLs {
		add(u)
	}
	if input.RawContent != "" {
		for _, line := range strings.Split(input.RawContent, "\n") {
			add(line)
		}
	}
	return out
}

func cleanDomain(s string) string {
	return urlutil.NormalizeDomain(s)
}

func dedupFindings(findings []module.Finding) []module.Finding {
	seen := make(map[string]struct{})
	var out []module.Finding
	for _, f := range findings {
		key := f.Type + "|" + f.URL
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, f)
		}
	}
	return out
}

func optInt(opts map[string]string, key string, def int) int {
	if opts == nil {
		return def
	}
	var value int
	if _, err := fmt.Sscanf(strings.TrimSpace(opts[key]), "%d", &value); err != nil || value < 1 {
		return def
	}
	return value
}
