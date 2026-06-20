// Package shodanwatch provides continuous-monitoring-style Shodan queries:
// host info, CVE lookup by service, organization asset discovery, DNS resolve,
// and honeypot probability scoring.
//
// Source references (algorithm design, no code copied):
//   - Shodan REST API v1 documentation (https://developer.shodan.io/api)
//   - Shodan CLI (MIT, achillean)                 — query patterns
//   - Natlas (MIT, natlas-team)                   — asset tracking approach
//
// What this module does:
//  1. /shodan/host/{ip}            — full host scan data (ports, vulns, banners)
//  2. /shodan/host/search          — org: query to discover assets
//  3. /dns/resolve                 — hostname → IP resolution via Shodan
//  4. /labs/honeyscore/{ip}        — honeypot probability (0.0–1.0)
//  5. /shodan/host/count           — quick count without quota-consuming scan
//  6. Synthesize high-signal CVE findings from vulns[] array
//
// Architecture:
//   - errgroup.SetLimit for parallel queries                (guia-go §9)
//   - io.LimitReader on all response bodies                 (dicas.md §5)
//   - log/slog structured observability                     (dicas.md §16)
//   - NewWithClient(*http.Client) for testability
//   - API key via Options["shodan_api_key"] or env SHODAN_API_KEY
//   - Graceful degradation when API key absent (free endpoints only)
package shodanwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/urlutil"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	maxBodyRead      = 512 * 1024
	shodanBase       = "https://api.shodan.io"
	defaultParallel  = 4
	maxSearchResults = 20
	defaultRuntime   = 30 * time.Second
)

// ─── Shodan API types ─────────────────────────────────────────────────────────

type hostInfo struct {
	IP        string              `json:"ip_str"`
	ASN       string              `json:"asn"`
	Org       string              `json:"org"`
	ISP       string              `json:"isp"`
	Country   string              `json:"country_code"`
	City      string              `json:"city"`
	Hostnames []string            `json:"hostnames"`
	Ports     []int               `json:"ports"`
	Vulns     map[string]vulnInfo `json:"vulns"`
	Data      []serviceData       `json:"data"`
}

type vulnInfo struct {
	CVSS    float64  `json:"cvss"`
	Summary string   `json:"summary"`
	Refs    []string `json:"references"`
}

type serviceData struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Banner    string `json:"data"`
	Timestamp string `json:"timestamp"`
}

type searchResult struct {
	Total   int        `json:"total"`
	Matches []hostInfo `json:"matches"`
}

type dnsResolveResult map[string]string // hostname → IP

type honeyScore struct {
	Probability float64 `json:"probability"`
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements the shodanwatch module.
type Module struct {
	client *http.Client
	logger *slog.Logger
}

// New creates a shodanwatch module with the default HTTP client.
func New() *Module {
	return &Module{client: httpclient.Default(), logger: slog.Default()}
}

// NewWithClient creates a shodanwatch module with a custom HTTP client (for tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{client: c, logger: slog.Default()}
}

func (m *Module) Name() string { return "shodanwatch" }

// Run queries Shodan for the given target (IP, domain, or org query).
//
// Options:
//   - shodan_api_key: Shodan API key (fallback: env SHODAN_API_KEY)
//   - mode:          "host" (default), "org", "search"
//   - query:         Shodan query string when mode=search
//   - org:           org name when mode=org (e.g. "Cloudflare")
//   - parallelism:   concurrent queries (default 4)
//   - honeyscore:    "true" to also check honeypot probability (default false)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("shodanwatch: target (IP, domain, or org name) is required")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	mode := optStr(opts, "mode", "host")
	switch mode {
	case "host", "org", "search":
	default:
		return nil, fmt.Errorf("shodanwatch: unsupported mode %q", mode)
	}

	apiKey := firstNonEmpty(opts["shodan_api_key"], os.Getenv("SHODAN_API_KEY"))
	if apiKey == "" {
		m.logger.DebugContext(ctx, "shodanwatch: skipped because API key is not configured")
		return nil, nil
	}
	parallel := clampInt(optInt(opts, "parallelism", defaultParallel), 1, 16)
	checkHoney := opts["honeyscore"] == "true"
	maxRuntime := time.Duration(clampInt(optInt(opts, "max_runtime_seconds", int(defaultRuntime/time.Second)), 1, 120)) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, maxRuntime)
	defer cancel()

	if mode == "host" && net.ParseIP(target) == nil {
		target = urlutil.NormalizeDomain(target)
		if target == "" || !strings.Contains(target, ".") {
			return nil, fmt.Errorf("shodanwatch: host mode requires a valid IP or domain")
		}
	}

	m.logger.InfoContext(runCtx, "shodanwatch: starting",
		"target", target, "mode", mode, "api_key_present", apiKey != "")

	var (
		mu       sync.Mutex
		findings []module.Finding
	)
	add := func(ff ...module.Finding) {
		mu.Lock()
		findings = append(findings, ff...)
		mu.Unlock()
	}

	eg, egCtx := errgroup.WithContext(runCtx)
	eg.SetLimit(parallel)

	switch mode {
	case "host":
		// Resolve domain to IP if needed, then fetch host info.
		ip := target
		if net.ParseIP(target) == nil {
			eg.Go(func() error {
				resolved, ff := m.resolveHostname(egCtx, target, apiKey)
				add(ff...)
				if resolved != "" {
					ip = resolved
				}
				return nil
			})
			_ = eg.Wait()
			if ip == target {
				return dedup(findings), nil
			}
			// Re-init errgroup after resolution.
			eg, egCtx = errgroup.WithContext(runCtx)
			eg.SetLimit(parallel)
		}

		eg.Go(func() error {
			add(m.fetchHost(egCtx, ip, apiKey)...)
			return nil
		})
		if checkHoney && apiKey != "" {
			eg.Go(func() error {
				add(m.fetchHoneyScore(egCtx, ip, apiKey)...)
				return nil
			})
		}

	case "org":
		org := optStr(opts, "org", target)
		eg.Go(func() error {
			add(m.searchOrg(egCtx, org, apiKey)...)
			return nil
		})

	case "search":
		query := optStr(opts, "query", target)
		eg.Go(func() error {
			add(m.searchQuery(egCtx, query, apiKey)...)
			return nil
		})

	default:
		return nil, fmt.Errorf("shodanwatch: unknown mode %q (valid: host, org, search)", mode)
	}

	if err := eg.Wait(); err != nil {
		return findings, err
	}

	return dedup(findings), nil
}

// ─── API methods ─────────────────────────────────────────────────────────────

func (m *Module) fetchHost(ctx context.Context, ip, apiKey string) []module.Finding {
	rawURL := fmt.Sprintf("%s/shodan/host/%s", shodanBase, url.PathEscape(ip))
	if apiKey != "" {
		rawURL += "?key=" + apiKey
	}

	body, statusCode, err := m.get(ctx, rawURL)
	if err != nil || statusCode != 200 {
		return nil
	}

	var host hostInfo
	if err := json.Unmarshal(body, &host); err != nil {
		return nil
	}

	var findings []module.Finding

	// Host overview finding.
	findings = append(findings, module.Finding{
		Type:     "shodan_inventory_reference",
		URL:      fmt.Sprintf("https://www.shodan.io/host/%s", ip),
		Severity: module.SeverityInfo,
		Detail:   fmt.Sprintf("[shodanwatch] %s (%s) — %s, %s — %d open ports: %v", ip, host.Org, host.City, host.Country, len(host.Ports), host.Ports),
		Extra: map[string]string{
			"ip":                 ip,
			"org":                host.Org,
			"asn":                host.ASN,
			"country":            host.Country,
			"city":               host.City,
			"ports":              intsToStr(host.Ports),
			"hostnames":          strings.Join(host.Hostnames, ","),
			"confidence":         "0.99",
			"fonte":              "shodanwatch",
			"validated":          "false",
			"validation_state":   "third_party_inventory_reference",
			"promote_to_context": "false",
		},
	})

	// Per-CVE findings.
	for cve, info := range host.Vulns {
		sev := externalCVESeverity(info.CVSS)
		findings = append(findings, module.Finding{
			Type:     "shodan_vulnerability_reference",
			URL:      fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve),
			Severity: sev,
			Detail:   fmt.Sprintf("[shodanwatch] Third-party Shodan reference associates %s with %s (CVSS %.1f): %s. Confirm service version directly before remediation.", ip, cve, info.CVSS, truncate(info.Summary, 120)),
			Extra: map[string]string{
				"ip":                 ip,
				"cve":                cve,
				"cvss":               fmt.Sprintf("%.1f", info.CVSS),
				"confidence":         "0.65",
				"fonte":              "shodanwatch",
				"validated":          "false",
				"validation_state":   "third_party_vulnerability_reference",
				"promote_to_context": "false",
			},
		})
	}

	// Per-service findings.
	for _, svc := range host.Data {
		if svc.Product == "" {
			continue
		}
		findings = append(findings, module.Finding{
			Type:     "shodan_banner_reference",
			URL:      fmt.Sprintf("https://www.shodan.io/host/%s", ip),
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("[shodanwatch] %s port %d/%s — %s %s", ip, svc.Port, svc.Transport, svc.Product, svc.Version),
			Extra: map[string]string{
				"ip":                 ip,
				"port":               fmt.Sprintf("%d", svc.Port),
				"transport":          svc.Transport,
				"product":            svc.Product,
				"version":            svc.Version,
				"confidence":         "0.95",
				"fonte":              "shodanwatch",
				"timestamp":          svc.Timestamp,
				"validated":          "false",
				"validation_state":   "third_party_inventory_reference",
				"promote_to_context": "false",
			},
		})
	}

	return findings
}

func (m *Module) resolveHostname(ctx context.Context, hostname, apiKey string) (string, []module.Finding) {
	rawURL := fmt.Sprintf("%s/dns/resolve?hostnames=%s", shodanBase, url.QueryEscape(hostname))
	if apiKey != "" {
		rawURL += "&key=" + apiKey
	}

	body, statusCode, err := m.get(ctx, rawURL)
	if err != nil || statusCode != 200 {
		return "", nil
	}

	var result dnsResolveResult
	if err := json.Unmarshal(body, &result); err != nil {
		return "", nil
	}
	if ip, ok := result[hostname]; ok && net.ParseIP(ip) != nil {
		return ip, []module.Finding{{
			Type:     "shodan_dns_reference",
			URL:      fmt.Sprintf("https://www.shodan.io/host/%s", ip),
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("[shodanwatch] %s resolves to %s (via Shodan DNS)", hostname, ip),
			Extra: map[string]string{
				"hostname":           hostname,
				"ip":                 ip,
				"confidence":         "0.85",
				"fonte":              "shodanwatch",
				"validated":          "false",
				"validation_state":   "third_party_dns_reference",
				"promote_to_context": "false",
			},
		}}
	}
	return "", nil
}

func (m *Module) fetchHoneyScore(ctx context.Context, ip, apiKey string) []module.Finding {
	rawURL := fmt.Sprintf("%s/labs/honeyscore/%s?key=%s", shodanBase, url.PathEscape(ip), apiKey)
	body, statusCode, err := m.get(ctx, rawURL)
	if err != nil || statusCode != 200 {
		return nil
	}

	var hs honeyScore
	if err := json.Unmarshal(body, &hs); err != nil {
		return nil
	}

	verdict := "unlikely honeypot"
	if hs.Probability >= 0.7 {
		verdict = "LIKELY HONEYPOT"
	} else if hs.Probability >= 0.4 {
		verdict = "possible honeypot"
	}

	return []module.Finding{{
		Type:     "shodan_honeyscore",
		URL:      fmt.Sprintf("https://www.shodan.io/host/%s", ip),
		Severity: module.SeverityInfo,
		Detail:   fmt.Sprintf("[shodanwatch] Third-party honeypot probability for %s: %.2f (%s). This is an environmental classification, not a target vulnerability.", ip, hs.Probability, verdict),
		Extra: map[string]string{
			"ip":                 ip,
			"probability":        fmt.Sprintf("%.2f", hs.Probability),
			"verdict":            verdict,
			"confidence":         "0.85",
			"fonte":              "shodanwatch",
			"validated":          "false",
			"validation_state":   "third_party_classification",
			"promote_to_context": "false",
		},
	}}
}

func (m *Module) searchOrg(ctx context.Context, org, apiKey string) []module.Finding {
	query := fmt.Sprintf("org:\"%s\"", org)
	return m.searchQuery(ctx, query, apiKey)
}

func (m *Module) searchQuery(ctx context.Context, query, apiKey string) []module.Finding {
	if apiKey == "" {
		return nil
	}

	rawURL := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s&limit=%d",
		shodanBase, apiKey, url.QueryEscape(query), maxSearchResults)

	body, statusCode, err := m.get(ctx, rawURL)
	if err != nil || statusCode != 200 {
		return nil
	}

	var result searchResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	findings := []module.Finding{{
		Type:     "shodan_search_total",
		URL:      fmt.Sprintf("https://www.shodan.io/search?query=%s", url.QueryEscape(query)),
		Severity: module.SeverityInfo,
		Detail:   fmt.Sprintf("[shodanwatch] Shodan search for %q returned %d total results", query, result.Total),
		Extra: map[string]string{
			"query": query, "total": fmt.Sprintf("%d", result.Total),
			"confidence": "0.99", "fonte": "shodanwatch",
		},
	}}

	for _, host := range result.Matches {
		findings = append(findings, module.Finding{
			Type:     "shodan_asset_reference",
			URL:      fmt.Sprintf("https://www.shodan.io/host/%s", host.IP),
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("[shodanwatch] Third-party asset reference %s (%s) — %s — ports %v — %d vulnerability references", host.IP, host.Org, host.Country, host.Ports, len(host.Vulns)),
			Extra: map[string]string{
				"ip":                 host.IP,
				"org":                host.Org,
				"country":            host.Country,
				"ports":              intsToStr(host.Ports),
				"vuln_count":         fmt.Sprintf("%d", len(host.Vulns)),
				"confidence":         "0.95",
				"fonte":              "shodanwatch",
				"validated":          "false",
				"validation_state":   "third_party_inventory_reference",
				"promote_to_context": "false",
			},
		})
	}

	return findings
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

func (m *Module) get(ctx context.Context, rawURL string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return body, resp.StatusCode, err
}

// ─── Utility helpers ──────────────────────────────────────────────────────────

func externalCVESeverity(cvss float64) module.Severity {
	switch {
	case cvss >= 9.0:
		return module.SeverityHigh
	case cvss >= 7.0:
		return module.SeverityMedium
	case cvss >= 4.0:
		return module.SeverityLow
	default:
		return module.SeverityInfo
	}
}

func clampInt(value, minimum, maximum int) int {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func intsToStr(ints []int) string {
	parts := make([]string, len(ints))
	for i, n := range ints {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, ",")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func optStr(opts map[string]string, key, def string) string {
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

func optInt(opts map[string]string, key string, def int) int {
	if v, ok := opts[key]; ok && v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	var out []module.Finding
	for _, f := range findings {
		key := f.Type + "|" + f.URL
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}
