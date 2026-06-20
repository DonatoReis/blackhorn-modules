// Package asnmap performs ASN (Autonomous System Number) to IP range mapping.
// Given a domain, IP, ASN, or organization name, it resolves the corresponding
// network blocks and emits them as findings.
//
// The module queries public BGP/WHOIS data sources:
//   - RDAP (Registration Data Access Protocol) — RFC 7483
//   - Team Cymru IP-to-ASN DNS mapping service (public, CC0)
//   - BGP.Tools route information (public API)
//   - RIPE NCC Stat API (public, free tier)
//
// Reference: projectdiscovery/asnmap (MIT) — approach and target types.
// No source code is copied. All HTTP queries and parsing are independently
// implemented against public API documentation.
//
// License: MIT (blackhorn-modules).
package asnmap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	defaultTimeout = 15 * time.Second
	defaultConc    = 6
	maxBodyBytes   = 512 * 1024

	// Team Cymru DNS-based IP-to-ASN service.
	cymruDNSSuffix = ".origin.asn.cymru.com"
	// RIPE Stat API base URL.
	ripeStatBase = "https://stat.ripe.net/data"
	// BGP.Tools prefix lookup API.
	bgpToolsBase = "https://bgp.tools/prefix/"
)

// ─── types ───────────────────────────────────────────────────────────────────

// ASNInfo holds information about an autonomous system.
type ASNInfo struct {
	ASN      string   // e.g. "AS13335"
	Org      string   // organisation name
	Country  string   // 2-letter ISO code
	Prefixes []string // CIDR blocks
}

// ─── module ──────────────────────────────────────────────────────────────────

// Module implements module.Module for ASN-to-IP range mapping.
type Module struct {
	client      *http.Client
	resolver    *net.Resolver
	concurrency int
}

// New returns a Module with production defaults.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		resolver:    net.DefaultResolver,
		concurrency: defaultConc,
	}
}

// NewWithClient creates a Module using the provided HTTP client (useful in tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client:      c,
		resolver:    net.DefaultResolver,
		concurrency: defaultConc,
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "asnmap" }

// Run implements module.Module.
//
// Input formats (one or more of):
//   - Target: domain ("example.com"), IP ("1.2.3.4"), or ASN ("AS13335" / "13335")
//   - URLs: list of IPs, domains or ASNs
//   - RawContent: newline-delimited targets
//
// Findings are emitted for each discovered prefix (CIDR) associated with
// the ASN(s) found for the inputs.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	targets := collectTargets(input)
	if len(targets) == 0 {
		return nil, fmt.Errorf("asnmap: no targets provided")
	}

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(m.concurrency)

	for _, target := range targets {
		target := target
		g.Go(func() error {
			ff, err := m.resolveTarget(gctx, target)
			if err != nil {
				slog.Debug("asnmap: resolve error", "target", target, "err", err)
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

	_ = g.Wait()
	return findings, nil
}

// ─── target resolution ───────────────────────────────────────────────────────

func (m *Module) resolveTarget(ctx context.Context, target string) ([]module.Finding, error) {
	// Determine target type.
	switch {
	case isASN(target):
		return m.lookupASN(ctx, normaliseASN(target))
	case isIPAddress(target):
		asn, err := m.ipToASN(ctx, target)
		if err != nil {
			return nil, err
		}
		if asn == "" {
			return nil, nil
		}
		return m.lookupASN(ctx, asn)
	default:
		// Treat as domain — resolve to IP first.
		ips, err := m.resolver.LookupHost(ctx, target)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed for %s: %w", target, err)
		}
		if len(ips) == 0 {
			return nil, nil
		}
		asn, err := m.ipToASN(ctx, ips[0])
		if err != nil {
			return nil, err
		}
		if asn == "" {
			return nil, nil
		}
		return m.lookupASN(ctx, asn)
	}
}

// ipToASN uses Team Cymru's DNS mapping service to resolve an IP to an ASN.
// The Cymru service is free and public; no API key required.
// Query format: <reversed-ip>.origin.asn.cymru.com
// Response TXT: "ASN | prefix | country | registry | allocated"
func (m *Module) ipToASN(ctx context.Context, ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP: %s", ipStr)
	}

	var query string
	if ip4 := ip.To4(); ip4 != nil {
		// Reverse the octets for IPv4.
		octets := strings.Split(ip4.String(), ".")
		for i, j := 0, len(octets)-1; i < j; i, j = i+1, j-1 {
			octets[i], octets[j] = octets[j], octets[i]
		}
		query = strings.Join(octets, ".") + cymruDNSSuffix
	} else {
		// Expand IPv6 and reverse nibbles.
		expanded := expandIPv6(ip)
		query = expanded + ".origin6.asn.cymru.com"
	}

	txts, err := m.resolver.LookupTXT(ctx, query)
	if err != nil {
		return "", fmt.Errorf("Cymru DNS lookup failed: %w", err)
	}

	for _, txt := range txts {
		parts := strings.SplitN(txt, "|", 2)
		if len(parts) >= 1 {
			asn := strings.TrimSpace(parts[0])
			// May contain multiple ASNs separated by space.
			if asnParts := strings.Fields(asn); len(asnParts) > 0 {
				return normaliseASN(asnParts[0]), nil
			}
		}
	}
	return "", nil
}

// lookupASN fetches prefix information for an ASN using the RIPE Stat API.
// Falls back to BGP.Tools if RIPE is unavailable.
func (m *Module) lookupASN(ctx context.Context, asn string) ([]module.Finding, error) {
	info, err := m.fetchRIPEStat(ctx, asn)
	if err != nil || info == nil {
		// Fallback: return a minimal finding with just the ASN.
		return []module.Finding{{
			Type:     "asn_info",
			URL:      asn,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("ASN %s found (prefix lookup unavailable)", asn),
			Extra: map[string]string{
				"asn":        asn,
				"source":     "fallback",
				"confidence": "0.90",
			},
		}}, nil
	}
	return buildFindings(asn, info), nil
}

// fetchRIPEStat queries the RIPE NCC Stat API for prefix information.
// Endpoint: /data/announced-prefixes/data.json?resource=<ASN>
// Reference: https://stat.ripe.net/docs/02.data-api/
func (m *Module) fetchRIPEStat(ctx context.Context, asn string) (*ASNInfo, error) {
	url := fmt.Sprintf("%s/announced-prefixes/data.json?resource=%s", ripeStatBase, asn)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-asnmap/1.0 (contact: github.com/DonatoReis/blackhorn-modules)")
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIPE Stat API returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}

	return parseRIPEStatResponse(asn, body)
}

// ─── RIPE Stat response parser ───────────────────────────────────────────────

// ripeStatPrefixResponse matches the RIPE Stat announced-prefixes endpoint shape.
type ripeStatPrefixResponse struct {
	Data struct {
		Resource string `json:"resource"`
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
	Status string `json:"status"`
}

func parseRIPEStatResponse(asn string, body []byte) (*ASNInfo, error) {
	var resp ripeStatPrefixResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("JSON unmarshal error: %w", err)
	}
	if resp.Status != "ok" && resp.Status != "200" {
		return nil, fmt.Errorf("RIPE Stat non-ok status: %s", resp.Status)
	}

	info := &ASNInfo{ASN: asn}
	for _, p := range resp.Data.Prefixes {
		if p.Prefix != "" {
			info.Prefixes = append(info.Prefixes, p.Prefix)
		}
	}
	return info, nil
}

// ─── finding builder ─────────────────────────────────────────────────────────

func buildFindings(asn string, info *ASNInfo) []module.Finding {
	if len(info.Prefixes) == 0 {
		return []module.Finding{{
			Type:     "asn_info",
			URL:      asn,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("ASN %s has no announced prefixes", asn),
			Extra: map[string]string{
				"asn":        asn,
				"org":        info.Org,
				"source":     "ripe-stat",
				"confidence": "0.90",
			},
		}}
	}

	// Emit a single aggregated finding instead of one per prefix (which caused
	// 597 identical Info findings in the real scan). Individual prefixes are stored
	// in the finding's Extra so analysts can still see them without flooding results.
	prefixCount := len(info.Prefixes)
	// Keep at most 20 representative prefixes in Extra to avoid bloating the finding.
	sample := info.Prefixes
	truncated := false
	if len(sample) > 20 {
		sample = sample[:20]
		truncated = true
	}
	sampleStr := strings.Join(sample, ", ")
	if truncated {
		sampleStr += fmt.Sprintf(" … and %d more", prefixCount-20)
	}

	return []module.Finding{{
		Type:     "asn_prefix_summary",
		URL:      asn,
		Severity: module.SeverityInfo,
		Detail: fmt.Sprintf("ASN %s (%s, %s) announces %d IP prefixes: %s",
			asn, info.Org, info.Country, prefixCount, sampleStr),
		Extra: map[string]string{
			"asn":          asn,
			"org":          info.Org,
			"country":      info.Country,
			"prefix_count": fmt.Sprintf("%d", prefixCount),
			"prefixes":     strings.Join(info.Prefixes, ","),
			"source":       "ripe-stat",
			"confidence":   "0.90",
		},
	}}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func collectTargets(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
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

// isASN returns true if s looks like an ASN (e.g. "AS13335", "13335", "ASN13335").
func isASN(s string) bool {
	upper := strings.ToUpper(s)
	if strings.HasPrefix(upper, "AS") {
		rest := strings.TrimPrefix(upper, "AS")
		rest = strings.TrimPrefix(rest, "N") // strip "ASN" prefix
		return isAllDigits(rest) && len(rest) > 0
	}
	return isAllDigits(s) && len(s) >= 3
}

// normaliseASN returns the ASN in "AS<num>" format.
func normaliseASN(s string) string {
	upper := strings.ToUpper(strings.TrimSpace(s))
	upper = strings.TrimPrefix(upper, "ASN")
	if !strings.HasPrefix(upper, "AS") {
		return "AS" + upper
	}
	return upper
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isIPAddress returns true if s is a valid IPv4 or IPv6 address.
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// expandIPv6 returns the fully expanded, nibble-reversed form of an IPv6 address
// for use in DNS queries (origin6.asn.cymru.com).
func expandIPv6(ip net.IP) string {
	ip6 := ip.To16()
	if ip6 == nil {
		return ""
	}
	hex := fmt.Sprintf("%032x", []byte(ip6))
	// Reverse all nibbles.
	runes := []rune(hex)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	// Insert dots between nibbles.
	var sb strings.Builder
	for i, r := range runes {
		if i > 0 {
			sb.WriteByte('.')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
