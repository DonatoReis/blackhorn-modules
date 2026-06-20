// Package certs queries Certificate Transparency logs to discover
// subdomains and certificate metadata for a target domain.
//
// Sources:
//   - crt.sh       — free, JSON API over CT log aggregation
//   - Censys       — certificados + hosts (requer API key)
//   - certspotter  — SSLMate CT log watcher (free tier)
//   - hackertarget — CT search free
//
// All findings include confidence scores, slog observability and
// redaction of any sensitive fields per dicas.md §18.
//
// Usage:
//
//	m := certs.New()
//	findings, err := m.Run(ctx, module.Input{
//	    Target:  "example.com",
//	    Options: map[string]string{
//	        "sources":      "crtsh,censys",
//	        "censys_id":    "<id>",
//	        "censys_secret":"<secret>",
//	        "max_results":  "200",
//	        "wildcard":     "true",
//	    },
//	})
package certs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/urlutil"
	"golang.org/x/sync/errgroup"
)

const (
	maxBodyCerts             = 4 * 1024 * 1024 // 4 MB
	maxParallel              = 4
	defaultMaxRuntimeSeconds = 30
)

// Module implements module.Module for certificate transparency queries.
type Module struct {
	client *http.Client
}

// New returns a Module with a default HTTP client.
func New() *Module {
	return NewWithClient(&http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     60 * time.Second,
		},
	})
}

// NewWithClient allows injecting a custom HTTP client (useful for tests).
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

// Name returns the canonical module identifier.
func (m *Module) Name() string { return "certs" }

// Run executes CT log queries and returns certificate findings.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("certs: target vazio")
	}
	// Normalise — strip scheme/path leaving bare domain
	target = normaliseDomain(target)
	if target == "" || net.ParseIP(target) != nil || !strings.Contains(target, ".") {
		return nil, fmt.Errorf("certs: target inválido após normalização")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}
	sourcesFilter := opts["sources"]
	maxResults := clampInt(optInt(opts, "max_results", 200), 1, 5000)
	includeWildcard := optBool(opts, "wildcard", true)
	maxRuntime := clampInt(optInt(opts, "max_runtime_seconds", defaultMaxRuntimeSeconds), 1, 300)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntime)*time.Second)
	defer cancel()

	slog.InfoContext(runCtx, "certs.Run iniciado",
		"target", target,
		"sources", sourcesFilter,
		"max_results", maxResults,
	)

	type sourceFunc struct {
		name string
		fn   func(context.Context, string, map[string]string, int) ([]module.Finding, error)
	}

	sources := []sourceFunc{
		{"crtsh", m.queryCRTsh},
		{"hackertarget", m.queryHackerTarget},
		{"certspotter", m.queryCertSpotter},
		{"censys", m.queryCensys},
	}

	var mu sync.Mutex
	var all []module.Finding

	g, gctx := errgroup.WithContext(runCtx)
	g.SetLimit(maxParallel)

	for _, s := range sources {
		s := s
		if !isWanted(sourcesFilter, s.name) {
			continue
		}
		g.Go(func() error {
			slog.DebugContext(gctx, "certs: consultando fonte", "source", s.name, "target", target)
			findings, err := s.fn(gctx, target, opts, maxResults)
			if err != nil {
				slog.WarnContext(gctx, "certs: fonte retornou erro",
					"source", s.name, "err", err)
				return nil // não aborta as outras fontes
			}
			mu.Lock()
			all = append(all, findings...)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	result := dedup(all)
	if !includeWildcard {
		result = filterWildcard(result)
	}

	slog.InfoContext(runCtx, "certs.Run concluído",
		"target", target,
		"total_findings", len(result),
	)
	return result, nil
}

// ─── crt.sh ───────────────────────────────────────────────────────────────────

type crtshEntry struct {
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
	IssuerName string `json:"issuer_name"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	ID         int64  `json:"id"`
}

func (m *Module) queryCRTsh(ctx context.Context, domain string, _ map[string]string, maxResults int) ([]module.Finding, error) {
	// crt.sh returns JSON — deduplicate via set
	u := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "blackhorn-certs/1.0 (OSINT; security research)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crtsh: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyCerts))
	if err != nil {
		return nil, err
	}

	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crtsh: parse JSON: %w", err)
	}

	seen := map[string]bool{}
	var findings []module.Finding

entryLoop:
	for _, e := range entries {
		if len(findings) >= maxResults {
			break
		}
		// name_value can contain multiple SANs separated by newline
		for _, name := range strings.Split(e.NameValue, "\n") {
			if len(findings) >= maxResults {
				break entryLoop
			}
			rawName := strings.TrimSpace(name)
			isWild := strings.HasPrefix(rawName, "*.")
			name = normalizeScopedName(rawName, domain)
			seenKey := strconv.FormatBool(isWild) + "|" + name
			if name == "" || name == domain || seen[seenKey] {
				continue
			}
			seen[seenKey] = true

			f := module.Finding{
				Type:     "ct_name_reference",
				URL:      fmt.Sprintf("https://crt.sh/?id=%d", e.ID),
				Severity: module.SeverityInfo,
				Extra: map[string]string{
					"subdomain":          name,
					"common_name":        e.CommonName,
					"issuer":             e.IssuerName,
					"not_before":         e.NotBefore,
					"not_after":          e.NotAfter,
					"source":             "crtsh",
					"validated":          "false",
					"validation_state":   "certificate_transparency_reference",
					"confidence":         "0.88",
					"promote_to_context": "false",
				},
			}

			// Detect wildcard
			if isWild {
				f.Type = "ct_wildcard_reference"
				f.Detail = fmt.Sprintf("Historical wildcard certificate reference '*.%s' issued by %s (source: crt.sh)", domain, e.IssuerName)
				f.Extra["wildcard"] = "true"
				f.Extra["pattern"] = rawName
				f.Extra["confidence"] = "0.82"
			} else {
				f.Detail = fmt.Sprintf("Certificate Transparency reference for '%s', issued by '%s', not_after %s", name, e.IssuerName, e.NotAfter)
			}

			// Expiration in a historical CT record is evidence, not proof that
			// the currently served certificate is expired.
			if isExpired(e.NotAfter) {
				f.Extra["expired"] = "true"
				f.Detail += " [historical certificate expired]"
			}

			findings = append(findings, f)
		}
	}
	return findings, nil
}

// ─── HackerTarget ─────────────────────────────────────────────────────────────

func (m *Module) queryHackerTarget(ctx context.Context, domain string, _ map[string]string, maxResults int) ([]module.Finding, error) {
	u := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-certs/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackertarget: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyCerts))
	if err != nil {
		return nil, err
	}

	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(text, "error") || strings.HasPrefix(text, "API count") {
		return nil, fmt.Errorf("hackertarget: %s", text)
	}

	var findings []module.Finding
	seen := map[string]bool{}

	for _, line := range strings.Split(text, "\n") {
		if len(findings) >= maxResults {
			break
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) < 1 {
			continue
		}
		host := normalizeScopedName(parts[0], domain)
		if host == "" || host == domain || seen[host] {
			continue
		}
		seen[host] = true

		ip := ""
		if len(parts) == 2 {
			ip = strings.TrimSpace(parts[1])
		}

		f := module.Finding{
			Type:     "passive_name_candidate",
			URL:      host,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("Unverified passive name '%s' discovered via HackerTarget for %s", host, domain),
			Extra: map[string]string{
				"subdomain":          host,
				"ip":                 ip,
				"source":             "hackertarget",
				"validated":          "false",
				"validation_state":   "passive_unverified",
				"confidence":         "0.55",
				"promote_to_context": "false",
			},
		}
		if net.ParseIP(ip) != nil {
			f.Type = "subdomain_resolved"
			f.Detail = fmt.Sprintf("DNS-confirmed subdomain '%s' resolves to %s via HackerTarget", host, ip)
			f.Extra["addresses"] = ip
			f.Extra["validated"] = "true"
			f.Extra["validation_state"] = "dns_confirmed_by_source"
			f.Extra["confidence"] = "0.95"
			f.Extra["promote_to_context"] = "true"
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ─── CertSpotter ──────────────────────────────────────────────────────────────

type certSpotterEntry struct {
	DNSNAMES []string `json:"dns_names"`
	NotAfter string   `json:"not_after"`
	Revoked  bool     `json:"revoked"`
}

func (m *Module) queryCertSpotter(ctx context.Context, domain string, opts map[string]string, maxResults int) ([]module.Finding, error) {
	apiKey := opts["certspotter_key"]
	u := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names",
		url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("User-Agent", "blackhorn-certs/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("certspotter: autenticação necessária (configure certspotter_key)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certspotter: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyCerts))
	if err != nil {
		return nil, err
	}

	var entries []certSpotterEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("certspotter: parse: %w", err)
	}

	seen := map[string]bool{}
	var findings []module.Finding

entryLoop:
	for _, e := range entries {
		if len(findings) >= maxResults {
			break
		}
		for _, name := range e.DNSNAMES {
			if len(findings) >= maxResults {
				break entryLoop
			}
			rawName := strings.TrimSpace(name)
			isWildcard := strings.HasPrefix(rawName, "*.")
			name = normalizeScopedName(rawName, domain)
			seenKey := strconv.FormatBool(isWildcard) + "|" + name
			if name == "" || name == domain || seen[seenKey] {
				continue
			}
			seen[seenKey] = true

			conf := "0.85"
			notes := ""
			if e.Revoked {
				conf = "0.75"
				notes = " [historical certificate revoked]"
			}
			if isExpired(e.NotAfter) {
				notes += " [historical certificate expired]"
			}

			findingType := "ct_name_reference"
			if isWildcard {
				findingType = "ct_wildcard_reference"
			}
			findings = append(findings, module.Finding{
				Type:     findingType,
				URL:      name,
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("Certificate Transparency reference for '%s' via CertSpotter, not_after %s%s", name, e.NotAfter, notes),
				Extra: map[string]string{
					"subdomain":          name,
					"not_after":          e.NotAfter,
					"revoked":            strconv.FormatBool(e.Revoked),
					"wildcard":           strconv.FormatBool(isWildcard),
					"source":             "certspotter",
					"validated":          "false",
					"validation_state":   "certificate_transparency_reference",
					"confidence":         conf,
					"promote_to_context": "false",
				},
			})
		}
	}
	return findings, nil
}

// ─── Censys ───────────────────────────────────────────────────────────────────

type censysSearchReq struct {
	Query   string   `json:"q"`
	PerPage int      `json:"per_page"`
	Fields  []string `json:"fields"`
}

type censysResult struct {
	Code   int `json:"code"`
	Status string
	Result struct {
		Hits []struct {
			Names []string `json:"names"`
			IP    string   `json:"ip"`
		} `json:"hits"`
	} `json:"result"`
}

func (m *Module) queryCensys(ctx context.Context, domain string, opts map[string]string, maxResults int) ([]module.Finding, error) {
	apiID := opts["censys_id"]
	apiSecret := opts["censys_secret"]
	if apiID == "" || apiSecret == "" {
		slog.DebugContext(ctx, "certs: censys sem credenciais — pulando")
		return nil, nil
	}

	query := fmt.Sprintf("parsed.names: %s", domain)
	payload, _ := json.Marshal(censysSearchReq{
		Query:   query,
		PerPage: min(maxResults, 100),
		Fields:  []string{"ip", "parsed.names"},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://search.censys.io/api/v2/hosts/search",
		strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(apiID, apiSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "blackhorn-certs/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("censys: credenciais inválidas")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("censys: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyCerts))
	if err != nil {
		return nil, err
	}

	var result censysResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("censys: parse: %w", err)
	}

	seen := map[string]bool{}
	var findings []module.Finding

	for _, hit := range result.Result.Hits {
		for _, name := range hit.Names {
			if len(findings) >= maxResults {
				return findings, nil
			}
			name = normalizeScopedName(name, domain)
			if name == "" || name == domain || seen[name] {
				continue
			}
			seen[name] = true

			findings = append(findings, module.Finding{
				Type:     "censys_name_reference",
				URL:      name,
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("Third-party Censys reference for '%s' with observed IP %s", name, hit.IP),
				Extra: map[string]string{
					"subdomain":          name,
					"ip":                 hit.IP,
					"source":             "censys",
					"validated":          "false",
					"validation_state":   "third_party_inventory_reference",
					"confidence":         "0.82",
					"promote_to_context": "false",
				},
			})
		}
	}
	return findings, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func normaliseDomain(raw string) string {
	return urlutil.NormalizeDomain(raw)
}

func normalizeScopedName(raw, domain string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.TrimPrefix(raw, "*.")
	name := urlutil.NormalizeDomain(raw)
	if name == "" || (name != domain && !strings.HasSuffix(name, "."+domain)) {
		return ""
	}
	return name
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

func optInt(opts map[string]string, key string, def int) int {
	v, ok := opts[key]
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func optBool(opts map[string]string, key string, def bool) bool {
	v, ok := opts[key]
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
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

func isExpired(notAfter string) bool {
	if notAfter == "" {
		return false
	}
	// Try common formats
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.999Z07:00",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, f := range formats {
		t, err := time.Parse(f, notAfter)
		if err == nil {
			return time.Now().After(t)
		}
	}
	return false
}

func filterWildcard(findings []module.Finding) []module.Finding {
	out := findings[:0]
	for _, f := range findings {
		if f.Extra["wildcard"] != "true" {
			out = append(out, f)
		}
	}
	return out
}

func dedup(findings []module.Finding) []module.Finding {
	index := make(map[string]int)
	out := make([]module.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Type + "|" + f.Extra["subdomain"]
		if existing, ok := index[key]; ok {
			out[existing].Extra["source"] = mergeCSV(out[existing].Extra["source"], f.Extra["source"])
			continue
		}
		index[key] = len(out)
		out = append(out, f)
	}
	return out
}

func mergeCSV(left, right string) string {
	set := make(map[string]struct{})
	for _, raw := range []string{left, right} {
		for _, value := range strings.Split(raw, ",") {
			value = strings.TrimSpace(value)
			if value != "" {
				set[value] = struct{}{}
			}
		}
	}
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
