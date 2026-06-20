// Package brandmon performs brand monitoring: typosquatting detection,
// look-alike domain discovery, social media impersonation and trademark
// abuse detection across multiple sources.
//
// Sources:
//   - URLScan.io     — searches for visually similar domains (free, API key optional)
//   - DNS probe      — checks common typo/variation patterns of the target domain
//   - dnstwist-style — generates typosquatting permutations and probes DNS
//   - Phishtank      — known phishing URLs matching the brand (free API)
//   - Google SERP    — searches via SerpAPI for brand impersonation (key optional)
//   - OpenPhish      — open feed of phishing URLs (free)
//
// Typosquatting techniques applied:
//   - Character transposition (exmaple.com)
//   - Missing character (exaple.com)
//   - Added character (exammple.com)
//   - Homograph substitution (examp1e.com)
//   - TLD variation (.net .org .co .io .biz)
//   - Combosquatting (-login, -secure, -verify)
//   - Bit-flip (rare but listed)
//
// Usage:
//
//	m := brandmon.New()
//	findings, err := m.Run(ctx, module.Input{
//	    Target:  "example.com",
//	    Options: map[string]string{
//	        "sources":       "dns,urlscan,phishtank",
//	        "urlscan_key":   "<key>",
//	        "max_typos":     "100",
//	    },
//	})
package brandmon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	maxBodyBrand             = 2 * 1024 * 1024 // 2 MB
	maxParallel              = 6
	defaultMaxRuntimeSeconds = 60
	defaultMaxResults        = 100
)

// Module implements module.Module for brand monitoring.
type Module struct {
	client   *http.Client
	resolver *net.Resolver
}

// New returns a Module with default HTTP client and resolver.
func New() *Module {
	return NewWithClient(&http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     60 * time.Second,
		},
	})
}

// NewWithClient allows injecting a custom HTTP client (useful for tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client: c,
		resolver: &net.Resolver{
			PreferGo: true,
		},
	}
}

// Name returns the canonical module identifier.
func (m *Module) Name() string { return "brandmon" }

// Run executes brand monitoring checks and returns findings.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("brandmon: target vazio")
	}

	// Normalise domain
	domain := normaliseDomain(target)
	if domain == "" || !strings.Contains(domain, ".") {
		return nil, fmt.Errorf("brandmon: target '%s' não é um domínio válido", target)
	}

	// Extract brand name (without TLD)
	brand := extractBrand(domain)

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}
	sourcesFilter := opts["sources"]
	maxTypos := clampInt(optInt(opts, "max_typos", 100), 1, 500)
	maxResults := clampInt(optInt(opts, "max_results", defaultMaxResults), 1, 500)
	maxRuntime := clampInt(optInt(opts, "max_runtime_seconds", defaultMaxRuntimeSeconds), 1, 300)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntime)*time.Second)
	defer cancel()

	slog.InfoContext(runCtx, "brandmon.Run iniciado",
		"target", target,
		"brand", brand,
		"domain", domain,
		"sources", sourcesFilter,
		"max_typos", maxTypos,
	)

	// Generate typosquatting candidates
	typos := generateTypos(domain, brand, maxTypos)

	type sourceFunc struct {
		name string
		fn   func(context.Context, string, string, []string, map[string]string) ([]module.Finding, error)
	}

	sources := []sourceFunc{
		{"dns", m.probeDNS},
		{"urlscan", m.queryURLScan},
		{"phishtank", m.queryPhishtank},
		{"openphish", m.queryOpenPhish},
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
			slog.DebugContext(gctx, "brandmon: consultando fonte",
				"source", s.name, "brand", brand)
			findings, err := s.fn(gctx, domain, brand, typos, opts)
			if err != nil {
				slog.WarnContext(gctx, "brandmon: fonte retornou erro",
					"source", s.name, "err", err)
				return nil
			}
			mu.Lock()
			all = append(all, findings...)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	result := decorateFindings(dedup(all), domain, brand)
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}
		return result[i].URL < result[j].URL
	})
	if len(result) > maxResults {
		result = result[:maxResults]
	}
	slog.InfoContext(runCtx, "brandmon.Run concluído",
		"target", target,
		"typos_checked", len(typos),
		"findings", len(result),
	)
	return result, nil
}

// ─── DNS probe ────────────────────────────────────────────────────────────────

func (m *Module) probeDNS(ctx context.Context, domain, _ string, typos []string, _ map[string]string) ([]module.Finding, error) {
	var mu sync.Mutex
	var findings []module.Finding

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(20) // DNS é barato

	for _, typo := range typos {
		typo := typo
		if typo == domain {
			continue // skip original
		}
		g.Go(func() error {
			addrs, err := m.resolver.LookupHost(gctx, typo)
			if err != nil || len(addrs) == 0 {
				return nil // não resolveu = sem finding
			}

			distance := levenshtein(domain, typo)
			sev := module.SeverityInfo
			conf := "0.78"

			if distance == 1 {
				sev = module.SeverityLow
				conf = "0.88"
			}

			f := module.Finding{
				Type:     "brand_domain_candidate",
				URL:      fmt.Sprintf("http://%s", typo),
				Severity: sev,
				Detail:   fmt.Sprintf("Domínio typosquatting '%s' resolve para %v (distância de edição: %d do original '%s')", typo, addrs, distance, domain),
				Extra: map[string]string{
					"typo_domain":   typo,
					"original":      domain,
					"resolved_ips":  strings.Join(addrs, ","),
					"edit_distance": strconv.Itoa(distance),
					"source":        "dns_probe",
					"confidence":    conf,
				},
			}
			mu.Lock()
			findings = append(findings, f)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()
	return findings, nil
}

// ─── URLScan.io ───────────────────────────────────────────────────────────────

type urlscanResult struct {
	Results []struct {
		Task struct {
			Domain string `json:"domain"`
			URL    string `json:"url"`
		} `json:"task"`
		Page struct {
			Domain string `json:"domain"`
			IP     string `json:"ip"`
		} `json:"page"`
	} `json:"results"`
	Total int `json:"total"`
}

func (m *Module) queryURLScan(ctx context.Context, domain, brand string, _ []string, opts map[string]string) ([]module.Finding, error) {
	apiKey := opts["urlscan_key"]

	// Search for similar domains mentioning the brand
	query := url.QueryEscape(fmt.Sprintf("domain:*%s* AND NOT domain:%s", brand, domain))
	u := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=%s&size=50", query)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("API-Key", apiKey)
	}
	req.Header.Set("User-Agent", "blackhorn-brandmon/1.0 (OSINT; security research)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("urlscan: rate limit atingido")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("urlscan: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBrand))
	if err != nil {
		return nil, err
	}

	var result urlscanResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("urlscan: parse: %w", err)
	}

	var findings []module.Finding
	for _, r := range result.Results {
		d := r.Page.Domain
		if d == "" {
			d = r.Task.Domain
		}
		d = normaliseDomain(d)
		if d == domain || d == "" || !hostnameContainsBrand(d, brand) {
			continue
		}

		findings = append(findings, module.Finding{
			Type:     "brand_domain_reference",
			URL:      r.Task.URL,
			Severity: module.SeverityInfo,
			Detail: fmt.Sprintf("Domínio '%s' encontrado via URLScan.io como possível impersonação da marca '%s' — foi escaneado recentemente",
				d, brand),
			Extra: map[string]string{
				"impersonating_domain": d,
				"original_brand":       brand,
				"original_domain":      domain,
				"scan_url":             r.Task.URL,
				"ip":                   r.Page.IP,
				"total_found":          strconv.Itoa(result.Total),
				"source":               "urlscan",
				"confidence":           "0.72",
			},
		})
	}
	return findings, nil
}

// ─── PhishTank ────────────────────────────────────────────────────────────────

type phishEntry struct {
	URL        string `json:"url"`
	Verified   string `json:"verified"`
	Target     string `json:"target"`
	PhishID    string `json:"phish_id"`
	VerifiedAt string `json:"verified_at"`
}

func (m *Module) queryPhishtank(ctx context.Context, domain, brand string, _ []string, opts map[string]string) ([]module.Finding, error) {
	apiKey := opts["phishtank_key"]

	formData := url.Values{
		"url":    {fmt.Sprintf("https://%s", domain)},
		"format": {"json"},
	}
	if apiKey != "" {
		formData.Set("app_key", apiKey)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://checkurl.phishtank.com/checkurl/",
		strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "blackhorn-brandmon/1.0 phishtank/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("phishtank: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBrand))
	if err != nil {
		return nil, err
	}

	// PhishTank response: {"meta":{"status":"success"},"results":{"url":"...","in_database":bool,...}}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("phishtank: parse: %w", err)
	}

	resultsRaw, ok := raw["results"]
	if !ok {
		return nil, nil
	}

	var results struct {
		InDatabase  bool   `json:"in_database"`
		Verified    bool   `json:"verified"`
		PhishID     string `json:"phish_id"`
		PhishDetail string `json:"phish_detail_page"`
	}
	if err := json.Unmarshal(resultsRaw, &results); err != nil {
		return nil, nil
	}

	if !results.InDatabase {
		return nil, nil
	}

	sev := module.SeverityLow
	conf := "0.80"
	note := "relatado mas não verificado"
	if results.Verified {
		sev = module.SeverityHigh
		conf = "0.95"
		note = "VERIFICADO como phishing"
	}

	return []module.Finding{{
		Type:     "phishing_reference",
		URL:      fmt.Sprintf("https://%s", domain),
		Severity: sev,
		Detail: fmt.Sprintf("Domínio '%s' está no banco PhishTank (%s) — associado à marca '%s' (ID: %s)",
			domain, note, brand, results.PhishID),
		Extra: map[string]string{
			"phish_id":         results.PhishID,
			"verified":         strconv.FormatBool(results.Verified),
			"phish_detail_url": results.PhishDetail,
			"brand":            brand,
			"source":           "phishtank",
			"confidence":       conf,
		},
	}}, nil
}

// ─── OpenPhish ────────────────────────────────────────────────────────────────

func (m *Module) queryOpenPhish(ctx context.Context, _, brand string, _ []string, _ map[string]string) ([]module.Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://openphish.com/feed.txt", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-brandmon/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openphish: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBrand))
	if err != nil {
		return nil, err
	}

	var findings []module.Finding
	brandLower := strings.ToLower(brand)

	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !urlHostnameContainsBrand(line, brandLower) {
			continue
		}

		findings = append(findings, module.Finding{
			Type:     "phishing_reference",
			URL:      line,
			Severity: module.SeverityMedium,
			Detail: fmt.Sprintf("URL de phishing '%s' encontrada no feed OpenPhish mencionando a marca '%s'",
				line, brand),
			Extra: map[string]string{
				"phishing_url": line,
				"brand":        brand,
				"source":       "openphish",
				"confidence":   "0.85",
			},
		})

		if len(findings) >= 20 {
			break // cap por marca
		}
	}
	return findings, nil
}

// ─── typosquatting generation ─────────────────────────────────────────────────

var commonTLDs = []string{
	".com", ".net", ".org", ".co", ".io", ".biz", ".info",
	".com.br", ".net.br", ".org.br", ".br",
	".xyz", ".online", ".site", ".store",
}

var homographMap = map[rune][]rune{
	'a': {'@', '4'},
	'e': {'3'},
	'i': {'1', 'l'},
	'o': {'0'},
	's': {'5'},
	'l': {'1'},
	'g': {'9'},
}

var comboSuffixes = []string{
	"-login", "-signin", "-account", "-secure", "-verify",
	"-support", "-help", "-service", "-online", "-web",
	"-brasil", "-br", "-auth", "-portal",
}

var comboPrefixes = []string{
	"login-", "signin-", "secure-", "my-", "www-",
}

func generateTypos(domain, brand string, max int) []string {
	seen := map[string]bool{domain: true}
	result := []string{}

	addIfNew := func(d string) {
		d = strings.ToLower(d)
		if !seen[d] && len(d) > 3 && len(d) < 64 && strings.Contains(d, ".") {
			seen[d] = true
			result = append(result, d)
		}
	}

	baseTLD := extractTLD(domain)

	// 1. TLD variations
	for _, tld := range commonTLDs {
		if len(result) >= max {
			break
		}
		addIfNew(brand + tld)
	}

	// 2. Combosquatting (brand + suffix)
	for _, suf := range comboSuffixes {
		if len(result) >= max {
			break
		}
		addIfNew(brand + suf + baseTLD)
	}

	// 3. Combosquatting (prefix + brand)
	for _, pre := range comboPrefixes {
		if len(result) >= max {
			break
		}
		addIfNew(pre + brand + baseTLD)
	}

	// 4. Missing char
	for i := 0; i < len(brand) && len(result) < max; i++ {
		typo := brand[:i] + brand[i+1:]
		if len(typo) > 2 {
			addIfNew(typo + baseTLD)
		}
	}

	// 5. Transposition
	for i := 0; i < len(brand)-1 && len(result) < max; i++ {
		runes := []rune(brand)
		runes[i], runes[i+1] = runes[i+1], runes[i]
		addIfNew(string(runes) + baseTLD)
	}

	// 6. Added char (double)
	for i := 0; i < len(brand) && len(result) < max; i++ {
		addIfNew(brand[:i] + string(brand[i]) + brand[i:] + baseTLD)
	}

	// 7. Homograph substitution
	for i, ch := range brand {
		if subs, ok := homographMap[ch]; ok {
			for _, sub := range subs {
				if len(result) >= max {
					break
				}
				typo := brand[:i] + string(sub) + brand[i+1:]
				addIfNew(typo + baseTLD)
			}
		}
	}

	return result
}

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	dp := make([]int, lb+1)
	for j := range dp {
		dp[j] = j
	}
	for i := 1; i <= la; i++ {
		prev := dp[0]
		dp[0] = i
		for j := 1; j <= lb; j++ {
			curr := dp[j]
			if ra[i-1] == rb[j-1] {
				dp[j] = prev
			} else {
				min3 := prev
				if dp[j-1]+1 < min3 {
					min3 = dp[j-1] + 1
				}
				if dp[j]+1 < min3 {
					min3 = dp[j] + 1
				}
				dp[j] = min3
			}
			prev = curr
		}
	}
	return dp[lb]
}

// ─── helpers ──────────────────────────────────────────────────────────────────

var reScheme = regexp.MustCompile(`^https?://`)

func normaliseDomain(raw string) string {
	raw = reScheme.ReplaceAllString(raw, "")
	raw = strings.SplitN(raw, "/", 2)[0]
	return strings.ToLower(strings.TrimSpace(raw))
}

func extractBrand(domain string) string {
	// example.com → example
	// example.co.uk → example
	parts := strings.Split(domain, ".")
	if len(parts) >= 1 {
		return parts[0]
	}
	return domain
}

func extractTLD(domain string) string {
	idx := strings.Index(domain, ".")
	if idx < 0 {
		return ".com"
	}
	return domain[idx:]
}

func hostnameContainsBrand(hostname, brand string) bool {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	needle := strings.ToLower(strings.TrimSpace(brand))
	if host == "" || len(needle) < 2 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == needle ||
			strings.HasPrefix(label, needle+"-") ||
			strings.HasSuffix(label, "-"+needle) {
			return true
		}
	}
	return false
}

func urlHostnameContainsBrand(rawURL, brand string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	return hostnameContainsBrand(parsed.Hostname(), brand)
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

func decorateFindings(findings []module.Finding, domain, brand string) []module.Finding {
	for i := range findings {
		if findings[i].Extra == nil {
			findings[i].Extra = map[string]string{}
		}
		findings[i].Extra["original_domain"] = domain
		findings[i].Extra["brand"] = brand
		findings[i].Extra["promote_to_context"] = "false"
		findings[i].Extra["threat_validated"] = "false"
		if findings[i].Extra["source"] == "dns_probe" {
			findings[i].Extra["validated"] = "true"
			findings[i].Extra["validation_state"] = "dns_resolution_confirmed_brand_link_unverified"
		} else {
			findings[i].Extra["validated"] = "false"
			findings[i].Extra["validation_state"] = "third_party_reference"
		}
	}
	return findings
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
