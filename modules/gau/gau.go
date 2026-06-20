// Package gau aggregates historical URLs from multiple passive sources:
// Wayback Machine (CDX API), Common Crawl (CC Index API), AlienVault OTX,
// and URLScan.io. This mirrors the behavior of lc/gau (MIT) and
// bp0lr/gauplus (MIT) — same source set, native Go implementation.
//
// Reference: lc/gau (MIT) + bp0lr/gauplus (MIT) — API endpoint patterns only;
// no source code copied. License: MIT (blackhorn-modules).
package gau

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/urlutil"
	"golang.org/x/sync/errgroup"
)

const (
	// defaultTimeout — OPTIMIZED: 15s vs original 25s.
	// Most sources return within 3-5s. 15s gives 3x headroom while failing
	// fast on degraded sources (vs waiting 25s for nothing).
	defaultTimeout = 15 * time.Second

	maxBodyBytes          = 8 * 1024 * 1024 // 8 MiB — CC responses can be large
	defaultPageLimit      = 10              // max CC index pages to fetch
	defaultMaxURLs        = 1000
	defaultMaxDomains     = 10
	defaultRuntimeSeconds = 90
	maxConcurrentSources  = 8
)

// ─── module ──────────────────────────────────────────────────────────────────

// Module aggregates historical URLs from passive sources.
type Module struct {
	client *http.Client
	// Sources selects which providers to query.
	// Default: ["wayback", "commoncrawl", "otx", "urlscan"]
	Sources []string
	// MaxURLs caps the total unique URLs returned (0 = no cap).
	MaxURLs int
	// IncludeSubdomains also fetches URLs for all subdomains of the target.
	IncludeSubdomains bool
	// Blacklist filters out URLs whose extension matches (e.g. "png,jpg,css").
	Blacklist []string
	// Whitelist keeps only URLs with matching extensions (empty = all).
	Whitelist []string

	// Overridable base URLs for testing.
	WaybackBaseURL     string
	CommonCrawlBaseURL string
	OTXBaseURL         string
	URLScanBaseURL     string
}

// New returns a Module with all passive sources enabled.
// Uses an optimized http.Transport with aggressive connection pooling:
//   - MaxIdleConnsPerHost=50: gau hammers the same hosts repeatedly; keeping
//     connections alive avoids TCP+TLS handshake overhead on every request.
//   - ForceAttemptHTTP2: Wayback Machine and URLScan support HTTP/2 multiplexing,
//     which sends multiple requests over one connection (no HOL blocking).
//   - DisableKeepAlives=false: explicit — connections must be reused.
//   - TLSHandshakeTimeout=3s: fail fast on TLS negotiation, not on data transfer.
func New() *Module {
	transport := &http.Transport{
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		MaxConnsPerHost:       50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     false,
		DisableCompression:    false,
	}
	return &Module{
		client: &http.Client{
			Timeout:   defaultTimeout,
			Transport: transport,
		},
		Sources: []string{"wayback", "commoncrawl", "otx", "urlscan"},
		MaxURLs: defaultMaxURLs,
	}
}

// NewWithClient creates a Module using the provided HTTP client.
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client:  c,
		Sources: []string{"wayback", "commoncrawl", "otx", "urlscan"},
		MaxURLs: defaultMaxURLs,
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "gau" }

// Run implements module.Module.
// Input.Target: domain to fetch URLs for (required).
// Input.URLs: additional domains.
// Input.Options:
//   - "sources":    comma-separated source list
//   - "max_urls":   cap on total references (default: 1000)
//   - "max_domains": cap on unique domains queried (default: 10)
//   - "max_runtime_seconds": global execution budget (default: 90)
//   - "subdomains": "true" to include subdomains (default: false)
//   - "blacklist":  comma-separated file extensions to exclude
//   - "whitelist":  comma-separated file extensions to keep only
//
// OPTIMIZATION: Common Crawl collinfo.json is prefetched asynchronously
// before the main source loop starts. This eliminates the ~500ms blocking
// delay that commoncrawl's goroutine caused in benchmarks — by the time
// the CC goroutine runs, the index list is already available.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	domains := collectDomains(input)
	if len(domains) == 0 {
		return nil, fmt.Errorf("gau: no domains provided")
	}

	sources, maxURLs, blacklist, whitelist := m.parseOptions(input.Options)
	maxDomains := optInt(input.Options, "max_domains", defaultMaxDomains)
	if len(domains) > maxDomains {
		domains = domains[:maxDomains]
	}
	maxRuntime := optInt(input.Options, "max_runtime_seconds", defaultRuntimeSeconds)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntime)*time.Second)
	defer cancel()

	// Prefetch Common Crawl collinfo.json in background if CC is a requested source.
	// This hides the network latency behind the time spent resolving/setup.
	var ccIndexesCh chan []ccIndex
	for _, s := range sources {
		if s == "commoncrawl" || s == "cc" {
			ccIndexesCh = make(chan []ccIndex, 1)
			go func() {
				indexes, err := m.fetchCCIndexList(runCtx)
				if err != nil {
					slog.Debug("gau: CC prefetch failed", "err", err)
					ccIndexesCh <- nil
					return
				}
				ccIndexesCh <- indexes
			}()
			break
		}
	}

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	g, gctx := errgroup.WithContext(runCtx)
	g.SetLimit(maxConcurrentSources)

	for _, domain := range domains {
		for _, source := range sources {
			domain, source := domain, source
			g.Go(func() error {
				var urls []string
				var err error
				if (source == "commoncrawl" || source == "cc") && ccIndexesCh != nil {
					// Use prefetched index list — avoids double-fetch
					urls, err = m.fetchCommonCrawlWithIndexes(gctx, domain, ccIndexesCh)
				} else {
					urls, err = m.fetchSource(gctx, source, domain)
				}
				if err != nil {
					slog.Debug("gau: source failed", "source", source, "domain", domain, "err", err)
					return nil
				}
				ff := buildFindings(domain, source, urls, blacklist, whitelist)
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
	if maxURLs > 0 && len(deduped) > maxURLs {
		deduped = deduped[:maxURLs]
	}
	return deduped, nil
}

// ─── option parsing ───────────────────────────────────────────────────────────

func (m *Module) parseOptions(opts map[string]string) (sources []string, maxURLs int, blacklist, whitelist []string) {
	if opts == nil {
		opts = make(map[string]string)
	}

	if v := opts["sources"]; v != "" {
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(strings.ToLower(s))
			if s != "" {
				sources = append(sources, s)
			}
		}
	}
	if len(sources) == 0 {
		sources = m.Sources
	}

	maxURLs = m.MaxURLs
	if v := opts["max_urls"]; v != "" {
		fmt.Sscanf(v, "%d", &maxURLs)
	}

	blacklist = m.Blacklist
	if v := opts["blacklist"]; v != "" {
		for _, ext := range strings.Split(v, ",") {
			blacklist = append(blacklist, strings.TrimSpace(strings.ToLower(ext)))
		}
	}

	whitelist = m.Whitelist
	if v := opts["whitelist"]; v != "" {
		whitelist = nil
		for _, ext := range strings.Split(v, ",") {
			whitelist = append(whitelist, strings.TrimSpace(strings.ToLower(ext)))
		}
	}

	return
}

// ─── source dispatcher ────────────────────────────────────────────────────────

func (m *Module) fetchSource(ctx context.Context, source, domain string) ([]string, error) {
	switch source {
	case "wayback":
		return m.fetchWayback(ctx, domain)
	case "commoncrawl", "cc":
		return m.fetchCommonCrawl(ctx, domain)
	case "otx", "alienvault":
		return m.fetchOTX(ctx, domain)
	case "urlscan":
		return m.fetchURLScan(ctx, domain)
	default:
		return nil, fmt.Errorf("unknown source: %q", source)
	}
}

// ─── Wayback Machine ─────────────────────────────────────────────────────────

func (m *Module) waybackBase() string {
	if m.WaybackBaseURL != "" {
		return m.WaybackBaseURL
	}
	return "https://web.archive.org"
}

// fetchWayback fetches historical URLs from the Wayback Machine CDX API.
//
// Uses a single request with a high limit (10000) — simple, reliable, fast.
// The CDX API paginates at pageSize=5000 records per page by default; with
// limit=10000 we get at most 2 implicit pages in one call. For most domains
// this is a single round-trip. Connection keep-alive reuses the TCP connection
// from prior requests to the same host, eliminating handshake overhead.
func (m *Module) fetchWayback(ctx context.Context, domain string) ([]string, error) {
	matchType := "domain"
	if !m.IncludeSubdomains {
		matchType = "host"
	}
	apiURL := fmt.Sprintf(
		"%s/cdx/search/cdx?url=%s&matchType=%s&output=json&fl=original&collapse=urlkey&limit=10000&filter=statuscode:200",
		m.waybackBase(), url.QueryEscape(domain), matchType,
	)

	body, code, err := m.get(ctx, apiURL)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("wayback: HTTP %d", code)
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("wayback: JSON parse error: %w", err)
	}

	var urls []string
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		u := row[0]
		if u == "original" || u == "" { // skip header row
			continue
		}
		urls = append(urls, u)
	}
	return urls, nil
}

// ─── Common Crawl ─────────────────────────────────────────────────────────────

type ccIndex struct {
	ID     string `json:"id"`
	CDXAPI string `json:"cdx-api"`
}

func (m *Module) ccBase() string {
	if m.CommonCrawlBaseURL != "" {
		return m.CommonCrawlBaseURL
	}
	return "https://index.commoncrawl.org"
}

// fetchCCIndexList fetches the Common Crawl index list from collinfo.json.
// Called once (in a background goroutine) and the result is shared via channel
// to avoid redundant HTTP round-trips when multiple domains are queried.
func (m *Module) fetchCCIndexList(ctx context.Context) ([]ccIndex, error) {
	indexURL := m.ccBase() + "/collinfo.json"
	body, code, err := m.get(ctx, indexURL)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("commoncrawl: collinfo HTTP %d", code)
	}
	var indexes []ccIndex
	if err := json.Unmarshal(body, &indexes); err != nil {
		return nil, fmt.Errorf("commoncrawl: collinfo parse error: %w", err)
	}
	return indexes, nil
}

// fetchCommonCrawlWithIndexes uses a pre-fetched index list from the channel.
// The channel carries the result of the background prefetch — reading it blocks
// only if the prefetch hasn't finished yet (typically < 200ms by this point).
// Channel is buffered(1) so re-send after read is safe and non-blocking.
func (m *Module) fetchCommonCrawlWithIndexes(ctx context.Context, domain string, indexesCh chan []ccIndex) ([]string, error) {
	var indexes []ccIndex
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case idx := <-indexesCh:
		indexes = idx
		// Put the value back so subsequent domain goroutines can also read it.
		// Non-blocking: if another goroutine already re-filled it, skip.
		select {
		case indexesCh <- indexes:
		default:
		}
	}
	if len(indexes) == 0 {
		return nil, nil
	}
	return m.queryCCIndexes(ctx, domain, indexes)
}

func (m *Module) fetchCommonCrawl(ctx context.Context, domain string) ([]string, error) {
	// Step 1: get available CC indexes.
	indexes, err := m.fetchCCIndexList(ctx)
	if err != nil {
		return nil, err
	}
	if len(indexes) == 0 {
		return nil, nil
	}
	return m.queryCCIndexes(ctx, domain, indexes)
}

// queryCCIndexes fans out CDX queries across N most-recent CC indexes.
func (m *Module) queryCCIndexes(ctx context.Context, domain string, indexes []ccIndex) ([]string, error) {
	// Use the most recent N indexes.
	limit := defaultPageLimit
	if limit > len(indexes) {
		limit = len(indexes)
	}

	var allURLs []string
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(limit)

	for i := 0; i < limit; i++ {
		idx := indexes[i]
		g.Go(func() error {
			urls, err := m.fetchCCIndex(gctx, idx.CDXAPI, domain)
			if err != nil {
				slog.Debug("gau: CC index fetch failed", "index", idx.ID, "err", err)
				return nil
			}
			mu.Lock()
			allURLs = append(allURLs, urls...)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()
	return allURLs, nil
}

func (m *Module) fetchCCIndex(ctx context.Context, cdxAPI, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("%s?url=%s/*&output=json&fl=url&limit=1000", cdxAPI, url.QueryEscape(domain))
	body, code, err := m.get(ctx, apiURL)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK && code != http.StatusNotFound {
		return nil, fmt.Errorf("CC index: HTTP %d", code)
	}
	if code == http.StatusNotFound || len(body) == 0 {
		return nil, nil
	}

	var urls []string
	// CC returns one JSON object per line.
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &obj); err == nil && obj.URL != "" {
			urls = append(urls, obj.URL)
		}
	}
	return urls, nil
}

// ─── AlienVault OTX ──────────────────────────────────────────────────────────

type otxResponse struct {
	URLList []struct {
		URL string `json:"url"`
	} `json:"url_list"`
	HasNext bool `json:"has_next"`
}

func (m *Module) otxBase() string {
	if m.OTXBaseURL != "" {
		return m.OTXBaseURL
	}
	return "https://otx.alienvault.com"
}

func (m *Module) fetchOTX(ctx context.Context, domain string) ([]string, error) {
	var urls []string
	page := 1
	for page <= 20 { // max 20 pages to avoid runaway
		apiURL := fmt.Sprintf(
			"%s/api/v1/indicators/domain/%s/url_list?limit=100&page=%d",
			m.otxBase(), url.PathEscape(domain), page,
		)
		body, code, err := m.get(ctx, apiURL)
		if err != nil {
			return urls, err
		}
		if code != http.StatusOK {
			break
		}

		var resp otxResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			break
		}
		for _, item := range resp.URLList {
			if item.URL != "" {
				urls = append(urls, item.URL)
			}
		}
		if !resp.HasNext {
			break
		}
		page++
	}
	return urls, nil
}

// ─── URLScan.io ───────────────────────────────────────────────────────────────

type urlscanResponse struct {
	Results []struct {
		Page struct {
			URL string `json:"url"`
		} `json:"page"`
	} `json:"results"`
	Total int `json:"total"`
}

func (m *Module) urlscanBase() string {
	if m.URLScanBaseURL != "" {
		return m.URLScanBaseURL
	}
	return "https://urlscan.io"
}

func (m *Module) fetchURLScan(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf(
		"%s/api/v1/search/?q=domain:%s&size=10000&fields=page.url",
		m.urlscanBase(), url.QueryEscape(domain),
	)
	body, code, err := m.get(ctx, apiURL)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("urlscan: HTTP %d", code)
	}

	var resp urlscanResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("urlscan: JSON parse error: %w", err)
	}

	var urls []string
	for _, r := range resp.Results {
		if r.Page.URL != "" {
			urls = append(urls, r.Page.URL)
		}
	}
	return urls, nil
}

// ─── finding builder ─────────────────────────────────────────────────────────

func buildFindings(domain, source string, urls, blacklist, whitelist []string) []module.Finding {
	findings := make([]module.Finding, 0, len(urls))
	for _, raw := range urls {
		canonical, ok := urlutil.CanonicalHTTP(raw)
		if !ok || !urlutil.InDomainScope(canonical, domain) || !matchesFilter(canonical, blacklist, whitelist) {
			continue
		}
		findings = append(findings, module.Finding{
			Type:     "historical_reference",
			URL:      canonical,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("URL found via %s for %s", source, domain),
			Extra: map[string]string{
				"source":             source,
				"domain":             domain,
				"url":                canonical,
				"confidence":         "0.85",
				"state":              "historical_unverified",
				"promote_to_context": "false",
			},
		})
	}
	return findings
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// matchesFilter returns true if the URL passes blacklist/whitelist checks.
func matchesFilter(rawURL string, blacklist, whitelist []string) bool {
	ext := urlExtension(rawURL)
	for _, b := range blacklist {
		if ext == b {
			return false
		}
	}
	if len(whitelist) > 0 {
		for _, w := range whitelist {
			if ext == w {
				return true
			}
		}
		return false
	}
	return true
}

// urlExtension returns the file extension of a URL path (lowercase, no dot).
func urlExtension(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	path := u.Path
	if i := strings.LastIndex(path, "."); i >= 0 {
		return strings.ToLower(path[i+1:])
	}
	return ""
}

func (m *Module) get(ctx context.Context, rawURL string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "blackhorn-gau/1.0")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return body, resp.StatusCode, err
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
		if _, ok := seen[f.URL]; !ok {
			seen[f.URL] = struct{}{}
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
