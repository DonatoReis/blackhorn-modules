// Package katana is an extended web crawler that goes beyond the basic BFS of
// the crawler module. It adds:
//   - Form discovery and field extraction (method, action, inputs, textareas, selects)
//   - JavaScript endpoint extraction (fetch(), axios, XMLHttpRequest, import patterns)
//   - Asset tracking (CSS, JS, images, fonts, media)
//   - robots.txt / sitemap.xml seed harvesting
//   - Configurable scope: same-host, same-domain, or allow-list
//   - BodySize cap + io.LimitReader on every read
//   - errgroup-based parallel BFS with depth control
//
// Reference: projectdiscovery/katana (MIT) — architecture and scope logic;
// no source code copied. License: MIT (blackhorn-modules).
package katana

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/urlutil"
	"golang.org/x/sync/errgroup"
)

const (
	defaultTimeout        = 15 * time.Second
	maxBodyBytes          = 2 * 1024 * 1024 // 2 MiB
	defaultDepth          = 3
	defaultParallel       = 10
	defaultMaxPages       = 300
	defaultMaxResults     = 1000
	defaultRuntimeSeconds = 180
)

// ─── finding types ────────────────────────────────────────────────────────────

const (
	TypeCrawled    = "crawled_url"
	TypeForm       = "form_field"
	TypeJSEndpoint = "js_endpoint"
	TypeAsset      = "asset_url"
	TypeRobots     = "robots_disallow"
	TypeSitemap    = "sitemap_url"
)

// ─── form structures ─────────────────────────────────────────────────────────

// FormField represents a single HTML form field.
type FormField struct {
	FormAction string
	FormMethod string
	Name       string
	Type       string // text, password, email, hidden, submit, select, textarea
	Value      string // default value if any
}

// ─── scope ────────────────────────────────────────────────────────────────────

// Scope controls which URLs are crawled.
type Scope string

const (
	ScopeSameHost   Scope = "host"   // same hostname only
	ScopeSameDomain Scope = "domain" // same eTLD+1
	ScopeAll        Scope = "all"    // follow all links (dangerous — use MaxDepth)
)

// ─── module ───────────────────────────────────────────────────────────────────

// Module is the katana extended crawler.
type Module struct {
	client *http.Client
	// MaxDepth is the BFS depth limit (default: 3).
	MaxDepth int
	// Parallelism is the max concurrent requests (default: 10).
	Parallelism int
	// Scope controls link-follow policy.
	Scope Scope
	// ExtractForms enables HTML form field discovery.
	ExtractForms bool
	// ExtractJS enables JavaScript endpoint extraction.
	ExtractJS bool
	// ExtractAssets enables asset URL collection.
	ExtractAssets bool
	// SeedRobots fetches /robots.txt to seed the crawl.
	SeedRobots bool
	// SeedSitemap fetches /sitemap.xml to seed the crawl.
	SeedSitemap bool
	// AllowedDomains is an optional extra scope allowlist.
	AllowedDomains []string
	// Headers are extra HTTP headers added to every request.
	Headers map[string]string
}

type runOptions struct {
	depth         int
	parallelism   int
	maxPages      int
	maxResults    int
	maxRuntime    int
	scope         Scope
	extractForms  bool
	extractJS     bool
	extractAssets bool
	seedRobots    bool
	seedSitemap   bool
}

// New returns a Module with sensible defaults.
func New() *Module {
	return &Module{
		client:        httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		MaxDepth:      defaultDepth,
		Parallelism:   defaultParallel,
		Scope:         ScopeSameHost,
		ExtractForms:  true,
		ExtractJS:     true,
		ExtractAssets: false,
		SeedRobots:    true,
		SeedSitemap:   true,
	}
}

// NewWithClient creates a Module using the provided HTTP client.
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client:       c,
		MaxDepth:     defaultDepth,
		Parallelism:  defaultParallel,
		Scope:        ScopeSameHost,
		ExtractForms: true,
		ExtractJS:    true,
		SeedRobots:   true,
		SeedSitemap:  true,
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "katana" }

// Run implements module.Module.
// Input.Target: seed URL (required).
// Input.URLs: additional seed URLs.
// Input.Options:
//   - "depth":         BFS depth (default: 3)
//   - "parallelism":   concurrency (default: 10)
//   - "scope":         host|domain|all
//   - "forms":         "true" to extract form fields
//   - "js":            "true" to extract JS endpoints
//   - "assets":        "true" to include asset URLs
//   - "robots":        "true" to seed from robots.txt
//   - "sitemap":       "true" to seed from sitemap.xml
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	if input.Target == "" && len(input.URLs) == 0 {
		return nil, fmt.Errorf("katana: no seed URLs provided")
	}

	options := m.parseOptions(input.Options)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(options.maxRuntime)*time.Second)
	defer cancel()

	seeds := collectSeeds(input)
	if len(seeds) == 0 {
		return nil, fmt.Errorf("katana: no valid seed URLs")
	}
	if len(seeds) > options.maxPages {
		seeds = seeds[:options.maxPages]
	}

	base := seeds[0] // primary base for scope computation
	baseParsed, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("katana: invalid seed URL %q: %w", base, err)
	}

	// BFS state
	type qItem struct {
		rawURL string
		depth  int
	}

	var (
		visited  = make(map[string]struct{})
		findings []module.Finding
		queue    []qItem
	)

	for _, s := range seeds {
		queue = append(queue, qItem{s, 0})
		visited[s] = struct{}{}
	}

	// Optionally seed from robots.txt / sitemap.xml.
	if options.seedRobots {
		robotsURLs := m.fetchRobots(runCtx, base)
		for _, u := range robotsURLs {
			findings = append(findings, candidateFinding(
				TypeRobots,
				u,
				"Disallow path observed in robots.txt",
				"robots.txt",
				"robots_disallow_candidate",
			))
		}
	}

	if options.seedSitemap {
		sitemapURLs := m.fetchSitemap(runCtx, base)
		for _, rawURL := range sitemapURLs {
			u, ok := urlutil.CanonicalHTTP(rawURL)
			if !ok {
				continue
			}
			findings = append(findings, candidateFinding(
				TypeSitemap,
				u,
				"URL observed in sitemap.xml",
				"sitemap.xml",
				"sitemap_location_candidate",
			))
			if len(visited) >= options.maxPages || !m.inScope(u, baseParsed, options.scope) {
				continue
			}
			if _, ok := visited[u]; !ok {
				visited[u] = struct{}{}
				queue = append(queue, qItem{u, 0})
			}
		}
	}

	for len(queue) > 0 && runCtx.Err() == nil && len(findings) < options.maxResults {
		// Drain queue into a batch for this BFS level.
		level := queue
		queue = nil

		g, gctx := errgroup.WithContext(runCtx)
		g.SetLimit(options.parallelism)

		type crawlResult struct {
			links    []string
			findings []module.Finding
		}
		results := make([]crawlResult, len(level))

		for i, item := range level {
			i, item := i, item
			if item.depth > options.depth {
				continue
			}
			g.Go(func() error {
				links, ff, err := m.crawlPage(gctx, item.rawURL, baseParsed, options)
				if err != nil {
					slog.Debug("katana: crawl error", "url", item.rawURL, "err", err)
					return nil
				}
				results[i] = crawlResult{links: links, findings: ff}
				return nil
			})
		}

		_ = g.Wait()

		for i, res := range results {
			findings = append(findings, res.findings...)
			for _, link := range res.links {
				if len(visited) >= options.maxPages {
					break
				}
				if _, ok := visited[link]; !ok {
					visited[link] = struct{}{}
					queue = append(queue, qItem{link, level[i].depth + 1})
				}
			}
		}
	}

	findings = dedupFindings(findings)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Type == findings[j].Type {
			return findings[i].URL < findings[j].URL
		}
		return findings[i].Type < findings[j].Type
	})
	if len(findings) > options.maxResults {
		findings = findings[:options.maxResults]
	}
	return findings, nil
}

// ─── page crawl ───────────────────────────────────────────────────────────────

func (m *Module) crawlPage(ctx context.Context, rawURL string, base *url.URL, options runOptions) (links []string, findings []module.Finding, err error) {
	body, code, contentType, err := m.get(ctx, rawURL)
	if err != nil {
		return nil, nil, err
	}

	// Record the crawled URL.
	findings = append(findings, module.Finding{
		Type:     TypeCrawled,
		URL:      rawURL,
		Severity: module.SeverityInfo,
		Detail:   fmt.Sprintf("Crawled [%d] %s", code, rawURL),
		Extra: map[string]string{
			"status_code":        fmt.Sprint(code),
			"content_type":       contentType,
			"confidence":         "0.98",
			"validated":          "true",
			"validation_state":   "http_response_confirmed",
			"promote_to_context": "true",
		},
	})

	if !strings.Contains(contentType, "html") && !strings.Contains(contentType, "javascript") {
		return nil, findings, nil
	}

	bodyStr := string(body)
	parsed, _ := url.Parse(rawURL)

	// HTML links.
	rawLinks := extractLinks(bodyStr, rawURL)
	for _, link := range rawLinks {
		abs := absoluteURL(parsed, link)
		if abs == "" {
			continue
		}
		if m.inScope(abs, base, options.scope) {
			links = append(links, abs)
		}
	}

	// Forms.
	if options.extractForms {
		forms := extractForms(bodyStr, rawURL)
		for _, f := range forms {
			findings = append(findings, module.Finding{
				Type:     TypeForm,
				URL:      f.FormAction,
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("Form field %q (%s) on %s", f.Name, f.Type, rawURL),
				Extra: map[string]string{
					"form_action":        f.FormAction,
					"form_method":        f.FormMethod,
					"field_name":         f.Name,
					"field_type":         f.Type,
					"field_value":        f.Value,
					"page_url":           rawURL,
					"confidence":         "0.95",
					"validated":          "true",
					"validation_state":   "observed_in_confirmed_response",
					"promote_to_context": "false",
				},
			})
			// Add form action to crawl queue if in scope.
			if f.FormAction != "" && m.inScope(f.FormAction, base, options.scope) {
				links = append(links, f.FormAction)
			}
		}
	}

	// JavaScript endpoint extraction.
	if options.extractJS {
		endpoints := extractJSEndpoints(bodyStr, rawURL)
		for _, ep := range endpoints {
			abs := absoluteURL(parsed, ep)
			if abs == "" || !m.inScope(abs, base, options.scope) {
				continue
			}
			finding := candidateFinding(
				TypeJSEndpoint,
				abs,
				fmt.Sprintf("JS endpoint observed on %s", rawURL),
				rawURL,
				"javascript_endpoint_candidate",
			)
			finding.Extra["endpoint"] = abs
			findings = append(findings, finding)
		}
	}

	// Asset URLs.
	if options.extractAssets {
		assets := extractAssets(bodyStr, rawURL)
		for _, a := range assets {
			abs := absoluteURL(parsed, a)
			if abs == "" || !m.inScope(abs, base, options.scope) {
				continue
			}
			findings = append(findings, candidateFinding(
				TypeAsset,
				abs,
				fmt.Sprintf("Asset reference observed on %s", rawURL),
				rawURL,
				"asset_reference_candidate",
			))
		}
	}

	return links, findings, nil
}

// ─── robots.txt ───────────────────────────────────────────────────────────────

func (m *Module) fetchRobots(ctx context.Context, base string) []string {
	parsed, err := url.Parse(base)
	if err != nil {
		return nil
	}
	robotsURL := parsed.Scheme + "://" + parsed.Host + "/robots.txt"
	body, code, _, err := m.get(ctx, robotsURL)
	if err != nil || code != http.StatusOK {
		return nil
	}

	var paths []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path := strings.TrimSpace(line[len("Disallow:"):])
			if path == "" || path == "/" {
				continue
			}
			full := parsed.Scheme + "://" + parsed.Host + path
			paths = append(paths, full)
		}
	}
	return paths
}

// ─── sitemap.xml ─────────────────────────────────────────────────────────────

type sitemapIndex struct {
	XMLName  xml.Name     `xml:"sitemapindex"`
	Sitemaps []sitemapLoc `xml:"sitemap"`
}

type sitemapURLSet struct {
	XMLName xml.Name     `xml:"urlset"`
	URLs    []sitemapLoc `xml:"url"`
}

type sitemapLoc struct {
	Loc string `xml:"loc"`
}

func (m *Module) fetchSitemap(ctx context.Context, base string) []string {
	parsed, err := url.Parse(base)
	if err != nil {
		return nil
	}
	sitemapURL := parsed.Scheme + "://" + parsed.Host + "/sitemap.xml"
	body, code, _, err := m.get(ctx, sitemapURL)
	if err != nil || code != http.StatusOK || len(body) == 0 {
		return nil
	}

	var urls []string

	// Try urlset first, then sitemapindex.
	var urlset sitemapURLSet
	if err := xml.Unmarshal(body, &urlset); err == nil && len(urlset.URLs) > 0 {
		for _, u := range urlset.URLs {
			if u.Loc != "" {
				urls = append(urls, u.Loc)
			}
		}
		return urls
	}

	var index sitemapIndex
	if err := xml.Unmarshal(body, &index); err == nil {
		for _, s := range index.Sitemaps {
			if s.Loc != "" {
				// Fetch nested sitemaps (one level).
				sub := m.fetchSitemapURL(ctx, s.Loc)
				urls = append(urls, sub...)
			}
		}
	}
	return urls
}

func (m *Module) fetchSitemapURL(ctx context.Context, sitemapURL string) []string {
	body, code, _, err := m.get(ctx, sitemapURL)
	if err != nil || code != http.StatusOK {
		return nil
	}
	var urlset sitemapURLSet
	if err := xml.Unmarshal(body, &urlset); err != nil {
		return nil
	}
	var urls []string
	for _, u := range urlset.URLs {
		if u.Loc != "" {
			urls = append(urls, u.Loc)
		}
	}
	return urls
}

// ─── link extraction (HTML) ───────────────────────────────────────────────────

var (
	reHref   = regexp.MustCompile(`(?i)href\s*=\s*["']([^"'#>]+)["']`)
	reSrc    = regexp.MustCompile(`(?i)src\s*=\s*["']([^"'#>]+)["']`)
	reAction = regexp.MustCompile(`(?i)action\s*=\s*["']([^"'#>]+)["']`)
)

func extractLinks(body, baseURL string) []string {
	var links []string
	for _, re := range []*regexp.Regexp{reHref, reSrc, reAction} {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 && m[1] != "" {
				links = append(links, m[1])
			}
		}
	}
	return links
}

// ─── form extraction ─────────────────────────────────────────────────────────

var (
	reForm      = regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	reFormAttr  = regexp.MustCompile(`(?i)(method|action)\s*=\s*["']([^"']+)["']`)
	reInput     = regexp.MustCompile(`(?i)<input([^>]*)>`)
	reInputAttr = regexp.MustCompile(`(?i)(name|type|value)\s*=\s*["']([^"']+)["']`)
	reTextarea  = regexp.MustCompile(`(?i)<textarea([^>]*)>`)
	reSelect    = regexp.MustCompile(`(?i)<select([^>]*)>`)
)

func extractForms(body, pageURL string) []FormField {
	var fields []FormField
	for _, fm := range reForm.FindAllStringSubmatch(body, -1) {
		if len(fm) < 3 {
			continue
		}
		formAttrs := fm[1]
		formBody := fm[2]
		action, method := pageURL, "GET"
		for _, a := range reFormAttr.FindAllStringSubmatch(formAttrs, -1) {
			if len(a) < 3 {
				continue
			}
			switch strings.ToLower(a[1]) {
			case "action":
				action = a[2]
			case "method":
				method = strings.ToUpper(a[2])
			}
		}
		// Resolve relative action.
		if !strings.HasPrefix(action, "http") {
			base, _ := url.Parse(pageURL)
			if ref, err := url.Parse(action); err == nil {
				action = base.ResolveReference(ref).String()
			}
		}

		// input fields.
		for _, inp := range reInput.FindAllStringSubmatch(formBody, -1) {
			if len(inp) < 2 {
				continue
			}
			attrs := attrMap(inp[1], reInputAttr)
			if attrs["name"] == "" {
				continue
			}
			fields = append(fields, FormField{
				FormAction: action,
				FormMethod: method,
				Name:       attrs["name"],
				Type:       attrs["type"],
				Value:      attrs["value"],
			})
		}

		// textarea fields.
		for _, ta := range reTextarea.FindAllStringSubmatch(formBody, -1) {
			if len(ta) < 2 {
				continue
			}
			attrs := attrMap(ta[1], reInputAttr)
			if attrs["name"] != "" {
				fields = append(fields, FormField{
					FormAction: action,
					FormMethod: method,
					Name:       attrs["name"],
					Type:       "textarea",
				})
			}
		}

		// select fields.
		for _, sel := range reSelect.FindAllStringSubmatch(formBody, -1) {
			if len(sel) < 2 {
				continue
			}
			attrs := attrMap(sel[1], reInputAttr)
			if attrs["name"] != "" {
				fields = append(fields, FormField{
					FormAction: action,
					FormMethod: method,
					Name:       attrs["name"],
					Type:       "select",
				})
			}
		}
	}
	return fields
}

func attrMap(s string, re *regexp.Regexp) map[string]string {
	m := make(map[string]string)
	for _, match := range re.FindAllStringSubmatch(s, -1) {
		if len(match) >= 3 {
			m[strings.ToLower(match[1])] = match[2]
		}
	}
	return m
}

// ─── JavaScript endpoint extraction ──────────────────────────────────────────

// q is a character class matching any quote style used in JS source.
const q = `["'` + "`" + `]`

var (
	// fetch("/api/...") | fetch(`/api/...`) | axios.get("/api/...")
	reFetch = regexp.MustCompile(`(?i)(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(` + q + `([^"'` + "`" + `\s]+)` + q)
	// $.ajax | $.get | $.post
	rejQuery = regexp.MustCompile(`(?i)\$\.(?:ajax|get|post|put|delete)\s*\(` + q + `([^"'` + "`" + `\s]+)` + q)
	// xhr.open("GET", "/...")
	reXHR = regexp.MustCompile(`(?i)\.open\s*\(["'][A-Z]+["']\s*,\s*` + q + `([^"'` + "`" + `\s]+)` + q)
	// import ... from "..." or import("...")
	reImport = regexp.MustCompile(`(?i)import\s*(?:\w+\s+from\s*)?` + q + `([^"'` + "`" + `\s]+)` + q)
	// src="..." for script tags
	reScriptSrc = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	// API path patterns: "/api/..." or "/v[n]/..."
	reAPIPath = regexp.MustCompile(`(?i)` + q + `(/(?:api|v\d+|graphql|rest)[^"'` + "`" + `\s]+)` + q)
)

func extractJSEndpoints(body, _ string) []string {
	seen := make(map[string]struct{})
	var endpoints []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			return
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			endpoints = append(endpoints, s)
		}
	}
	for _, re := range []*regexp.Regexp{reFetch, rejQuery, reXHR, reImport, reScriptSrc, reAPIPath} {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 {
				add(m[1])
			}
		}
	}
	return endpoints
}

// ─── asset extraction ─────────────────────────────────────────────────────────

var (
	// src="..." for img, script, iframe, audio, video, embed
	reAssetSrc = regexp.MustCompile(`(?i)<(?:img|script|iframe|audio|video|embed|source)[^>]+src\s*=\s*["']([^"']+)["']`)
	// href="..." for link/stylesheet
	reStylesheet = regexp.MustCompile(`(?i)<link[^>]+href\s*=\s*["']([^"']+)["']`)
)

func extractAssets(body, _ string) []string {
	var assets []string
	for _, re := range []*regexp.Regexp{reAssetSrc, reStylesheet} {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 && m[1] != "" {
				assets = append(assets, m[1])
			}
		}
	}
	return assets
}

// ─── scope check ─────────────────────────────────────────────────────────────

func (m *Module) inScope(rawURL string, base *url.URL, scope Scope) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if !strings.HasPrefix(u.Scheme, "http") {
		return false
	}
	switch scope {
	case ScopeSameHost:
		return u.Host == base.Host
	case ScopeSameDomain:
		return sameDomain(u.Hostname(), base.Hostname())
	case ScopeAll:
		return true
	}
	return false
}

// sameDomain returns true if a and b share the same eTLD+1 heuristic.
func sameDomain(a, b string) bool {
	return eTLDPlus1(a) == eTLDPlus1(b)
}

// eTLDPlus1 returns a simple eTLD+1 approximation: last two dot-separated labels.
func eTLDPlus1(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// ─── option parsing ───────────────────────────────────────────────────────────

func (m *Module) parseOptions(opts map[string]string) runOptions {
	depth := m.MaxDepth
	if depth < 0 {
		depth = defaultDepth
	}
	parallelism := m.Parallelism
	if parallelism <= 0 {
		parallelism = defaultParallel
	}
	scope := m.Scope
	if scope != ScopeSameHost && scope != ScopeSameDomain && scope != ScopeAll {
		scope = ScopeSameHost
	}

	options := runOptions{
		depth:         clampInt(optionInt(opts, "depth", depth), 0, 5),
		parallelism:   clampInt(optionInt(opts, "parallelism", parallelism), 1, 32),
		maxPages:      clampInt(optionInt(opts, "max_pages", defaultMaxPages), 1, 3000),
		maxResults:    clampInt(optionInt(opts, "max_results", defaultMaxResults), 1, 10000),
		maxRuntime:    clampInt(optionInt(opts, "max_runtime_seconds", defaultRuntimeSeconds), 1, 600),
		scope:         scope,
		extractForms:  optionBool(opts, "forms", m.ExtractForms),
		extractJS:     optionBool(opts, "js", m.ExtractJS),
		extractAssets: optionBool(opts, "assets", m.ExtractAssets),
		seedRobots:    optionBool(opts, "robots", m.SeedRobots),
		seedSitemap:   optionBool(opts, "sitemap", m.SeedSitemap),
	}
	if opts != nil {
		switch Scope(strings.ToLower(strings.TrimSpace(opts["scope"]))) {
		case ScopeSameHost:
			options.scope = ScopeSameHost
		case ScopeSameDomain:
			options.scope = ScopeSameDomain
		case ScopeAll:
			options.scope = ScopeAll
		}
	}
	return options
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func (m *Module) get(ctx context.Context, rawURL string) ([]byte, int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, "", err
	}
	req.Header.Set("User-Agent", "blackhorn-katana/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml,*/*")
	for k, v := range m.Headers {
		req.Header.Set(k, v)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	ct := resp.Header.Get("Content-Type")
	return body, resp.StatusCode, ct, err
}

func collectSeeds(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if !strings.Contains(s, "://") {
			s = "http://" + s
		}
		canonical, ok := urlutil.CanonicalHTTP(s)
		if !ok {
			return
		}
		if _, exists := seen[canonical]; !exists {
			seen[canonical] = struct{}{}
			out = append(out, canonical)
		}
	}
	if input.Target != "" {
		add(input.Target)
	}
	for _, u := range input.URLs {
		add(u)
	}
	return out
}

func absoluteURL(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "javascript:") {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(r)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	// Strip fragment.
	abs.Fragment = ""
	canonical, ok := urlutil.CanonicalHTTP(abs.String())
	if !ok {
		return ""
	}
	return canonical
}

func dedupFindings(findings []module.Finding) []module.Finding {
	seen := make(map[string]struct{})
	var out []module.Finding
	for _, f := range findings {
		key := f.Type + "|" + f.URL
		if f.Type == TypeForm {
			key = TypeForm + "|" + f.Extra["page_url"] + "|" + f.Extra["field_name"]
		}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, f)
		}
	}
	return out
}

func candidateFinding(findingType, rawURL, detail, source, validationState string) module.Finding {
	return module.Finding{
		Type:     findingType,
		URL:      rawURL,
		Severity: module.SeverityInfo,
		Detail:   detail,
		Extra: map[string]string{
			"source":             source,
			"confidence":         "0.80",
			"validated":          "false",
			"validation_state":   validationState,
			"promote_to_context": "false",
			"source_validated":   "true",
		},
	}
}

func optionInt(options map[string]string, key string, fallback int) int {
	if options == nil {
		return fallback
	}
	value, err := strconv.Atoi(strings.TrimSpace(options[key]))
	if err != nil {
		return fallback
	}
	return value
}

func optionBool(options map[string]string, key string, fallback bool) bool {
	if options == nil {
		return fallback
	}
	raw, ok := options[key]
	if !ok {
		return fallback
	}
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return value
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
