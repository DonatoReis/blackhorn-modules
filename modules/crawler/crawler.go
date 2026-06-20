// Package crawler is a faithful port of projectdiscovery/katana (MIT License).
//
// Source reference: github.com/projectdiscovery/katana/pkg/engine/standard/crawl.go,
// pkg/navigation/request.go, pkg/navigation/response.go.
//
// Strategy: katana's standard (non-headless) engine uses net/http + goquery for
// HTML parsing. We implement the same algorithm using stdlib net/http + regexp
// for link extraction, respecting the same structures (Request, Response) and
// mirroring katana's scope validation and deduplication logic.
//
// What is ported faithfully:
//   - Request / Response structs — identical JSON tags to katana navigation package
//   - Crawl BFS loop with depth limit — mirrors katana CrawlSession / Crawler
//   - io.LimitReader on every body read — mirrors katana BodyReadSize cap
//   - Scope validation (same-host / same-domain) — mirrors katana scope options
//   - Deduplication via seen URL set — mirrors katana uniqueFilter
//   - context propagation + cancellation — guia-go §9
//   - errgroup.SetLimit for concurrent page fetches — guia-go §9
//   - log/slog observability — dicas.md §16
package crawler

import (
	"context"
	"crypto/tls"
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

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/urlutil"
	"golang.org/x/sync/errgroup"
)

const (
	// defaultMaxDepth mirrors katana default crawl depth = 3.
	defaultMaxDepth = 3

	// defaultBodyReadSize mirrors katana Options.BodyReadSize = 2 MB.
	defaultBodyReadSize = 2 * 1024 * 1024

	// defaultTimeout per HTTP request.
	defaultTimeout = 10 * time.Second

	// defaultConcurrency — errgroup limit per depth level.
	defaultConcurrency = 10

	defaultMaxPages       = 200
	defaultMaxResults     = 500
	defaultRuntimeSeconds = 120
)

// ─── Navigation types — mirrors katana pkg/navigation ────────────────────────

// Request mirrors katana navigation.Request (identical JSON tags).
type Request struct {
	Method    string `json:"method,omitempty"`
	URL       string `json:"endpoint,omitempty"`
	Body      string `json:"body,omitempty"`
	Depth     int    `json:"-"`
	Tag       string `json:"tag,omitempty"`
	Attribute string `json:"attribute,omitempty"`
	Source    string `json:"source,omitempty"`
}

// Response mirrors katana navigation.Response (simplified).
type Response struct {
	URL          string
	StatusCode   int
	ContentType  string
	Body         string
	Depth        int
	RootHostname string
}

// ─── Link extraction — mirrors katana parser package ─────────────────────────

// hrefRE extracts href= and src= attribute values from HTML.
var hrefRE = regexp.MustCompile(`(?i)(?:href|src|action|data-href)\s*=\s*["']([^"'#\s]+)["']`)

// formActionRE extracts form action URLs.
var formActionRE = regexp.MustCompile(`(?i)<form[^>]+action\s*=\s*["']([^"']+)["']`)

// absoluteURL resolves a potentially-relative URL against a base.
func absoluteURL(base, ref string) string {
	if strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "mailto:") ||
		strings.HasPrefix(ref, "tel:") || strings.HasPrefix(ref, "data:") {
		return ""
	}
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	resolved := b.ResolveReference(r)
	// Drop fragment.
	resolved.Fragment = ""
	canonical, ok := urlutil.CanonicalHTTP(resolved.String())
	if !ok {
		return ""
	}
	return canonical
}

// extractLinks extracts all navigable links from an HTML body.
// Mirrors katana parser/htmlparser.go ParseResponse().
func extractLinks(body, baseURL string) []Request {
	seen := map[string]bool{}
	var reqs []Request

	add := func(rawURL, tag, attr string) {
		abs := absoluteURL(baseURL, rawURL)
		if abs == "" || seen[abs] {
			return
		}
		seen[abs] = true
		reqs = append(reqs, Request{
			Method:    "GET",
			URL:       abs,
			Tag:       tag,
			Attribute: attr,
			Source:    baseURL,
		})
	}

	for _, m := range hrefRE.FindAllStringSubmatch(body, -1) {
		add(m[1], "a", "href")
	}
	for _, m := range formActionRE.FindAllStringSubmatch(body, -1) {
		add(m[1], "form", "action")
	}
	return reqs
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements module.Module for web crawling.
type Module struct {
	logger *slog.Logger
	client *http.Client
}

// New returns a Module with production defaults.
func New() *Module {
	return &Module{
		logger: slog.Default().With("module", "crawler"),
		client: &http.Client{
			Timeout: defaultTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec
					MinVersion:         tls.VersionTLS10,
				},
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

// NewWithClient returns a Module with an injected http.Client (for tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{
		logger: slog.Default().With("module", "crawler"),
		client: c,
	}
}

// Name satisfies module.Module.
func (m *Module) Name() string { return "crawler" }

// Run satisfies module.Module.
// Input.Target or Input.URLs[0] is the seed URL.
//
// Options:
//
//	"depth"               — max crawl depth (default: 3, maximum: 5)
//	"scope"               — "subdomain" (default) or "strict" (same host only)
//	"concurrency"         — concurrent fetches per level (default: 10)
//	"max_pages"           — maximum number of pages scheduled (default: 200)
//	"max_results"         — maximum number of findings returned (default: 500)
//	"max_runtime_seconds" — global execution budget (default: 120)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	seed := input.Target
	if seed == "" && len(input.URLs) > 0 {
		seed = input.URLs[0]
	}
	if seed == "" {
		return nil, fmt.Errorf("crawler: no seed URL provided")
	}

	// Normalise seed to absolute URL.
	if !strings.HasPrefix(seed, "http://") && !strings.HasPrefix(seed, "https://") {
		seed = "https://" + seed
	}
	var ok bool
	seed, ok = urlutil.CanonicalHTTP(seed)
	if !ok {
		return nil, fmt.Errorf("crawler: invalid seed URL")
	}

	seedURL, err := url.Parse(seed)
	if err != nil {
		return nil, fmt.Errorf("crawler: invalid seed URL %q: %w", seed, err)
	}

	// Options.
	maxDepth := clampInt(optionInt(input.Options, "depth", defaultMaxDepth), 0, 5)
	scopeMode := "subdomain" // default: same apex domain
	if s, ok := input.Options["scope"]; ok {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "strict":
			scopeMode = "strict"
		case "subdomain":
			scopeMode = "subdomain"
		}
	}
	concurrency := optionInt(input.Options, "concurrency", 0)
	if concurrency == 0 {
		concurrency = optionInt(input.Options, "parallelism", defaultConcurrency)
	}
	concurrency = clampInt(concurrency, 1, 32)
	maxPages := clampInt(optionInt(input.Options, "max_pages", defaultMaxPages), 1, 2000)
	maxResults := clampInt(optionInt(input.Options, "max_results", defaultMaxResults), 1, 5000)
	maxRuntime := optionInt(input.Options, "max_runtime_seconds", 0)
	if maxRuntime == 0 {
		maxRuntime = optionInt(input.Options, "timeout", defaultRuntimeSeconds)
	}
	maxRuntime = clampInt(maxRuntime, 1, 600)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntime)*time.Second)
	defer cancel()

	apexDomain := extractApex(seedURL.Hostname())
	m.logger.InfoContext(runCtx, "starting crawl",
		"seed", seed, "max_depth", maxDepth, "scope", scopeMode,
		"max_pages", maxPages, "max_results", maxResults)

	// Shared state — mirrors katana uniqueFilter.
	seen := map[string]bool{seed: true}

	// BFS queue.
	type qitem struct {
		req   Request
		depth int
	}
	queue := []qitem{{req: Request{Method: "GET", URL: seed, Depth: 0}, depth: 0}}

	var findings []module.Finding

	for len(queue) > 0 && !isDone(runCtx) && len(findings) < maxResults {
		// Pull current level.
		current := queue
		queue = nil

		eg, gctx := errgroup.WithContext(runCtx)
		eg.SetLimit(concurrency)

		type levelResult struct {
			resp     Response
			children []Request
		}
		resultsCh := make(chan levelResult, len(current))

		for _, item := range current {
			item := item
			eg.Go(func() error {
				resp, children := m.fetchPage(gctx, item.req, apexDomain, scopeMode, item.depth)
				select {
				case resultsCh <- levelResult{resp: resp, children: children}:
				case <-gctx.Done():
				}
				return nil
			})
		}

		waitCh := make(chan error, 1)
		go func() {
			waitCh <- eg.Wait()
			close(resultsCh)
		}()

		for lr := range resultsCh {
			if lr.resp.StatusCode > 0 {
				findings = append(findings, responseToFinding(lr.resp))
			}
			// Enqueue children if within depth limit.
			if lr.resp.Depth < maxDepth {
				for _, child := range lr.children {
					if len(seen) >= maxPages {
						break
					}
					if !seen[child.URL] && inScope(child.URL, seedURL, apexDomain, scopeMode) {
						seen[child.URL] = true
						queue = append(queue, qitem{req: child, depth: lr.resp.Depth + 1})
					}
				}
			}
		}

		if err := <-waitCh; err != nil && !isDone(runCtx) {
			return findings, err
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].URL < findings[j].URL
	})
	if len(findings) > maxResults {
		findings = findings[:maxResults]
	}
	m.logger.InfoContext(ctx, "crawl complete",
		"urls_found", len(findings), "pages_scheduled", len(seen),
		"budget_exhausted", runCtx.Err() != nil)
	return findings, nil
}

// fetchPage fetches a URL and extracts child links.
// Mirrors katana Crawler.makeRequest() + parser.ParseResponse().
func (m *Module) fetchPage(ctx context.Context, req Request, apexDomain, scopeMode string, depth int) (Response, []Request) {
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, nil)
	if err != nil {
		return Response{}, nil
	}
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-crawler/1.0)")
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")

	resp, err := m.client.Do(httpReq)
	if err != nil {
		return Response{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, defaultBodyReadSize))
	bodyStr := string(body)

	nav := Response{
		URL:          req.URL,
		StatusCode:   resp.StatusCode,
		ContentType:  resp.Header.Get("Content-Type"),
		Body:         bodyStr,
		Depth:        depth,
		RootHostname: apexDomain,
	}

	m.logger.InfoContext(ctx, "crawled",
		"url", req.URL, "status", resp.StatusCode, "depth", depth)

	// Extract links only from HTML responses.
	if !strings.Contains(nav.ContentType, "html") {
		return nav, nil
	}
	children := extractLinks(bodyStr, req.URL)
	return nav, children
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// inScope checks whether a URL is within the crawl scope.
// Mirrors katana scope validation.
func inScope(rawURL string, seed *url.URL, apexDomain, mode string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	switch mode {
	case "strict":
		return u.Hostname() == seed.Hostname()
	default: // "subdomain" — same apex
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		apex := strings.ToLower(strings.TrimSuffix(apexDomain, "."))
		return host == apex || strings.HasSuffix(host, "."+apex)
	}
}

// extractApex returns the apex domain (last two labels) from a hostname.
// e.g. "sub.example.com" → "example.com"
func extractApex(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

// isDone returns true if the context is cancelled.
func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// responseToFinding converts a crawl Response to a module.Finding.
// Detail field mirrors dicas.md §17 — explicability.
func responseToFinding(r Response) module.Finding {
	return module.Finding{
		Type:     "crawled_url",
		Severity: module.SeverityInfo,
		URL:      r.URL,
		Detail:   fmt.Sprintf("Crawled: %s [HTTP %d] depth=%d", r.URL, r.StatusCode, r.Depth),
		Extra: map[string]string{
			"url":                r.URL,
			"status_code":        strconv.Itoa(r.StatusCode),
			"content_type":       r.ContentType,
			"depth":              strconv.Itoa(r.Depth),
			"confidence":         "0.98",
			"validated":          "true",
			"validation_state":   "http_response_confirmed",
			"promote_to_context": "true",
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

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
