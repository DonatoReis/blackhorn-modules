// Package urlfinder extracts URLs from JavaScript files, HTML pages, and raw
// content by applying a set of regex and string-matching strategies. It is
// inspired by projectdiscovery/urlfinder (MIT) and tomnomnom/waybackurls
// (MIT) but independently re-implemented.
//
// Extraction strategies:
//   - JS endpoint strings: paths in quotes, template literals, fetch/axios calls
//   - HTML href/src/action attributes
//   - Inline <script> blocks
//   - sourceMappingURL comments (reveals source map paths)
//   - Webpack chunk URLs (runtime.js __webpack_require__ patterns)
//   - API base URLs from JS variables (apiBase, baseURL, BASE_URL, etc.)
//   - Relative and absolute paths normalised to the document origin
//
// License: MIT (blackhorn-modules). No code copied from urlfinder.
package urlfinder

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/urlutil"
	"golang.org/x/sync/errgroup"
)

const (
	defaultTimeout        = 15 * time.Second
	defaultConc           = 10
	defaultMaxTargets     = 100
	defaultMaxResults     = 1000
	defaultRuntimeSeconds = 180
	maxBodyBytes          = 2 * 1024 * 1024 // 2 MiB — JS bundles can be large
)

// ─── compiled regexes ────────────────────────────────────────────────────────

var (
	// Matches strings in single or double quotes that look like URL paths or full URLs.
	reQuotedURL = regexp.MustCompile(`["']([a-zA-Z0-9_\-/.?=&#%@:+!,;*(){}[\]\\~]{5,256})["']`)

	// Matches template literals with URL-like content.
	reTemplateLiteral = regexp.MustCompile("`([a-zA-Z0-9_\\-/.?=&#%@:+!,;*(){}\\[\\]\\\\~]{5,256})`")

	// Matches href, src, action attributes in HTML.
	reHTMLAttr = regexp.MustCompile(`(?i)(href|src|action|data-src|data-href)\s*=\s*["']([^"'>\s]{3,512})["']`)

	// Matches fetch(), axios(), XMLHttpRequest.open() calls.
	reFetchCall = regexp.MustCompile(`(?i)(?:fetch|axios(?:\.(get|post|put|delete|patch))?|XMLHttpRequest|\.open)\s*\(["'\x60]([^"'\x60\s)]{3,256})["'\x60]`)

	// Matches common JS API base variable patterns.
	reAPIBase = regexp.MustCompile(`(?i)(?:apiBase|baseURL?|API_URL|BASE_URL|api_endpoint|backendURL?)\s*[=:]\s*["'\x60]([^"'\x60\s]{5,256})["'\x60]`)

	// Matches sourceMappingURL comments.
	reSourceMap = regexp.MustCompile(`//[#@]\s*sourceMappingURL\s*=\s*(\S+)`)

	// Matches webpack chunk path patterns.
	reWebpackChunk = regexp.MustCompile(`["']([^"']+\.chunk\.js)["']`)

	// Matches require('...') and import '...' statements.
	reRequireImport = regexp.MustCompile(`(?i)(?:require|import)\s*\(\s*["']([^"']{3,256})["']\s*\)`)

	// Matches absolute URLs.
	reAbsoluteURL = regexp.MustCompile(`https?://[a-zA-Z0-9][a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,512}`)
)

// ─── module ──────────────────────────────────────────────────────────────────

// Module implements module.Module for URL extraction.
type Module struct {
	client      *http.Client
	concurrency int
	// Scope limits extracted URLs to the given domains. Empty = no filtering.
	Scope []string
	// IncludeExternal includes URLs from external domains when true.
	IncludeExternal bool
}

// New returns a Module with production defaults.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		concurrency: defaultConc,
	}
}

// NewWithClient creates a Module using the provided HTTP client (useful in tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client:      c,
		concurrency: defaultConc,
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "urlfinder" }

// Run implements module.Module.
// Accepts Target (single URL to fetch and extract from),
// URLs (slice of pages to scan), or RawContent (content to scan directly).
// Returns one Finding per unique extracted URL.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	maxResults := clampInt(optInt(input.Options, "max_results", defaultMaxResults), 1, 10000)
	includeExternal := m.IncludeExternal || optBool(input.Options, "include_external", false)
	scope := append([]string(nil), m.Scope...)

	// RawContent mode — scan provided content directly.
	if input.RawContent != "" && input.Target == "" && len(input.URLs) == 0 {
		extracted := extractAll(input.RawContent, "", scope, includeExternal)
		if len(extracted) > maxResults {
			extracted = extracted[:maxResults]
		}
		return buildFindings(extracted, "", scope), nil
	}

	urls := collectURLs(input)
	if len(urls) == 0 {
		return nil, fmt.Errorf("urlfinder: no URLs provided")
	}
	maxTargets := clampInt(optInt(input.Options, "max_targets", defaultMaxTargets), 1, 1000)
	if len(urls) > maxTargets {
		urls = urls[:maxTargets]
	}
	if len(scope) == 0 {
		scope = domainsFromURLs(urls)
	}
	maxRuntime := clampInt(optInt(input.Options, "max_runtime_seconds", defaultRuntimeSeconds), 1, 600)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntime)*time.Second)
	defer cancel()

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	g, gctx := errgroup.WithContext(runCtx)
	g.SetLimit(m.concurrency)

	for _, rawURL := range urls {
		rawURL := rawURL
		g.Go(func() error {
			content, baseURL, err := m.fetch(gctx, rawURL)
			if err != nil {
				slog.Debug("urlfinder: fetch error", "url", rawURL, "err", err)
				return nil
			}
			extracted := extractAll(content, baseURL, scope, includeExternal)
			ff := buildFindings(extracted, rawURL, scope)
			if len(ff) > 0 {
				mu.Lock()
				findings = append(findings, ff...)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()
	deduped := dedupFindings(findings)
	sort.SliceStable(deduped, func(i, j int) bool {
		return deduped[i].URL < deduped[j].URL
	})
	if len(deduped) > maxResults {
		deduped = deduped[:maxResults]
	}
	return deduped, nil
}

// ─── fetch ───────────────────────────────────────────────────────────────────

func (m *Module) fetch(ctx context.Context, rawURL string) (content, baseURL string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-urlfinder/1.0)")
	req.Header.Set("Accept", "*/*")

	resp, err := m.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusBadRequest {
		return "", "", fmt.Errorf("urlfinder: source returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", "", err
	}

	// Determine the effective base URL (after redirects).
	effective := resp.Request.URL.String()
	return string(body), effective, nil
}

// ─── extraction engine ───────────────────────────────────────────────────────

// extractAll applies all extraction strategies to content and returns unique URLs.
func extractAll(content, baseURL string, scope []string, includeExternal bool) []string {
	seen := make(map[string]struct{})
	var out []string

	add := func(s string) {
		s = normaliseURL(s, baseURL)
		if s == "" {
			return
		}
		if !isValidURL(s) {
			return
		}
		if !includeExternal && len(scope) > 0 && !inScope(s, scope) {
			return
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}

	// Strategy 1: absolute URLs.
	for _, m := range reAbsoluteURL.FindAllString(content, -1) {
		add(m)
	}

	// Strategy 2: HTML attributes.
	for _, sm := range reHTMLAttr.FindAllStringSubmatch(content, -1) {
		if len(sm) >= 3 {
			add(sm[2])
		}
	}

	// Strategy 3: fetch/axios/XHR calls.
	for _, sm := range reFetchCall.FindAllStringSubmatch(content, -1) {
		if len(sm) >= 2 {
			add(sm[len(sm)-1])
		}
	}

	// Strategy 4: API base variables.
	for _, sm := range reAPIBase.FindAllStringSubmatch(content, -1) {
		if len(sm) >= 2 {
			add(sm[1])
		}
	}

	// Strategy 5: quoted URL-like strings.
	for _, sm := range reQuotedURL.FindAllStringSubmatch(content, -1) {
		if len(sm) >= 2 {
			add(sm[1])
		}
	}

	// Strategy 6: template literals.
	for _, sm := range reTemplateLiteral.FindAllStringSubmatch(content, -1) {
		if len(sm) >= 2 {
			add(sm[1])
		}
	}

	// Strategy 7: sourceMappingURL.
	for _, sm := range reSourceMap.FindAllStringSubmatch(content, -1) {
		if len(sm) >= 2 {
			add(sm[1])
		}
	}

	// Strategy 8: webpack chunks.
	for _, sm := range reWebpackChunk.FindAllStringSubmatch(content, -1) {
		if len(sm) >= 2 {
			add(sm[1])
		}
	}

	// Strategy 9: require/import statements.
	for _, sm := range reRequireImport.FindAllStringSubmatch(content, -1) {
		if len(sm) >= 2 {
			add(sm[1])
		}
	}

	return out
}

// ─── finding builder ─────────────────────────────────────────────────────────

func buildFindings(urls []string, sourceURL string, scope []string) []module.Finding {
	findings := make([]module.Finding, 0, len(urls))
	for _, u := range urls {
		extra := map[string]string{
			"url":                    u,
			"confidence":             "0.75",
			"validated":              "false",
			"validation_state":       "content_extraction_candidate",
			"promote_to_context":     "false",
			"target_scope_validated": strconv.FormatBool(len(scope) > 0 && inScope(u, scope)),
			"source_validated":       strconv.FormatBool(sourceURL != ""),
		}
		if sourceURL != "" {
			extra["source"] = sourceURL
		}
		findings = append(findings, module.Finding{
			Type:     "web_location_candidate",
			URL:      u,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("URL extracted: %s", u),
			Extra:    extra,
		})
	}
	return findings
}

func dedupFindings(findings []module.Finding) []module.Finding {
	seen := make(map[string]struct{})
	out := findings[:0]
	for _, f := range findings {
		if _, ok := seen[f.URL]; !ok {
			seen[f.URL] = struct{}{}
			out = append(out, f)
		}
	}
	return out
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func collectURLs(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
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
	if input.RawContent != "" {
		for _, line := range strings.Split(input.RawContent, "\n") {
			add(line)
		}
	}
	return out
}

// normaliseURL resolves s against the base URL (for relative paths).
func normaliseURL(s, baseURL string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "/" || s == "." || strings.HasPrefix(s, "#") ||
		strings.ContainsAny(s, "{}[]\\") || strings.HasPrefix(strings.ToLower(s), "javascript:") {
		return ""
	}
	var candidate string
	// Already absolute.
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		candidate = strings.TrimRight(s, ".,;)'\"")
		if canonical, ok := urlutil.CanonicalHTTP(candidate); ok {
			return canonical
		}
		return ""
	}
	// Protocol-relative.
	if strings.HasPrefix(s, "//") {
		scheme := "https"
		if baseURL != "" && strings.HasPrefix(baseURL, "http://") {
			scheme = "http"
		}
		candidate = strings.TrimRight(scheme+":"+s, ".,;)'\"")
		if canonical, ok := urlutil.CanonicalHTTP(candidate); ok {
			return canonical
		}
		return ""
	}
	// Relative path — resolve against base.
	if baseURL == "" {
		return ""
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(s)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	canonical, ok := urlutil.CanonicalHTTP(resolved.String())
	if !ok {
		return ""
	}
	return canonical
}

// isValidURL returns true if s is a plausible HTTP(S) URL.
func isValidURL(s string) bool {
	_, ok := urlutil.CanonicalHTTP(s)
	return ok
}

// inScope returns true if u belongs to one of the scope domains.
func inScope(u string, scope []string) bool {
	for _, s := range scope {
		if urlutil.InDomainScope(u, s) {
			return true
		}
	}
	return false
}

func domainsFromURLs(urls []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(urls))
	for _, raw := range urls {
		domain := urlutil.NormalizeDomain(raw)
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; !ok {
			seen[domain] = struct{}{}
			out = append(out, domain)
		}
	}
	return out
}

func optInt(opts map[string]string, key string, def int) int {
	if opts == nil {
		return def
	}
	value, err := strconv.Atoi(strings.TrimSpace(opts[key]))
	if err != nil || value < 1 {
		return def
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

func optBool(opts map[string]string, key string, def bool) bool {
	if opts == nil {
		return def
	}
	raw, ok := opts[key]
	if !ok {
		return def
	}
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return def
	}
	return value
}
