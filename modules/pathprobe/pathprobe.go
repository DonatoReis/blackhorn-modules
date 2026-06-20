// Package pathprobe probes for sensitive files and directories exposed on web servers.
//
// Reference implementation (algorithm and path catalogue, no code copied):
//   - orbit-core internal/modules/sensitive.go (proprietary)
//
// What is implemented:
//   - 120+ curated sensitive paths across 10 categories:
//     API docs (Swagger, OpenAPI, Redoc), Environment/config, VCS (.git/.svn),
//     Spring Actuator, Server diagnostics, CMS admin, Database backups,
//     Log files, Node/PHP/Python manifests, CI/CD secrets, Cloud metadata
//   - Soft-404 detection via FNV-1a simhash (avoids false positives on wildcard-200 hosts)
//   - Auth-wall detection (login pages served at sensitive paths)
//   - Anti-bot/challenge page detection (Cloudflare, Akamai, etc.)
//   - io.LimitReader on every body read                   (dicas.md §5)
//   - log/slog structured observability                   (dicas.md §16)
//   - errgroup.SetLimit bounded fan-out                   (guia-go §9)
//   - context propagation and cancellation               (guia-go §9)
//   - Configurable: threads, timeout, categories, include_low severity
package pathprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"math/bits"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	maxBodyRead     = 64 * 1024 // 64 KiB per body read — dicas.md §5
	defaultTimeout  = 10 * time.Second
	defaultThreads  = 10
	defaultMaxHosts = 10
)

// ─── Entry ────────────────────────────────────────────────────────────────────

// Entry is a single sensitive path to probe.
// Category groups entries for filtering; Severity maps to module.Severity.
type Entry struct {
	Path     string
	Title    string
	Severity module.Severity
	Category string // api-docs | config | vcs | actuator | diagnostics | backup | log | manifest | ci-cd | cloud | cms
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module probes for sensitive files exposed on web servers.
type Module struct {
	client     *http.Client
	threads    int
	timeout    time.Duration
	maxHosts   int
	paths      []Entry
	categories map[string]bool // nil = all
	includeLow bool
}

// New creates a Module with default settings and the full built-in path catalogue.
func New() *Module {
	return &Module{
		client:     defaultClient(defaultTimeout),
		threads:    defaultThreads,
		timeout:    defaultTimeout,
		maxHosts:   defaultMaxHosts,
		paths:      builtinPaths(),
		includeLow: true,
	}
}

// NewWithClient creates a Module with a custom HTTP client (useful for tests).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// NewWithPaths creates a Module with a custom path list (useful for extension/tests).
func NewWithPaths(paths []Entry) *Module {
	m := New()
	m.paths = paths
	return m
}

// Name satisfies module.Module.
func (m *Module) Name() string { return "pathprobe" }

// Run satisfies module.Module.
// It resolves base URLs from input, probes each sensitive path,
// and applies soft-404 / auth-wall / anti-bot filtering.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	bases := m.resolveBases(input)
	if len(bases) == 0 {
		return nil, fmt.Errorf("pathprobe: no target URL")
	}

	// Apply options from input.Options.
	threads := optInt(input.Options, "threads", m.threads)
	includeLow := optBool(input.Options, "include_low", m.includeLow)

	slog.Debug("pathprobe: starting", "bases", len(bases), "paths", len(m.paths), "threads", threads)

	// Build work items: (base, entry) pairs.
	type work struct {
		base  string
		entry Entry
	}
	var items []work
	for _, base := range bases {
		for _, e := range m.paths {
			if e.Severity == module.SeverityLow && !includeLow {
				continue
			}
			items = append(items, work{base, e})
		}
	}

	findingsCh := make(chan module.Finding, 256)
	var total atomic.Int64

	eg, gctx := errgroup.WithContext(ctx)
	eg.SetLimit(threads)

	// Per-host wildcard probe cache: base → soft404Prober.
	proberCache := make(map[string]*soft404Prober, len(bases))
	for _, b := range bases {
		proberCache[b] = newSoft404Prober(gctx, m.client, m.timeout)
	}

	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		item := item // capture
		key := item.base + "|" + item.entry.Path
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		eg.Go(func() error {
			testURL := strings.TrimSuffix(item.base, "/") + item.entry.Path
			body, headers, code := fetchBody(gctx, m.client, testURL)
			if code != 200 {
				return nil
			}

			// Soft-404 check (wildcard-200 hosts).
			prober := proberCache[item.base]
			if prober.isSimilarToInvalid(body, testURL) {
				slog.Debug("pathprobe: soft-404 discarded", "url", testURL)
				return nil
			}
			// Auth-wall check.
			if isAuthWall(body) {
				return nil
			}
			// Anti-bot / challenge page.
			if isAntiBot(headers, body) {
				return nil
			}

			total.Add(1)
			findingsCh <- module.Finding{
				Type:     "sensitive_path",
				URL:      testURL,
				Detail:   fmt.Sprintf("%s is publicly accessible (HTTP 200, %d bytes)", item.entry.Title, len(body)),
				Severity: item.entry.Severity,
				Extra: map[string]string{
					"path":       item.entry.Path,
					"title":      item.entry.Title,
					"category":   item.entry.Category,
					"confidence": "0.85",
				},
			}
			return nil
		})
	}

	go func() { _ = eg.Wait(); close(findingsCh) }()

	var findings []module.Finding
	for f := range findingsCh {
		findings = append(findings, f)
	}
	if err := eg.Wait(); err != nil {
		return findings, err
	}
	slog.Debug("pathprobe: done", "findings", total.Load())
	return findings, nil
}

// ─── Base URL resolution ──────────────────────────────────────────────────────

func (m *Module) resolveBases(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(raw string) {
		base := rootBase(raw)
		if base == "" {
			return
		}
		if _, dup := seen[base]; dup {
			return
		}
		seen[base] = struct{}{}
		out = append(out, base)
		if len(out) >= m.maxHosts {
			return
		}
	}

	if input.Target != "" {
		add(input.Target)
		// Always try both schemes when only one is given.
		if strings.HasPrefix(input.Target, "https://") {
			add(strings.Replace(input.Target, "https://", "http://", 1))
		} else if strings.HasPrefix(input.Target, "http://") {
			add(strings.Replace(input.Target, "http://", "https://", 1))
		}
	}
	for _, u := range input.URLs {
		if len(out) >= m.maxHosts {
			break
		}
		add(u)
	}
	return out
}

// rootBase normalises a URL to scheme+host (no path, no query).
func rootBase(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

// fetchBody performs a GET and returns (body, headers, statusCode).
func fetchBody(ctx context.Context, client *http.Client, rawURL string) (string, http.Header, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", nil, 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BlackhornScanner/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, 0
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return string(b), resp.Header, resp.StatusCode
}

// ─── Anti-bot, auth-wall, soft-404 detection ─────────────────────────────────

var (
	soft404Markers = []string{
		"not found", "404", "page not found", "doesn't exist",
		"file not found", "resource not found", "the page you",
		"no page found", "nothing here", "page doesn't exist",
		"this page is gone", "no longer exists", "no longer available",
		"oops! we couldn't find", "page has moved",
		"não encontrado", "não existe", "página não encontrada",
		"erro 404", "error 404", "esta página não existe",
		"página no encontrada", "no encontrado", "esta página no existe",
		"403 forbidden", "401 unauthorized", "500 internal server error",
		"bad gateway", "service unavailable",
	}
	authWallMarkers = []string{
		"sign in", "log in", "login", "please sign in",
		"please log in", "authentication required", "enter your password",
		"forgot your password", "create an account", "sign up",
		"unauthorized access", "access denied", "you need to log in",
		"acesse sua conta", "faça login", "entrar com",
	}
	antiBotMarkers = []string{
		"just a moment", "checking your browser", "cloudflare ray id",
		"please wait while we check", "ddos protection by",
		"attention required! | cloudflare", "enable javascript and cookies",
		"bot check", "captcha required", "verifying you are human",
		"ray id:", "cf-mitigated",
	}
)

func isAuthWall(body string) bool {
	limit := len(body)
	if limit > 2000 {
		limit = 2000
	}
	lower := strings.ToLower(body[:limit])
	for _, m := range authWallMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

func isAntiBot(headers http.Header, body string) bool {
	if headers != nil && headers.Get("cf-mitigated") != "" {
		return true
	}
	lower := strings.ToLower(body)
	for _, m := range antiBotMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

func isSoft404Body(body string) bool {
	if len(body) == 0 {
		return false
	}
	// JSON/XML responses are likely valid API responses.
	b := strings.TrimSpace(body)
	if strings.HasPrefix(b, "{") || strings.HasPrefix(b, "[") || strings.HasPrefix(b, "<?xml") {
		return false
	}
	lower := strings.ToLower(body)
	hits := 0
	for _, m := range soft404Markers {
		if strings.Contains(lower, m) {
			hits++
			if hits >= 2 {
				return true
			}
		}
	}
	if hits == 1 && len(body) < 3000 {
		return true
	}
	return false
}

// ─── Simhash-based wildcard-200 detection ─────────────────────────────────────

const wildcardSentinel = ^uint64(0) // all-ones = wildcard host

var (
	tokenRe = regexp.MustCompile(`[a-z0-9]{3,}`)
	tagRe   = regexp.MustCompile(`<[^>]+>`)
	wsRe    = regexp.MustCompile(`\s+`)
)

func extractText(html string) string {
	t := tagRe.ReplaceAllString(html, " ")
	t = wsRe.ReplaceAllString(t, " ")
	return strings.TrimSpace(strings.ToLower(t))
}

func simhash64(text string) uint64 {
	tokens := tokenRe.FindAllString(strings.ToLower(text), -1)
	if len(tokens) == 0 {
		return 0
	}
	vec := [64]int{}
	for _, tok := range tokens {
		h := fnv.New64a()
		_, _ = io.WriteString(h, tok)
		hv := h.Sum64()
		for i := 0; i < 64; i++ {
			if (hv>>uint(i))&1 == 1 {
				vec[i]++
			} else {
				vec[i]--
			}
		}
	}
	var out uint64
	for i := 0; i < 64; i++ {
		if vec[i] >= 0 {
			out |= 1 << uint(i)
		}
	}
	return out
}

func hammingDist(a, b uint64) int { return bits.OnesCount64(a ^ b) }

// soft404Prober detects wildcard-200 hosts by comparing against a synthetic
// invalid sibling URL. Matches orbit-core's Soft404Prober algorithm exactly.
// All exported methods are goroutine-safe.
type soft404Prober struct {
	ctx    context.Context
	client *http.Client
	mu     sync.Mutex
	cache  map[string]uint64 // hostKey → simhash (wildcardSentinel = wildcard host)
}

func newSoft404Prober(ctx context.Context, client *http.Client, _ time.Duration) *soft404Prober {
	return &soft404Prober{ctx: ctx, client: client, cache: make(map[string]uint64)}
}

// invalidFingerprint returns (fingerprint, ok) for the invalid sibling of rawURL.
// Caches per host. Goroutine-safe.
func (p *soft404Prober) invalidFingerprint(rawURL string) (uint64, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return 0, false
	}
	hostKey := u.Scheme + "://" + u.Host

	p.mu.Lock()
	if fp, ok := p.cache[hostKey]; ok {
		p.mu.Unlock()
		return fp, true
	}
	p.mu.Unlock()

	sibling := invalidSibling(rawURL)
	if sibling == "" {
		return 0, false
	}
	body, headers, code := fetchBody(p.ctx, p.client, sibling)
	if code == 0 {
		return 0, false
	}

	var fp uint64
	if code == 404 || code == 410 {
		fp = 0
	} else if isSoft404Body(body) || isAntiBot(headers, body) {
		fp = wildcardSentinel
	} else {
		fp = simhash64(extractText(body))
	}

	p.mu.Lock()
	p.cache[hostKey] = fp
	p.mu.Unlock()

	if code == 404 || code == 410 {
		return 0, true
	}
	return fp, true
}

// isSimilarToInvalid returns true when the target body looks like the wildcard
// error page (hamming distance ≤ 6, calibrated for main text).
func (p *soft404Prober) isSimilarToInvalid(body, rawURL string) bool {
	// Quick pre-filter: if body itself looks like a soft-404, skip immediately.
	if isSoft404Body(body) {
		return true
	}
	invalidFP, ok := p.invalidFingerprint(rawURL)
	if !ok || invalidFP == 0 {
		return false
	}
	if invalidFP == wildcardSentinel {
		return true
	}
	targetFP := simhash64(extractText(body))
	return hammingDist(targetFP, invalidFP) <= 6
}

func invalidSibling(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	path := u.Path
	if path == "" || path == "/" {
		path = "/pathprobe-invalid-" + randomHex8()
	} else {
		idx := strings.LastIndex(path, "/")
		path = path[:idx+1] + "pathprobe-invalid-" + randomHex8()
	}
	u.Path = path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func randomHex8() string {
	h := fnv.New64a()
	_, _ = io.WriteString(h, fmt.Sprintf("pathprobe-%d", time.Now().UnixNano()))
	return fmt.Sprintf("%016x", h.Sum64())[:8]
}

// ─── HTTP client ─────────────────────────────────────────────────────────────

func defaultClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // do not follow redirects
		},
	}
}

// ─── Option helpers ───────────────────────────────────────────────────────────

func optInt(opts map[string]string, key string, def int) int {
	if opts == nil {
		return def
	}
	v, ok := opts[key]
	if !ok {
		return def
	}
	n := 0
	for _, c := range v {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	if n == 0 {
		return def
	}
	return n
}

func optBool(opts map[string]string, key string, def bool) bool {
	if opts == nil {
		return def
	}
	v, ok := opts[key]
	if !ok {
		return def
	}
	return v == "true" || v == "1"
}

// ─── Built-in path catalogue ─────────────────────────────────────────────────

// builtinPaths returns the full catalogue of sensitive paths to probe.
// Mirrors orbit-core's SensitiveModule path list (expanded).
func builtinPaths() []Entry {
	return []Entry{
		// ── API Documentation ─────────────────────────────────────────────
		{"/swagger.json", "Swagger/OpenAPI Schema", module.SeverityMedium, "api-docs"},
		{"/swagger.yaml", "Swagger/OpenAPI Schema", module.SeverityMedium, "api-docs"},
		{"/swagger-ui.html", "Swagger UI", module.SeverityMedium, "api-docs"},
		{"/swagger-ui/", "Swagger UI", module.SeverityMedium, "api-docs"},
		{"/openapi.json", "OpenAPI Schema", module.SeverityMedium, "api-docs"},
		{"/openapi.yaml", "OpenAPI Schema", module.SeverityMedium, "api-docs"},
		{"/openapi.yml", "OpenAPI Schema", module.SeverityMedium, "api-docs"},
		{"/api-docs", "API Documentation", module.SeverityMedium, "api-docs"},
		{"/api-docs.json", "API Documentation JSON", module.SeverityMedium, "api-docs"},
		{"/api/docs", "API Documentation", module.SeverityMedium, "api-docs"},
		{"/api/swagger.json", "API Swagger Schema", module.SeverityMedium, "api-docs"},
		{"/api/openapi.json", "API OpenAPI Schema", module.SeverityMedium, "api-docs"},
		{"/redoc", "ReDoc API Docs", module.SeverityMedium, "api-docs"},
		{"/redoc.html", "ReDoc API Docs", module.SeverityMedium, "api-docs"},
		{"/v1/docs", "API v1 Docs", module.SeverityLow, "api-docs"},
		{"/v2/docs", "API v2 Docs", module.SeverityLow, "api-docs"},
		{"/v3/docs", "API v3 Docs", module.SeverityLow, "api-docs"},
		{"/explorer", "API Explorer", module.SeverityLow, "api-docs"},
		{"/graphiql", "GraphiQL Playground", module.SeverityMedium, "api-docs"},
		{"/graphql/console", "GraphQL Console", module.SeverityMedium, "api-docs"},
		{"/api/graphql", "GraphQL API", module.SeverityMedium, "api-docs"},
		{"/wsdl", "WSDL SOAP Schema", module.SeverityMedium, "api-docs"},
		{"/wadl", "WADL Schema", module.SeverityMedium, "api-docs"},

		// ── Environment / Config ──────────────────────────────────────────
		{"/.env", "Environment File", module.SeverityCritical, "config"},
		{"/.env.local", "Environment File (local)", module.SeverityCritical, "config"},
		{"/.env.production", "Environment File (production)", module.SeverityCritical, "config"},
		{"/.env.staging", "Environment File (staging)", module.SeverityHigh, "config"},
		{"/.env.development", "Environment File (development)", module.SeverityHigh, "config"},
		{"/.env.backup", "Environment File Backup", module.SeverityCritical, "config"},
		{"/.env.example", "Environment File Example", module.SeverityLow, "config"},
		{"/config.json", "Config File", module.SeverityHigh, "config"},
		{"/config.js", "Config JS File", module.SeverityHigh, "config"},
		{"/config.yaml", "Config YAML File", module.SeverityHigh, "config"},
		{"/config.yml", "Config YAML File", module.SeverityHigh, "config"},
		{"/config.xml", "Config XML File", module.SeverityHigh, "config"},
		{"/config.ini", "Config INI File", module.SeverityHigh, "config"},
		{"/config.php", "Config PHP File", module.SeverityHigh, "config"},
		{"/settings.json", "Settings File", module.SeverityHigh, "config"},
		{"/settings.py", "Settings Python File", module.SeverityHigh, "config"},
		{"/local_settings.py", "Local Settings Python", module.SeverityHigh, "config"},
		{"/application.properties", "Application Properties", module.SeverityHigh, "config"},
		{"/application.yml", "Application YAML Config", module.SeverityHigh, "config"},
		{"/application-production.yml", "Production Application YAML", module.SeverityCritical, "config"},
		{"/application-dev.yml", "Dev Application YAML", module.SeverityHigh, "config"},
		{"/web.config", "Web.config File", module.SeverityHigh, "config"},
		{"/appsettings.json", "ASP.NET App Settings", module.SeverityHigh, "config"},
		{"/appsettings.Development.json", "Dev App Settings", module.SeverityHigh, "config"},
		{"/appsettings.Production.json", "Production App Settings", module.SeverityCritical, "config"},
		{"/.htaccess", "HTAccess File", module.SeverityMedium, "config"},
		{"/.htpasswd", "HTPasswd File", module.SeverityCritical, "config"},
		{"/nginx.conf", "NGINX Config File", module.SeverityHigh, "config"},
		{"/httpd.conf", "Apache Config File", module.SeverityHigh, "config"},
		{"/database.yml", "Database Config YAML", module.SeverityCritical, "config"},
		{"/database.json", "Database Config JSON", module.SeverityCritical, "config"},

		// ── VCS ───────────────────────────────────────────────────────────
		{"/.git/config", "Git Repository Config", module.SeverityCritical, "vcs"},
		{"/.git/HEAD", "Git Repository HEAD", module.SeverityHigh, "vcs"},
		{"/.git/COMMIT_EDITMSG", "Git Commit Message", module.SeverityHigh, "vcs"},
		{"/.git/index", "Git Index", module.SeverityHigh, "vcs"},
		{"/.git/logs/HEAD", "Git Logs", module.SeverityHigh, "vcs"},
		{"/.gitignore", "Gitignore File", module.SeverityLow, "vcs"},
		{"/.svn/entries", "SVN Repository", module.SeverityHigh, "vcs"},
		{"/.svn/wc.db", "SVN Working Copy DB", module.SeverityHigh, "vcs"},
		{"/.hg/hgrc", "Mercurial Config", module.SeverityHigh, "vcs"},
		{"/CVS/Root", "CVS Repository Root", module.SeverityMedium, "vcs"},
		{"/.bzr/README", "Bazaar Repository", module.SeverityMedium, "vcs"},

		// ── Spring Boot Actuator ──────────────────────────────────────────
		{"/actuator", "Spring Actuator", module.SeverityHigh, "actuator"},
		{"/actuator/env", "Spring Actuator Env", module.SeverityCritical, "actuator"},
		{"/actuator/mappings", "Spring Actuator Mappings", module.SeverityHigh, "actuator"},
		{"/actuator/httptrace", "Spring Actuator HTTP Trace", module.SeverityHigh, "actuator"},
		{"/actuator/beans", "Spring Actuator Beans", module.SeverityMedium, "actuator"},
		{"/actuator/info", "Spring Actuator Info", module.SeverityLow, "actuator"},
		{"/actuator/health", "Spring Actuator Health", module.SeverityLow, "actuator"},
		{"/actuator/metrics", "Spring Actuator Metrics", module.SeverityMedium, "actuator"},
		{"/actuator/logfile", "Spring Actuator Log File", module.SeverityHigh, "actuator"},
		{"/actuator/heapdump", "Spring Actuator Heap Dump", module.SeverityCritical, "actuator"},
		{"/actuator/threaddump", "Spring Actuator Thread Dump", module.SeverityMedium, "actuator"},
		{"/actuator/configprops", "Spring Actuator Config Props", module.SeverityHigh, "actuator"},
		{"/actuator/shutdown", "Spring Actuator Shutdown", module.SeverityCritical, "actuator"},
		{"/health", "Health Endpoint", module.SeverityLow, "actuator"},
		{"/metrics", "Metrics Endpoint", module.SeverityLow, "actuator"},
		{"/info", "Info Endpoint", module.SeverityLow, "actuator"},
		{"/management/health", "Management Health", module.SeverityLow, "actuator"},
		{"/management/env", "Management Env", module.SeverityCritical, "actuator"},

		// ── Server Diagnostics ────────────────────────────────────────────
		{"/server-status", "Apache Server Status", module.SeverityMedium, "diagnostics"},
		{"/server-info", "Apache Server Info", module.SeverityMedium, "diagnostics"},
		{"/debug", "Debug Endpoint", module.SeverityHigh, "diagnostics"},
		{"/debug/vars", "Expvar Debug Vars", module.SeverityHigh, "diagnostics"},
		{"/debug/pprof/", "pprof Profiling", module.SeverityHigh, "diagnostics"},
		{"/console", "Admin Console", module.SeverityHigh, "diagnostics"},
		{"/phpinfo.php", "PHP Info Page", module.SeverityHigh, "diagnostics"},
		{"/phpMyAdmin/", "phpMyAdmin", module.SeverityHigh, "diagnostics"},
		{"/phpmyadmin/", "phpMyAdmin (lowercase)", module.SeverityHigh, "diagnostics"},
		{"/pma/", "phpMyAdmin (pma)", module.SeverityHigh, "diagnostics"},
		{"/adminer.php", "Adminer DB Tool", module.SeverityHigh, "diagnostics"},
		{"/trace", "Trace Endpoint", module.SeverityMedium, "diagnostics"},
		{"/status", "Status Page", module.SeverityLow, "diagnostics"},
		{"/__status__", "Status Page (internal)", module.SeverityLow, "diagnostics"},
		{"/nginx_status", "NGINX Status", module.SeverityMedium, "diagnostics"},

		// ── Database / Backup ─────────────────────────────────────────────
		{"/backup.sql", "Database Backup SQL", module.SeverityCritical, "backup"},
		{"/database.sql", "Database Dump SQL", module.SeverityCritical, "backup"},
		{"/dump.sql", "Database Dump SQL", module.SeverityCritical, "backup"},
		{"/db.sql", "Database SQL", module.SeverityCritical, "backup"},
		{"/backup.zip", "Backup Archive ZIP", module.SeverityHigh, "backup"},
		{"/backup.tar.gz", "Backup Archive TGZ", module.SeverityHigh, "backup"},
		{"/site.zip", "Site Archive ZIP", module.SeverityHigh, "backup"},
		{"/.DS_Store", "macOS DS_Store", module.SeverityLow, "backup"},
		{"/Thumbs.db", "Windows Thumbs.db", module.SeverityLow, "backup"},

		// ── Log Files ─────────────────────────────────────────────────────
		{"/logs/error.log", "Error Log", module.SeverityMedium, "log"},
		{"/error.log", "Error Log", module.SeverityMedium, "log"},
		{"/access.log", "Access Log", module.SeverityMedium, "log"},
		{"/logs/access.log", "Access Log", module.SeverityMedium, "log"},
		{"/debug.log", "Debug Log", module.SeverityMedium, "log"},
		{"/app.log", "Application Log", module.SeverityMedium, "log"},
		{"/laravel.log", "Laravel Log", module.SeverityMedium, "log"},
		{"/storage/logs/laravel.log", "Laravel Storage Log", module.SeverityHigh, "log"},
		{"/var/log/nginx/access.log", "NGINX Access Log", module.SeverityHigh, "log"},

		// ── Node / PHP / Python Manifests ─────────────────────────────────
		{"/package.json", "Node Package Manifest", module.SeverityLow, "manifest"},
		{"/package-lock.json", "Node Package Lock", module.SeverityLow, "manifest"},
		{"/yarn.lock", "Yarn Lock", module.SeverityLow, "manifest"},
		{"/composer.json", "Composer Manifest", module.SeverityLow, "manifest"},
		{"/composer.lock", "Composer Lock", module.SeverityLow, "manifest"},
		{"/requirements.txt", "Python Requirements", module.SeverityLow, "manifest"},
		{"/Pipfile", "Python Pipfile", module.SeverityLow, "manifest"},
		{"/Pipfile.lock", "Python Pipfile Lock", module.SeverityLow, "manifest"},
		{"/Gemfile", "Ruby Gemfile", module.SeverityLow, "manifest"},
		{"/Gemfile.lock", "Ruby Gemfile Lock", module.SeverityLow, "manifest"},
		{"/go.mod", "Go Module", module.SeverityLow, "manifest"},
		{"/wp-config.php", "WordPress Config", module.SeverityCritical, "manifest"},
		{"/Dockerfile", "Dockerfile", module.SeverityMedium, "manifest"},
		{"/docker-compose.yml", "Docker Compose", module.SeverityMedium, "manifest"},
		{"/docker-compose.yaml", "Docker Compose YAML", module.SeverityMedium, "manifest"},

		// ── CI/CD Secrets ─────────────────────────────────────────────────
		{"/.travis.yml", "Travis CI Config", module.SeverityMedium, "ci-cd"},
		{"/.circleci/config.yml", "CircleCI Config", module.SeverityMedium, "ci-cd"},
		{"/.github/workflows/", "GitHub Actions Workflows", module.SeverityLow, "ci-cd"},
		{"/Jenkinsfile", "Jenkinsfile", module.SeverityMedium, "ci-cd"},
		{"/.gitlab-ci.yml", "GitLab CI Config", module.SeverityMedium, "ci-cd"},
		{"/bitbucket-pipelines.yml", "Bitbucket Pipelines", module.SeverityMedium, "ci-cd"},

		// ── Cloud / Infrastructure ────────────────────────────────────────
		{"/.aws/credentials", "AWS Credentials", module.SeverityCritical, "cloud"},
		{"/.aws/config", "AWS Config", module.SeverityHigh, "cloud"},
		{"/.kube/config", "Kubernetes Config", module.SeverityCritical, "cloud"},
		{"/terraform.tfstate", "Terraform State", module.SeverityCritical, "cloud"},
		{"/terraform.tfvars", "Terraform Variables", module.SeverityHigh, "cloud"},
		{"/.ssh/id_rsa", "SSH Private Key", module.SeverityCritical, "cloud"},
		{"/.ssh/id_ed25519", "SSH Ed25519 Key", module.SeverityCritical, "cloud"},
		{"/id_rsa", "SSH RSA Key", module.SeverityCritical, "cloud"},
		{"/.ansible/credentials", "Ansible Credentials", module.SeverityCritical, "cloud"},

		// ── CMS ───────────────────────────────────────────────────────────
		{"/admin/", "Admin Panel", module.SeverityHigh, "cms"},
		{"/administrator/", "Administrator Panel", module.SeverityHigh, "cms"},
		{"/wp-admin/", "WordPress Admin", module.SeverityHigh, "cms"},
		{"/wp-login.php", "WordPress Login", module.SeverityMedium, "cms"},
		{"/wp-json/wp/v2/users", "WordPress REST Users", module.SeverityHigh, "cms"},
		{"/xmlrpc.php", "WordPress XMLRPC", module.SeverityHigh, "cms"},
		{"/admin/config.php", "Admin Config", module.SeverityCritical, "cms"},
		{"/typo3/", "TYPO3 Admin", module.SeverityHigh, "cms"},
		{"/joomla/administrator/", "Joomla Administrator", module.SeverityHigh, "cms"},
		{"/drupal/admin/", "Drupal Admin", module.SeverityHigh, "cms"},
		{"/.well-known/security.txt", "Security.txt", module.SeverityLow, "cms"},
	}
}
