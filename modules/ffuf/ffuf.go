// Package ffuf implements a pure-Go HTTP fuzzer that mirrors the core
// behavior of ffuf (ffuf/ffuf, MIT) — directory busting, parameter fuzzing,
// and virtual-host fuzzing — without external dependencies.
//
// Reference: ffuf/ffuf (MIT) — mode/filter logic derived from the original
// tool's design; no source code copied. License: MIT (blackhorn-modules).
package ffuf

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	defaultTimeout  = 10 * time.Second
	maxBodyBytes    = 512 * 1024 // 512 KiB per response
	defaultThreads  = 40
	fuzzPlaceholder = "FUZZ"
)

// ─── fuzzing modes ────────────────────────────────────────────────────────────

// Mode selects what to fuzz.
type Mode string

const (
	ModeDir   Mode = "dir"   // path suffix: /FUZZ
	ModeQuery Mode = "query" // GET parameter: ?FUZZ=value
	ModeVhost Mode = "vhost" // Host header: FUZZ.target
	ModeBody  Mode = "body"  // POST body parameter: key=FUZZ
)

// ─── result ───────────────────────────────────────────────────────────────────

// Result holds a single successful probe.
type Result struct {
	Word       string
	StatusCode int
	Size       int
	Lines      int
	Words      int
	URL        string
	Redirected string // non-empty if response was a redirect
}

// ─── filter ───────────────────────────────────────────────────────────────────

// Filter controls what responses are considered "found".
type Filter struct {
	// Codes is an allowlist of HTTP status codes (empty = any non-filtered).
	Codes []int
	// FilterCodes is a denylist of status codes to suppress.
	FilterCodes []int
	// MinSize / MaxSize filter by response body size (0 = no limit).
	MinSize int
	MaxSize int
	// MinWords / MaxWords filter by word count (0 = no limit).
	MinWords int
	MaxWords int
}

// accepts returns true if the response passes the filter.
func (f Filter) accepts(code, size, words int) bool {
	for _, fc := range f.FilterCodes {
		if code == fc {
			return false
		}
	}
	if len(f.Codes) > 0 {
		found := false
		for _, c := range f.Codes {
			if code == c {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.MinSize > 0 && size < f.MinSize {
		return false
	}
	if f.MaxSize > 0 && size > f.MaxSize {
		return false
	}
	if f.MinWords > 0 && words < f.MinWords {
		return false
	}
	if f.MaxWords > 0 && words > f.MaxWords {
		return false
	}
	return true
}

// ─── module ───────────────────────────────────────────────────────────────────

// Module is the ffuf fuzzer.
type Module struct {
	client *http.Client
	// Mode selects what to fuzz (default: dir).
	Mode Mode
	// Wordlist supplies words to fuzz. If nil, a built-in list is used.
	Wordlist []string
	// Threads is the parallelism degree (default: 40).
	Threads int
	// Filter controls response acceptance.
	Filter Filter
	// Headers are extra HTTP headers added to every request.
	Headers map[string]string
	// FollowRedirects allows redirect following (default: false — redirects are
	// reported as findings but not followed).
	FollowRedirects bool
	// CustomFuzz, if set, replaces the FUZZ marker in the URL template directly.
	// Used for custom fuzzing scenarios (e.g., "https://example.com/FUZZ.php").
	CustomFuzz string
	// PostBody is the raw POST body template; FUZZ is replaced per word.
	// Only used in ModeBody.
	PostBody string
}

// New returns a Module with sensible defaults.
func New() *Module {
	return &Module{
		client:  httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		Mode:    ModeDir,
		Threads: defaultThreads,
		Filter: Filter{
			FilterCodes: []int{404},
		},
	}
}

// NewWithClient creates a Module using the provided HTTP client.
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client:  c,
		Mode:    ModeDir,
		Threads: defaultThreads,
		Filter: Filter{
			FilterCodes: []int{404},
		},
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "ffuf" }

// Run implements module.Module.
// Input.Target: base URL to fuzz (required).
// Input.Options:
//   - "mode":         dir|query|vhost|body (default: dir)
//   - "wordlist":     newline-separated words (overrides built-in)
//   - "threads":      concurrency (default: 40)
//   - "filter_codes": comma-separated codes to reject (default: 404)
//   - "match_codes":  comma-separated codes to accept (default: any non-filtered)
//   - "post_body":    POST body template for body mode (FUZZ replaced per word)
//   - "custom_fuzz":  URL template with FUZZ placeholder
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	if input.Target == "" {
		return nil, fmt.Errorf("ffuf: no target URL provided")
	}

	mode, wordlist, threads, filter, postBody, customFuzz := m.parseOptions(input)

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(threads)

	for _, word := range wordlist {
		word := word
		if word == "" {
			continue
		}
		g.Go(func() error {
			result, err := m.probe(gctx, input.Target, word, mode, postBody, customFuzz)
			if err != nil {
				slog.Debug("ffuf: probe error", "word", word, "err", err)
				return nil // soft fail per probe
			}
			if result == nil {
				return nil
			}
			if !filter.accepts(result.StatusCode, result.Size, result.Words) {
				return nil
			}
			f := toFinding(result, word, mode)
			mu.Lock()
			findings = append(findings, f)
			mu.Unlock()
			return nil
		})
	}

	_ = g.Wait()
	return dedupFindings(findings), nil
}

// ─── probe ────────────────────────────────────────────────────────────────────

func (m *Module) probe(ctx context.Context, target, word string, mode Mode, postBody, customFuzz string) (*Result, error) {
	rawURL, method, body := buildRequest(target, word, mode, postBody, customFuzz)
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-ffuf/1.0")
	if mode == ModeVhost {
		host := strings.ReplaceAll(word, " ", "") + "." + hostFromURL(target)
		req.Host = host
	}
	for k, v := range m.Headers {
		req.Header.Set(k, v)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Don't follow redirects unless configured.
	client := m.client
	if !m.FollowRedirects {
		client = noRedirectClient(m.client)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}

	size := len(respBody)
	words := countWords(respBody)
	lines := countLines(respBody)

	result := &Result{
		Word:       word,
		StatusCode: resp.StatusCode,
		Size:       size,
		Words:      words,
		Lines:      lines,
		URL:        rawURL,
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		result.Redirected = loc
	}
	return result, nil
}

// ─── request builder ─────────────────────────────────────────────────────────

func buildRequest(base, word string, mode Mode, postBody, customFuzz string) (rawURL, method, body string) {
	base = strings.TrimRight(base, "/")
	switch mode {
	case ModeDir:
		if customFuzz != "" {
			rawURL = strings.ReplaceAll(customFuzz, fuzzPlaceholder, url.PathEscape(word))
		} else {
			rawURL = base + "/" + url.PathEscape(word)
		}
		method = http.MethodGet
	case ModeQuery:
		rawURL = base + "?" + url.QueryEscape(word) + "=1"
		method = http.MethodGet
	case ModeVhost:
		rawURL = base
		method = http.MethodGet
	case ModeBody:
		rawURL = base
		method = http.MethodPost
		if postBody != "" {
			body = strings.ReplaceAll(postBody, fuzzPlaceholder, url.QueryEscape(word))
		} else {
			body = "data=" + url.QueryEscape(word)
		}
	default:
		rawURL = base + "/" + url.PathEscape(word)
		method = http.MethodGet
	}
	return
}

// ─── finding builder ─────────────────────────────────────────────────────────

func toFinding(r *Result, word string, mode Mode) module.Finding {
	sev := severityForCode(r.StatusCode)
	detail := fmt.Sprintf("[%d] %s — size:%d words:%d lines:%d",
		r.StatusCode, r.URL, r.Size, r.Words, r.Lines)
	extra := map[string]string{
		"status_code": fmt.Sprint(r.StatusCode),
		"size":        fmt.Sprint(r.Size),
		"words":       fmt.Sprint(r.Words),
		"lines":       fmt.Sprint(r.Lines),
		"mode":        string(mode),
		"word":        word,
		"confidence":  "0.80",
	}
	if r.Redirected != "" {
		extra["redirect"] = r.Redirected
	}
	return module.Finding{
		Type:     "fuzzing_hit",
		URL:      r.URL,
		Severity: sev,
		Detail:   detail,
		Extra:    extra,
	}
}

func severityForCode(code int) module.Severity {
	switch {
	case code >= 500:
		return module.SeverityHigh
	case code == 200 || code == 201:
		return module.SeverityMedium
	case code >= 300 && code < 400:
		return module.SeverityLow
	default:
		return module.SeverityInfo
	}
}

// ─── option parsing ───────────────────────────────────────────────────────────

func (m *Module) parseOptions(input module.Input) (mode Mode, wordlist []string, threads int, filter Filter, postBody, customFuzz string) {
	opts := input.Options
	if opts == nil {
		opts = make(map[string]string)
	}

	mode = m.Mode
	if v := opts["mode"]; v != "" {
		mode = Mode(strings.ToLower(v))
	}

	threads = m.Threads
	if threads <= 0 {
		threads = defaultThreads
	}
	if v := opts["threads"]; v != "" {
		fmt.Sscanf(v, "%d", &threads)
	}

	filter = m.Filter
	if v := opts["filter_codes"]; v != "" {
		filter.FilterCodes = parseCodes(v)
	}
	if v := opts["match_codes"]; v != "" {
		filter.Codes = parseCodes(v)
	}

	postBody = m.PostBody
	if v := opts["post_body"]; v != "" {
		postBody = v
	}

	customFuzz = m.CustomFuzz
	if v := opts["custom_fuzz"]; v != "" {
		customFuzz = v
	}

	// Wordlist priority: input.Options > input.RawContent > Module.Wordlist > built-in.
	if v := opts["wordlist"]; v != "" {
		wordlist = parseWordlist(v)
	} else if input.RawContent != "" {
		wordlist = parseWordlist(input.RawContent)
	} else if len(m.Wordlist) > 0 {
		wordlist = m.Wordlist
	} else {
		wordlist = builtinWordlist(mode)
	}

	return
}

func parseCodes(s string) []int {
	var codes []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var c int
		fmt.Sscanf(part, "%d", &c)
		if c > 0 {
			codes = append(codes, c)
		}
	}
	return codes
}

func parseWordlist(s string) []string {
	var words []string
	for _, w := range strings.Split(s, "\n") {
		w = strings.TrimSpace(w)
		if w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}
	return words
}

// ─── built-in wordlists ───────────────────────────────────────────────────────

// builtinWordlist returns a curated wordlist for the given mode.
// Modeled after SecLists common paths (MIT) — independent list, not copied.
func builtinWordlist(mode Mode) []string {
	switch mode {
	case ModeVhost:
		return builtinVhosts
	case ModeQuery:
		return builtinParams
	default:
		return builtinPaths
	}
}

// builtinPaths: common web directories and files.
var builtinPaths = []string{
	// Admin / management
	"admin", "admin.php", "admin.html", "administrator", "administrador",
	"dashboard", "panel", "control", "manage", "management", "manager",
	"login", "login.php", "login.html", "signin", "sign-in", "auth",
	"logout", "logoff", "signout",
	// Configuration / sensitive files
	".env", ".env.local", ".env.production", ".env.backup",
	".git/HEAD", ".git/config", ".gitignore",
	"config.php", "config.json", "config.yaml", "config.yml",
	"settings.php", "settings.py", "settings.json",
	"database.php", "db.php", "connection.php",
	"wp-config.php", "wp-config.php.bak",
	"application.properties", "application.yml",
	// Backup / temp files
	"backup", "backup.zip", "backup.tar.gz", "backup.sql",
	"db.sql", "dump.sql", "database.sql",
	"old", "tmp", "temp", "test", "dev",
	// APIs
	"api", "api/v1", "api/v2", "api/v3",
	"graphql", "graphiql", "swagger", "swagger.json", "swagger.yaml",
	"openapi.json", "openapi.yaml", "api-docs", "api-docs.json",
	"jsonrpc", "rpc",
	// Status / monitoring
	"health", "healthz", "health-check", "ping", "status",
	"metrics", "actuator", "actuator/health", "actuator/env",
	"debug", "info", "version",
	// Upload / media
	"upload", "uploads", "files", "file", "media", "images", "img",
	"documents", "docs", "static", "assets", "public",
	// Common directories
	"css", "js", "javascript", "include", "includes",
	"lib", "libs", "library", "vendor",
	"src", "source", "app", "apps", "web",
	// CMS / framework specific
	"wp-admin", "wp-login.php", "wp-content", "wp-json",
	"joomla", "drupal", "magento", "prestashop",
	"phpmyadmin", "pma", "myadmin", "phpmyadmin2",
	"phpinfo.php", "info.php", "test.php",
	// Server utilities
	"server-status", "server-info", ".htaccess", ".htpasswd",
	"robots.txt", "sitemap.xml", "sitemap.xml.gz",
	"crossdomain.xml", "clientaccesspolicy.xml",
	// Logs
	"log", "logs", "error_log", "access_log", "error.log", "access.log",
	// User / account pages
	"user", "users", "account", "accounts", "profile",
	"register", "registration", "signup", "sign-up",
	"forgot-password", "reset-password", "change-password",
	// Search / data
	"search", "query", "find", "filter", "export", "import", "download",
	// E-commerce
	"checkout", "cart", "shop", "store", "order", "orders", "payment",
	// Misc common hits
	"404.php", "error.php", "403.php",
	"cgi-bin", "cgi-bin/test.cgi",
	".DS_Store", "thumbs.db",
}

// builtinParams: common GET/POST parameter names for injection testing.
var builtinParams = []string{
	"id", "user", "username", "password", "passwd", "email",
	"name", "first_name", "last_name", "fname", "lname",
	"page", "p", "pg", "pageid", "page_id", "pagenum",
	"search", "q", "query", "s", "keyword", "keywords",
	"url", "link", "href", "src", "redirect", "return", "next", "back",
	"file", "filename", "path", "filepath", "dir", "directory",
	"token", "key", "api_key", "apikey", "auth", "access_token",
	"lang", "language", "locale", "currency", "country",
	"debug", "test", "dev", "preview",
	"callback", "jsonp", "action", "method",
	"sort", "order", "orderby", "order_by", "asc", "desc",
	"limit", "offset", "start", "end", "from", "to",
	"type", "format", "output", "view",
	"category", "cat", "tag", "tags", "section", "sub",
	"data", "input", "value", "val", "param",
}

// builtinVhosts: common virtual-host prefixes for vhost fuzzing.
var builtinVhosts = []string{
	"dev", "development", "staging", "stage", "uat", "qa", "test",
	"sandbox", "beta", "alpha", "demo", "preview",
	"admin", "management", "portal", "dashboard", "panel",
	"api", "api-v1", "api-v2", "rest", "graphql",
	"mail", "smtp", "pop3", "imap", "webmail", "mx",
	"ftp", "sftp", "files", "static", "assets", "media",
	"vpn", "remote", "secure", "internal", "corp",
	"db", "database", "mysql", "mongo", "redis", "elastic",
	"git", "svn", "ci", "jenkins", "gitlab", "bitbucket",
	"monitoring", "metrics", "grafana", "kibana", "splunk",
	"docs", "documentation", "wiki", "help", "support",
	"blog", "news", "careers", "shop", "store",
	"cdn", "img", "images", "download", "downloads",
	"old", "legacy", "archive", "backup",
	"mobile", "m", "app", "apps",
	"www", "www2", "ns1", "ns2",
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func countWords(b []byte) int {
	return len(strings.Fields(string(b)))
}

func countLines(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	return strings.Count(string(b), "\n") + 1
}

func hostFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
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

// noRedirectClient wraps an existing client with no-redirect transport.
func noRedirectClient(base *http.Client) *http.Client {
	clone := *base
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
}
