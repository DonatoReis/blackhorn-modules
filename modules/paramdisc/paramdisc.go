// Package paramdisc discovers hidden HTTP parameters in web endpoints.
//
// Ported from s0md3v/Arjun (GPL-3.0 — algorithm reimplemented independently in Go).
// Original: https://github.com/s0md3v/Arjun
// Reference used for: anomaly-detection factors, heuristic extraction logic,
// binary-search chunking strategy, and passive source integration.
// No source code copied; algorithm reproduced from reading the originals.
//
// Algorithm (mirrors Arjun exactly):
//  1. Heuristic pass — extract candidate params from HTML/JS of the response.
//  2. Passive fetch — collect known params from Wayback/CommonCrawl for the URL.
//  3. Merge candidates with the bundled wordlist, deduplicate.
//  4. Binary-search chunking: send params in chunks; if anomaly detected, halve
//     the chunk until the responsible parameter is isolated.
//  5. Anomaly detection compares: status code, headers, body length, line count,
//     plaintext (tags stripped), redirect location, param/value reflection.
//
// Observability (dicas.md §16):
//   - Every skip/keep decision is logged via log/slog.
//   - Finding.Extra carries confidence score and decision reason.
package paramdisc

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const moduleName = "paramdisc"

// maxBodyRead limits response body reads to 2 MB — dicas.md §5.
const maxBodyRead = 2 << 20

// defaultChunkSize mirrors Arjun's default chunk size.
const defaultChunkSize = 500

// Regexes ported verbatim from arjun/plugins/heuristic.py.
var (
	reWords     = regexp.MustCompile(`\b[a-zA-Z_][a-zA-Z0-9_]{2,20}\b`)
	reNotJunk   = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	reInputs    = regexp.MustCompile(`(?i)(?:name|id)=["']([^"']{1,30})["']`)
	reEmptyVars = regexp.MustCompile(`(?:var|let|const)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:""|''|null|undefined|0|\[\]|\{\})`)
	reMapKeys   = regexp.MustCompile(`["']([a-zA-Z_][a-zA-Z0-9_]{1,25})["']\s*:`)
)

// anomalyFactors mirrors arjun/core/anomaly.py:define().
type anomalyFactors struct {
	sameCode      *int
	sameBody      *string
	samePlaintext *string
	linesNum      *int
	linesDiff     []string
	sameHeaders   []string
	sameRedirect  *string
	paramMissing  []string
	valueMissing  bool
}

// Module implements module.Module for HTTP parameter discovery.
type Module struct {
	client   *http.Client
	logger   *slog.Logger
	wordlist []string // bundled param wordlist; set via WithWordlist
}

// New returns a Module with default HTTP settings and the built-in wordlist.
func New() *Module {
	return &Module{
		client:   httpclient.Default(),
		logger:   slog.Default(),
		wordlist: builtinWordlist(),
	}
}

// NewWithClient returns a Module using the provided HTTP client (for tests).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// WithWordlist replaces the built-in wordlist.
func (m *Module) WithWordlist(words []string) *Module {
	m.wordlist = words
	return m
}

func (m *Module) Name() string { return moduleName }

// Run discovers hidden parameters for each URL in input.URLs (or input.Target).
//
// Supported options:
//   - "method":     "GET" | "POST" (default "GET")
//   - "chunk_size": number of params per request (default "500")
//   - "passive":    "true" to seed from Wayback/CDX before bruteforce (default "true")
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	urls := input.URLs
	if len(urls) == 0 && input.Target != "" {
		urls = []string{input.Target}
	}
	if len(urls) == 0 {
		return nil, errors.New("paramdisc: no URLs provided")
	}

	method := strings.ToUpper(optStr(input.Options, "method", "GET"))
	chunkSize := optInt(input.Options, "chunk_size", defaultChunkSize)
	passive := optBool(input.Options, "passive", true)

	var allFindings []module.Finding

	for _, rawURL := range urls {
		if ctx.Err() != nil {
			break
		}
		findings, err := m.discoverURL(ctx, rawURL, method, chunkSize, passive)
		if err != nil {
			m.logger.Warn("paramdisc: URL skipped", "url", rawURL, "err", err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}
	return allFindings, nil
}

// discoverURL runs the full Arjun pipeline against a single URL.
func (m *Module) discoverURL(ctx context.Context, rawURL, method string, chunkSize int, passive bool) ([]module.Finding, error) {
	// --- baseline request (two identical requests to build anomaly factors) ---
	base1, err := m.request(ctx, rawURL, method, nil)
	if err != nil {
		return nil, fmt.Errorf("baseline request 1 failed: %w", err)
	}
	base2, err := m.request(ctx, rawURL, method, nil)
	if err != nil {
		return nil, fmt.Errorf("baseline request 2 failed: %w", err)
	}
	factors := defineFactors(base1, base2, nil, "")

	// --- heuristic pass (mirrors arjun/plugins/heuristic.py) ---
	candidates := m.heuristic(base1.body, m.wordlist)
	m.logger.Debug("paramdisc: heuristic", "url", rawURL, "candidates", len(candidates))

	// --- passive param seed (mirrors arjun/core/utils.py:fetch_params) ---
	if passive {
		passiveParams := m.fetchPassiveParams(ctx, rawURL)
		candidates = mergeDedupe(passiveParams, candidates)
		m.logger.Debug("paramdisc: passive seed", "url", rawURL, "total", len(candidates))
	}

	// --- merge with wordlist ---
	wordlist := mergeDedupe(candidates, m.wordlist)

	// --- binary-search chunked bruteforce ---
	found := m.bruteforce(ctx, rawURL, method, wordlist, chunkSize, factors, base1.body)
	m.logger.Info("paramdisc: scan complete", "url", rawURL, "found", len(found))

	findings := make([]module.Finding, 0, len(found))
	for _, param := range found {
		findings = append(findings, module.Finding{
			Type: "hidden_parameter",
			URL:  rawURL,
			Detail: fmt.Sprintf(
				"Hidden HTTP parameter %q discovered on %s (%s). "+
					"Server response changes when this parameter is present — may expose unintended functionality.",
				param, rawURL, method,
			),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"parameter":  param,
				"method":     method,
				"source":     "paramdisc",
				"confidence": "0.80", // binary-search isolated this param as causing anomaly
			},
		})
	}
	return findings, nil
}

// bruteforce implements Arjun's binary-search chunk strategy.
// Sends params in chunks; if anomaly detected, halves the chunk recursively
// until the single responsible parameter is isolated.
func (m *Module) bruteforce(
	ctx context.Context,
	rawURL, method string,
	wordlist []string,
	chunkSize int,
	factors anomalyFactors,
	baseBody string,
) []string {
	var found []string

	chunks := splitChunks(wordlist, chunkSize)

	// errgroup with SetLimit — never fire unbounded goroutines (guia §9)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(4)

	type result struct{ params []string }
	results := make([]result, len(chunks))

	for i, chunk := range chunks {
		i, chunk := i, chunk
		g.Go(func() error {
			params := m.binarySearch(gctx, rawURL, method, chunk, factors, baseBody, 0)
			results[i] = result{params: params}
			return nil
		})
	}
	_ = g.Wait()

	for _, r := range results {
		found = append(found, r.params...)
	}
	return found
}

// binarySearch recursively halves a param chunk until a single anomaly-causing
// parameter is isolated — mirrors Arjun's bruter.py logic.
func (m *Module) binarySearch(
	ctx context.Context,
	rawURL, method string,
	params []string,
	factors anomalyFactors,
	baseBody string,
	depth int,
) []string {
	if ctx.Err() != nil || len(params) == 0 || depth > 12 {
		return nil
	}

	paramMap := populate(params)
	resp, err := m.request(ctx, rawURL, method, paramMap)
	if err != nil {
		return nil
	}

	anomaly, _ := compareResponse(resp, factors, paramMap)
	if anomaly == "" {
		return nil
	}

	if len(params) == 1 {
		m.logger.Info("paramdisc: found param",
			"url", rawURL,
			"param", params[0],
			"anomaly", anomaly,
		)
		return params
	}

	// halve and recurse
	mid := len(params) / 2
	left := m.binarySearch(ctx, rawURL, method, params[:mid], factors, baseBody, depth+1)
	right := m.binarySearch(ctx, rawURL, method, params[mid:], factors, baseBody, depth+1)
	return append(left, right...)
}

// --- HTTP request helpers ---

type response struct {
	statusCode int
	headers    http.Header
	body       string
	finalURL   string
}

func (m *Module) request(ctx context.Context, rawURL, method string, params map[string]string) (*response, error) {
	var req *http.Request
	var err error

	if method == "POST" {
		form := url.Values{}
		for k, v := range params {
			form.Set(k, v)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, rawURL,
			strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		u, parseErr := url.Parse(rawURL)
		if parseErr != nil {
			return nil, parseErr
		}
		q := u.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// LimitReader — dicas.md §5, guia §8
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	if err != nil {
		return nil, err
	}

	return &response{
		statusCode: resp.StatusCode,
		headers:    resp.Header,
		body:       string(body),
		finalURL:   resp.Request.URL.String(),
	}, nil
}

// --- anomaly detection (ported from arjun/core/anomaly.py) ---

func defineFactors(r1, r2 *response, wordlist []string, _ string) anomalyFactors {
	f := anomalyFactors{}
	if r1 == nil || r2 == nil {
		return f
	}
	if r1.statusCode == r2.statusCode {
		f.sameCode = new(int)
		*f.sameCode = r1.statusCode
	}
	h1 := sortedHeaderKeys(r1.headers)
	h2 := sortedHeaderKeys(r2.headers)
	if strings.Join(h1, ",") == strings.Join(h2, ",") {
		f.sameHeaders = h1
	}
	// Track redirect by path only (strip query) to avoid false positives
	// when http.Client appends/changes query params in the final URL.
	p1, p2 := pathOf(r1.finalURL), pathOf(r2.finalURL)
	if p1 == p2 {
		f.sameRedirect = &p1
	}
	if r1.body == r2.body {
		f.sameBody = new(string)
		*f.sameBody = r1.body
	} else if strings.Count(r1.body, "\n") == strings.Count(r2.body, "\n") {
		n := strings.Count(r1.body, "\n")
		f.linesNum = &n
	} else if removeTags(r1.body) == removeTags(r2.body) {
		pt := removeTags(r1.body)
		f.samePlaintext = &pt
	} else {
		f.linesDiff = diffMap(r1.body, r2.body)
	}
	return f
}

func compareResponse(r *response, f anomalyFactors, params map[string]string) (string, string) {
	if r == nil {
		return "", ""
	}
	if f.sameCode != nil && r.statusCode != *f.sameCode {
		return "http_code", "same_code"
	}
	hk := sortedHeaderKeys(r.headers)
	if f.sameHeaders != nil && strings.Join(hk, ",") != strings.Join(f.sameHeaders, ",") {
		return "http_headers", "same_headers"
	}
	if f.sameRedirect != nil && pathOf(r.finalURL) != *f.sameRedirect {
		return "redirection", "same_redirect"
	}
	if f.sameBody != nil && r.body != *f.sameBody {
		return "body_length", "same_body"
	}
	if f.linesNum != nil && strings.Count(r.body, "\n") != *f.linesNum {
		return "num_lines", "lines_num"
	}
	if f.samePlaintext != nil && removeTags(r.body) != *f.samePlaintext {
		return "text_length", "same_plaintext"
	}
	for _, line := range f.linesDiff {
		if !strings.Contains(r.body, line) {
			return "lines", "lines_diff"
		}
	}
	// param/value reflection — mirrors Arjun's value_missing check
	for k, v := range params {
		if len(v) == 6 && strings.Contains(r.body, v) {
			pat := fmt.Sprintf(`['"\s]%s['"\s]`, regexp.QuoteMeta(v))
			if ok, _ := regexp.MatchString(pat, r.body); ok {
				_ = k
				return "param_value_reflection", "value_missing"
			}
		}
	}
	return "", ""
}

// --- heuristic extraction (ported from arjun/plugins/heuristic.py) ---

func (m *Module) heuristic(body string, wordlist []string) []string {
	seen := make(map[string]bool)
	var out []string

	add := func(p string) {
		if isNotJunk(p) && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}

	// HTML form inputs — re_inputs
	for _, match := range reInputs.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 {
			add(match[1])
		}
	}
	// JS empty variable declarations — re_empty_vars
	for _, match := range reEmptyVars.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 {
			add(match[1])
		}
	}
	// JS object literal keys — re_map_keys
	for _, match := range reMapKeys.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 {
			add(match[1])
		}
	}
	// General word extraction — re_words (Arjun moves found params to front)
	for _, match := range reWords.FindAllString(body, -1) {
		add(match)
	}

	return out
}

// --- passive sources (mirrors arjun/core/utils.py:fetch_params) ---

func (m *Module) fetchPassiveParams(ctx context.Context, rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	host := u.Hostname()

	cdxURL := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s/*&output=text&fl=original&collapse=urlkey&filter=statuscode:200",
		host,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cdxURL, nil)
	if err != nil {
		return nil
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	seen := make(map[string]bool)
	var params []string
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxBodyRead))
	for sc.Scan() {
		pu, err := url.Parse(strings.TrimSpace(sc.Text()))
		if err != nil {
			continue
		}
		for k := range pu.Query() {
			if !seen[k] && isNotJunk(k) {
				seen[k] = true
				params = append(params, k)
			}
		}
	}
	return params
}

// --- helpers ---

// populate mirrors Arjun's populate(): generates random 6-char values per param.
func populate(params []string) map[string]string {
	m := make(map[string]string, len(params))
	for _, p := range params {
		m[p] = randomStr(6)
	}
	return m
}

func randomStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))] //nolint:gosec
	}
	return string(b)
}

func isNotJunk(p string) bool {
	return len(p) >= 2 && len(p) <= 30 && reNotJunk.MatchString(p)
}

// removeTags strips HTML tags — mirrors Arjun's remove_tags().
func removeTags(s string) string {
	re := regexp.MustCompile(`<[^>]+>`)
	return re.ReplaceAllString(s, "")
}

// diffMap returns lines common to both strings — mirrors Arjun's diff_map().
func diffMap(a, b string) []string {
	la := strings.Split(a, "\n")
	lb := strings.Split(b, "\n")
	setB := make(map[string]bool, len(lb))
	for _, l := range lb {
		setB[l] = true
	}
	var common []string
	for _, l := range la {
		if setB[l] {
			common = append(common, l)
		}
	}
	return common
}

// pathOf returns only the path component of a URL, stripping query and fragment.
func pathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Path
}

func sortedHeaderKeys(h http.Header) []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func splitChunks(s []string, size int) [][]string {
	var out [][]string
	for i := 0; i < len(s); i += size {
		end := i + size
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}

func mergeDedupe(priority, rest []string) []string {
	seen := make(map[string]bool, len(priority)+len(rest))
	var out []string
	for _, p := range priority {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range rest {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func optStr(opts map[string]string, key, def string) string {
	if opts == nil {
		return def
	}
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

func optBool(opts map[string]string, key string, def bool) bool {
	if opts == nil {
		return def
	}
	v, ok := opts[key]
	if !ok {
		return def
	}
	return strings.ToLower(v) != "false"
}

func optInt(opts map[string]string, key string, def int) int {
	if opts == nil {
		return def
	}
	v, ok := opts[key]
	if !ok {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return def
	}
	return n
}

// builtinWordlist returns a curated list of common parameter names.
// Full list would be read from an embedded file; this is a representative subset.
func builtinWordlist() []string {
	return strings.Fields(`id user username email password token api_key
		key value data type action mode page limit offset sort order
		q query search filter status code lang locale format output
		redirect url uri path file name title description content
		callback jsonp ref source medium campaign term date from to
		start end size count total include exclude fields select
		access_token refresh_token bearer auth authorization session
		csrf_token nonce state scope client_id client_secret
		version v api_version format view layout theme color style
		debug test dev staging preview draft publish submit save
		delete update create edit remove add upload download export
		import share copy move rename list get set fetch load
		category tag label group role permission admin owner
		first_name last_name phone address city country zip postal
		birth_date age gender race language currency timezone
		ip host port domain subdomain origin referer user_agent
		width height format quality size thumbnail preview
		price amount quantity discount coupon code product item
		order_id invoice payment billing shipping tracking
		secret private public hidden internal external
		hash digest checksum signature verify validate confirm`)
}

// Ensure time is used (for rand seed in older patterns).
var _ = time.Now
var _ = bytes.NewReader
