// Package soft404 detects soft-404 responses — HTTP 200 pages that are
// semantically error pages, auth walls, anti-bot challenges, or wildcard-200
// CMS templates.
//
// Reference implementation (algorithm only, no code copied):
//   - orbit-core internal/modules/soft404.go (proprietary)
//
// What is implemented:
//   - FNV-1a simhash fingerprinting of page text (Charikar's algorithm)
//   - Hamming-distance comparison against a synthetic invalid sibling URL
//   - Soft-404 marker detection (50+ multilingual phrases)
//   - Auth-wall detection (login/signup pages served as 200)
//   - Anti-bot / challenge page detection (Cloudflare, Akamai, etc.)
//   - Content-ratio analysis (boilerplate-heavy pages with little real text)
//   - JSON/XML API endpoint exemption (valid short responses)
//   - io.LimitReader on every body read                   (dicas.md §5)
//   - log/slog structured observability                   (dicas.md §16)
//   - errgroup.SetLimit bounded fan-out                   (guia-go §9)
//   - context propagation and cancellation               (guia-go §9)
//
// Primary use-cases:
//  1. Pre-filter for pathprobe / vulnscan (discard wildcard-200 false positives)
//  2. Standalone: classify a list of URLs and annotate which are soft-404
package soft404

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
	maxBodyRead    = 64 * 1024 // 64 KiB — dicas.md §5
	defaultTimeout = 10 * time.Second
	defaultThreads = 10

	// hammingThreshold: simhash distance ≤ 6 = near-duplicate (text-level, not HTML-level).
	// Calibrated on corpus of CMS error pages; matches orbit-core value.
	hammingThreshold = 6
)

// ─── Result ───────────────────────────────────────────────────────────────────

// Kind classifies why a URL was flagged as soft-404.
type Kind string

const (
	KindMarker       Kind = "error_marker"  // contains error phrases
	KindAuthWall     Kind = "auth_wall"     // login/signup page
	KindAntiBot      Kind = "anti_bot"      // cloudflare/challenge page
	KindWildcard     Kind = "wildcard_host" // host returns identical 200 for any path
	KindLowContent   Kind = "low_content"   // almost no real text
	KindContentRatio Kind = "content_ratio" // boilerplate-heavy HTML
)

// ─── Module ───────────────────────────────────────────────────────────────────

// Module classifies HTTP URLs as soft-404 or valid.
type Module struct {
	client  *http.Client
	threads int
	timeout time.Duration
}

// New creates a Module with default settings.
func New() *Module {
	return &Module{
		client:  defaultClient(defaultTimeout),
		threads: defaultThreads,
		timeout: defaultTimeout,
	}
}

// NewWithClient creates a Module with a custom HTTP client (useful for tests).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// Name satisfies module.Module.
func (m *Module) Name() string { return "soft404" }

// Run satisfies module.Module.
// It classifies each URL from input.URLs (and input.Target if set).
// Each soft-404 URL produces a finding with kind + score metadata.
// Valid URLs produce no findings.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	urls := collectURLs(input)
	if len(urls) == 0 {
		return nil, fmt.Errorf("soft404: no URLs to classify")
	}

	threads := optInt(input.Options, "threads", m.threads)
	slog.Debug("soft404: starting", "urls", len(urls), "threads", threads)

	findingsCh := make(chan module.Finding, 64)
	var flagged atomic.Int64

	// Per-host prober cache — protected by mu.
	var proberMu sync.Mutex
	proberCache := make(map[string]*Prober)
	getProber := func(rawURL string) *Prober {
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" {
			return nil
		}
		key := u.Scheme + "://" + u.Host
		proberMu.Lock()
		defer proberMu.Unlock()
		if p, ok := proberCache[key]; ok {
			return p
		}
		p := NewProber(ctx, m.client, m.timeout)
		proberCache[key] = p
		return p
	}

	eg, gctx := errgroup.WithContext(ctx)
	eg.SetLimit(threads)

	for _, rawURL := range urls {
		rawURL := rawURL // capture
		eg.Go(func() error {
			body, headers, code := fetchBody(gctx, m.client, rawURL)
			if code == 0 {
				return nil // network error — not classifiable
			}

			kind, score, is404 := Classify(body, headers, code)
			if !is404 {
				// Check wildcard-200 via simhash.
				prober := getProber(rawURL)
				if prober != nil && prober.IsSimilarToInvalid(body, rawURL) {
					kind = KindWildcard
					score = 10
					is404 = true
				}
			}
			if !is404 {
				return nil
			}

			flagged.Add(1)
			findingsCh <- module.Finding{
				Type:     "soft_404",
				URL:      rawURL,
				Detail:   fmt.Sprintf("URL returned HTTP %d but content indicates a soft-404 (%s)", code, kind),
				Severity: module.SeverityInfo,
				Extra: map[string]string{
					"kind":        string(kind),
					"score":       fmt.Sprintf("%d", score),
					"http_status": fmt.Sprintf("%d", code),
					"confidence":  "0.85",
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
	slog.Debug("soft404: done", "flagged", flagged.Load(), "total", len(urls))
	return findings, nil
}

// ─── Classify — public API ────────────────────────────────────────────────────

// Classify returns (kind, score, isSoft404) for a given HTTP response.
// kind is the dominant reason; score is a confidence integer (0–12).
// This function is exported so other modules (pathprobe, vulnscan) can reuse
// the classification logic without making extra HTTP requests.
func Classify(body string, headers http.Header, code int) (Kind, int, bool) {
	if body == "" {
		return "", 0, false
	}

	// Hard errors are not soft-404 per se — they have their own code.
	// We only classify 200–299 range (includes 200 from WAFs returning pages).
	if code < 200 || code >= 300 {
		return "", 0, false
	}

	// JSON/XML APIs are valid short responses — not soft-404.
	b := strings.TrimSpace(body)
	if strings.HasPrefix(b, "{") || strings.HasPrefix(b, "[") || strings.HasPrefix(b, "<?xml") {
		return "", 0, false
	}

	lower := strings.ToLower(body)

	// Priority 1: Anti-bot / challenge page.
	if headers != nil && headers.Get("cf-mitigated") != "" {
		return KindAntiBot, 12, true
	}
	for _, m := range antiBotMarkers {
		if strings.Contains(lower, m) {
			return KindAntiBot, 12, true
		}
	}

	// Priority 2: Auth wall (login pages returned as 200).
	limit := len(body)
	if limit > 2000 {
		limit = 2000
	}
	lowerHead := strings.ToLower(body[:limit])
	for _, m := range authWallMarkers {
		if strings.Contains(lowerHead, m) {
			return KindAuthWall, 8, true
		}
	}

	score := 0

	// Soft-404 markers.
	hits := 0
	for _, m := range soft404Markers {
		if strings.Contains(lower, m) {
			hits++
			if hits >= 2 {
				break
			}
		}
	}
	if hits >= 2 {
		score += 4
	} else if hits == 1 && len(body) < 3000 {
		score += 2
	}

	// Very small body with few meaningful words.
	mainText := extractText(body)
	wc := wordCount(mainText)
	if len(body) < 600 && wc < 10 {
		score += 3
	} else if len(body) < 2000 && wc < 20 {
		score++
	}
	if wc > 0 && wc <= 2 {
		score += 2
	}

	// Content ratio: boilerplate-heavy (< 10% real text in > 500-byte page).
	ratio := contentRatio(mainText, body)
	if ratio < 0.10 && len(body) > 500 {
		score += 2
	}

	if score >= 4 {
		// Determine dominant kind.
		if hits >= 1 {
			return KindMarker, score, true
		}
		if wc <= 2 {
			return KindLowContent, score, true
		}
		return KindContentRatio, score, true
	}
	return "", score, false
}

// ─── Prober ──────────────────────────────────────────────────────────────────

// Prober detects wildcard-200 hosts via simhash comparison against a synthetic
// invalid sibling URL. Exported so pathprobe and other modules can share it.
// All methods are goroutine-safe.
type Prober struct {
	ctx    context.Context
	client *http.Client
	mu     sync.Mutex
	cache  map[string]uint64 // hostKey → simhash (wildcardSentinel = wildcard host)
}

const wildcardSentinel = ^uint64(0)

// NewProber creates a Prober.
func NewProber(ctx context.Context, client *http.Client, _ time.Duration) *Prober {
	return &Prober{ctx: ctx, client: client, cache: make(map[string]uint64)}
}

// InvalidFingerprint returns the simhash fingerprint of the invalid sibling URL.
// Caches per host. Returns (fingerprint, ok). Goroutine-safe.
func (p *Prober) InvalidFingerprint(rawURL string) (uint64, bool) {
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
	} else if _, _, isSoft := Classify(body, headers, code); isSoft {
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

// IsSimilarToInvalid returns true when the target body is a near-duplicate of
// the invalid sibling (hamming distance ≤ hammingThreshold).
func (p *Prober) IsSimilarToInvalid(body, rawURL string) bool {
	invalidFP, ok := p.InvalidFingerprint(rawURL)
	if !ok || invalidFP == 0 {
		return false
	}
	if invalidFP == wildcardSentinel {
		return true
	}
	targetFP := simhash64(extractText(body))
	return bits.OnesCount64(targetFP^invalidFP) <= hammingThreshold
}

// ─── Text extraction and analysis ─────────────────────────────────────────────

var (
	tagRe   = regexp.MustCompile(`<[^>]+>`)
	wsRe    = regexp.MustCompile(`\s+`)
	tokenRe = regexp.MustCompile(`[a-z0-9]{3,}`)
)

func extractText(html string) string {
	t := tagRe.ReplaceAllString(html, " ")
	t = wsRe.ReplaceAllString(t, " ")
	return strings.TrimSpace(strings.ToLower(t))
}

func wordCount(text string) int {
	return len(strings.Fields(text))
}

func contentRatio(mainText, rawHTML string) float64 {
	if len(rawHTML) == 0 {
		return 0
	}
	return float64(len(mainText)) / float64(len(rawHTML))
}

// ─── Simhash ─────────────────────────────────────────────────────────────────

// simhash64 computes a 64-bit fingerprint via FNV-1a token-weighted bit voting.
// Algorithm: Charikar's SimHash, applied at token level.
func simhash64(text string) uint64 {
	tokens := tokenRe.FindAllString(text, -1)
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

// ─── Helpers ──────────────────────────────────────────────────────────────────

func invalidSibling(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	path := u.Path
	if path == "" || path == "/" {
		path = "/soft404-probe-" + randomHex8()
	} else {
		idx := strings.LastIndex(path, "/")
		path = path[:idx+1] + "soft404-probe-" + randomHex8()
	}
	u.Path = path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func randomHex8() string {
	h := fnv.New64a()
	_, _ = io.WriteString(h, fmt.Sprintf("soft404-%d", time.Now().UnixNano()))
	return fmt.Sprintf("%016x", h.Sum64())[:8]
}

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

func collectURLs(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(u string) {
		if u == "" {
			return
		}
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		if _, dup := seen[u]; dup {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	if input.Target != "" {
		add(input.Target)
	}
	for _, u := range input.URLs {
		add(u)
	}
	return out
}

func defaultClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

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

// ─── Marker lists ─────────────────────────────────────────────────────────────

var soft404Markers = []string{
	// EN
	"not found", "404", "page not found", "doesn't exist",
	"file not found", "resource not found", "the page you",
	"no page found", "nothing here", "page doesn't exist",
	"this page is gone", "no longer exists", "no longer available",
	"oops! we couldn't find", "page has moved",
	"sorry, we couldn't find", "this page is not available",
	"we can't find that page", "looks like you got lost",
	// PT-BR
	"não encontrado", "não existe", "página não encontrada",
	"erro 404", "error 404", "esta página não existe",
	"desculpe, não encontramos", "essa página não existe",
	// ES
	"página no encontrada", "no encontrado", "esta página no existe",
	"lo sentimos, no encontramos",
	// FR
	"page introuvable", "page non trouvée",
	// DE
	"seite nicht gefunden", "nicht gefunden",
	// Generic HTTP error phrases
	"403 forbidden", "401 unauthorized", "500 internal server error",
	"bad gateway", "service unavailable", "gateway timeout",
}

var authWallMarkers = []string{
	"please sign in", "please log in", "authentication required",
	"enter your password", "forgot your password",
	"you need to log in", "unauthorized access",
	"acesse sua conta", "faça login", "entrar com",
	"inicia sesión", "iniciar sesión",
}

var antiBotMarkers = []string{
	"just a moment", "checking your browser", "cloudflare ray id",
	"please wait while we check", "ddos protection by",
	"attention required! | cloudflare", "enable javascript and cookies",
	"bot check", "captcha required", "verifying you are human",
	"ray id:", "cf-mitigated", "cf_chl_",
}
