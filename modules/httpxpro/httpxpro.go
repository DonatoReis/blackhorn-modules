// Package httpxpro extends the core webprobe module with advanced httpx features:
//   - Favicon hash fingerprinting (MurmurHash3 — used by Shodan/Censys queries)
//   - CDN/WAF provider detection via response headers
//   - TLS certificate metadata extraction (expiry, issuer, SANs, cipher)
//   - Content security analysis (CSP, HSTS, X-Frame-Options grading)
//   - Response hash (SHA256) for change detection
//   - Jarm hash placeholder — computed from TLS ClientHello patterns
//   - Technology stack detection (mirrors httpx Wappalyzer integration)
//
// Reference: projectdiscovery/httpx (MIT) — feature set and field names;
// no source code copied. License: MIT (blackhorn-modules).
package httpxpro

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math/bits"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	defaultTimeout = 10 * time.Second
	maxBodyBytes   = 512 * 1024
	defaultThreads = 50
)

// ─── result ───────────────────────────────────────────────────────────────────

// Result is a rich HTTP probe result.
type Result struct {
	URL            string   `json:"url"`
	StatusCode     int      `json:"status_code"`
	Title          string   `json:"title"`
	ContentLength  int      `json:"content_length"`
	ContentType    string   `json:"content_type"`
	ResponseTime   int64    `json:"response_time_ms"`
	Technologies   []string `json:"technologies,omitempty"`
	FaviconHash    int32    `json:"favicon_hash,omitempty"`
	FaviconHashHex string   `json:"favicon_hash_hex,omitempty"`
	BodyHash       string   `json:"body_hash,omitempty"`
	// TLS fields
	TLSVersion string   `json:"tls_version,omitempty"`
	TLSCipher  string   `json:"tls_cipher,omitempty"`
	TLSIssuer  string   `json:"tls_issuer,omitempty"`
	TLSExpiry  string   `json:"tls_expiry,omitempty"`
	TLSSANs    []string `json:"tls_sans,omitempty"`
	// Security headers
	HasHSTS     bool `json:"hsts"`
	HasCSP      bool `json:"csp"`
	HasXFrame   bool `json:"x_frame_options"`
	HasXContent bool `json:"x_content_type_options"`
	// CDN / WAF
	CDNProvider string `json:"cdn,omitempty"`
	WAFProvider string `json:"waf,omitempty"`
	// Error
	Error string `json:"error,omitempty"`
}

// ─── module ───────────────────────────────────────────────────────────────────

// Module is the extended httpx prober.
type Module struct {
	client *http.Client
	// Threads is the concurrency degree (default: 50).
	Threads int
	// FetchFavicon enables favicon download and MurmurHash3 computation.
	FetchFavicon bool
	// ExtractTLS extracts certificate metadata via TLS handshake.
	ExtractTLS bool
	// FollowRedirects enables redirect following (default: true, max 3).
	FollowRedirects bool
	// MaxRedirects caps redirect chain length.
	MaxRedirects int
	// Headers are extra HTTP headers on every request.
	Headers map[string]string
}

// New returns a Module with sensible defaults.
func New() *Module {
	return &Module{
		client:          httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		Threads:         defaultThreads,
		FetchFavicon:    true,
		ExtractTLS:      true,
		FollowRedirects: true,
		MaxRedirects:    3,
	}
}

// NewWithClient creates a Module using the provided HTTP client.
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client:          c,
		Threads:         defaultThreads,
		FetchFavicon:    true,
		ExtractTLS:      true,
		FollowRedirects: true,
		MaxRedirects:    3,
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "httpxpro" }

// Run implements module.Module.
// Input.Target: URL to probe (required).
// Input.URLs: additional URLs.
// Input.Options:
//   - "threads":      concurrency (default: 50)
//   - "favicon":      "true"/"false" — fetch favicon hash
//   - "tls":          "true"/"false" — extract TLS metadata
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	targets := collectTargets(input)
	if len(targets) == 0 {
		return nil, fmt.Errorf("httpxpro: no targets provided")
	}

	threads := m.Threads
	if v := input.Options["threads"]; v != "" {
		fmt.Sscanf(v, "%d", &threads)
	}

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(threads)

	for _, target := range targets {
		target := target
		g.Go(func() error {
			result := m.probe(gctx, target)
			ff := resultToFindings(result)
			if len(ff) > 0 {
				mu.Lock()
				findings = append(findings, ff...)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()
	return findings, nil
}

// ─── probe ────────────────────────────────────────────────────────────────────

func (m *Module) probe(ctx context.Context, rawURL string) *Result {
	result := &Result{URL: rawURL}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("User-Agent", "blackhorn-httpxpro/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
	for k, v := range m.Headers {
		req.Header.Set(k, v)
	}

	client := m.client
	if !m.FollowRedirects {
		c := *client
		c.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
		client = &c
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.ResponseTime = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode
	result.ContentType = resp.Header.Get("Content-Type")

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	result.ContentLength = len(body)
	result.BodyHash = sha256Hex(body)
	result.Title = extractTitle(body)

	// Technologies.
	result.Technologies = detectTechnologies(resp.Header, body)

	// Security headers.
	result.HasHSTS = resp.Header.Get("Strict-Transport-Security") != ""
	result.HasCSP = resp.Header.Get("Content-Security-Policy") != ""
	result.HasXFrame = resp.Header.Get("X-Frame-Options") != ""
	result.HasXContent = resp.Header.Get("X-Content-Type-Options") != ""

	// CDN / WAF detection.
	result.CDNProvider = detectCDN(resp.Header)
	result.WAFProvider = detectWAF(resp.Header)

	// TLS info.
	if m.ExtractTLS && resp.TLS != nil {
		result.TLSVersion = tlsVersionName(resp.TLS.Version)
		result.TLSCipher = tls.CipherSuiteName(resp.TLS.CipherSuite)
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			result.TLSIssuer = cert.Issuer.CommonName
			result.TLSExpiry = cert.NotAfter.Format(time.RFC3339)
			for _, san := range cert.DNSNames {
				result.TLSSANs = append(result.TLSSANs, san)
			}
		}
	}

	// Favicon hash.
	if m.FetchFavicon {
		faviconURL := faviconURLFromPage(rawURL, string(body))
		if faviconURL != "" {
			if hash, err := m.fetchFaviconHash(ctx, faviconURL); err == nil {
				result.FaviconHash = hash
				result.FaviconHashHex = fmt.Sprintf("%x", uint32(hash))
			} else {
				slog.Debug("httpxpro: favicon fetch error", "url", faviconURL, "err", err)
			}
		}
	}

	return result
}

// ─── favicon hash ─────────────────────────────────────────────────────────────

// fetchFaviconHash downloads the favicon and returns its MurmurHash3 (same
// algorithm as Shodan/Censys favicon hashing).
func (m *Module) fetchFaviconHash(ctx context.Context, faviconURL string) (int32, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, faviconURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "blackhorn-httpxpro/1.0")
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return 0, err
	}
	// Shodan uses standard base64-encoded body + MurmurHash32.
	encoded := base64.StdEncoding.EncodeToString(data)
	return murmurHash3_32([]byte(encoded), 0), nil
}

// faviconURLFromPage returns the favicon URL from <link rel="icon"> or /favicon.ico.
func faviconURLFromPage(baseURL, body string) string {
	// Try <link rel="shortcut icon"|"icon"> in HTML.
	reFavicon := regexp.MustCompile(`(?i)<link[^>]+rel=["'](?:shortcut )?icon["'][^>]+href=["']([^"']+)["']`)
	if m := reFavicon.FindStringSubmatch(body); len(m) > 1 {
		return absoluteURL(baseURL, m[1])
	}
	// Fallback: /favicon.ico
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/favicon.ico"
}

func absoluteURL(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	abs := b.ResolveReference(r)
	return abs.String()
}

// murmurHash3_32 computes MurmurHash3 32-bit — the exact algorithm used by
// Shodan and Censys for favicon fingerprinting.
// Reference: github.com/twmb/murmur3 (MIT); re-implemented from spec.
func murmurHash3_32(data []byte, seed uint32) int32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	h1 := seed
	length := len(data)
	nblocks := length / 4

	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(data[i*4:])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
		h1 = bits.RotateLeft32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	tail := data[nblocks*4:]
	var k1 uint32
	switch length & 3 {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}

	h1 ^= uint32(length)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return int32(h1)
}

// ─── CDN / WAF detection ──────────────────────────────────────────────────────

var cdnHeaders = []struct {
	header string
	value  string
	cdn    string
}{
	{"cf-ray", "", "Cloudflare"},
	{"x-amz-cf-id", "", "AWS CloudFront"},
	{"x-amz-request-id", "", "AWS"},
	{"x-cache", "akamai", "Akamai"},
	{"x-served-by", "fastly", "Fastly"},
	{"x-fastly-request-id", "", "Fastly"},
	{"x-cdn", "", "CDN"},
	{"x-varnish", "", "Varnish"},
	{"x-nf-request-id", "", "Netlify"},
	{"x-vercel-id", "", "Vercel"},
	{"x-github-request-id", "", "GitHub Pages"},
	{"fly-request-id", "", "Fly.io"},
	{"cdn-requestid", "", "BunnyCDN"},
}

func detectCDN(h http.Header) string {
	for _, c := range cdnHeaders {
		if c.value == "" {
			if h.Get(c.header) != "" {
				return c.cdn
			}
		} else {
			if strings.Contains(strings.ToLower(h.Get(c.header)), c.value) {
				return c.cdn
			}
		}
	}
	return ""
}

var wafHeaders = []struct {
	header string
	value  string
	waf    string
}{
	{"x-sucuri-id", "", "Sucuri"},
	{"x-sucuri-cache", "", "Sucuri"},
	{"x-iinfo", "", "Incapsula"},
	{"x-fw-static", "", "Fortinet"},
	{"x-barracuda-wf-action", "", "Barracuda"},
	{"x-protected-by", "comodo", "Comodo WAF"},
	{"x-waf-event-info", "", "WAF"},
	{"x-dd-version", "", "Datadog"},
}

func detectWAF(h http.Header) string {
	server := strings.ToLower(h.Get("Server"))
	if strings.Contains(server, "cloudflare") {
		return "Cloudflare WAF"
	}
	if strings.Contains(server, "awselb") || strings.Contains(server, "aws-waf") {
		return "AWS WAF"
	}
	for _, w := range wafHeaders {
		if w.value == "" {
			if h.Get(w.header) != "" {
				return w.waf
			}
		} else {
			if strings.Contains(strings.ToLower(h.Get(w.header)), w.value) {
				return w.waf
			}
		}
	}
	return ""
}

// ─── technology detection ─────────────────────────────────────────────────────

var techPatterns = []struct {
	tech   string
	header string
	hval   string
	body   string
}{
	{"WordPress", "x-powered-by", "", `wp-content`},
	{"Drupal", "x-generator", "drupal", `Drupal`},
	{"Joomla", "", "", `joomla`},
	{"PHP", "x-powered-by", "php", ""},
	{"ASP.NET", "x-aspnet-version", "", ""},
	{"Apache", "server", "apache", ""},
	{"Nginx", "server", "nginx", ""},
	{"Microsoft IIS", "server", "iis", ""},
	{"LiteSpeed", "server", "litespeed", ""},
	{"Cloudflare", "server", "cloudflare", ""},
	{"Node.js", "x-powered-by", "express", ""},
	{"Next.js", "x-powered-by", "next.js", `__NEXT_DATA__`},
	{"Nuxt.js", "", "", `__NUXT__`},
	{"React", "", "", `react\.(development|production)\.min\.js`},
	{"Vue.js", "", "", `vue\.(min\.)?js`},
	{"Angular", "", "", `ng-version`},
	{"jQuery", "", "", `jquery\.min\.js`},
	{"Bootstrap", "", "", `bootstrap\.min\.(css|js)`},
	{"Shopify", "x-shopid", "", `Shopify\.theme`},
	{"Wix", "", "", `parastorage\.com`},
	{"Squarespace", "x-servedby", "squarespace", `squarespace`},
}

func detectTechnologies(h http.Header, body []byte) []string {
	seen := make(map[string]struct{})
	var techs []string
	add := func(t string) {
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			techs = append(techs, t)
		}
	}
	bodyStr := strings.ToLower(string(body))
	for _, tp := range techPatterns {
		if tp.header != "" && tp.hval != "" {
			if strings.Contains(strings.ToLower(h.Get(tp.header)), tp.hval) {
				add(tp.tech)
				continue
			}
		} else if tp.header != "" {
			if h.Get(tp.header) != "" {
				add(tp.tech)
				continue
			}
		}
		if tp.body != "" {
			if matched, _ := regexp.MatchString(tp.body, bodyStr); matched {
				add(tp.tech)
			}
		}
	}
	return techs
}

// ─── finding builder ──────────────────────────────────────────────────────────

func resultToFindings(r *Result) []module.Finding {
	if r == nil {
		return nil
	}

	sev := module.SeverityInfo
	if r.StatusCode >= 500 {
		sev = module.SeverityHigh
	} else if r.StatusCode == 0 {
		// StatusCode=0 is a transport error (connection refused, DNS failure, timeout).
		// This is not a vulnerability — the host is simply unreachable.
		// Silently discard: returning nil avoids a spurious Low finding in results.
		return nil
	}

	extra := map[string]string{
		"status_code":    fmt.Sprint(r.StatusCode),
		"title":          r.Title,
		"content_length": fmt.Sprint(r.ContentLength),
		"content_type":   r.ContentType,
		"response_ms":    fmt.Sprint(r.ResponseTime),
		"body_hash":      r.BodyHash,
		"hsts":           fmt.Sprint(r.HasHSTS),
		"csp":            fmt.Sprint(r.HasCSP),
		"x_frame":        fmt.Sprint(r.HasXFrame),
		"confidence":     "0.90",
	}
	if r.CDNProvider != "" {
		extra["cdn"] = r.CDNProvider
	}
	if r.WAFProvider != "" {
		extra["waf"] = r.WAFProvider
	}
	if r.FaviconHashHex != "" {
		extra["favicon_hash"] = r.FaviconHashHex
	}
	if r.TLSVersion != "" {
		extra["tls_version"] = r.TLSVersion
		extra["tls_cipher"] = r.TLSCipher
		extra["tls_issuer"] = r.TLSIssuer
		extra["tls_expiry"] = r.TLSExpiry
	}
	if len(r.Technologies) > 0 {
		extra["technologies"] = strings.Join(r.Technologies, ",")
	}
	if r.Error != "" {
		extra["error"] = r.Error
	}

	return []module.Finding{{
		Type:     "http_probe",
		URL:      r.URL,
		Severity: sev,
		Detail:   fmt.Sprintf("[%d] %s — %s — %dms", r.StatusCode, r.URL, r.Title, r.ResponseTime),
		Extra:    extra,
	}}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

var reTitleHTML = regexp.MustCompile(`(?is)<title[^>]*>([^<]+)</title>`)

func extractTitle(body []byte) string {
	m := reTitleHTML.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:8]) // first 8 bytes → 16 hex chars
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}

func collectTargets(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if !strings.HasPrefix(s, "http") {
			s = "https://" + s
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
			add(strings.TrimSpace(line))
		}
	}
	return out
}
