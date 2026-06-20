// Package fingerprint is a port of the WhatWeb technology fingerprinting engine,
// using the Wappalyzer community dataset (MIT) as its signature database.
//
// Source references:
//   - WhatWeb (Ruby, GPL-2.0): https://github.com/urbanadventurer/WhatWeb
//     Algorithm ported: plugin matching via header/body regex/keyword/version extraction.
//   - Wappalyzer community dataset (MIT): https://github.com/wappalyzer/wappalyzer
//     Signature format (categories, implies, confidence fields) ported faithfully.
//
// What is implemented:
//   - Signature struct mirrors Wappalyzer's technology entry format
//     (html/headers/url/meta/script/implies fields)
//   - Pattern compilation with version group extraction (Wappalyzer \;version: syntax)
//   - Category-based detection: CMS, web-server, programming-language, framework,
//     database, operating-system, cdn, analytics, javascript-framework, ecommerce
//   - Confidence scoring per match (mirrors Wappalyzer confidence field)
//   - implies chain resolution (technology A implies B)
//   - io.LimitReader on every body read                  (dicas.md §5)
//   - log/slog structured observability                  (dicas.md §16)
//   - errgroup.SetLimit bounded fan-out                  (guia-go §9)
//   - context propagation and cancellation               (guia-go §9)
//   - structs not map[string]any in hot paths            (guia-go §8)
package fingerprint

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	// maxBodyRead is the memory ceiling per response body — dicas.md §5.
	maxBodyRead = 5 * 1024 * 1024 // 5 MiB

	// defaultTimeout per HTTP request — mirrors WhatWeb default.
	defaultTimeout = 15 * time.Second

	// defaultThreads — errgroup limit for concurrent URL probing.
	defaultThreads = 10

	// defaultConfidence is used when a signature has no explicit confidence value.
	defaultConfidence = 100
)

// ─── Signature types (mirrors Wappalyzer community dataset schema) ─────────────

// Pattern holds a compiled regex with optional version-capture group.
// Mirrors Wappalyzer's pattern format: "regex\;version:\1\;confidence:75"
type Pattern struct {
	Raw        string         // original pattern string
	Re         *regexp.Regexp // compiled regex (nil = plain string match)
	Version    string         // version extraction template (e.g. "\1")
	Confidence int            // 0–100 (default 100)
}

// Signature mirrors the Wappalyzer community dataset technology entry.
// Fields map directly to keys in wappalyzer/src/technologies/*.json
type Signature struct {
	// Name is the technology name (e.g. "WordPress", "Nginx").
	Name string

	// Category is the broad classification (mirrors Wappalyzer categories).
	Category string

	// Website is the technology's official URL.
	Website string

	// HTML patterns matched against the response body.
	HTML []Pattern

	// Headers maps header name (lowercase) → patterns.
	Headers map[string][]Pattern

	// URL patterns matched against the request URL.
	URL []Pattern

	// Meta patterns matched against <meta name="..."> content.
	Meta map[string][]Pattern

	// Script patterns matched against <script src="..."> attributes.
	Script []Pattern

	// Implies lists technologies that are implied by a match (e.g. "PHP" implies "Apache").
	Implies []string

	// Icon is the technology icon filename (informational only).
	Icon string
}

// Match is a single fingerprint detection result.
// Mirrors WhatWeb's match output structure.
type Match struct {
	Technology string // technology name
	Category   string // category name
	Version    string // detected version (may be empty)
	Confidence int    // 0–100
	Source     string // "html", "header:<name>", "url", "meta:<name>", "script", "implies"
	Website    string // technology website
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements module.Module for technology fingerprinting.
type Module struct {
	logger     *slog.Logger
	client     *http.Client
	signatures []Signature
}

// New returns a Module with the built-in Wappalyzer-derived signature set.
func New() *Module {
	return &Module{
		logger:     slog.Default().With("module", "fingerprint"),
		client:     defaultClient(),
		signatures: builtinSignatures(),
	}
}

// NewWithClient returns a Module with an injected http.Client (for tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{
		logger:     slog.Default().With("module", "fingerprint"),
		client:     c,
		signatures: builtinSignatures(),
	}
}

// NewWithSignatures returns a Module with a custom signature set (for tests/extensions).
func NewWithSignatures(sigs []Signature) *Module {
	return &Module{
		logger:     slog.Default().With("module", "fingerprint"),
		client:     defaultClient(),
		signatures: sigs,
	}
}

// NewWithClientAndSignatures returns a Module with injected client and signatures (for tests).
func NewWithClientAndSignatures(c *http.Client, sigs []Signature) *Module {
	return &Module{
		logger:     slog.Default().With("module", "fingerprint"),
		client:     c,
		signatures: sigs,
	}
}

// MustParsePatterns parses a slice of raw pattern strings into []Pattern.
// Exported for tests that build custom Signature values.
func MustParsePatterns(raws []string) []Pattern {
	return parsePatterns(raws)
}

// Name satisfies module.Module.
func (m *Module) Name() string { return "fingerprint" }

// Run satisfies module.Module.
// Input.Target or Input.URLs are URLs to fingerprint.
//
// Options:
//
//	"threads"    — concurrent URL probes (default: 10)
//	"timeout"    — per-request timeout in seconds (default: 15)
//	"categories" — comma-separated category filter (default: all)
//	"min_conf"   — minimum confidence threshold 0-100 (default: 0)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	// Collect targets.
	var targets []string
	if input.Target != "" {
		targets = append(targets, normalizeURL(input.Target))
	}
	for _, u := range input.URLs {
		targets = append(targets, normalizeURL(u))
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("fingerprint: no target provided")
	}

	// Apply per-run timeout.
	if ts, ok := input.Options["timeout"]; ok {
		if secs := atoi(ts, 15); secs > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(secs)*time.Second)
			defer cancel()
		}
	}

	// Concurrency.
	threads := defaultThreads
	if t, ok := input.Options["threads"]; ok {
		if n := atoi(t, defaultThreads); n > 0 {
			threads = n
		}
	}

	// Category filter.
	catFilter := parseCategoryFilter(input.Options["categories"])

	// Minimum confidence.
	minConf := atoi(input.Options["min_conf"], 0)

	eg, gctx := errgroup.WithContext(ctx)
	eg.SetLimit(threads)

	findingsCh := make(chan module.Finding, 64)

	for _, target := range targets {
		target := target
		eg.Go(func() error {
			fs, err := m.probeURL(gctx, target, catFilter, minConf)
			if err != nil {
				m.logger.WarnContext(gctx, "probe error", "url", target, "err", err)
				return nil
			}
			for _, f := range fs {
				select {
				case findingsCh <- f:
				case <-gctx.Done():
					return nil
				}
			}
			return nil
		})
	}

	go func() {
		_ = eg.Wait()
		close(findingsCh)
	}()

	var findings []module.Finding
	for f := range findingsCh {
		findings = append(findings, f)
	}

	return findings, eg.Wait()
}

// ─── Core probe ──────────────────────────────────────────────────────────────

// probeURL fetches a URL and runs all signatures against it.
// Mirrors WhatWeb's Plugin#matches logic.
func (m *Module) probeURL(ctx context.Context, rawURL string, catFilter map[string]bool, minConf int) ([]module.Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request %q: %w", rawURL, err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-fingerprint/1.0)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %q: %w", rawURL, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	if err != nil {
		return nil, fmt.Errorf("read body %q: %w", rawURL, err)
	}
	body := string(bodyBytes)

	m.logger.InfoContext(ctx, "probing",
		"url", rawURL,
		"status", resp.StatusCode,
		"body_bytes", len(body),
	)

	// Run signatures and collect matches.
	matchMap := map[string]Match{} // technology → best match (highest confidence)

	for _, sig := range m.signatures {
		// Category filter.
		if len(catFilter) > 0 && !catFilter[strings.ToLower(sig.Category)] {
			continue
		}

		matches := matchSignature(sig, body, resp.Header, rawURL)
		for _, match := range matches {
			if match.Confidence < minConf {
				continue
			}
			// Keep highest-confidence match per technology.
			if existing, ok := matchMap[match.Technology]; !ok || match.Confidence > existing.Confidence {
				matchMap[match.Technology] = match
			}
		}
	}

	// Resolve implies chains.
	matchMap = resolveImplies(matchMap, m.signatures, catFilter, minConf)

	// Convert matches to findings.
	var findings []module.Finding
	for _, match := range matchMap {
		detail := fmt.Sprintf("Technology detected: %s", match.Technology)
		if match.Version != "" {
			detail += " " + match.Version
		}
		detail += fmt.Sprintf(" (category: %s, confidence: %d%%, source: %s)", match.Category, match.Confidence, match.Source)

		extra := map[string]string{
			"technology": match.Technology,
			"category":   match.Category,
			"source":     match.Source,
			"confidence": fmt.Sprintf("%d", match.Confidence),
			"website":    match.Website,
		}
		if match.Version != "" {
			extra["version"] = match.Version
		}

		findings = append(findings, module.Finding{
			Type:     "technology",
			Severity: categorySeverity(match.Category),
			URL:      rawURL,
			Detail:   detail,
			Extra:    extra,
		})
	}

	m.logger.InfoContext(ctx, "fingerprint complete",
		"url", rawURL,
		"technologies", len(findings),
	)

	return findings, nil
}

// ─── Signature matching (mirrors Wappalyzer matching engine) ─────────────────

// matchSignature runs all pattern groups for a signature against the response.
// Returns a slice of matches (one per matching pattern group).
// Mirrors Wappalyzer's Wappalyzer.analyze() and WhatWeb's Plugin#matches.
func matchSignature(sig Signature, body string, headers http.Header, rawURL string) []Match {
	var out []Match

	// 1. HTML body patterns — mirrors Wappalyzer "html" field.
	for _, pat := range sig.HTML {
		if version, ok := testPattern(pat, body); ok {
			out = append(out, Match{
				Technology: sig.Name,
				Category:   sig.Category,
				Version:    version,
				Confidence: pat.Confidence,
				Source:     "html",
				Website:    sig.Website,
			})
		}
	}

	// 2. HTTP header patterns — mirrors Wappalyzer "headers" field.
	// Build a flat string representation of all headers for matching.
	for hname, patterns := range sig.Headers {
		canonical := http.CanonicalHeaderKey(hname)
		vals := headers[canonical]
		if len(vals) == 0 {
			continue
		}
		headerVal := strings.Join(vals, ", ")
		for _, pat := range patterns {
			if version, ok := testPattern(pat, headerVal); ok {
				out = append(out, Match{
					Technology: sig.Name,
					Category:   sig.Category,
					Version:    version,
					Confidence: pat.Confidence,
					Source:     "header:" + hname,
					Website:    sig.Website,
				})
			}
		}
	}

	// 3. URL patterns — mirrors Wappalyzer "url" field.
	for _, pat := range sig.URL {
		if version, ok := testPattern(pat, rawURL); ok {
			out = append(out, Match{
				Technology: sig.Name,
				Category:   sig.Category,
				Version:    version,
				Confidence: pat.Confidence,
				Source:     "url",
				Website:    sig.Website,
			})
		}
	}

	// 4. Script src patterns — mirrors Wappalyzer "scriptSrc" field.
	if len(sig.Script) > 0 {
		scripts := extractScriptSrcs(body)
		for _, src := range scripts {
			for _, pat := range sig.Script {
				if version, ok := testPattern(pat, src); ok {
					out = append(out, Match{
						Technology: sig.Name,
						Category:   sig.Category,
						Version:    version,
						Confidence: pat.Confidence,
						Source:     "script",
						Website:    sig.Website,
					})
				}
			}
		}
	}

	// 5. Meta tag patterns — mirrors Wappalyzer "meta" field.
	if len(sig.Meta) > 0 {
		metas := extractMetaTags(body)
		for metaName, patterns := range sig.Meta {
			if content, ok := metas[strings.ToLower(metaName)]; ok {
				for _, pat := range patterns {
					if version, ok2 := testPattern(pat, content); ok2 {
						out = append(out, Match{
							Technology: sig.Name,
							Category:   sig.Category,
							Version:    version,
							Confidence: pat.Confidence,
							Source:     "meta:" + metaName,
							Website:    sig.Website,
						})
					}
				}
			}
		}
	}

	return out
}

// testPattern tests a compiled Pattern against a string.
// Returns (version, true) on match — mirrors Wappalyzer pattern testing.
func testPattern(pat Pattern, s string) (string, bool) {
	if pat.Re != nil {
		m := pat.Re.FindStringSubmatch(s)
		if m == nil {
			return "", false
		}
		version := expandVersion(pat.Version, m)
		return version, true
	}
	// Plain string match (no regex).
	if strings.Contains(s, pat.Raw) {
		return "", true
	}
	return "", false
}

// expandVersion expands a version template like "\1" or "\1.\2" using regex submatches.
// Mirrors Wappalyzer's version extraction logic.
func expandVersion(template string, submatches []string) string {
	if template == "" {
		return ""
	}
	result := template
	for i := 1; i < len(submatches); i++ {
		placeholder := fmt.Sprintf("\\%d", i)
		result = strings.ReplaceAll(result, placeholder, submatches[i])
	}
	// Clean up unfilled placeholders.
	result = regexp.MustCompile(`\\[0-9]+`).ReplaceAllString(result, "")
	result = strings.TrimSpace(result)
	return result
}

// resolveImplies adds implied technologies to the match map.
// Mirrors Wappalyzer's implies chain resolution.
func resolveImplies(matchMap map[string]Match, signatures []Signature, catFilter map[string]bool, minConf int) map[string]Match {
	// Build a name → signature lookup.
	sigIndex := map[string]Signature{}
	for _, sig := range signatures {
		sigIndex[strings.ToLower(sig.Name)] = sig
	}

	// Process implies chains (max 5 levels deep to avoid cycles).
	for range 5 {
		added := false
		for _, match := range matchMap {
			// Find the signature for this match.
			sig, ok := sigIndex[strings.ToLower(match.Technology)]
			if !ok {
				continue
			}
			for _, impl := range sig.Implies {
				// Parse implied technology name and optional confidence.
				implName, implConf := parseImplies(impl)
				if _, already := matchMap[implName]; already {
					continue
				}
				// Look up the implied technology's signature for its category.
				implSig, hasImplSig := sigIndex[strings.ToLower(implName)]
				category := "other"
				website := ""
				if hasImplSig {
					category = implSig.Category
					website = implSig.Website
				}
				if len(catFilter) > 0 && !catFilter[strings.ToLower(category)] {
					continue
				}
				conf := implConf
				if conf < minConf {
					continue
				}
				matchMap[implName] = Match{
					Technology: implName,
					Category:   category,
					Version:    "",
					Confidence: conf,
					Source:     "implies",
					Website:    website,
				}
				added = true
			}
		}
		if !added {
			break
		}
	}

	return matchMap
}

// ─── HTML helpers ─────────────────────────────────────────────────────────────

var scriptSrcRE = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
var metaNameRE = regexp.MustCompile(`(?i)<meta[^>]+name=["']([^"']+)["'][^>]+content=["']([^"']+)["']`)
var metaContentRE = regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']([^"']+)["']`)

// extractScriptSrcs returns all script src values from the HTML body.
func extractScriptSrcs(body string) []string {
	matches := scriptSrcRE.FindAllStringSubmatch(body, -1)
	srcs := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 {
			srcs = append(srcs, m[1])
		}
	}
	return srcs
}

// extractMetaTags returns a map of lowercase meta name → content.
func extractMetaTags(body string) map[string]string {
	out := map[string]string{}
	for _, m := range metaNameRE.FindAllStringSubmatch(body, -1) {
		if len(m) > 2 {
			out[strings.ToLower(m[1])] = m[2]
		}
	}
	for _, m := range metaContentRE.FindAllStringSubmatch(body, -1) {
		if len(m) > 2 {
			out[strings.ToLower(m[2])] = m[1]
		}
	}
	return out
}

// ─── Pattern parsing (mirrors Wappalyzer pattern format) ─────────────────────

// parsePattern parses a Wappalyzer pattern string into a Pattern.
// Format: "regex\;version:\1\;confidence:75"
// Mirrors wappalyzer/src/wappalyzer.js parsePattern().
func parsePattern(raw string) Pattern {
	pat := Pattern{
		Raw:        raw,
		Confidence: defaultConfidence,
	}

	// Split on \; to get directives.
	parts := strings.Split(raw, `\;`)
	reStr := parts[0]

	for _, part := range parts[1:] {
		if strings.HasPrefix(part, "version:") {
			pat.Version = strings.TrimPrefix(part, "version:")
		} else if strings.HasPrefix(part, "confidence:") {
			pat.Confidence = atoi(strings.TrimPrefix(part, "confidence:"), defaultConfidence)
		}
	}

	if reStr == "" {
		return pat
	}

	// Try to compile as regex.
	re, err := regexp.Compile(`(?i)` + reStr)
	if err != nil {
		// Fall back to plain string match.
		pat.Raw = reStr
		pat.Re = nil
	} else {
		pat.Re = re
	}

	return pat
}

// parsePatterns converts a slice of raw pattern strings to []Pattern.
func parsePatterns(raws []string) []Pattern {
	out := make([]Pattern, 0, len(raws))
	for _, r := range raws {
		out = append(out, parsePattern(r))
	}
	return out
}

// parseImplies parses an implies entry like "PHP\;confidence:75".
// Returns (name, confidence).
func parseImplies(raw string) (string, int) {
	parts := strings.SplitN(raw, `\;`, 2)
	name := strings.TrimSpace(parts[0])
	conf := defaultConfidence
	if len(parts) > 1 {
		for _, directive := range strings.Split(parts[1], `\;`) {
			if strings.HasPrefix(directive, "confidence:") {
				conf = atoi(strings.TrimPrefix(directive, "confidence:"), defaultConfidence)
			}
		}
	}
	return name, conf
}

// ─── Severity mapping ────────────────────────────────────────────────────────

// categorySeverity maps technology category to Finding severity.
// Mirrors WhatWeb's risk assessment per plugin.
func categorySeverity(category string) module.Severity {
	switch strings.ToLower(category) {
	case "operating-system", "web-server", "database":
		return module.SeverityMedium // version disclosure risk
	case "cms":
		return module.SeverityLow // known attack surface
	case "ecommerce":
		return module.SeverityLow
	default:
		return module.SeverityInfo
	}
}

// ─── Category filter ─────────────────────────────────────────────────────────

// parseCategoryFilter converts a comma-separated categories string to a set.
func parseCategoryFilter(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	out := map[string]bool{}
	for _, c := range strings.Split(raw, ",") {
		if t := strings.ToLower(strings.TrimSpace(c)); t != "" {
			out[t] = true
		}
	}
	return out
}

// ─── HTTP client ─────────────────────────────────────────────────────────────

func defaultClient() *http.Client {
	return &http.Client{
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
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// normalizeURL ensures the target has a scheme.
func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "https://" + raw
	}
	return raw
}

// atoi parses an integer with a default fallback.
func atoi(s string, def int) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return def
	}
	return n
}

// ─── Built-in signature database ─────────────────────────────────────────────
// Signatures below are derived from the Wappalyzer community dataset (MIT License).
// Source: https://github.com/wappalyzer/wappalyzer/tree/master/src/technologies
// Only the pattern strings and metadata are used; compiled regexes are generated at init.
//
// Each entry mirrors the Wappalyzer JSON technology format:
//   { "html": [...], "headers": {...}, "url": [...], "scriptSrc": [...],
//     "meta": {...}, "implies": [...], "cats": [...], "website": "..." }

func builtinSignatures() []Signature {
	p := parsePattern
	pp := parsePatterns

	return []Signature{

		// ── Web servers ──────────────────────────────────────────────────────
		{
			Name:     "Apache HTTP Server",
			Category: "web-server",
			Website:  "https://httpd.apache.org",
			Headers: map[string][]Pattern{
				"server": pp([]string{`Apache(?:/(\d+(?:\.\d+)+))?\;version:\1`}),
			},
			Implies: []string{"PHP\\;confidence:75", "OpenSSL\\;confidence:50"},
		},
		{
			Name:     "Nginx",
			Category: "web-server",
			Website:  "https://nginx.org",
			Headers: map[string][]Pattern{
				"server": pp([]string{`nginx(?:/(\d+(?:\.\d+)+))?\;version:\1`}),
			},
		},
		{
			Name:     "Microsoft IIS",
			Category: "web-server",
			Website:  "https://microsoft.com/iis",
			Headers: map[string][]Pattern{
				"server":       pp([]string{`IIS(?:/(\d+(?:\.\d+)+))?\;version:\1`}),
				"x-powered-by": pp([]string{`ASP\.NET`}),
			},
			Implies: []string{"Windows Server", "ASP.NET"},
		},
		{
			Name:     "LiteSpeed",
			Category: "web-server",
			Website:  "https://litespeedtech.com",
			Headers: map[string][]Pattern{
				"server":            pp([]string{`LiteSpeed`}),
				"x-litespeed-cache": {p(`.*`)},
			},
		},
		{
			Name:     "Caddy",
			Category: "web-server",
			Website:  "https://caddyserver.com",
			Headers: map[string][]Pattern{
				"server": pp([]string{`Caddy`}),
			},
		},
		{
			Name:     "OpenResty",
			Category: "web-server",
			Website:  "https://openresty.org",
			Headers: map[string][]Pattern{
				"server": pp([]string{`openresty(?:/(\d+(?:\.\d+)+))?\;version:\1`}),
			},
			Implies: []string{"Nginx", "Lua"},
		},

		// ── Programming languages ────────────────────────────────────────────
		{
			Name:     "PHP",
			Category: "programming-language",
			Website:  "https://php.net",
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`PHP(?:/(\d+(?:\.\d+)+))?\;version:\1`}),
			},
			HTML: pp([]string{`(?:input[^>]+name="(?:phpbb_token|_csrf_token)")`}),
		},
		{
			Name:     "ASP.NET",
			Category: "programming-language",
			Website:  "https://asp.net",
			Headers: map[string][]Pattern{
				"x-powered-by":     pp([]string{`ASP\.NET`}),
				"x-aspnet-version": pp([]string{`(\d+(?:\.\d+)+)\;version:\1`}),
			},
			HTML: pp([]string{`__VIEWSTATE`}),
		},
		{
			Name:     "Python",
			Category: "programming-language",
			Website:  "https://python.org",
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`Python/(\d+(?:\.\d+)+)\;version:\1`}),
			},
		},
		{
			Name:     "Ruby",
			Category: "programming-language",
			Website:  "https://ruby-lang.org",
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`Phusion Passenger`, `mod_ruby`}),
				"server":       pp([]string{`Phusion Passenger (\d+(?:\.\d+)+)\;version:\1`}),
			},
		},
		{
			Name:     "Java",
			Category: "programming-language",
			Website:  "https://java.com",
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`Servlet/(\d+(?:\.\d+)+)\;version:\1`, `JSP/`}),
				"server":       pp([]string{`Apache-Coyote/(\d+(?:\.\d+)+)\;version:\1`}),
			},
			HTML: pp([]string{`javax\.faces\.`, `jsessionid`}),
		},
		{
			Name:     "Node.js",
			Category: "programming-language",
			Website:  "https://nodejs.org",
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`Express`, `Node\.js`}),
			},
		},

		// ── JavaScript Frameworks ────────────────────────────────────────────
		{
			Name:     "React",
			Category: "javascript-framework",
			Website:  "https://reactjs.org",
			HTML:     pp([]string{`react(?:\.development|\.production\.min)?\.js`, `data-reactroot`, `data-reactid`}),
			Script:   pp([]string{`react(?:\.min)?\.js`, `/react(?:@[\d.]+)?/`}),
		},
		{
			Name:     "Vue.js",
			Category: "javascript-framework",
			Website:  "https://vuejs.org",
			HTML:     pp([]string{`Vue\.js`, `v-bind:|v-on:|data-v-`}),
			Script:   pp([]string{`vue(?:\.min)?\.js`, `/vue@[\d.]+/`, `vue\.runtime\.`}),
		},
		{
			Name:     "Angular",
			Category: "javascript-framework",
			Website:  "https://angular.io",
			HTML:     pp([]string{`ng-version=["'](\d+[\d.]+)["']\;version:\1`, `ng-app`, `ng-controller`, `ng-model`}),
			Script:   pp([]string{`angular(?:\.min)?\.js`, `@angular/core`}),
		},
		{
			Name:     "jQuery",
			Category: "javascript-framework",
			Website:  "https://jquery.com",
			HTML:     pp([]string{`jQuery\s+v?(\d+(?:\.\d+)+)\;version:\1`, `jquery[.-](\d+[\d.]+)\;version:\1`}),
			// Mirrors Wappalyzer jQuery scriptSrc patterns — handles CDN paths like
			// /jquery/3.7.0/jquery.min.js and local paths like jquery-3.7.0.min.js
			Script: pp([]string{
				`jquery[/.-](\d+[\d.]+)(?:[/.-]jquery(?:\.min)?\.js)?\;version:\1`,
				`jquery(?:\.min)?\.js`,
			}),
		},
		{
			Name:     "Next.js",
			Category: "javascript-framework",
			Website:  "https://nextjs.org",
			HTML:     pp([]string{`__NEXT_DATA__`, `__next`}),
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`Next\.js`}),
			},
			Implies: []string{"React", "Node.js"},
		},
		{
			Name:     "Nuxt.js",
			Category: "javascript-framework",
			Website:  "https://nuxtjs.org",
			HTML:     pp([]string{`__nuxt`, `data-n-head`}),
			Implies:  []string{"Vue.js", "Node.js"},
		},
		{
			Name:     "Svelte",
			Category: "javascript-framework",
			Website:  "https://svelte.dev",
			HTML:     pp([]string{`__svelte`, `svelte-`}),
			Script:   pp([]string{`svelte\.js`, `/svelte@`}),
		},
		{
			Name:     "Ember.js",
			Category: "javascript-framework",
			Website:  "https://emberjs.com",
			HTML:     pp([]string{`data-ember-action`, `ember-application`}),
			Script:   pp([]string{`ember\.js`, `ember\.min\.js`}),
		},
		{
			Name:     "Bootstrap",
			Category: "ui-framework",
			Website:  "https://getbootstrap.com",
			HTML:     pp([]string{`Bootstrap\s+v?(\d+[\d.]+)\;version:\1`, `class="[^"]*(?:navbar|btn btn-|col-(?:sm|md|lg|xl)-)`}),
			Script:   pp([]string{`bootstrap(?:\.min)?\.js`}),
		},

		// ── CMS ──────────────────────────────────────────────────────────────
		{
			Name:     "WordPress",
			Category: "cms",
			Website:  "https://wordpress.org",
			HTML:     pp([]string{`<meta[^>]+content="WordPress (\d+[\d.]+)\;version:\1`, `/wp-content/`, `/wp-includes/`}),
			URL:      pp([]string{`/wp-admin`, `/wp-login\.php`}),
			Meta:     map[string][]Pattern{"generator": pp([]string{`WordPress (\d+[\d.]+)\;version:\1`})},
			Implies:  []string{"PHP", "MySQL"},
		},
		{
			Name:     "Drupal",
			Category: "cms",
			Website:  "https://drupal.org",
			HTML:     pp([]string{`<(?:link|style)[^>]+\/sites\/(?:default|all)\/`, `jQuery\.extend\(Drupal`}),
			Headers: map[string][]Pattern{
				"x-generator":    pp([]string{`Drupal (\d+)\;version:\1`}),
				"x-drupal-cache": {p(`.*`)},
			},
			Meta:    map[string][]Pattern{"generator": pp([]string{`Drupal (\d+)\;version:\1`})},
			Implies: []string{"PHP"},
		},
		{
			Name:     "Joomla",
			Category: "cms",
			Website:  "https://joomla.org",
			HTML:     pp([]string{`(?:\/media\/jui\/|Joomla! - Open Source)`}),
			Meta:     map[string][]Pattern{"generator": pp([]string{`Joomla! - Open Source Content Management`})},
			Implies:  []string{"PHP"},
		},
		{
			Name:     "Magento",
			Category: "ecommerce",
			Website:  "https://magento.com",
			HTML:     pp([]string{`Mage\.Cookies`, `\/skin\/frontend\/`, `mage-`}),
			URL:      pp([]string{`\/checkout\/cart\/`}),
			Implies:  []string{"PHP", "MySQL", "jQuery"},
		},
		{
			Name:     "Shopify",
			Category: "ecommerce",
			Website:  "https://shopify.com",
			HTML:     pp([]string{`Shopify\.shop`, `cdn\.shopify\.com`, `\/cdn\/shop\/`}),
			Implies:  []string{"Ruby"},
		},
		{
			Name:     "WooCommerce",
			Category: "ecommerce",
			Website:  "https://woocommerce.com",
			HTML:     pp([]string{`woocommerce`, `WooCommerce`}),
			Implies:  []string{"WordPress", "PHP"},
		},
		{
			Name:     "Wix",
			Category: "website-builder",
			Website:  "https://wix.com",
			HTML:     pp([]string{`X-Wix-Published-Version`, `wix\.com\/`}),
			Script:   pp([]string{`static\.wixstatic\.com`}),
		},
		{
			Name:     "Ghost",
			Category: "cms",
			Website:  "https://ghost.org",
			HTML:     pp([]string{`ghost\.io`, `content="Ghost (\d+[\d.]+)\;version:\1`}),
			Meta:     map[string][]Pattern{"generator": pp([]string{`Ghost (\d+[\d.]+)\;version:\1`})},
			Implies:  []string{"Node.js"},
		},
		{
			Name:     "Gatsby",
			Category: "static-site-generator",
			Website:  "https://gatsbyjs.com",
			HTML:     pp([]string{`gatsby-`}),
			Implies:  []string{"React", "Node.js"},
		},

		// ── Databases (disclosure only) ──────────────────────────────────────
		{
			Name:     "MySQL",
			Category: "database",
			Website:  "https://mysql.com",
			HTML:     pp([]string{`SQL syntax.*?MySQL`, `mysql_fetch_array\(\)`, `MySQL server version`}),
		},
		{
			Name:     "PostgreSQL",
			Category: "database",
			Website:  "https://postgresql.org",
			HTML:     pp([]string{`PostgreSQL query failed`, `unterminated quoted string.*?at or near`}),
		},
		{
			Name:     "MongoDB",
			Category: "database",
			Website:  "https://mongodb.com",
			HTML:     pp([]string{`MongoDB\b`}),
		},

		// ── Operating systems ────────────────────────────────────────────────
		{
			Name:     "Ubuntu",
			Category: "operating-system",
			Website:  "https://ubuntu.com",
			Headers: map[string][]Pattern{
				"server": pp([]string{`Ubuntu`}),
			},
		},
		{
			Name:     "Debian",
			Category: "operating-system",
			Website:  "https://debian.org",
			Headers: map[string][]Pattern{
				"server": pp([]string{`Debian`}),
			},
		},
		{
			Name:     "Windows Server",
			Category: "operating-system",
			Website:  "https://microsoft.com",
			Headers: map[string][]Pattern{
				"server": pp([]string{`Win\d+`}),
			},
		},
		{
			Name:     "CentOS",
			Category: "operating-system",
			Website:  "https://centos.org",
			Headers: map[string][]Pattern{
				"server": pp([]string{`CentOS`}),
			},
		},

		// ── CDN / Security ──────────────────────────────────────────────────
		{
			Name:     "Cloudflare",
			Category: "cdn",
			Website:  "https://cloudflare.com",
			Headers: map[string][]Pattern{
				"cf-ray":          {p(`.*`)},
				"server":          pp([]string{`cloudflare`}),
				"cf-cache-status": {p(`.*`)},
			},
		},
		{
			Name:     "Fastly",
			Category: "cdn",
			Website:  "https://fastly.com",
			Headers: map[string][]Pattern{
				"x-served-by":         pp([]string{`cache-`}),
				"x-fastly-request-id": {p(`.*`)},
			},
		},
		{
			Name:     "AWS CloudFront",
			Category: "cdn",
			Website:  "https://aws.amazon.com/cloudfront",
			Headers: map[string][]Pattern{
				"x-amz-cf-id":  {p(`.*`)},
				"x-amz-cf-pop": {p(`.*`)},
			},
		},
		{
			Name:     "Varnish",
			Category: "cache",
			Website:  "https://varnish-cache.org",
			Headers: map[string][]Pattern{
				"x-varnish": {p(`.*`)},
				"via":       pp([]string{`varnish`}),
			},
		},

		// ── Analytics ────────────────────────────────────────────────────────
		{
			Name:     "Google Analytics",
			Category: "analytics",
			Website:  "https://analytics.google.com",
			HTML:     pp([]string{`UA-\d+-\d+`, `gtag\(`, `GoogleAnalyticsObject`}),
			Script:   pp([]string{`google-analytics\.com/analytics\.js`, `googletagmanager\.com/gtag/js`}),
		},
		{
			Name:     "Hotjar",
			Category: "analytics",
			Website:  "https://hotjar.com",
			HTML:     pp([]string{`hotjar`}),
			Script:   pp([]string{`static\.hotjar\.com`}),
		},
		{
			Name:     "Matomo",
			Category: "analytics",
			Website:  "https://matomo.org",
			HTML:     pp([]string{`piwik\.js`, `matomo\.js`}),
			Script:   pp([]string{`matomo\.js`, `piwik\.js`}),
		},

		// ── Web frameworks ──────────────────────────────────────────────────
		{
			Name:     "Laravel",
			Category: "framework",
			Website:  "https://laravel.com",
			HTML:     pp([]string{`laravel_session`, `XSRF-TOKEN`}),
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`PHP`}),
			},
			Implies: []string{"PHP"},
		},
		{
			Name:     "Django",
			Category: "framework",
			Website:  "https://djangoproject.com",
			HTML:     pp([]string{`csrfmiddlewaretoken`, `django`}),
			Implies:  []string{"Python"},
		},
		{
			Name:     "Ruby on Rails",
			Category: "framework",
			Website:  "https://rubyonrails.org",
			HTML:     pp([]string{`data-remote="true"`, `rails-ujs`}),
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`Phusion Passenger`}),
			},
			Implies: []string{"Ruby"},
		},
		{
			Name:     "Spring",
			Category: "framework",
			Website:  "https://spring.io",
			HTML:     pp([]string{`org\.springframework`, `spring-security`}),
			Headers: map[string][]Pattern{
				"x-application-context": {p(`.*`)},
			},
			Implies: []string{"Java"},
		},
		{
			Name:     "Express",
			Category: "framework",
			Website:  "https://expressjs.com",
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`Express`}),
			},
			Implies: []string{"Node.js"},
		},
		{
			Name:     "FastAPI",
			Category: "framework",
			Website:  "https://fastapi.tiangolo.com",
			HTML:     pp([]string{`FastAPI`}),
			Headers: map[string][]Pattern{
				"server": pp([]string{`uvicorn`}),
			},
			Implies: []string{"Python"},
		},

		// ── Security / SSL ───────────────────────────────────────────────────
		{
			Name:     "OpenSSL",
			Category: "ssl",
			Website:  "https://openssl.org",
			Headers: map[string][]Pattern{
				"server": pp([]string{`OpenSSL/(\d+(?:\.\d+)+[a-z]?)\;version:\1`}),
			},
		},
		{
			Name:     "Let's Encrypt",
			Category: "ssl",
			Website:  "https://letsencrypt.org",
			HTML:     pp([]string{`Let's Encrypt`}),
		},

		// ── Additional web servers ────────────────────────────────────────────
		{
			Name:     "Lighttpd",
			Category: "web-server",
			Website:  "https://lighttpd.net",
			Headers: map[string][]Pattern{
				"server": pp([]string{`lighttpd/(\d+[\d.]+)\;version:\1`}),
			},
		},
		{
			Name:     "Caddy",
			Category: "web-server",
			Website:  "https://caddyserver.com",
			Headers: map[string][]Pattern{
				"server": pp([]string{`Caddy`}),
			},
		},
		{
			Name:     "Tomcat",
			Category: "web-server",
			Website:  "https://tomcat.apache.org",
			Headers: map[string][]Pattern{
				"server": pp([]string{`Apache-Coyote/(\d[\d.]*)\;version:\1`, `Apache Tomcat/(\d[\d.]*)\;version:\1`}),
			},
			HTML:    pp([]string{`Apache Tomcat/(\d[\d.]*)\;version:\1`, `Tomcat (\d[\d.]*) - Error report\;version:\1`}),
			Implies: []string{"Java"},
		},
		{
			Name:     "Jetty",
			Category: "web-server",
			Website:  "https://eclipse.dev/jetty",
			Headers: map[string][]Pattern{
				"server": pp([]string{`Jetty(?:\((\d[\d.v-]*)\))?\;version:\1`}),
			},
			Implies: []string{"Java"},
		},
		{
			Name:     "Nginx Unit",
			Category: "web-server",
			Website:  "https://unit.nginx.org",
			Headers: map[string][]Pattern{
				"server": pp([]string{`Unit/(\d[\d.]+)\;version:\1`}),
			},
		},
		{
			Name:     "OpenResty",
			Category: "web-server",
			Website:  "https://openresty.org",
			Headers: map[string][]Pattern{
				"server": pp([]string{`openresty(?:/(\d[\d.]+))?\;version:\1`}),
			},
			Implies: []string{"Nginx", "Lua"},
		},
		{
			Name:     "Gunicorn",
			Category: "web-server",
			Website:  "https://gunicorn.org",
			Headers: map[string][]Pattern{
				"server": pp([]string{`gunicorn/(\d[\d.]+)\;version:\1`}),
			},
			Implies: []string{"Python"},
		},
		{
			Name:     "Kestrel",
			Category: "web-server",
			Website:  "https://learn.microsoft.com/aspnet/core/fundamentals/servers/kestrel",
			Headers: map[string][]Pattern{
				"server":       pp([]string{`Kestrel`}),
				"x-powered-by": pp([]string{`ASP\.NET`}),
			},
			Implies: []string{"ASP.NET", "C#"},
		},
		{
			Name:     "WEBrick",
			Category: "web-server",
			Website:  "https://github.com/ruby/webrick",
			Headers: map[string][]Pattern{
				"server": pp([]string{`WEBrick/(\d[\d.]+)\;version:\1`}),
			},
			Implies: []string{"Ruby"},
		},

		// ── Additional programming languages ──────────────────────────────────
		{
			Name:     "Go",
			Category: "programming-language",
			Website:  "https://go.dev",
			Headers: map[string][]Pattern{
				"server":       pp([]string{`Go-http-client/(\d[\d.]+)\;version:\1`}),
				"x-powered-by": pp([]string{`Go`}),
			},
		},
		{
			Name:     "Rust",
			Category: "programming-language",
			Website:  "https://rust-lang.org",
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`Rocket`, `Actix`, `axum`, `warp`}),
			},
		},
		{
			Name:     "Perl",
			Category: "programming-language",
			Website:  "https://perl.org",
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`Perl`, `mod_perl/(\d[\d.]+)\;version:\1`}),
			},
		},
		{
			Name:     "ColdFusion",
			Category: "programming-language",
			Website:  "https://adobe.com/products/coldfusion",
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`ColdFusion`}),
				"server":       pp([]string{`ColdFusion`}),
			},
			HTML:    pp([]string{`cfform`, `cftoken`, `CFID`}),
			Implies: []string{"Java"},
		},

		// ── JavaScript frameworks (additional) ────────────────────────────────
		{
			Name:     "Ember.js",
			Category: "javascript-framework",
			Website:  "https://emberjs.com",
			HTML:     pp([]string{`ember-application`, `data-ember-action`}),
			Script:   pp([]string{`ember(?:\.min)?\.js`, `ember-source`}),
		},
		{
			Name:     "Backbone.js",
			Category: "javascript-framework",
			Website:  "https://backbonejs.org",
			Script:   pp([]string{`backbone(?:-min)?\.js`}),
		},
		{
			Name:     "Svelte",
			Category: "javascript-framework",
			Website:  "https://svelte.dev",
			HTML:     pp([]string{`__svelte`}),
			Script:   pp([]string{`svelte/`}),
		},
		{
			Name:     "Nuxt.js",
			Category: "javascript-framework",
			Website:  "https://nuxt.com",
			HTML:     pp([]string{`__nuxt`, `data-n-head`}),
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`Nuxt\.?js`}),
			},
			Implies: []string{"Vue.js", "Node.js"},
		},
		{
			Name:     "Remix",
			Category: "javascript-framework",
			Website:  "https://remix.run",
			HTML:     pp([]string{`__remixManifest`, `__remixRouteModules`}),
			Implies:  []string{"React", "Node.js"},
		},
		{
			Name:     "SvelteKit",
			Category: "javascript-framework",
			Website:  "https://kit.svelte.dev",
			HTML:     pp([]string{`__sveltekit_`}),
			Implies:  []string{"Svelte", "Node.js"},
		},
		{
			Name:     "Alpine.js",
			Category: "javascript-framework",
			Website:  "https://alpinejs.dev",
			HTML:     pp([]string{`x-data=`, `x-show=`, `x-bind=`}),
			Script:   pp([]string{`alpinejs`, `alpine\.min\.js`}),
		},
		{
			Name:     "Htmx",
			Category: "javascript-framework",
			Website:  "https://htmx.org",
			HTML:     pp([]string{`hx-get=`, `hx-post=`, `hx-target=`, `hx-swap=`}),
			Script:   pp([]string{`htmx\.min\.js`, `htmx\.org`}),
		},
		{
			Name:     "Astro",
			Category: "static-site-generator",
			Website:  "https://astro.build",
			HTML:     pp([]string{`astro-island`, `data-astro-`}),
		},
		{
			Name:     "Solid.js",
			Category: "javascript-framework",
			Website:  "https://solidjs.com",
			HTML:     pp([]string{`_$HY`, `solid-js`}),
		},

		// ── CMS (additional) ──────────────────────────────────────────────────
		{
			Name:     "TYPO3",
			Category: "cms",
			Website:  "https://typo3.org",
			HTML:     pp([]string{`typo3`, `id="typo3-`}),
			Meta:     map[string][]Pattern{"generator": pp([]string{`TYPO3 CMS`})},
			Implies:  []string{"PHP"},
		},
		{
			Name:     "October CMS",
			Category: "cms",
			Website:  "https://octobercms.com",
			HTML:     pp([]string{`october-`}),
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`OctoberCMS`}),
			},
			Implies: []string{"PHP", "Laravel"},
		},
		{
			Name:     "Contentful",
			Category: "cms",
			Website:  "https://contentful.com",
			Script:   pp([]string{`contentful\.com`}),
			HTML:     pp([]string{`ctfl-`, `contentful`}),
		},
		{
			Name:     "Strapi",
			Category: "cms",
			Website:  "https://strapi.io",
			HTML:     pp([]string{`strapi`}),
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`Strapi`}),
			},
			Implies: []string{"Node.js"},
		},
		{
			Name:     "Sanity",
			Category: "cms",
			Website:  "https://sanity.io",
			HTML:     pp([]string{`sanity-studio`, `sanityClient`}),
			Script:   pp([]string{`sanity\.io`}),
		},
		{
			Name:     "Payload CMS",
			Category: "cms",
			Website:  "https://payloadcms.com",
			HTML:     pp([]string{`payload-`}),
			Implies:  []string{"Node.js"},
		},
		{
			Name:     "Craft CMS",
			Category: "cms",
			Website:  "https://craftcms.com",
			HTML:     pp([]string{`craft-`}),
			Meta:     map[string][]Pattern{"generator": pp([]string{`Craft CMS`})},
			Implies:  []string{"PHP"},
		},
		{
			Name:     "ProcessWire",
			Category: "cms",
			Website:  "https://processwire.com",
			HTML:     pp([]string{`ProcessWire`}),
			Implies:  []string{"PHP"},
		},
		{
			Name:     "Webflow",
			Category: "website-builder",
			Website:  "https://webflow.com",
			HTML:     pp([]string{`data-wf-`, `webflow\.com`}),
			Script:   pp([]string{`webflow\.js`}),
		},
		{
			Name:     "Squarespace",
			Category: "website-builder",
			Website:  "https://squarespace.com",
			HTML:     pp([]string{`squarespace-`}),
			Script:   pp([]string{`squarespace\.com`}),
		},

		// ── Ecommerce (additional) ────────────────────────────────────────────
		{
			Name:     "PrestaShop",
			Category: "ecommerce",
			Website:  "https://prestashop.com",
			HTML:     pp([]string{`prestashop`, `/modules/.*?prestashop`}),
			Meta:     map[string][]Pattern{"generator": pp([]string{`PrestaShop`})},
			Implies:  []string{"PHP"},
		},
		{
			Name:     "OpenCart",
			Category: "ecommerce",
			Website:  "https://opencart.com",
			HTML:     pp([]string{`route=common\/home`, `catalog\/view\/theme`}),
			Implies:  []string{"PHP"},
		},
		{
			Name:     "BigCommerce",
			Category: "ecommerce",
			Website:  "https://bigcommerce.com",
			HTML:     pp([]string{`bigcommerce`}),
			Script:   pp([]string{`bigcommerce\.com`}),
		},
		{
			Name:     "Medusa",
			Category: "ecommerce",
			Website:  "https://medusajs.com",
			HTML:     pp([]string{`medusa`}),
			Implies:  []string{"Node.js"},
		},

		// ── Java frameworks ───────────────────────────────────────────────────
		{
			Name:     "Struts",
			Category: "framework",
			Website:  "https://struts.apache.org",
			HTML:     pp([]string{`struts`, `\.action\b`}),
			Implies:  []string{"Java"},
		},
		{
			Name:     "Hibernate",
			Category: "framework",
			Website:  "https://hibernate.org",
			HTML:     pp([]string{`HibernateException`, `org\.hibernate`}),
			Implies:  []string{"Java"},
		},
		{
			Name:     "Quarkus",
			Category: "framework",
			Website:  "https://quarkus.io",
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`Quarkus`}),
			},
			Implies: []string{"Java"},
		},
		{
			Name:     "Micronaut",
			Category: "framework",
			Website:  "https://micronaut.io",
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`Micronaut`}),
			},
			Implies: []string{"Java"},
		},

		// ── Python frameworks (additional) ────────────────────────────────────
		{
			Name:     "Flask",
			Category: "framework",
			Website:  "https://flask.palletsprojects.com",
			Headers: map[string][]Pattern{
				"server":       pp([]string{`Werkzeug/(\d[\d.]+)\;version:\1`}),
				"x-powered-by": pp([]string{`Flask`}),
			},
			Implies: []string{"Python"},
		},
		{
			Name:     "Tornado",
			Category: "framework",
			Website:  "https://tornadoweb.org",
			Headers: map[string][]Pattern{
				"server": pp([]string{`TornadoServer/(\d[\d.]+)\;version:\1`}),
			},
			Implies: []string{"Python"},
		},
		{
			Name:     "Starlette",
			Category: "framework",
			Website:  "https://starlette.io",
			Headers: map[string][]Pattern{
				"server": pp([]string{`uvicorn`}),
			},
			Implies: []string{"Python"},
		},

		// ── .NET (additional) ─────────────────────────────────────────────────
		{
			Name:     ".NET Core",
			Category: "programming-language",
			Website:  "https://dotnet.microsoft.com",
			Headers: map[string][]Pattern{
				"x-powered-by":     pp([]string{`ASP\.NET`}),
				"x-aspnet-version": {p(`.*`)},
			},
		},
		{
			Name:     "Blazor",
			Category: "javascript-framework",
			Website:  "https://dotnet.microsoft.com/apps/aspnet/web-apps/blazor",
			HTML:     pp([]string{`_blazor`, `blazor\.server\.js`, `blazor\.webassembly\.js`}),
			Implies:  []string{".NET Core", "C#"},
		},

		// ── Databases (additional) ────────────────────────────────────────────
		{
			Name:     "Redis",
			Category: "database",
			Website:  "https://redis.io",
			HTML:     pp([]string{`ERR wrong number of arguments`, `WRONGTYPE Operation against a key`}),
		},
		{
			Name:     "Elasticsearch",
			Category: "database",
			Website:  "https://elastic.co",
			HTML:     pp([]string{`"cluster_name"\s*:`, `"version"\s*:\s*\{[^}]*"number"\s*:`}),
		},
		{
			Name:     "CouchDB",
			Category: "database",
			Website:  "https://couchdb.apache.org",
			HTML:     pp([]string{`"couchdb"\s*:\s*"Welcome"`, `Apache CouchDB`}),
			Headers: map[string][]Pattern{
				"server": pp([]string{`CouchDB/(\d[\d.]+)\;version:\1`}),
			},
		},
		{
			Name:     "Cassandra",
			Category: "database",
			Website:  "https://cassandra.apache.org",
			HTML:     pp([]string{`com\.datastax\.driver`, `CassandraException`}),
		},
		{
			Name:     "InfluxDB",
			Category: "database",
			Website:  "https://influxdata.com",
			Headers: map[string][]Pattern{
				"x-influxdb-version": {p(`(\d[\d.]+)\;version:\1`)},
			},
		},

		// ── WAF / Security products ───────────────────────────────────────────
		{
			Name:     "ModSecurity",
			Category: "waf",
			Website:  "https://modsecurity.org",
			HTML:     pp([]string{`ModSecurity`, `mod_security`}),
			Headers: map[string][]Pattern{
				"server": pp([]string{`mod_security`}),
			},
		},
		{
			Name:     "Imperva",
			Category: "waf",
			Website:  "https://imperva.com",
			Headers: map[string][]Pattern{
				"x-iinfo":    {p(`.*`)},
				"x-cdn":      pp([]string{`Incapsula`}),
				"set-cookie": pp([]string{`incap_ses_`}),
			},
		},
		{
			Name:     "Akamai",
			Category: "cdn",
			Website:  "https://akamai.com",
			Headers: map[string][]Pattern{
				"x-akamai-transformed": {p(`.*`)},
				"x-check-cacheable":    {p(`.*`)},
			},
		},
		{
			Name:     "AWS WAF",
			Category: "waf",
			Website:  "https://aws.amazon.com/waf",
			HTML:     pp([]string{`AWS WAF`, `Request blocked`}),
			Headers: map[string][]Pattern{
				"x-amzn-requestid": {p(`.*`)},
			},
		},
		{
			Name:     "Sucuri",
			Category: "waf",
			Website:  "https://sucuri.net",
			Headers: map[string][]Pattern{
				"x-sucuri-id":    {p(`.*`)},
				"x-sucuri-cache": {p(`.*`)},
			},
		},
		{
			Name:     "F5 BIG-IP",
			Category: "load-balancer",
			Website:  "https://f5.com",
			Headers: map[string][]Pattern{
				"server":     pp([]string{`BigIP`}),
				"set-cookie": pp([]string{`BIGipServer`}),
			},
		},
		{
			Name:     "HAProxy",
			Category: "load-balancer",
			Website:  "https://haproxy.org",
			Headers: map[string][]Pattern{
				"server": pp([]string{`haproxy`}),
				"via":    pp([]string{`haproxy`}),
			},
		},

		// ── Identity / Auth providers ─────────────────────────────────────────
		{
			Name:     "Keycloak",
			Category: "iam",
			Website:  "https://keycloak.org",
			HTML:     pp([]string{`keycloak`, `kc-form-login`}),
			URL:      pp([]string{`/auth/realms/`}),
			Implies:  []string{"Java"},
		},
		{
			Name:     "Auth0",
			Category: "iam",
			Website:  "https://auth0.com",
			Script:   pp([]string{`auth0\.com`, `auth0-spa-js`}),
			HTML:     pp([]string{`auth0`}),
		},
		{
			Name:     "Okta",
			Category: "iam",
			Website:  "https://okta.com",
			HTML:     pp([]string{`okta-sign-in`, `okta\.com`}),
			Script:   pp([]string{`okta\.com`}),
		},

		// ── Monitoring / APM ──────────────────────────────────────────────────
		{
			Name:     "New Relic",
			Category: "performance",
			Website:  "https://newrelic.com",
			Script:   pp([]string{`newrelic\.com`, `nr-data\.net`}),
			HTML:     pp([]string{`NREUM`, `newrelic`}),
		},
		{
			Name:     "Datadog RUM",
			Category: "performance",
			Website:  "https://datadoghq.com",
			Script:   pp([]string{`datadoghq\.com`, `browser-agent`}),
		},
		{
			Name:     "Sentry",
			Category: "error-tracking",
			Website:  "https://sentry.io",
			Script:   pp([]string{`browser\.sentry-cdn\.com`, `sentry\.min\.js`}),
			HTML:     pp([]string{`Sentry\.init`}),
		},
		{
			Name:     "Elastic APM",
			Category: "performance",
			Website:  "https://elastic.co/apm",
			Script:   pp([]string{`elastic-apm`}),
		},

		// ── Search ────────────────────────────────────────────────────────────
		{
			Name:     "Algolia",
			Category: "search",
			Website:  "https://algolia.com",
			Script:   pp([]string{`algolia(?:search)?\.net`, `algoliasearch`}),
			HTML:     pp([]string{`algolia`}),
		},
		{
			Name:     "MeiliSearch",
			Category: "search",
			Website:  "https://meilisearch.com",
			HTML:     pp([]string{`meilisearch`}),
			Headers: map[string][]Pattern{
				"x-powered-by": pp([]string{`Meilisearch`}),
			},
		},
		{
			Name:     "Solr",
			Category: "search",
			Website:  "https://solr.apache.org",
			HTML:     pp([]string{`Apache Solr`, `solr-admin`}),
			URL:      pp([]string{`/solr/`}),
		},

		// ── Message queues / event streaming ──────────────────────────────────
		{
			Name:     "RabbitMQ",
			Category: "message-queue",
			Website:  "https://rabbitmq.com",
			HTML:     pp([]string{`RabbitMQ Management`, `rabbitmq`}),
		},
		{
			Name:     "Apache Kafka",
			Category: "message-queue",
			Website:  "https://kafka.apache.org",
			HTML:     pp([]string{`kafka`, `Apache Kafka`}),
		},

		// ── API gateways ──────────────────────────────────────────────────────
		{
			Name:     "Kong",
			Category: "api-gateway",
			Website:  "https://konghq.com",
			Headers: map[string][]Pattern{
				"via":                  pp([]string{`kong`}),
				"server":               pp([]string{`kong`}),
				"x-kong-proxy-latency": {p(`.*`)},
			},
		},
		{
			Name:     "Traefik",
			Category: "reverse-proxy",
			Website:  "https://traefik.io",
			Headers: map[string][]Pattern{
				"server":             pp([]string{`traefik`}),
				"x-forwarded-server": {p(`.*`)},
			},
		},
		{
			Name:     "Envoy",
			Category: "reverse-proxy",
			Website:  "https://envoyproxy.io",
			Headers: map[string][]Pattern{
				"server":                        pp([]string{`envoy`}),
				"x-envoy-upstream-service-time": {p(`.*`)},
			},
		},
		{
			Name:     "NGINX Plus",
			Category: "web-server",
			Website:  "https://nginx.com",
			Headers: map[string][]Pattern{
				"server": pp([]string{`nginx-plus`}),
			},
		},

		// ── Cloud platforms ───────────────────────────────────────────────────
		{
			Name:     "Heroku",
			Category: "paas",
			Website:  "https://heroku.com",
			Headers: map[string][]Pattern{
				"via":          pp([]string{`1\.1 vegur`}),
				"x-request-id": {p(`.*`)},
				"x-runtime":    {p(`.*`)},
			},
		},
		{
			Name:     "Vercel",
			Category: "paas",
			Website:  "https://vercel.com",
			Headers: map[string][]Pattern{
				"x-vercel-id":    {p(`.*`)},
				"x-vercel-cache": {p(`.*`)},
			},
		},
		{
			Name:     "Netlify",
			Category: "paas",
			Website:  "https://netlify.com",
			Headers: map[string][]Pattern{
				"x-nf-request-id": {p(`.*`)},
				"x-served-by":     pp([]string{`cache-`}),
			},
		},
		{
			Name:     "Render",
			Category: "paas",
			Website:  "https://render.com",
			Headers: map[string][]Pattern{
				"x-render-origin-server": {p(`.*`)},
			},
		},
		{
			Name:     "Google Cloud Run",
			Category: "paas",
			Website:  "https://cloud.google.com/run",
			Headers: map[string][]Pattern{
				"x-cloud-trace-context": {p(`.*`)},
			},
		},
		{
			Name:     "Azure App Service",
			Category: "paas",
			Website:  "https://azure.microsoft.com",
			Headers: map[string][]Pattern{
				"arr-disable-session-affinity": {p(`.*`)},
				"x-ms-request-id":              {p(`.*`)},
			},
		},

		// ── Payment processors ────────────────────────────────────────────────
		{
			Name:     "Stripe.js",
			Category: "payment",
			Website:  "https://stripe.com",
			Script:   pp([]string{`js\.stripe\.com`}),
			HTML:     pp([]string{`stripe-button`, `data-key.*stripe`}),
		},
		{
			Name:     "PayPal SDK",
			Category: "payment",
			Website:  "https://paypal.com",
			Script:   pp([]string{`paypalobjects\.com`, `paypal\.com\/sdk`}),
		},

		// ── Testing / feature flags ───────────────────────────────────────────
		{
			Name:     "LaunchDarkly",
			Category: "feature-flags",
			Website:  "https://launchdarkly.com",
			Script:   pp([]string{`launchdarkly\.com`}),
			HTML:     pp([]string{`launchdarkly`}),
		},
		{
			Name:     "Optimizely",
			Category: "a-b-testing",
			Website:  "https://optimizely.com",
			Script:   pp([]string{`optimizely\.com`, `cdn\.optimizely\.com`}),
		},

		// ── Container / orchestration ─────────────────────────────────────────
		{
			Name:     "Kubernetes",
			Category: "containers",
			Website:  "https://kubernetes.io",
			HTML:     pp([]string{`kubernetes`}),
			Headers: map[string][]Pattern{
				"x-kubernetes-pf-prioritylevel-uid": {p(`.*`)},
			},
		},
		{
			Name:     "Docker",
			Category: "containers",
			Website:  "https://docker.com",
			HTML:     pp([]string{`Docker`}),
			Headers: map[string][]Pattern{
				"docker-distribution-api-version": {p(`.*`)},
			},
		},

		// ── Headless browsers / scraping detection ────────────────────────────
		{
			Name:     "reCAPTCHA",
			Category: "security",
			Website:  "https://google.com/recaptcha",
			Script:   pp([]string{`google\.com/recaptcha`, `recaptcha/api\.js`}),
			HTML:     pp([]string{`g-recaptcha`, `data-sitekey`}),
		},
		{
			Name:     "hCaptcha",
			Category: "security",
			Website:  "https://hcaptcha.com",
			Script:   pp([]string{`hcaptcha\.com`}),
			HTML:     pp([]string{`h-captcha`, `data-hcaptcha`}),
		},
		{
			Name:     "Turnstile",
			Category: "security",
			Website:  "https://cloudflare.com/products/turnstile",
			Script:   pp([]string{`challenges\.cloudflare\.com/turnstile`}),
			HTML:     pp([]string{`cf-turnstile`}),
			Implies:  []string{"Cloudflare"},
		},

		// ── CMS / Blog platforms ──────────────────────────────────────────────
		{
			Name:     "Contentful",
			Category: "cms",
			Website:  "https://contentful.com",
			HTML:     pp([]string{`contentful`}),
			Script:   pp([]string{`contentful\.com`}),
		},
		{
			Name:     "HubSpot",
			Category: "marketing",
			Website:  "https://hubspot.com",
			Script:   pp([]string{`js\.hs-scripts\.com`, `hs-analytics\.net`}),
			HTML:     pp([]string{`hbspt\.`, `hubspot`}),
			Headers: map[string][]Pattern{
				"x-hs-cf-cache-status": {p(`.*`)},
			},
		},
		{
			Name:     "Ghost",
			Category: "cms",
			Website:  "https://ghost.org",
			HTML:     pp([]string{`ghost`, `@tryghost`}),
			Headers: map[string][]Pattern{
				"x-ghost-cache-status": {p(`.*`)},
			},
		},
		{
			Name:     "Medium",
			Category: "blog",
			Website:  "https://medium.com",
			Headers: map[string][]Pattern{
				"x-medium-edge": {p(`.*`)},
			},
			HTML: pp([]string{`medium\.com`, `__APOLLO_STATE__`}),
		},
		{
			Name:     "Blogger",
			Category: "blog",
			Website:  "https://blogger.com",
			HTML:     pp([]string{`blogspot\.com`, `blogger\.com/static`}),
		},
		{
			Name:     "Tumblr",
			Category: "blog",
			Website:  "https://tumblr.com",
			HTML:     pp([]string{`tumblr\.com`, `assets\.tumblr\.com`}),
		},
		{
			Name:     "Webflow",
			Category: "cms",
			Website:  "https://webflow.com",
			HTML:     pp([]string{`webflow\.com`, `Webflow`}),
			Headers: map[string][]Pattern{
				"x-wf-request-id": {p(`.*`)},
			},
		},
		{
			Name:     "Squarespace",
			Category: "cms",
			Website:  "https://squarespace.com",
			HTML:     pp([]string{`squarespace\.com`, `squarespace-cdn`}),
			Headers: map[string][]Pattern{
				"x-servedby": {p(`squarespace`)},
			},
		},
		{
			Name:     "Wix",
			Category: "cms",
			Website:  "https://wix.com",
			HTML:     pp([]string{`wix\.com`, `parastorage\.com`}),
		},
		{
			Name:     "GitBook",
			Category: "docs",
			Website:  "https://gitbook.com",
			HTML:     pp([]string{`gitbook\.com`, `gitbook-legacy`}),
			Headers: map[string][]Pattern{
				"x-gitbook-version": {p(`.*`)},
			},
		},
		{
			Name:     "ReadTheDocs",
			Category: "docs",
			Website:  "https://readthedocs.io",
			HTML:     pp([]string{`readthedocs\.io`, `sphinx_rtd_theme`}),
		},
		{
			Name:     "Mkdocs",
			Category: "docs",
			Website:  "https://mkdocs.org",
			HTML:     pp([]string{`mkdocs`, `material-theme`}),
		},

		// ── E-commerce ────────────────────────────────────────────────────────
		{
			Name:     "Shopify",
			Category: "ecommerce",
			Website:  "https://shopify.com",
			HTML:     pp([]string{`shopify`, `Shopify\.theme`, `cdn\.shopify\.com`}),
			Headers: map[string][]Pattern{
				"x-shopid":        {p(`.*`)},
				"x-shopify-stage": {p(`.*`)},
			},
		},
		{
			Name:     "WooCommerce",
			Category: "ecommerce",
			Website:  "https://woocommerce.com",
			HTML:     pp([]string{`woocommerce`, `wp-content/plugins/woocommerce`}),
		},
		{
			Name:     "Magento",
			Category: "ecommerce",
			Website:  "https://magento.com",
			HTML:     pp([]string{`Mage\.`, `mage/`, `\/skin\/frontend\/`}),
			Headers: map[string][]Pattern{
				"x-magento-cache-debug": {p(`.*`)},
			},
		},
		{
			Name:     "OpenCart",
			Category: "ecommerce",
			Website:  "https://opencart.com",
			HTML:     pp([]string{`route=common\/home`, `catalog\/view\/theme`}),
		},
		{
			Name:     "PrestaShop",
			Category: "ecommerce",
			Website:  "https://prestashop.com",
			HTML:     pp([]string{`PrestaShop`, `prestashop`}),
			Headers: map[string][]Pattern{
				"x-prestashop-cache": {p(`.*`)},
			},
		},
		{
			Name:     "BigCommerce",
			Category: "ecommerce",
			Website:  "https://bigcommerce.com",
			HTML:     pp([]string{`bigcommerce`, `bc-storefront`}),
			Headers: map[string][]Pattern{
				"x-bc-deployment-id": {p(`.*`)},
			},
		},

		// ── DevOps / CI tools ─────────────────────────────────────────────────
		{
			Name:     "Jenkins",
			Category: "ci",
			Website:  "https://jenkins.io",
			HTML:     pp([]string{`Jenkins`, `jenkins-ci`}),
			Headers: map[string][]Pattern{
				"x-jenkins": {p(`.*`)},
			},
		},
		{
			Name:     "GitLab",
			Category: "vcs",
			Website:  "https://gitlab.com",
			HTML:     pp([]string{`GitLab`, `gitlab-ci`}),
			Headers: map[string][]Pattern{
				"x-gitlab-meta": {p(`.*`)},
			},
		},
		{
			Name:     "Gitea",
			Category: "vcs",
			Website:  "https://gitea.io",
			HTML:     pp([]string{`Gitea`, `gitea\.com`}),
		},
		{
			Name:     "Gogs",
			Category: "vcs",
			Website:  "https://gogs.io",
			HTML:     pp([]string{`Gogs`, `gogs\.io`}),
		},
		{
			Name:     "Jira",
			Category: "project-management",
			Website:  "https://atlassian.com/jira",
			HTML:     pp([]string{`JIRA`, `atlassian\.net`}),
			Headers: map[string][]Pattern{
				"x-arequestid": {p(`.*`)},
				"atl-traceid":  {p(`.*`)},
			},
		},
		{
			Name:     "Confluence",
			Category: "wiki",
			Website:  "https://atlassian.com/confluence",
			HTML:     pp([]string{`Confluence`, `confluence`}),
			Headers: map[string][]Pattern{
				"x-confluence-request-time": {p(`.*`)},
			},
		},
		{
			Name:     "SonarQube",
			Category: "code-quality",
			Website:  "https://sonarqube.org",
			HTML:     pp([]string{`SonarQube`, `sq-header-logo`}),
		},
		{
			Name:     "Nexus Repository",
			Category: "repository",
			Website:  "https://sonatype.com",
			HTML:     pp([]string{`nexus`, `Sonatype`}),
		},
		{
			Name:     "Artifactory",
			Category: "repository",
			Website:  "https://jfrog.com",
			HTML:     pp([]string{`Artifactory`, `JFrog`}),
		},

		// ── Observability / monitoring ────────────────────────────────────────
		{
			Name:     "Grafana",
			Category: "monitoring",
			Website:  "https://grafana.com",
			HTML:     pp([]string{`grafana`, `Grafana`}),
			Headers: map[string][]Pattern{
				"x-grafana-origin": {p(`.*`)},
			},
		},
		{
			Name:     "Prometheus",
			Category: "monitoring",
			Website:  "https://prometheus.io",
			HTML:     pp([]string{`Prometheus`, `prometheus`}),
		},
		{
			Name:     "Kibana",
			Category: "monitoring",
			Website:  "https://elastic.co/kibana",
			HTML:     pp([]string{`kibana`, `kbn-name`}),
			Headers: map[string][]Pattern{
				"kbn-name": {p(`kibana`)},
			},
		},
		{
			Name:     "Splunk",
			Category: "monitoring",
			Website:  "https://splunk.com",
			HTML:     pp([]string{`Splunk`, `splunkd`}),
		},
		{
			Name:     "Zabbix",
			Category: "monitoring",
			Website:  "https://zabbix.com",
			HTML:     pp([]string{`Zabbix`, `zbx_session`}),
		},
		{
			Name:     "Nagios",
			Category: "monitoring",
			Website:  "https://nagios.org",
			HTML:     pp([]string{`Nagios`, `nagios`}),
		},
		{
			Name:     "PagerDuty",
			Category: "monitoring",
			Website:  "https://pagerduty.com",
			Script:   pp([]string{`pagerduty\.com`}),
		},

		// ── Security / WAF ────────────────────────────────────────────────────
		{
			Name:     "Barracuda WAF",
			Category: "waf",
			Website:  "https://barracuda.com",
			Headers: map[string][]Pattern{
				"x-barracuda-wf-action": {p(`.*`)},
			},
		},
		{
			Name:     "Citrix NetScaler",
			Category: "lb",
			Website:  "https://citrix.com",
			Headers: map[string][]Pattern{
				"via":   {p(`NS-CACHE`)},
				"ns_af": {p(`.*`)},
			},
		},
		{
			Name:     "Incapsula",
			Category: "waf",
			Website:  "https://incapsula.com",
			Headers: map[string][]Pattern{
				"x-iinfo": {p(`.*`)},
			},
		},
		{
			Name:     "Reblaze",
			Category: "waf",
			Website:  "https://reblaze.com",
			Headers: map[string][]Pattern{
				"server":               {p(`reblaze`)},
				"x-reblaze-protection": {p(`.*`)},
			},
		},
		{
			Name:     "Wordfence",
			Category: "waf",
			Website:  "https://wordfence.com",
			HTML:     pp([]string{`wordfence`, `Wordfence`}),
		},
		{
			Name:     "Comodo WAF",
			Category: "waf",
			Website:  "https://comodo.com",
			Headers: map[string][]Pattern{
				"x-protected-by": {p(`comodo`)},
			},
		},

		// ── CDN / hosting ────────────────────────────────────────────────────
		{
			Name:     "Cloudflare Workers",
			Category: "serverless",
			Website:  "https://workers.cloudflare.com",
			Headers: map[string][]Pattern{
				"cf-worker": {p(`.*`)},
			},
			Implies: []string{"Cloudflare"},
		},
		{
			Name:     "Netlify",
			Category: "hosting",
			Website:  "https://netlify.com",
			Headers: map[string][]Pattern{
				"x-netlify":       {p(`.*`)},
				"x-nf-request-id": {p(`.*`)},
			},
		},
		{
			Name:     "Vercel",
			Category: "hosting",
			Website:  "https://vercel.com",
			Headers: map[string][]Pattern{
				"x-vercel-id":    {p(`.*`)},
				"x-vercel-cache": {p(`.*`)},
			},
		},
		{
			Name:     "GitHub Pages",
			Category: "hosting",
			Website:  "https://pages.github.com",
			Headers: map[string][]Pattern{
				"x-github-request-id": {p(`.*`)},
			},
		},
		{
			Name:     "Fly.io",
			Category: "hosting",
			Website:  "https://fly.io",
			Headers: map[string][]Pattern{
				"fly-request-id": {p(`.*`)},
			},
		},
		{
			Name:     "DigitalOcean App Platform",
			Category: "hosting",
			Website:  "https://digitalocean.com",
			Headers: map[string][]Pattern{
				"do-connecting-ip": {p(`.*`)},
			},
		},
		{
			Name:     "Bunny CDN",
			Category: "cdn",
			Website:  "https://bunny.net",
			Headers: map[string][]Pattern{
				"cdn-pullzone":  {p(`.*`)},
				"cdn-requestid": {p(`.*`)},
			},
		},
		{
			Name:     "KeyCDN",
			Category: "cdn",
			Website:  "https://keycdn.com",
			Headers: map[string][]Pattern{
				"x-edge-location": {p(`.*`)},
			},
		},
		{
			Name:     "StackPath",
			Category: "cdn",
			Website:  "https://stackpath.com",
			Headers: map[string][]Pattern{
				"x-sp-edge": {p(`.*`)},
			},
		},

		// ── Auth / identity ───────────────────────────────────────────────────
		{
			Name:     "Cognito",
			Category: "auth",
			Website:  "https://aws.amazon.com/cognito",
			Script:   pp([]string{`cognito-identity\.amazonaws\.com`, `amazon-cognito`}),
		},
		{
			Name:     "Firebase Auth",
			Category: "auth",
			Website:  "https://firebase.google.com",
			Script:   pp([]string{`firebase\.googleapis\.com`, `firebaseapp\.com`}),
			HTML:     pp([]string{`firebase`}),
		},
		{
			Name:     "Supabase",
			Category: "backend",
			Website:  "https://supabase.com",
			Script:   pp([]string{`supabase\.co`, `supabase\.com`}),
			HTML:     pp([]string{`supabase`}),
		},
		{
			Name:     "PocketBase",
			Category: "backend",
			Website:  "https://pocketbase.io",
			HTML:     pp([]string{`pocketbase`, `PocketBase`}),
		},
		{
			Name:     "Appwrite",
			Category: "backend",
			Website:  "https://appwrite.io",
			HTML:     pp([]string{`appwrite`}),
			Headers: map[string][]Pattern{
				"x-appwrite-id": {p(`.*`)},
			},
		},

		// ── Frontend frameworks expanded ──────────────────────────────────────
		{
			Name:     "Tailwind CSS",
			Category: "css",
			Website:  "https://tailwindcss.com",
			HTML:     pp([]string{`tailwindcss`, `tw-`, `class="[^"]*(?:flex|grid|p-\d|m-\d|text-|bg-|border-)`}),
		},
		{
			Name:     "Material UI",
			Category: "ui",
			Website:  "https://mui.com",
			HTML:     pp([]string{`MuiButton`, `MuiBox`, `MuiContainer`, `mui\.com`}),
		},
		{
			Name:     "Chakra UI",
			Category: "ui",
			Website:  "https://chakra-ui.com",
			HTML:     pp([]string{`chakra-ui`, `chakra`}),
		},
		{
			Name:     "Ant Design",
			Category: "ui",
			Website:  "https://ant.design",
			HTML:     pp([]string{`antd`, `ant-design`, `ant-btn`}),
		},
		{
			Name:     "Bulma",
			Category: "css",
			Website:  "https://bulma.io",
			HTML:     pp([]string{`bulma`, `class="button is-`}),
		},
		{
			Name:     "Foundation",
			Category: "css",
			Website:  "https://get.foundation",
			HTML:     pp([]string{`foundation`, `zurb\.com`}),
		},
		{
			Name:     "Semantic UI",
			Category: "css",
			Website:  "https://semantic-ui.com",
			HTML:     pp([]string{`semantic\.min\.css`, `semantic-ui`}),
		},
		{
			Name:     "FontAwesome",
			Category: "icons",
			Website:  "https://fontawesome.com",
			HTML:     pp([]string{`fa-solid`, `fa-regular`, `fa-brands`, `font-awesome`}),
			Script:   pp([]string{`fontawesome\.com`}),
		},
		{
			Name:     "Lodash",
			Category: "js-library",
			Website:  "https://lodash.com",
			Script:   pp([]string{`lodash\.js`, `lodash\.min\.js`}),
			HTML:     pp([]string{`_\.VERSION`, `\blodash\b`}),
		},
		{
			Name:     "Underscore.js",
			Category: "js-library",
			Website:  "https://underscorejs.org",
			Script:   pp([]string{`underscore\.js`, `underscore-min\.js`}),
		},
		{
			Name:     "Moment.js",
			Category: "js-library",
			Website:  "https://momentjs.com",
			Script:   pp([]string{`moment\.js`, `moment\.min\.js`}),
		},
		{
			Name:     "Chart.js",
			Category: "js-library",
			Website:  "https://chartjs.org",
			Script:   pp([]string{`chart\.js`, `chart\.min\.js`, `Chart\.js`}),
		},
		{
			Name:     "D3.js",
			Category: "js-library",
			Website:  "https://d3js.org",
			Script:   pp([]string{`d3\.js`, `d3\.min\.js`, `d3-selection`}),
		},
		{
			Name:     "Three.js",
			Category: "js-library",
			Website:  "https://threejs.org",
			Script:   pp([]string{`three\.js`, `three\.min\.js`}),
		},
		{
			Name:     "GSAP",
			Category: "js-library",
			Website:  "https://greensock.com",
			Script:   pp([]string{`gsap\.js`, `gsap\.min\.js`, `TweenMax`, `TimelineMax`}),
		},

		// ── Payment / analytics expanded ──────────────────────────────────────
		{
			Name:     "Google Tag Manager",
			Category: "analytics",
			Website:  "https://tagmanager.google.com",
			Script:   pp([]string{`googletagmanager\.com/gtm\.js`, `gtag\/js`}),
			HTML:     pp([]string{`GTM-`}),
		},
		{
			Name:     "Adobe Analytics",
			Category: "analytics",
			Website:  "https://adobe.com/analytics",
			Script:   pp([]string{`omniture\.com`, `adobe\.com/AppMeasurement`, `s_code\.js`}),
		},
		{
			Name:     "Mixpanel",
			Category: "analytics",
			Website:  "https://mixpanel.com",
			Script:   pp([]string{`mixpanel\.com`, `mixpanel-2\.min\.js`}),
		},
		{
			Name:     "Amplitude",
			Category: "analytics",
			Website:  "https://amplitude.com",
			Script:   pp([]string{`amplitude\.com`, `amplitude-js`}),
		},
		{
			Name:     "Segment",
			Category: "analytics",
			Website:  "https://segment.com",
			Script:   pp([]string{`cdn\.segment\.com`, `analytics\.js`}),
		},
		{
			Name:     "FullStory",
			Category: "analytics",
			Website:  "https://fullstory.com",
			Script:   pp([]string{`fullstory\.com`, `fs\.js`}),
		},
		{
			Name:     "Heap",
			Category: "analytics",
			Website:  "https://heapanalytics.com",
			Script:   pp([]string{`heapanalytics\.com`, `heap-`}),
		},
		{
			Name:     "Intercom",
			Category: "crm",
			Website:  "https://intercom.com",
			Script:   pp([]string{`intercomcdn\.com`, `intercom-`}),
			HTML:     pp([]string{`Intercom\(`}),
		},
		{
			Name:     "Zendesk",
			Category: "crm",
			Website:  "https://zendesk.com",
			Script:   pp([]string{`zendesk\.com`, `zopim`}),
			HTML:     pp([]string{`zopim`, `zE\(`}),
		},
		{
			Name:     "Drift",
			Category: "crm",
			Website:  "https://drift.com",
			Script:   pp([]string{`js\.driftt\.com`, `drift\.com`}),
		},
		{
			Name:     "Crisp",
			Category: "crm",
			Website:  "https://crisp.chat",
			Script:   pp([]string{`crisp\.chat`, `client\.crisp\.chat`}),
			HTML:     pp([]string{`\$crisp`}),
		},

		// ── OS / servers ─────────────────────────────────────────────────────
		{
			Name:     "FreeBSD",
			Category: "os",
			Website:  "https://freebsd.org",
			Headers: map[string][]Pattern{
				"server": {p(`FreeBSD`)},
			},
		},
		{
			Name:     "Alpine Linux",
			Category: "os",
			Website:  "https://alpinelinux.org",
			Headers: map[string][]Pattern{
				"server": {p(`Alpine`)},
			},
		},
		{
			Name:     "Amazon Linux",
			Category: "os",
			Website:  "https://aws.amazon.com/amazon-linux-ami",
			Headers: map[string][]Pattern{
				"server": {p(`amzn`)},
			},
		},
		{
			Name:     "Oracle Linux",
			Category: "os",
			Website:  "https://oracle.com/linux",
			Headers: map[string][]Pattern{
				"server": {p(`Oracle`)},
			},
		},

		// ── Misc ──────────────────────────────────────────────────────────────
		{
			Name:     "Apache Struts",
			Category: "framework",
			Website:  "https://struts.apache.org",
			HTML:     pp([]string{`Struts`, `struts2`}),
			Headers: map[string][]Pattern{
				"x-struts": {p(`.*`)},
			},
		},
		{
			Name:     "Grails",
			Category: "framework",
			Website:  "https://grails.org",
			HTML:     pp([]string{`Grails`, `grails`}),
		},
		{
			Name:     "Ktor",
			Category: "framework",
			Website:  "https://ktor.io",
			Headers: map[string][]Pattern{
				"server": {p(`ktor`)},
			},
		},
		{
			Name:     "Helidon",
			Category: "framework",
			Website:  "https://helidon.io",
			Headers: map[string][]Pattern{
				"server": {p(`Helidon`)},
			},
		},
		{
			Name:     "Javalin",
			Category: "framework",
			Website:  "https://javalin.io",
			Headers: map[string][]Pattern{
				"server": {p(`Javalin`)},
			},
		},
		{
			Name:     "CherryPy",
			Category: "framework",
			Website:  "https://cherrypy.dev",
			Headers: map[string][]Pattern{
				"server": {p(`CherryPy`)},
			},
		},
		{
			Name:     "Bottle",
			Category: "framework",
			Website:  "https://bottlepy.org",
			Headers: map[string][]Pattern{
				"server": {p(`Bottle`)},
			},
		},
		{
			Name:     "Falcon",
			Category: "framework",
			Website:  "https://falconframework.org",
			Headers: map[string][]Pattern{
				"server": {p(`Falcon`)},
			},
		},
		{
			Name:     "Sanic",
			Category: "framework",
			Website:  "https://sanic.dev",
			Headers: map[string][]Pattern{
				"server": {p(`sanic`)},
			},
		},
		{
			Name:     "Lumen",
			Category: "framework",
			Website:  "https://lumen.laravel.com",
			Headers: map[string][]Pattern{
				"x-powered-by": {p(`Lumen`)},
			},
		},
		{
			Name:     "Symfony",
			Category: "framework",
			Website:  "https://symfony.com",
			HTML:     pp([]string{`symfony`, `Symfony`}),
			Headers: map[string][]Pattern{
				"x-powered-by": {p(`Symfony`)},
			},
		},
		{
			Name:     "CodeIgniter",
			Category: "framework",
			Website:  "https://codeigniter.com",
			HTML:     pp([]string{`CodeIgniter`, `ci_session`}),
		},
		{
			Name:     "CakePHP",
			Category: "framework",
			Website:  "https://cakephp.org",
			HTML:     pp([]string{`CakePHP`, `CAKEPHP`}),
		},
		{
			Name:     "Yii",
			Category: "framework",
			Website:  "https://yiiframework.com",
			HTML:     pp([]string{`Yii`, `yii`}),
			Headers: map[string][]Pattern{
				"x-powered-by": {p(`Yii`)},
			},
		},
		{
			Name:     "Zend Framework",
			Category: "framework",
			Website:  "https://framework.zend.com",
			HTML:     pp([]string{`Zend`, `zf-version`}),
		},
		{
			Name:     "Slim",
			Category: "framework",
			Website:  "https://slimframework.com",
			Headers: map[string][]Pattern{
				"x-powered-by": {p(`Slim`)},
			},
		},
		{
			Name:     "Typo3 Neos",
			Category: "cms",
			Website:  "https://neos.io",
			HTML:     pp([]string{`neos`, `TYPO3 Neos`}),
		},
		{
			Name:     "MODx",
			Category: "cms",
			Website:  "https://modx.com",
			HTML:     pp([]string{`modx`, `MODx`}),
		},
		{
			Name:     "ExpressionEngine",
			Category: "cms",
			Website:  "https://expressionengine.com",
			HTML:     pp([]string{`ExpressionEngine`}),
		},
		{
			Name:     "OpenWRT",
			Category: "router",
			Website:  "https://openwrt.org",
			HTML:     pp([]string{`OpenWRT`, `luci`}),
		},
		{
			Name:     "pfSense",
			Category: "router",
			Website:  "https://pfsense.org",
			HTML:     pp([]string{`pfSense`, `pfsense`}),
		},
		{
			Name:     "Fortinet FortiGate",
			Category: "firewall",
			Website:  "https://fortinet.com",
			HTML:     pp([]string{`fortigate`, `FortiGate`, `FortiOS`}),
		},
		{
			Name:     "Palo Alto PAN-OS",
			Category: "firewall",
			Website:  "https://paloaltonetworks.com",
			HTML:     pp([]string{`PAN-OS`, `GlobalProtect`}),
		},
		{
			Name:     "Cisco ASA",
			Category: "firewall",
			Website:  "https://cisco.com",
			HTML:     pp([]string{`Cisco ASA`, `CISCO`}),
		},
		{
			Name:     "Juniper Junos",
			Category: "network",
			Website:  "https://juniper.net",
			HTML:     pp([]string{`Juniper`, `JUNOS`}),
		},
		{
			Name:     "MikroTik",
			Category: "router",
			Website:  "https://mikrotik.com",
			HTML:     pp([]string{`MikroTik`, `RouterOS`}),
		},
		{
			Name:     "Portainer",
			Category: "containers",
			Website:  "https://portainer.io",
			HTML:     pp([]string{`Portainer`, `portainer`}),
		},
		{
			Name:     "Rancher",
			Category: "containers",
			Website:  "https://rancher.com",
			HTML:     pp([]string{`Rancher`, `rancher`}),
		},
		{
			Name:     "ArgoCD",
			Category: "devops",
			Website:  "https://argoproj.github.io",
			HTML:     pp([]string{`argocd`, `Argo CD`}),
		},
		{
			Name:     "Vault",
			Category: "secrets",
			Website:  "https://vaultproject.io",
			HTML:     pp([]string{`HashiCorp Vault`, `vault`}),
			Headers: map[string][]Pattern{
				"x-vault-index": {p(`.*`)},
			},
		},
		{
			Name:     "Consul",
			Category: "discovery",
			Website:  "https://consul.io",
			HTML:     pp([]string{`Consul`, `HashiCorp Consul`}),
		},
		{
			Name:     "Nomad",
			Category: "orchestration",
			Website:  "https://nomadproject.io",
			HTML:     pp([]string{`Nomad`, `HashiCorp Nomad`}),
		},
		{
			Name:     "MinIO",
			Category: "storage",
			Website:  "https://min.io",
			HTML:     pp([]string{`MinIO`, `minio`}),
			Headers: map[string][]Pattern{
				"x-amz-request-id": {p(`.*`)},
				"server":           {p(`MinIO`)},
			},
		},
		{
			Name:     "Nextcloud",
			Category: "cloud",
			Website:  "https://nextcloud.com",
			HTML:     pp([]string{`Nextcloud`, `nextcloud`}),
		},
		{
			Name:     "Owncloud",
			Category: "cloud",
			Website:  "https://owncloud.com",
			HTML:     pp([]string{`ownCloud`, `owncloud`}),
		},
		{
			Name:     "Mattermost",
			Category: "chat",
			Website:  "https://mattermost.com",
			HTML:     pp([]string{`Mattermost`, `mattermost`}),
		},
		{
			Name:     "Rocketchat",
			Category: "chat",
			Website:  "https://rocket.chat",
			HTML:     pp([]string{`Rocket\.Chat`, `rocketchat`}),
		},
		{
			Name:     "Discourse",
			Category: "forum",
			Website:  "https://discourse.org",
			HTML:     pp([]string{`Discourse`, `discourse`}),
			Headers: map[string][]Pattern{
				"x-discourse-route": {p(`.*`)},
			},
		},
	}
}
