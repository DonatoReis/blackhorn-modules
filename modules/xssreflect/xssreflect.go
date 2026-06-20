// Package xssreflect detects reflected XSS candidates by injecting canary
// strings into URL parameters and checking whether dangerous characters
// survive unencoded in the response body.
//
// Source reference: tomnomnom/kxss (MIT) + dalfox (MIT, hahwul).
// Detection logic reimplemented from scratch.
//
// Design:
//   - Injects a unique canary (BHR+12hex) per parameter/probe combination
//   - Checks whether dangerous characters (' " < > ` ) are reflected raw
//   - Classifies the context: HTML body, attribute, script, URL-encoded
//   - 8 canary variants covering different injection vectors
//   - errgroup.SetLimit(Parallelism) fan-out
//   - io.LimitReader on all reads
//   - log/slog observability
//   - sync.Mutex protecting findings
//   - NewWithClient / NewWithProbes for testability
package xssreflect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	DefaultTimeout     = 10 * time.Second
	DefaultParallelism = 10
	maxBodyRead        = 512 * 1024

	canaryPrefix = "BHR"
)

// ─── Probe ────────────────────────────────────────────────────────────────────

// Probe defines a single XSS reflection test variant.
type Probe struct {
	// ID is a unique slug.
	ID string
	// Suffix appended after the canary in the injected value.
	// {CANARY} is replaced with the unique canary string.
	Template string
	// Tags are metadata tags.
	Tags []string
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements reflected XSS candidate detection.
type Module struct {
	client      *http.Client
	probes      []Probe
	parallelism int
	logger      *slog.Logger
}

// New returns a Module with all built-in probes.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: DefaultTimeout}),
		probes:      builtinProbes(),
		parallelism: DefaultParallelism,
		logger:      slog.Default(),
	}
}

// NewWithClient returns a Module using the supplied HTTP client.
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// NewWithProbes returns a Module with custom probes.
func NewWithProbes(probes []Probe) *Module {
	m := New()
	m.probes = probes
	return m
}

// NewWithProbesAndClient returns a Module with custom probes and HTTP client.
func NewWithProbesAndClient(probes []Probe, c *http.Client) *Module {
	m := New()
	m.probes = probes
	m.client = c
	return m
}

// Name returns the module name.
func (m *Module) Name() string { return "xssreflect" }

// Run probes every URL in input.URLs for reflected XSS by injecting canary
// strings into each query parameter.
//
// Options:
//   - "parallelism" — max concurrent probes (default: 10)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	targets := collectTargets(input)
	if len(targets) == 0 {
		return nil, nil
	}

	parallelism := m.parallelism
	if v := input.Options["parallelism"]; v != "" {
		if p, err := parseInt(v); err == nil && p > 0 {
			parallelism = p
		}
	}

	var (
		mu       sync.Mutex
		seen     = make(map[string]struct{})
		findings []module.Finding
	)

	addFinding := func(f module.Finding) {
		mu.Lock()
		defer mu.Unlock()
		key := f.URL + "|" + f.Extra["parameter"] + "|" + f.Extra["probe_id"]
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			findings = append(findings, f)
		}
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(parallelism)

	for _, rawURL := range targets {
		rawURL := rawURL
		eg.Go(func() error {
			fs := m.probeURL(egCtx, rawURL)
			for _, f := range fs {
				addFinding(f)
			}
			return nil
		})
	}

	_ = eg.Wait()
	return findings, nil
}

// probeURL tests each query parameter of rawURL with all probes.
func (m *Module) probeURL(ctx context.Context, rawURL string) []module.Finding {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	params := u.Query()
	if len(params) == 0 {
		return nil
	}

	var findings []module.Finding

	for paramName := range params {
		if ctx.Err() != nil {
			break
		}
		for _, probe := range m.probes {
			if ctx.Err() != nil {
				break
			}
			f := m.runProbe(ctx, u, rawURL, paramName, probe)
			if f != nil {
				findings = append(findings, *f)
			}
		}
	}
	return findings
}

func (m *Module) runProbe(ctx context.Context, u *url.URL, rawURL, paramName string, probe Probe) *module.Finding {
	canary := newCanary()
	inject := strings.ReplaceAll(probe.Template, "{CANARY}", canary)

	injectedURL := injectParam(u, paramName, inject)
	body, statusCode, err := m.fetch(ctx, injectedURL)
	if err != nil {
		m.logger.DebugContext(ctx, "xssreflect: fetch failed",
			"url", rawURL, "param", paramName, "probe", probe.ID, "err", err)
		return nil
	}

	reflected, context_ := classifyReflection(canary, inject, body)
	if len(reflected) == 0 {
		return nil
	}

	m.logger.InfoContext(ctx, "xssreflect: candidate found",
		"url", rawURL, "param", paramName, "probe", probe.ID,
		"reflected", strings.Join(reflected, ""), "context", context_)

	return &module.Finding{
		Type:     "reflected_xss_candidate",
		Severity: severityFor(reflected),
		URL:      rawURL,
		Detail: fmt.Sprintf("[XSSReflect] param %q probe %s: unencoded %q in %s context (status %d)",
			paramName, probe.ID, strings.Join(reflected, ""), context_, statusCode),
		Extra: map[string]string{
			"parameter":       paramName,
			"probe_id":        probe.ID,
			"reflected_chars": strings.Join(reflected, ""),
			"context":         context_,
			"injected_url":    injectedURL,
			"canary":          canary,
			"tags":            "xss,reflected," + strings.Join(probe.Tags, ","),
			"confidence":      "0.80",
		},
	}
}

// fetch performs a GET request and returns the response body as a string.
func (m *Module) fetch(ctx context.Context, target string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-xssreflect/1.0)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := m.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return string(body), resp.StatusCode, nil
}

// ─── Detection ────────────────────────────────────────────────────────────────

// dangerousChars are the characters that signal XSS when unencoded.
var dangerousChars = []string{"<", ">", `"`, "'", "`", "(", ")"}

// htmlEncodings maps dangerous chars to their HTML entity forms.
// If the char appears in the body only in encoded form, it's NOT a finding.
var htmlEncodings = map[string][]string{
	"<": {"&lt;", "&#60;", "&#x3C;", "&#x3c;"},
	">": {"&gt;", "&#62;", "&#x3E;", "&#x3e;"},
	`"`: {"&quot;", "&#34;", "&#x22;"},
	"'": {"&#39;", "&apos;", "&#x27;"},
	"`": {"&#96;", "&#x60;"},
	"(": {"&#40;", "&#x28;"},
	")": {"&#41;", "&#x29;"},
}

// classifyReflection returns which dangerous characters from the inject payload
// appear UNENCODED in the body near the canary, plus the context.
//
// Strategy:
//  1. Find the canary literal in the body.
//  2. Extract the suffix starting immediately after the canary.
//  3. Build the "inject suffix" — everything in inject AFTER the canary
//     (i.e., the dangerous part of the payload that follows the canary).
//  4. Check each dangerous char:
//     a. If the inject suffix (chars ONLY from inject, not the canary) appears
//     verbatim in the body suffix → raw reflection → flag it.
//     b. If the body suffix contains only HTML-encoded forms of the char → safe.
//
// This avoids false positives from HTML structural tags in the page template.
func classifyReflection(canary, inject, body string) ([]string, string) {
	// Find canary literal in body.
	idx := strings.Index(body, canary)
	if idx < 0 {
		return nil, ""
	}

	// The part of inject that follows the canary (the "dangerous suffix").
	// inject = canary + dangerousSuffix
	dangerousSuffix := strings.TrimPrefix(inject, canary)

	// Suffix in body starting after the canary.
	// Limit to at most 3× the dangerous suffix length — HTML-encoding can
	// expand each char to at most 6 chars (e.g. &quot;), so 3× is generous.
	// This prevents picking up chars from structural HTML tags further in body.
	bodySuffixFull := body[idx+len(canary):]
	maxLen := max(len(dangerousSuffix)*6, 30)
	bodySuffix := bodySuffixFull[:min(len(bodySuffixFull), maxLen)]

	// Determine context.
	prefix := body[max(0, idx-30):idx]
	shortSuffix := bodySuffix[:min(len(bodySuffix), 40)]
	context_ := "body"
	if inScriptContext(prefix) {
		context_ = "script"
	} else if inAttrContext(prefix, shortSuffix) {
		context_ = "attribute"
	}

	// For each dangerous char present in the inject payload, check if it
	// appears UNENCODED in the body suffix.
	var reflected []string
	for _, ch := range dangerousChars {
		if !strings.Contains(dangerousSuffix, ch) {
			continue
		}
		if isUnencodedIn(ch, bodySuffix) {
			reflected = append(reflected, ch)
		}
	}
	return reflected, context_
}

// isUnencodedIn returns true if the char ch appears in text in its raw form
// (not as an HTML entity and not as an HTML structural tag).
//
// For angle brackets specifically, we distinguish:
//   - Raw `<` that is NOT the start of an HTML tag (e.g. `<b`, `</`, `<!`)
//     → this is a real unencoded reflection
//   - Raw `<` that IS the start of an HTML structural tag (e.g. `</body>`, `<br>`)
//     → this came from the server template, not the inject
func isUnencodedIn(ch, text string) bool {
	if !strings.Contains(text, ch) {
		return false
	}
	// Strip all known HTML entity encodings.
	stripped := text
	for _, enc := range htmlEncodings[ch] {
		stripped = strings.ReplaceAll(stripped, enc, "")
	}
	if !strings.Contains(stripped, ch) {
		return false
	}
	// For < and >, do a stricter check: ensure the remaining occurrence
	// is not just the start/end of an HTML structural tag.
	if ch == "<" {
		// After stripping entities, check if any remaining '<' is NOT
		// part of a standard HTML tag (letter, /, !, ?).
		// Any '<' not followed by letter/!/? is "raw injection".
		for i, r := range stripped {
			if r == '<' {
				if i+1 < len(stripped) {
					next := stripped[i+1]
					// '<' followed by a-z, A-Z, /, ! or ? is an HTML tag — skip.
					if (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') ||
						next == '/' || next == '!' || next == '?' {
						continue
					}
				}
				// Raw '<' not part of an HTML tag.
				return true
			}
		}
		return false
	}
	if ch == ">" {
		// '>' from HTML tag closings is structural. We only consider '>' as a
		// raw injection if it appears in a non-tag context — i.e., preceded by
		// something other than a word/slash (which would make it a tag close).
		// Scan stripped for '>' not immediately preceded by a tag identifier.
		for i, r := range stripped {
			if r == '>' {
				// Look at what precedes this '>'.
				if i > 0 {
					prev := stripped[i-1]
					// '>' after alphanumeric or '/' is likely a closing tag or
					// self-closing tag. After '"' it's closing an attribute value.
					// Note: single-quote is NOT included — it could be a reflected char.
					if (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') ||
						(prev >= '0' && prev <= '9') || prev == '/' || prev == '"' {
						continue
					}
				}
				// '>' not following a tag identifier — raw injection.
				return true
			}
		}
		return false
	}
	return true
}

func inScriptContext(prefix string) bool {
	lower := strings.ToLower(prefix)
	// Simple heuristic: <script or already inside a script block.
	return strings.Contains(lower, "<script") ||
		(strings.Count(lower, "<script") == 0 && strings.Contains(lower, "script>"))
}

func inAttrContext(prefix, suffix string) bool {
	// If we see = or quote just before canary → inside an attribute.
	trimmed := strings.TrimRight(prefix, " \t\r\n")
	if len(trimmed) == 0 {
		return false
	}
	last := trimmed[len(trimmed)-1]
	return last == '=' || last == '"' || last == '\'' ||
		strings.Contains(suffix, `="`) || strings.Contains(suffix, `='`)
}

// severityFor assigns severity based on which characters were reflected.
func severityFor(chars []string) module.Severity {
	set := make(map[string]struct{}, len(chars))
	for _, c := range chars {
		set[c] = struct{}{}
	}
	_, hasLt := set["<"]
	_, hasGt := set[">"]
	_, hasQ := set[`"`]
	_, hasSq := set["'"]
	_, hasBt := set["`"]

	if (hasLt && hasGt) || (hasBt && (hasQ || hasSq)) {
		return module.SeverityHigh
	}
	return module.SeverityMedium
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func newCanary() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return canaryPrefix + hex.EncodeToString(b)
}

// injectParam returns the URL with paramName set to value.
func injectParam(u *url.URL, paramName, value string) string {
	clone := *u
	q := clone.Query()
	q.Set(paramName, value)
	clone.RawQuery = q.Encode()
	return clone.String()
}

func collectTargets(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
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

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n, err
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── Built-in Probes ──────────────────────────────────────────────────────────

func builtinProbes() []Probe {
	return []Probe{
		{
			ID: "basic-all", Tags: []string{"basic"},
			Template: `{CANARY}'"<>`,
		},
		{
			ID: "html-tag", Tags: []string{"html", "tag"},
			Template: `{CANARY}<b>`,
		},
		{
			ID: "attr-double-quote", Tags: []string{"attr", "dq"},
			Template: `{CANARY}"onmouseover=1`,
		},
		{
			ID: "attr-single-quote", Tags: []string{"attr", "sq"},
			Template: `{CANARY}'onmouseover=1`,
		},
		{
			ID: "script-break", Tags: []string{"script"},
			Template: `{CANARY}</script><script>`,
		},
		{
			ID: "backtick", Tags: []string{"template-literal"},
			Template: "{CANARY}`${1}",
		},
		{
			ID: "angle-only", Tags: []string{"angle"},
			Template: `{CANARY}<>`,
		},
		{
			ID: "parens", Tags: []string{"function-call"},
			Template: `{CANARY}()`,
		},
	}
}
