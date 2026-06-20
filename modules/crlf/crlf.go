// Package crlf implements CRLF Injection detection.
//
// Source reference: crlfuzz (MIT, Dwi Siswanto/Julio Casal) +
// Burp Suite CRLF checks + portswigger.net/web-security/response-splitting.
// Detection logic reimplemented from scratch.
//
// CRLF Injection occurs when an attacker injects carriage-return (\r, %0d)
// and line-feed (\n, %0a) characters into HTTP headers, causing:
//   - HTTP Response Splitting (inject arbitrary headers or body)
//   - Set-Cookie header injection
//   - XSS via injected headers
//   - Cache poisoning via injected status line
//
// Detection strategy:
//   - Inject payloads in: query parameter values, URL path, HTTP headers (Referer, User-Agent, Host)
//   - Look for reflected injected header in response headers
//   - If Set-Cookie injected value appears in response → confirmed injection
//   - Detect double-encoding, mixed case, unicode variants (%E5%98%8A%E5%98%8D)
//
// Architecture:
//   - Probe struct: ID, Location (query/header), Inject (payload), InjectedHeader, InjectedValue, Severity, Tags
//   - injectTarget: builds URLs/headers with payload
//   - detectReflection: looks for InjectedHeader in response with InjectedValue
//   - errgroup.SetLimit(Parallelism) fan-out across URLs × probes
//   - io.LimitReader on all response reads
//   - log/slog observability
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) + NewWithProbes([]Probe) for testability
package crlf

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

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	DefaultTimeout     = 10 * time.Second
	DefaultParallelism = 10
	maxBodyRead        = 256 * 1024 // 256 KB

	// LocationQuery injects into a query parameter value.
	LocationQuery = "query"
	// LocationHeader injects into a request header value.
	LocationHeader = "header"
)

// ─── Probe ────────────────────────────────────────────────────────────────────

// Probe defines a CRLF injection test.
type Probe struct {
	// ID is a unique slug identifier.
	ID string
	// Location is where the payload is injected (LocationQuery or LocationHeader).
	Location string
	// Inject is the raw injection payload. {PARAM} is replaced with the current parameter name.
	Inject string
	// TargetHeader is the request header used when Location == LocationHeader.
	TargetHeader string
	// InjectedHeader is the header name expected to appear in the response.
	InjectedHeader string
	// InjectedValue is the value expected in the injected header.
	InjectedValue string
	// Severity is the finding severity.
	Severity module.Severity
	// Tags are metadata tags.
	Tags []string
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements CRLF Injection detection.
type Module struct {
	client      *http.Client
	probes      []Probe
	parallelism int
	logger      *slog.Logger
}

// New returns a Module with all built-in CRLF probes.
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

// NewWithProbes returns a Module with custom probes (testability).
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
func (m *Module) Name() string { return "crlf" }

// Run tests all target URLs for CRLF injection.
//
// Options:
//   - "parallelism" — max concurrent probes (default: 10)
//   - "location"    — comma-separated filter: "query", "header" (default: both)
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

	probes := filterProbes(m.probes, input.Options["location"])

	var (
		mu       sync.Mutex
		seen     = make(map[string]struct{})
		findings []module.Finding
	)

	addFinding := func(f module.Finding) {
		mu.Lock()
		defer mu.Unlock()
		key := f.URL + "|" + f.Type + "|" + f.Extra["probe_id"]
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			findings = append(findings, f)
		}
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(parallelism)

	for _, rawURL := range targets {
		for _, probe := range probes {
			rawURL := rawURL
			probe := probe
			eg.Go(func() error {
				fs := m.runProbe(egCtx, rawURL, probe)
				for _, f := range fs {
					addFinding(f)
				}
				return nil
			})
		}
	}

	_ = eg.Wait()
	return findings, nil
}

// runProbe executes a single CRLF probe against one URL.
func (m *Module) runProbe(ctx context.Context, rawURL string, probe Probe) []module.Finding {
	var findings []module.Finding

	switch probe.Location {
	case LocationQuery:
		findings = append(findings, m.probeQuery(ctx, rawURL, probe)...)
	case LocationHeader:
		findings = append(findings, m.probeHeader(ctx, rawURL, probe)...)
	}

	return findings
}

// probeQuery injects the payload into each query parameter value.
func (m *Module) probeQuery(ctx context.Context, rawURL string, probe Probe) []module.Finding {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	params := parsed.Query()
	if len(params) == 0 {
		// Try injecting as a new parameter if no existing ones.
		params.Set("q", "test")
	}

	var findings []module.Finding
	for param := range params {
		injected := injectValue(probe.Inject, param)
		newParams := cloneQuery(params)
		newParams.Set(param, injected)
		parsed2 := *parsed
		parsed2.RawQuery = newParams.Encode()

		f := m.sendAndDetect(ctx, parsed2.String(), nil, probe, rawURL, param)
		findings = append(findings, f...)
	}
	return findings
}

// probeHeader injects the payload into a request header.
func (m *Module) probeHeader(ctx context.Context, rawURL string, probe Probe) []module.Finding {
	injected := injectValue(probe.Inject, probe.TargetHeader)
	headers := map[string]string{
		probe.TargetHeader: injected,
	}
	return m.sendAndDetect(ctx, rawURL, headers, probe, rawURL, probe.TargetHeader)
}

// sendAndDetect sends the request and checks for CRLF injection reflection.
func (m *Module) sendAndDetect(ctx context.Context, probeURL string, extraHeaders map[string]string, probe Probe, origURL, injectionPoint string) []module.Finding {
	req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
	if err != nil {
		m.logger.DebugContext(ctx, "crlf: bad probe URL", "url", probeURL, "err", err)
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-crlf/1.0)")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		m.logger.DebugContext(ctx, "crlf: request failed", "url", probeURL, "err", err)
		return nil
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))

	if !detectReflection(resp.Header, probe.InjectedHeader, probe.InjectedValue) {
		return nil
	}

	m.logger.InfoContext(ctx, "crlf: injection detected",
		"url", origURL, "probe", probe.ID, "point", injectionPoint)

	return []module.Finding{{
		Type:     "crlf_injection",
		Severity: probe.Severity,
		URL:      origURL,
		Detail: fmt.Sprintf("[CRLF] %s injection via %s (%s): header %s=%s reflected in response",
			probe.ID, probe.Location, injectionPoint, probe.InjectedHeader, probe.InjectedValue),
		Extra: map[string]string{
			"probe_id":        probe.ID,
			"location":        probe.Location,
			"injection_point": injectionPoint,
			"injected_header": probe.InjectedHeader,
			"injected_value":  probe.InjectedValue,
			"tags":            "crlf," + strings.Join(probe.Tags, ","),
			"confidence":      "0.90", // injected CRLF header reflected in response headers
		},
	}}
}

// detectReflection checks if the injectedHeader with injectedValue appears in response headers.
func detectReflection(headers http.Header, injectedHeader, injectedValue string) bool {
	target := strings.ToLower(injectedHeader)
	for k, vals := range headers {
		if strings.ToLower(k) == target {
			for _, v := range vals {
				if strings.Contains(strings.ToLower(v), strings.ToLower(injectedValue)) {
					return true
				}
			}
		}
	}
	return false
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// injectValue replaces {PARAM} in the inject template with the actual param name.
func injectValue(inject, param string) string {
	return strings.ReplaceAll(inject, "{PARAM}", param)
}

// filterProbes filters probes by location.
func filterProbes(probes []Probe, locationFilter string) []Probe {
	if locationFilter == "" {
		return probes
	}
	allowed := make(map[string]struct{})
	for _, loc := range strings.Split(locationFilter, ",") {
		allowed[strings.TrimSpace(strings.ToLower(loc))] = struct{}{}
	}
	var out []Probe
	for _, p := range probes {
		if _, ok := allowed[p.Location]; ok {
			out = append(out, p)
		}
	}
	return out
}

func cloneQuery(src url.Values) url.Values {
	dst := make(url.Values, len(src))
	for k, vs := range src {
		dst[k] = append([]string(nil), vs...)
	}
	return dst
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

// ─── Built-in Probes ──────────────────────────────────────────────────────────

// builtinProbes returns the default CRLF injection probe set.
// Based on crlfuzz payload list (MIT) and portswigger research.
func builtinProbes() []Probe {
	const (
		// injectedHeader is the canary header injected by all probes.
		injectedHeader = "X-CRLF-Injected"
		injectedValue  = "crlftest"
	)

	// Helper — build the full payload that appends the canary header.
	// The structure is: <user_value><CRLF><injectedHeader>: <injectedValue>
	// Encoding variants of \r\n:
	type enc struct{ id, crlf string }
	encodings := []enc{
		{"plain", "%0d%0a"},
		{"lf-only", "%0a"},
		{"cr-only", "%0d"},
		{"double-encode", "%250d%250a"},
		{"double-lf", "%250a"},
		{"double-cr", "%250d"},
		{"unicode", "%E5%98%8A%E5%98%8D"},
		{"unicode-lf", "%E5%98%8A"},
		{"unicode-cr", "%E5%98%8D"},
		{"tab-space", "%09"},
		{"null-inject", "%00%0d%0a"},
	}

	var probes []Probe

	// Query injection probes — inject into query param values.
	for _, e := range encodings {
		inject := "crlfpayload" + e.crlf + injectedHeader + ":%20" + injectedValue
		probes = append(probes, Probe{
			ID:             "query-" + e.id,
			Location:       LocationQuery,
			Inject:         inject,
			InjectedHeader: injectedHeader,
			InjectedValue:  injectedValue,
			Severity:       module.SeverityHigh,
			Tags:           []string{"response-splitting", "header-injection", e.id},
		})
	}

	// Set-Cookie injection via query param.
	for _, e := range []enc{{"plain", "%0d%0a"}, {"lf-only", "%0a"}, {"unicode", "%E5%98%8A%E5%98%8D"}} {
		inject := "crlfpayload" + e.crlf + "Set-Cookie:%20crlfcookie=injected"
		probes = append(probes, Probe{
			ID:             "query-setcookie-" + e.id,
			Location:       LocationQuery,
			Inject:         inject,
			InjectedHeader: "Set-Cookie",
			InjectedValue:  "crlfcookie=injected",
			Severity:       module.SeverityHigh,
			Tags:           []string{"set-cookie", "cookie-injection", e.id},
		})
	}

	// Header-based injection — inject into Referer, User-Agent, Host headers.
	headerTargets := []string{"Referer", "User-Agent", "X-Forwarded-For"}
	for _, hdr := range headerTargets {
		for _, e := range []enc{{"plain", "%0d%0a"}, {"lf-only", "%0a"}} {
			inject := "https://attacker.example.com" + e.crlf + injectedHeader + ":%20" + injectedValue
			if hdr != "Referer" {
				inject = "legit-value" + e.crlf + injectedHeader + ":%20" + injectedValue
			}
			probes = append(probes, Probe{
				ID:             "header-" + strings.ToLower(hdr) + "-" + e.id,
				Location:       LocationHeader,
				Inject:         inject,
				TargetHeader:   hdr,
				InjectedHeader: injectedHeader,
				InjectedValue:  injectedValue,
				Severity:       module.SeverityHigh,
				Tags:           []string{"header-injection", strings.ToLower(hdr), e.id},
			})
		}
	}

	return probes
}
