// Package openredirect implements Open Redirect vulnerability detection.
//
// Source reference: dalfox-openredirect (MIT) +
// PayloadsAllTheThings/Open-Redirect (MIT) +
// PortSwigger Web Security Academy open-redirect research.
// Detection logic reimplemented from scratch.
//
// Open Redirect occurs when a web application accepts user-controlled input
// that specifies a URL to redirect to. Attackers abuse this for phishing,
// token theft, OAuth token leakage, and SSRF escalation.
//
// Detection strategy:
//   - Inject redirect payloads into: query parameter values containing
//     redirect-like keywords (redirect, return, url, next, to, goto, dest,
//     destination, forward, r, u, location, target, link, ref, ret, redir, ru,
//     continue, returnto, returnurl, redirect_url, redirect_uri, callback,
//     success_url, cancel_url, logout_url, error_url)
//   - Detect via: Location header pointing to attacker domain,
//     body containing attacker domain in href/src/window.location
//   - Bypass variants: // attacker.com, https://attacker.com,
//     https:attacker.com, \attacker.com, //attacker.com%2F@target.com,
//     attacker.com, ///attacker.com, /%09//attacker.com, data: scheme,
//     https://attacker.com?q=target.com (trusted domain as param)
//
// Architecture:
//   - Probe struct: ID, Inject (payload with {ATTACKER} placeholder), Detect func
//   - extractRedirectParams: detect redirect-like param names
//   - errgroup.SetLimit(Parallelism) fan-out
//   - io.LimitReader on all response reads
//   - log/slog observability
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) + NewWithProbes([]Probe) for testability
package openredirect

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

	// DefaultAttacker is the attacker domain used in probes.
	DefaultAttacker = "blackhorn-redir.attacker.net"
)

// redirectParamKeywords are parameter names that indicate redirect handling.
var redirectParamKeywords = []string{
	"redirect", "return", "url", "next", "to", "goto", "dest", "destination",
	"forward", "r", "u", "location", "target", "link", "ref", "ret", "redir",
	"ru", "continue", "returnto", "returnurl", "redirect_url", "redirect_uri",
	"callback", "success_url", "cancel_url", "logout_url", "error_url",
	"back", "backurl", "returl", "relaystate", "origin", "checkout",
}

// ─── Probe ────────────────────────────────────────────────────────────────────

// Probe defines a redirect injection test.
type Probe struct {
	// ID is a unique slug.
	ID string
	// Inject is the payload value. {ATTACKER} is replaced with the attacker domain.
	Inject string
	// Detect tests the response for successful redirect.
	Detect func(resp *http.Response, body, attacker string) bool
	// Severity is the finding severity.
	Severity module.Severity
	// Tags are metadata tags.
	Tags []string
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements Open Redirect detection.
type Module struct {
	client      *http.Client
	probes      []Probe
	parallelism int
	attacker    string
	logger      *slog.Logger
}

// New returns a Module with all built-in open redirect probes.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: DefaultTimeout}),
		probes:      builtinProbes(),
		parallelism: DefaultParallelism,
		attacker:    DefaultAttacker,
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
func (m *Module) Name() string { return "openredirect" }

// Run tests all target URLs for open redirect vulnerabilities.
//
// Options:
//   - "parallelism" — max concurrent probes (default: 10)
//   - "attacker"    — attacker domain to inject (default: blackhorn-redir.attacker.net)
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
	attacker := m.attacker
	if v := input.Options["attacker"]; v != "" {
		attacker = v
	}

	var (
		mu       sync.Mutex
		seen     = make(map[string]struct{})
		findings []module.Finding
	)

	addFinding := func(f module.Finding) {
		mu.Lock()
		defer mu.Unlock()
		key := f.URL + "|" + f.Extra["probe_id"] + "|" + f.Extra["param"]
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			findings = append(findings, f)
		}
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(parallelism)

	for _, rawURL := range targets {
		params := extractRedirectParams(rawURL)
		if len(params) == 0 {
			continue
		}
		for _, probe := range m.probes {
			for _, param := range params {
				rawURL := rawURL
				probe := probe
				param := param
				eg.Go(func() error {
					f := m.runProbe(egCtx, rawURL, probe, param, attacker)
					if f != nil {
						addFinding(*f)
					}
					return nil
				})
			}
		}
	}

	_ = eg.Wait()
	return findings, nil
}

func (m *Module) runProbe(ctx context.Context, rawURL string, probe Probe, param, attacker string) *module.Finding {
	inject := strings.ReplaceAll(probe.Inject, "{ATTACKER}", attacker)

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	q := parsed.Query()
	q.Set(param, inject)
	parsed.RawQuery = q.Encode()
	probeURL := parsed.String()

	// Use a non-following client to detect Location header directly.
	noRedir := noRedirectClient(m.client)

	req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-openredirect/1.0)")

	resp, err := noRedir.Do(req)
	if err != nil {
		m.logger.DebugContext(ctx, "openredirect: request failed", "url", probeURL, "err", err)
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))

	if !probe.Detect(resp, string(body), attacker) {
		return nil
	}

	m.logger.InfoContext(ctx, "openredirect: found",
		"url", rawURL, "probe", probe.ID, "param", param)

	return &module.Finding{
		Type:     "open_redirect",
		Severity: probe.Severity,
		URL:      rawURL,
		Detail: fmt.Sprintf("[OpenRedirect] %s via param=%s → %s",
			probe.ID, param, inject),
		Extra: map[string]string{
			"probe_id":    probe.ID,
			"param":       param,
			"inject":      inject,
			"status_code": fmt.Sprintf("%d", resp.StatusCode),
			"tags":        "openredirect," + strings.Join(probe.Tags, ","),
			"confidence":  "0.90",
		},
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// extractRedirectParams returns query parameter names that look like redirects.
func extractRedirectParams(rawURL string) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	q := parsed.Query()
	if len(q) == 0 {
		return nil
	}

	var out []string
	for param := range q {
		pLower := strings.ToLower(param)
		for _, kw := range redirectParamKeywords {
			if pLower == kw || strings.Contains(pLower, kw) {
				out = append(out, param)
				break
			}
		}
	}
	return out
}

// noRedirectClient returns a copy of the client that does NOT follow redirects,
// so we can inspect the Location header directly.
func noRedirectClient(base *http.Client) *http.Client {
	copy := *base
	copy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &copy
}

// locationPointsTo checks if Location header points to the attacker domain.
func locationPointsTo(resp *http.Response, attacker string) bool {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return false
	}
	locLower := strings.ToLower(loc)
	attackerLower := strings.ToLower(attacker)
	return strings.Contains(locLower, attackerLower)
}

// bodyContainsAttacker checks if response body references the attacker domain.
func bodyContainsAttacker(body, attacker string) bool {
	return strings.Contains(strings.ToLower(body), strings.ToLower(attacker))
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

// builtinProbes returns the default open redirect probe set.
// Based on PayloadsAllTheThings/Open-Redirect (MIT) and dalfox (MIT) payloads.
func builtinProbes() []Probe {
	detect := func(resp *http.Response, body, attacker string) bool {
		return locationPointsTo(resp, attacker) || bodyContainsAttacker(body, attacker)
	}

	return []Probe{
		{
			ID:       "absolute-https",
			Inject:   "https://{ATTACKER}",
			Detect:   detect,
			Severity: module.SeverityHigh,
			Tags:     []string{"absolute", "https"},
		},
		{
			ID:       "absolute-http",
			Inject:   "http://{ATTACKER}",
			Detect:   detect,
			Severity: module.SeverityHigh,
			Tags:     []string{"absolute", "http"},
		},
		{
			ID:       "double-slash",
			Inject:   "//{ATTACKER}",
			Detect:   detect,
			Severity: module.SeverityHigh,
			Tags:     []string{"scheme-relative", "double-slash"},
		},
		{
			ID:       "triple-slash",
			Inject:   "///{ATTACKER}",
			Detect:   detect,
			Severity: module.SeverityHigh,
			Tags:     []string{"triple-slash"},
		},
		{
			ID:       "backslash",
			Inject:   "\\{ATTACKER}",
			Detect:   detect,
			Severity: module.SeverityHigh,
			Tags:     []string{"backslash"},
		},
		{
			ID:       "https-colon-noslash",
			Inject:   "https:{ATTACKER}",
			Detect:   detect,
			Severity: module.SeverityMedium,
			Tags:     []string{"no-slashes"},
		},
		{
			ID:       "attacker-as-param",
			Inject:   "https://trusted.example.com?x={ATTACKER}",
			Detect:   detect,
			Severity: module.SeverityLow,
			Tags:     []string{"param-confusion"},
		},
		{
			ID:       "tab-bypass",
			Inject:   "https://{ATTACKER}%09",
			Detect:   detect,
			Severity: module.SeverityHigh,
			Tags:     []string{"tab-bypass"},
		},
		{
			ID:       "null-byte",
			Inject:   "https://{ATTACKER}%00",
			Detect:   detect,
			Severity: module.SeverityHigh,
			Tags:     []string{"null-byte"},
		},
		{
			ID:       "at-sign-bypass",
			Inject:   "https://trusted@{ATTACKER}",
			Detect:   detect,
			Severity: module.SeverityHigh,
			Tags:     []string{"at-sign"},
		},
		{
			ID:       "double-encode",
			Inject:   "https%3A%2F%2F{ATTACKER}",
			Detect:   detect,
			Severity: module.SeverityMedium,
			Tags:     []string{"double-encode"},
		},
		{
			ID:       "whitespace-prefix",
			Inject:   " https://{ATTACKER}",
			Detect:   detect,
			Severity: module.SeverityMedium,
			Tags:     []string{"whitespace"},
		},
	}
}
