// Package cacheprobe detects web cache poisoning vulnerabilities.
//
// Source references:
//   - param-miner (Apache-2.0): https://github.com/PortSwigger/param-miner
//     Algorithm ported: unkeyed input discovery, cache buster technique,
//     header injection via unkeyed headers, fat GET probe.
//   - Web Cache Poisoning research by James Kettle (PortSwigger, 2018):
//     https://portswigger.net/research/practical-web-cache-poisoning
//
// What is implemented:
//   - Cache detection (X-Cache, Age, CF-Cache-Status headers)
//   - Unkeyed header injection (X-Forwarded-Host, X-Host, X-Forwarded-Scheme)
//   - Fat GET request probe (body in GET request, mirrors param-miner)
//   - Cache-Control misconfiguration (no-store missing on sensitive pages)
//   - Vary header analysis (missing Vary: Origin for CORS responses)
//   - X-Original-URL / X-Rewrite-URL path override
//   - Cache-buster technique to avoid poisoning real cached content
//   - io.LimitReader on every body read                  (dicas.md §5)
//   - log/slog structured observability                  (dicas.md §16)
//   - context propagation and cancellation               (guia-go §9)
//   - errgroup.SetLimit bounded fan-out                  (guia-go §9)
package cacheprobe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	maxBodyRead    = 2 * 1024 * 1024 // 2 MiB — dicas.md §5
	defaultTimeout = 15 * time.Second
	defaultThreads = 6
)

// ─── Check ───────────────────────────────────────────────────────────────────

// Check represents a single cache poisoning probe.
type Check struct {
	ID          string
	Name        string
	Description string
	Severity    module.Severity
	Tags        []string
	Run         func(ctx context.Context, m *Module, target string) []module.Finding
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module is the cacheprobe scanner.
type Module struct {
	checks  []Check
	client  *http.Client
	threads int
	logger  *slog.Logger
}

// New creates a Module with all built-in checks.
func New() *Module {
	return NewWithChecks(builtinChecks())
}

// NewWithChecks creates a Module with the provided checks.
func NewWithChecks(checks []Check) *Module {
	return &Module{
		checks:  checks,
		client:  defaultHTTPClient(),
		threads: defaultThreads,
		logger:  slog.Default().With("module", "cacheprobe"),
	}
}

// NewWithClient creates a Module with a custom HTTP client.
func NewWithClient(client *http.Client) *Module {
	m := New()
	m.client = client
	return m
}

// Name implements module.Module.
func (m *Module) Name() string { return "cacheprobe" }

// Run implements module.Module.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	targets := input.URLs
	if len(targets) == 0 && input.Target != "" {
		targets = []string{input.Target}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("cacheprobe: at least one URL required")
	}

	maxTargets := 100
	if v := input.Options["max_targets"]; v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			maxTargets = n
		}
	}
	if len(targets) > maxTargets {
		targets = targets[:maxTargets]
	}

	maxRuntimeSec := 180
	if v := input.Options["max_runtime_seconds"]; v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			maxRuntimeSec = n
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntimeSec)*time.Second)
	defer cancel()

	m.logger.InfoContext(runCtx, "starting cache poisoning audit",
		"targets", len(targets), "max_runtime_s", maxRuntimeSec)

	findingsCh := make(chan module.Finding, 128)
	eg, gctx := errgroup.WithContext(runCtx)
	eg.SetLimit(m.threads)

	for _, target := range targets {
		target := target
		for _, chk := range m.checks {
			chk := chk
			eg.Go(func() error {
				findings := chk.Run(gctx, m, target)
				for _, f := range findings {
					select {
					case findingsCh <- f:
					case <-gctx.Done():
						return nil
					}
				}
				return nil
			})
		}
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- eg.Wait()
		close(findingsCh)
	}()

	var results []module.Finding
	for f := range findingsCh {
		results = append(results, f)
	}
	if err := <-waitCh; err != nil {
		return results, fmt.Errorf("cacheprobe: worker failed: %w", err)
	}
	if err := runCtx.Err(); err != nil {
		return results, fmt.Errorf("cacheprobe: runtime budget exceeded: %w", err)
	}
	return results, nil
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

// cacheBuster returns a random 8-hex-char string for cache busting.
// Mirrors param-miner's cache buster technique.
func cacheBuster() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type result struct {
	resp    *http.Response
	body    string
	headers http.Header
}

func (m *Module) do(ctx context.Context, req *http.Request) (*result, error) {
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead)) // dicas.md §5
	if err != nil {
		return &result{resp: resp, headers: resp.Header}, err
	}
	return &result{resp: resp, body: string(body), headers: resp.Header}, nil
}

func (m *Module) get(ctx context.Context, u string, headers map[string]string) (*result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-cacheprobe/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return m.do(ctx, req)
}

func newFinding(checkID, checkName, target string, sev module.Severity, detail string, extra map[string]string) module.Finding {
	if extra == nil {
		extra = map[string]string{}
	}
	extra["check_id"] = checkID
	extra["check_name"] = checkName
	extra["confidence"] = "0.85"
	return module.Finding{
		Type:     "cache_poisoning",
		Severity: sev,
		URL:      target,
		Detail:   detail,
		Extra:    extra,
	}
}

// ─── Built-in checks ─────────────────────────────────────────────────────────

func builtinChecks() []Check {
	return []Check{
		// CACHE-001 — Cache detection
		{
			ID:          "CACHE-001",
			Name:        "Cache Detection",
			Description: "Detect if a caching layer is present via response headers",
			Severity:    module.SeverityInfo,
			Tags:        []string{"cache", "detection"},
			Run: func(ctx context.Context, m *Module, target string) []module.Finding {
				r, err := m.get(ctx, target, nil)
				if err != nil {
					return nil
				}
				cacheHeaders := []string{
					"X-Cache", "CF-Cache-Status", "Age", "X-Varnish",
					"X-Cache-Hits", "Surrogate-Control", "CDN-Cache-Control",
				}
				var detected []string
				for _, h := range cacheHeaders {
					if v := r.headers.Get(h); v != "" {
						detected = append(detected, h+": "+v)
					}
				}
				if len(detected) == 0 {
					return nil
				}
				return []module.Finding{newFinding("CACHE-001", "Cache Detection", target, module.SeverityInfo,
					"Response headers indicate a caching layer is present. Further cache poisoning tests are applicable.",
					map[string]string{"cache_headers": strings.Join(detected, "; ")},
				)}
			},
		},

		// CACHE-002 — X-Forwarded-Host injection (unkeyed header)
		{
			ID:          "CACHE-002",
			Name:        "X-Forwarded-Host Injection",
			Description: "Unkeyed X-Forwarded-Host header reflected in response, enabling cache poisoning",
			Severity:    module.SeverityHigh,
			Tags:        []string{"cache-poisoning", "unkeyed-header"},
			Run: func(ctx context.Context, m *Module, target string) []module.Finding {
				buster := cacheBuster()
				probeURL := addBuster(target, buster)
				canary := "evil-" + buster + ".example.com"
				r, err := m.get(ctx, probeURL, map[string]string{"X-Forwarded-Host": canary})
				if err != nil {
					return nil
				}
				loc := r.headers.Get("Location")
				if strings.Contains(r.body, canary) || strings.Contains(loc, canary) {
					return []module.Finding{newFinding("CACHE-002", "X-Forwarded-Host Injection", target, module.SeverityHigh,
						fmt.Sprintf("X-Forwarded-Host: %s was reflected in the response. Unkeyed header enables cache poisoning to inject arbitrary content.", canary),
						map[string]string{"canary": canary},
					)}
				}
				return nil
			},
		},

		// CACHE-003 — X-Host header injection
		{
			ID:          "CACHE-003",
			Name:        "X-Host Header Injection",
			Description: "Unkeyed X-Host header reflected in response",
			Severity:    module.SeverityHigh,
			Tags:        []string{"cache-poisoning", "unkeyed-header"},
			Run: func(ctx context.Context, m *Module, target string) []module.Finding {
				buster := cacheBuster()
				canary := "evil-" + buster + ".example.com"
				r, err := m.get(ctx, addBuster(target, buster), map[string]string{"X-Host": canary})
				if err != nil {
					return nil
				}
				if strings.Contains(r.body, canary) {
					return []module.Finding{newFinding("CACHE-003", "X-Host Injection", target, module.SeverityHigh,
						fmt.Sprintf("X-Host: %s was reflected in the response body (unkeyed header).", canary),
						map[string]string{"canary": canary},
					)}
				}
				return nil
			},
		},

		// CACHE-004 — X-Forwarded-Scheme injection
		{
			ID:          "CACHE-004",
			Name:        "X-Forwarded-Scheme Injection",
			Description: "Unkeyed X-Forwarded-Scheme can downgrade to HTTP",
			Severity:    module.SeverityMedium,
			Tags:        []string{"cache-poisoning", "unkeyed-header", "https-downgrade"},
			Run: func(ctx context.Context, m *Module, target string) []module.Finding {
				buster := cacheBuster()
				r, err := m.get(ctx, addBuster(target, buster), map[string]string{
					"X-Forwarded-Scheme": "http",
					"X-Forwarded-Proto":  "http",
				})
				if err != nil {
					return nil
				}
				loc := r.headers.Get("Location")
				if r.resp != nil && r.resp.StatusCode >= 300 && r.resp.StatusCode < 400 &&
					strings.HasPrefix(loc, "http://") {
					return []module.Finding{newFinding("CACHE-004", "X-Forwarded-Scheme Downgrade", target, module.SeverityMedium,
						fmt.Sprintf("Server redirected to %q when X-Forwarded-Scheme: http was sent. Caching this redirect can force HTTPS users to HTTP.", loc),
						map[string]string{"location": loc},
					)}
				}
				return nil
			},
		},

		// CACHE-005 — Fat GET probe (mirrors param-miner)
		{
			ID:          "CACHE-005",
			Name:        "Fat GET Body Accepted",
			Description: "Server accepts request body in GET requests (fat GET), which may be unkeyed by cache",
			Severity:    module.SeverityMedium,
			Tags:        []string{"cache-poisoning", "fat-get"},
			Run: func(ctx context.Context, m *Module, target string) []module.Finding {
				buster := cacheBuster()
				canary := "fatget_" + buster
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, target,
					strings.NewReader("search="+canary))
				if err != nil {
					return nil
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("User-Agent", "blackhorn-cacheprobe/1.0")

				r, err := m.do(ctx, req)
				if err != nil {
					return nil
				}
				if strings.Contains(r.body, canary) {
					return []module.Finding{newFinding("CACHE-005", "Fat GET Body Accepted", target, module.SeverityMedium,
						fmt.Sprintf("GET request body parameter %q was reflected. If cache ignores request body (common), this enables parameter injection via fat GET.", canary),
						map[string]string{"canary": canary},
					)}
				}
				return nil
			},
		},

		// CACHE-006 — Cache-Control misconfiguration
		{
			ID:          "CACHE-006",
			Name:        "Sensitive Page Cacheable",
			Description: "Authentication-related page missing Cache-Control: no-store",
			Severity:    module.SeverityMedium,
			Tags:        []string{"cache", "sensitive-data"},
			Run: func(ctx context.Context, m *Module, target string) []module.Finding {
				for _, suffix := range []string{"/login", "/account", "/profile", "/dashboard", "/admin"} {
					probeURL := strings.TrimRight(target, "/") + suffix
					r, err := m.get(ctx, probeURL, nil)
					if err != nil || r.resp == nil || r.resp.StatusCode != 200 {
						continue
					}
					cc := r.headers.Get("Cache-Control")
					if !strings.Contains(cc, "no-store") && !strings.Contains(cc, "private") {
						return []module.Finding{newFinding("CACHE-006", "Sensitive Page Cacheable", probeURL, module.SeverityMedium,
							fmt.Sprintf("Path %q returned 200 without Cache-Control: no-store or private (got: %q). Sensitive data may be cached.", suffix, cc),
							map[string]string{"cache_control": cc, "path": suffix},
						)}
					}
				}
				return nil
			},
		},

		// CACHE-007 — Vary: Origin missing on CORS response
		{
			ID:          "CACHE-007",
			Name:        "Missing Vary: Origin on CORS Response",
			Description: "CORS response missing Vary: Origin can cause incorrect caching of ACAO header",
			Severity:    module.SeverityMedium,
			Tags:        []string{"cache", "cors", "vary"},
			Run: func(ctx context.Context, m *Module, target string) []module.Finding {
				r, err := m.get(ctx, target, map[string]string{"Origin": "https://test.example.com"})
				if err != nil {
					return nil
				}
				acao := r.headers.Get("Access-Control-Allow-Origin")
				if acao == "" {
					return nil
				}
				vary := r.headers.Get("Vary")
				if !strings.Contains(strings.ToLower(vary), "origin") {
					return []module.Finding{newFinding("CACHE-007", "Missing Vary: Origin", target, module.SeverityMedium,
						fmt.Sprintf("Response includes ACAO: %q but Vary is %q. Without Vary: Origin, caches may serve wrong ACAO header to different origins.", acao, vary),
						map[string]string{"acao": acao, "vary": vary},
					)}
				}
				return nil
			},
		},

		// CACHE-008 — X-Original-URL path override
		{
			ID:          "CACHE-008",
			Name:        "X-Original-URL Path Override",
			Description: "X-Original-URL header overrides the request path (may be unkeyed)",
			Severity:    module.SeverityHigh,
			Tags:        []string{"cache-poisoning", "unkeyed-header", "path-override"},
			Run: func(ctx context.Context, m *Module, target string) []module.Finding {
				buster := cacheBuster()
				r, err := m.get(ctx, addBuster(target, buster), map[string]string{
					"X-Original-URL": "/admin",
					"X-Rewrite-URL":  "/admin",
				})
				if err != nil {
					return nil
				}
				if strings.Contains(r.body, "admin") || strings.Contains(r.body, "dashboard") {
					return []module.Finding{newFinding("CACHE-008", "X-Original-URL Path Override", target, module.SeverityHigh,
						"Server appears to have served a different path via X-Original-URL header. If cached, enables bypassing access controls via cache poisoning.",
						nil,
					)}
				}
				return nil
			},
		},
	}
}

// addBuster appends a random cache buster parameter to a URL.
func addBuster(u, buster string) string {
	if strings.Contains(u, "?") {
		return u + "&" + buster + "=1"
	}
	return u + "?" + buster + "=1"
}

// ─── HTTP client ─────────────────────────────────────────────────────────────

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			MaxIdleConns:        20,
			MaxIdleConnsPerHost: 5,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
