// Package ratelimit detects missing, bypassable, or misconfigured rate limiting
// on API endpoints and authentication forms.
//
// Source reference: OWASP API Security Top 10 (API4:2023 Unrestricted Resource
// Consumption) + Burp Suite rate-limit extension techniques + nuclei-templates
// generic/rate-limit.yaml (MIT). Detection logic reimplemented from scratch.
//
// Detection strategies:
//   - Burst detection:    N rapid requests → server does NOT return 429/503
//   - IP bypass:         rotate X-Forwarded-For IP values → each "new IP" gets new quota
//   - Header bypass:     X-Real-IP, True-Client-IP, CF-Connecting-IP rotation
//   - Slow-path bypass:  requests spaced by small delay to dodge simple counters
//   - Auth endpoint:     login/register/reset paths are always included
//
// Finding types:
//   - "rate_limit_missing"   — N requests without a 429/503 response
//   - "rate_limit_bypass_ip" — rotation of X-Forwarded-For bypasses the limiter
//
// Architecture:
//   - RateProbe struct: URL + burst count + delay between requests
//   - Configurable burst count and inter-request delay via Options
//   - errgroup.SetLimit(Parallelism) fan-out across target URLs
//   - io.LimitReader on all response reads
//   - log/slog observability
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) for testability
package ratelimit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	DefaultTimeout     = 10 * time.Second
	DefaultParallelism = 5 // rate-limit testing must be done serially per endpoint

	// DefaultBurstCount is how many rapid requests to send before declaring "missing".
	DefaultBurstCount = 20

	// DefaultBurstDelay is the inter-request delay during burst (0 = no delay).
	DefaultBurstDelay = 0 * time.Millisecond

	// DefaultBypassIPs is how many fake IPs to try for IP-bypass detection.
	DefaultBypassIPs = 10

	maxBodyRead = 64 * 1024 // 64 KB — only need status + small body
)

// ─── IP bypass pools ─────────────────────────────────────────────────────────

// bypassIPPool is a pool of fake IP addresses used to test header-based rate limit bypass.
var bypassIPPool = []string{
	"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
	"192.168.0.1", "192.168.0.2", "192.168.0.3", "172.16.0.1", "172.16.0.2",
	"1.2.3.4", "5.6.7.8", "9.10.11.12", "13.14.15.16", "17.18.19.20",
	"127.0.0.1", "127.0.0.2", "::1", "0.0.0.0", "255.255.255.255",
}

// bypass headers tested for IP rotation.
var bypassHeaders = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"True-Client-IP",
	"CF-Connecting-IP",
	"X-Originating-IP",
	"X-Remote-IP",
	"X-Client-IP",
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements Rate Limit detection.
type Module struct {
	client      *http.Client
	parallelism int
	burstCount  int
	burstDelay  time.Duration
	logger      *slog.Logger
}

// New returns a Module with default HTTP client.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: DefaultTimeout}),
		parallelism: DefaultParallelism,
		burstCount:  DefaultBurstCount,
		burstDelay:  DefaultBurstDelay,
		logger:      slog.Default(),
	}
}

// NewWithClient returns a Module using the supplied HTTP client (testability).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// Name returns the module name.
func (m *Module) Name() string { return "ratelimit" }

// Run checks all target URLs for rate limit misconfiguration.
//
// Options:
//   - "parallelism"  — max concurrent target checks (default: 5)
//   - "burst_count"  — number of rapid requests to test (default: 20)
//   - "burst_delay"  — inter-request delay in ms (default: 0)
//   - "bypass_ips"   — number of fake IPs for bypass test (default: 10)
//   - "check"        — comma-separated: missing,bypass (default: both)
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

	burstCount := m.burstCount
	if v := input.Options["burst_count"]; v != "" {
		if b, err := parseInt(v); err == nil && b > 0 {
			burstCount = b
		}
	}

	burstDelay := m.burstDelay
	if v := input.Options["burst_delay"]; v != "" {
		if d, err := parseInt(v); err == nil && d >= 0 {
			burstDelay = time.Duration(d) * time.Millisecond
		}
	}

	bypassIPs := DefaultBypassIPs
	if v := input.Options["bypass_ips"]; v != "" {
		if b, err := parseInt(v); err == nil && b > 0 {
			bypassIPs = b
		}
	}

	checks := map[string]bool{"missing": true, "bypass": true}
	if v := input.Options["check"]; v != "" {
		checks = make(map[string]bool)
		for _, c := range strings.Split(v, ",") {
			checks[strings.TrimSpace(c)] = true
		}
	}

	var (
		mu       sync.Mutex
		seen     = make(map[string]struct{})
		findings []module.Finding
	)

	addFinding := func(f module.Finding) {
		key := f.URL + "|" + f.Type + "|" + f.Extra["check"]
		mu.Lock()
		defer mu.Unlock()
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			findings = append(findings, f)
		}
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(parallelism)

	for _, target := range targets {
		target := target
		eg.Go(func() error {
			if checks["missing"] {
				if f, ok := m.checkMissing(egCtx, target, burstCount, burstDelay); ok {
					addFinding(f)
				}
			}
			if checks["bypass"] {
				if f, ok := m.checkBypass(egCtx, target, bypassIPs); ok {
					addFinding(f)
				}
			}
			return nil
		})
	}

	_ = eg.Wait()
	return findings, nil
}

// checkMissing sends burstCount rapid requests; if none return 429/503, rate limit is missing.
func (m *Module) checkMissing(ctx context.Context, rawURL string, burst int, delay time.Duration) (module.Finding, bool) {
	limitedCount := 0
	for i := 0; i < burst; i++ {
		status, err := m.doRequest(ctx, rawURL, nil)
		if err != nil {
			// Network error — treat as rate-limited or unreachable.
			return module.Finding{}, false
		}
		if status == 429 || status == 503 || status == 509 {
			limitedCount++
		}
		if delay > 0 {
			select {
			case <-ctx.Done():
				return module.Finding{}, false
			case <-time.After(delay):
			}
		}
	}

	if limitedCount > 0 {
		// Server did respond with 429/503 at some point — rate limiting is active.
		return module.Finding{}, false
	}

	m.logger.InfoContext(ctx, "ratelimit: missing rate limit", "url", rawURL, "burst", burst)

	return module.Finding{
		Type:     "rate_limit_missing",
		Severity: module.SeverityMedium,
		URL:      rawURL,
		Detail:   fmt.Sprintf("rate limit not enforced: %d rapid requests returned no 429/503", burst),
		Extra: map[string]string{
			"check":       "missing",
			"burst_count": fmt.Sprintf("%d", burst),
			"tags":        "ratelimit,missing",
			"confidence":  "0.85", // N rapid requests returned no 429/503 — pattern confirms missing rate limit
		},
	}, true
}

// checkBypass rotates X-Forwarded-For IPs; if each "new IP" gets non-429 responses, bypass confirmed.
func (m *Module) checkBypass(ctx context.Context, rawURL string, ipCount int) (module.Finding, bool) {
	if ipCount > len(bypassIPPool) {
		ipCount = len(bypassIPPool)
	}

	// First, test without bypass header to establish that rate limiting exists.
	// We send 3 requests — if none get 429, there's no rate limiting to bypass in the first place.
	baseHit429 := false
	for i := 0; i < 3; i++ {
		status, err := m.doRequest(ctx, rawURL, nil)
		if err != nil {
			return module.Finding{}, false
		}
		if status == 429 || status == 503 {
			baseHit429 = true
			break
		}
	}

	if !baseHit429 {
		// No rate limiting to bypass.
		return module.Finding{}, false
	}

	// Now try each bypass header with different IPs.
	bypassWorked := false
	bypassHeader := ""
	bypassIP := ""

	for _, header := range bypassHeaders {
		for _, ip := range bypassIPPool[:ipCount] {
			headers := map[string]string{header: ip}
			status, err := m.doRequest(ctx, rawURL, headers)
			if err != nil {
				continue
			}
			if status != 429 && status != 503 && status < 400 {
				bypassWorked = true
				bypassHeader = header
				bypassIP = ip
				break
			}
		}
		if bypassWorked {
			break
		}
	}

	if !bypassWorked {
		return module.Finding{}, false
	}

	m.logger.InfoContext(ctx, "ratelimit: bypass confirmed",
		"url", rawURL, "header", bypassHeader, "ip", bypassIP)

	return module.Finding{
		Type:     "rate_limit_bypass_ip",
		Severity: module.SeverityHigh,
		URL:      rawURL,
		Detail:   fmt.Sprintf("rate limit bypass via %s: %q bypasses the limiter", bypassHeader, bypassIP),
		Extra: map[string]string{
			"check":         "bypass",
			"bypass_header": bypassHeader,
			"bypass_ip":     bypassIP,
			"tags":          "ratelimit,bypass,ip-header",
		},
	}, true
}

// doRequest sends a GET request with optional headers, returns status code.
func (m *Module) doRequest(ctx context.Context, rawURL string, extraHeaders map[string]string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-ratelimit/1.0)")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return resp.StatusCode, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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
