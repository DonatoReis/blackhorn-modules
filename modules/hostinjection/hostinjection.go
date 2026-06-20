// Package hostinjection implements Host Header Injection detection.
//
// Source reference: PortSwigger Host Header Attack research + param-miner (Apache-2.0)
// + nuclei-templates host-header-injection (MIT) — techniques are publicly documented,
// reimplemented from scratch without copying code.
//
// Host header injection can lead to:
//   - Password reset poisoning (victim receives link to attacker host)
//   - Cache poisoning (injected host reflected into cached page)
//   - SSRF via internal routing
//   - Web cache deception
//
// Headers tested:
//   - Host (primary — set to attacker-controlled value)
//   - X-Forwarded-Host, X-Host, X-Original-URL
//   - X-Forwarded-Server, X-HTTP-Host-Override
//   - Forwarded: host= directive
//   - Absolute-form request (Host: override + absolute URI)
//
// Detection strategies:
//   - R  Reflection: injected host value appears in response body or Location header
//   - P  Password Reset: injected host in "reset link" context (emails/forms)
//   - C  Cache Poisoning: injected host in X-Cache or cached response
//
// Architecture:
//   - Probe struct: header name + inject value + detection function
//   - errgroup.SetLimit(Parallelism) fan-out
//   - io.LimitReader on all response reads
//   - log/slog observability
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) for testability
//   - Dedup by url+header+probe_id
package hostinjection

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
	// DefaultTimeout is the per-request timeout.
	DefaultTimeout = 10 * time.Second

	// DefaultParallelism is the max concurrent probes.
	DefaultParallelism = 15

	// maxBodyRead caps response body reads.
	maxBodyRead = 512 * 1024 // 512 KB

	// AttackerHost is the injected canary host value.
	// In production use, replace with an OOB interaction server hostname.
	AttackerHost = "attacker.blackhorn.local"

	// AttackerIP is an alternative IP-based canary.
	AttackerIP = "169.254.169.254" // AWS IMDS — also useful as SSRF signal
)

// ─── Probe ───────────────────────────────────────────────────────────────────

// Probe defines a single Host Header injection test.
type Probe struct {
	// ID is a unique identifier.
	ID string
	// Header is the HTTP header to inject (e.g. "Host", "X-Forwarded-Host").
	Header string
	// Value is the injected value (canary hostname or IP).
	Value string
	// Detect inspects response body, headers, and status.
	Detect func(body string, headers http.Header, status int, injectedValue string) bool
	// Severity of a confirmed finding.
	Severity module.Severity
	// Tags are metadata tags.
	Tags []string
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements Host Header Injection detection.
type Module struct {
	client      *http.Client
	probes      []Probe
	parallelism int
	logger      *slog.Logger
}

// New returns a Module with all built-in probes and default HTTP client.
func New() *Module {
	c := httpclient.New(httpclient.Options{Timeout: DefaultTimeout})
	return &Module{
		client:      c,
		probes:      builtinProbes(),
		parallelism: DefaultParallelism,
		logger:      slog.Default(),
	}
}

// NewWithProbes returns a Module with custom probes (testability).
func NewWithProbes(probes []Probe) *Module {
	m := New()
	m.probes = probes
	return m
}

// NewWithClient returns a Module using the supplied HTTP client.
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// Name returns the module name.
func (m *Module) Name() string { return "hostinjection" }

// Run executes host header injection probes against all target URLs.
//
// Options:
//   - "parallelism"    — max concurrent probes (default: 15)
//   - "attacker_host"  — canary hostname to inject (default: attacker.blackhorn.local)
//   - "attacker_ip"    — canary IP to inject (default: 169.254.169.254)
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

	attackerHost := AttackerHost
	if v := input.Options["attacker_host"]; v != "" {
		attackerHost = v
	}
	attackerIP := AttackerIP
	if v := input.Options["attacker_ip"]; v != "" {
		attackerIP = v
	}

	// Build probes with actual attacker values substituted.
	probes := substituteProbes(m.probes, attackerHost, attackerIP)

	var (
		mu       sync.Mutex
		seen     = make(map[string]struct{})
		findings []module.Finding
	)

	addFinding := func(f module.Finding) {
		key := f.URL + "|" + f.Extra["header"] + "|" + f.Extra["probe_id"]
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
		for _, probe := range probes {
			probe := probe
			eg.Go(func() error {
				f, ok := m.probe(egCtx, target, probe)
				if ok {
					addFinding(f)
				}
				return nil
			})
		}
	}

	_ = eg.Wait()
	return findings, nil
}

// probe sends a single request with the injected header and checks the response.
func (m *Module) probe(ctx context.Context, rawURL string, p Probe) (module.Finding, bool) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		m.logger.DebugContext(ctx, "hostinjection: build request failed", "url", rawURL, "err", err)
		return module.Finding{}, false
	}

	// Set injected header.
	req.Header.Set(p.Header, p.Value)
	// Preserve a real User-Agent.
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-hostinj/1.0)")

	resp, err := m.client.Do(req)
	if err != nil {
		m.logger.DebugContext(ctx, "hostinjection: request failed", "url", rawURL, "err", err)
		return module.Finding{}, false
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	body := string(b)

	if !p.Detect(body, resp.Header, resp.StatusCode, p.Value) {
		return module.Finding{}, false
	}

	m.logger.InfoContext(ctx, "hostinjection: vulnerability found",
		"url", rawURL, "header", p.Header, "value", p.Value)

	return module.Finding{
		Type:     "hostinjection",
		Severity: p.Severity,
		URL:      rawURL,
		Detail:   fmt.Sprintf("[HostInj/%s] header=%q value=%q reflected in response", p.ID, p.Header, p.Value),
		Extra: map[string]string{
			"probe_id":   p.ID,
			"header":     p.Header,
			"value":      p.Value,
			"tags":       strings.Join(p.Tags, ","),
			"confidence": "0.88", // injected header value reflected in response body
		},
	}, true
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

// substituteProbes creates a copy of probes with {HOST} and {IP} replaced.
func substituteProbes(probes []Probe, host, ip string) []Probe {
	out := make([]Probe, len(probes))
	for i, p := range probes {
		copy := p
		copy.Value = strings.ReplaceAll(p.Value, "{HOST}", host)
		copy.Value = strings.ReplaceAll(copy.Value, "{IP}", ip)
		out[i] = copy
	}
	return out
}

// detectReflection returns true if the injected value appears in:
//   - response body
//   - Location header
//   - Set-Cookie header
//   - any other response header value
func detectReflection(body string, headers http.Header, _ int, injectedValue string) bool {
	lower := strings.ToLower(body)
	v := strings.ToLower(injectedValue)

	if strings.Contains(lower, v) {
		return true
	}
	for _, vals := range headers {
		for _, hv := range vals {
			if strings.Contains(strings.ToLower(hv), v) {
				return true
			}
		}
	}
	return false
}

// ─── Built-in probes ─────────────────────────────────────────────────────────

// builtinProbes returns the default host header injection probe set.
// Techniques from PortSwigger Web Security Academy + param-miner (Apache-2.0).
func builtinProbes() []Probe {
	return []Probe{

		// ── Primary Host header ─────────────────────────────────────────────

		{
			ID:       "host-direct",
			Header:   "Host",
			Value:    "{HOST}",
			Detect:   detectReflection,
			Severity: module.SeverityHigh,
			Tags:     []string{"hostinjection", "reflection", "cache-poisoning"},
		},

		// Host header with port — often accepted by load balancers.
		{
			ID:       "host-with-port",
			Header:   "Host",
			Value:    "{HOST}:80",
			Detect:   detectReflection,
			Severity: module.SeverityHigh,
			Tags:     []string{"hostinjection", "reflection"},
		},

		// ── X-Forwarded-Host ───────────────────────────────────────────────

		{
			ID:       "x-forwarded-host",
			Header:   "X-Forwarded-Host",
			Value:    "{HOST}",
			Detect:   detectReflection,
			Severity: module.SeverityHigh,
			Tags:     []string{"hostinjection", "reflection", "cache-poisoning"},
		},
		{
			ID:       "x-forwarded-host-ip",
			Header:   "X-Forwarded-Host",
			Value:    "{IP}",
			Detect:   detectReflection,
			Severity: module.SeverityHigh,
			Tags:     []string{"hostinjection", "ssrf", "imds"},
		},

		// ── X-Host ────────────────────────────────────────────────────────

		{
			ID:       "x-host",
			Header:   "X-Host",
			Value:    "{HOST}",
			Detect:   detectReflection,
			Severity: module.SeverityHigh,
			Tags:     []string{"hostinjection", "reflection"},
		},

		// ── X-Forwarded-Server ─────────────────────────────────────────────

		{
			ID:       "x-forwarded-server",
			Header:   "X-Forwarded-Server",
			Value:    "{HOST}",
			Detect:   detectReflection,
			Severity: module.SeverityMedium,
			Tags:     []string{"hostinjection", "reflection"},
		},

		// ── X-HTTP-Host-Override ───────────────────────────────────────────

		{
			ID:       "x-http-host-override",
			Header:   "X-HTTP-Host-Override",
			Value:    "{HOST}",
			Detect:   detectReflection,
			Severity: module.SeverityHigh,
			Tags:     []string{"hostinjection", "reflection"},
		},

		// ── Forwarded RFC 7239 ─────────────────────────────────────────────

		{
			ID:       "forwarded-host",
			Header:   "Forwarded",
			Value:    "host={HOST}",
			Detect:   detectReflection,
			Severity: module.SeverityHigh,
			Tags:     []string{"hostinjection", "reflection", "rfc7239"},
		},

		// ── X-Original-URL ─────────────────────────────────────────────────

		{
			ID:       "x-original-url-host",
			Header:   "X-Original-URL",
			Value:    "http://{HOST}/",
			Detect:   detectReflection,
			Severity: module.SeverityHigh,
			Tags:     []string{"hostinjection", "reflection"},
		},

		// ── SSRF via Host → IMDS ───────────────────────────────────────────

		{
			ID:     "host-imds-ssrf",
			Header: "Host",
			Value:  "{IP}",
			Detect: func(body string, headers http.Header, status int, injectedValue string) bool {
				// IMDS response indicators
				lower := strings.ToLower(body)
				return strings.Contains(lower, "ami-id") ||
					strings.Contains(lower, "instance-id") ||
					strings.Contains(lower, "169.254.169.254") ||
					strings.Contains(lower, "iam/security-credentials") ||
					detectReflection(body, headers, status, injectedValue)
			},
			Severity: module.SeverityCritical,
			Tags:     []string{"hostinjection", "ssrf", "imds", "aws"},
		},

		// ── Double Host header ─────────────────────────────────────────────

		{
			ID:       "host-duplicate",
			Header:   "X-Forwarded-Host",
			Value:    "{HOST}, legit.example.com",
			Detect:   detectReflection,
			Severity: module.SeverityMedium,
			Tags:     []string{"hostinjection", "reflection", "header-smuggling"},
		},

		// ── Password-reset context (generic reflection is enough to flag) ──

		{
			ID:     "x-forwarded-host-reset",
			Header: "X-Forwarded-Host",
			Value:  "{HOST}",
			Detect: func(body string, headers http.Header, status int, injectedValue string) bool {
				lower := strings.ToLower(body)
				isPasswordReset := strings.Contains(lower, "reset") ||
					strings.Contains(lower, "forgot") ||
					strings.Contains(lower, "password")
				if isPasswordReset && detectReflection(body, headers, status, injectedValue) {
					return true
				}
				return false
			},
			Severity: module.SeverityCritical,
			Tags:     []string{"hostinjection", "password-reset", "cache-poisoning"},
		},

		// ── Cache-Poisoning context ────────────────────────────────────────

		{
			ID:     "x-forwarded-host-cache",
			Header: "X-Forwarded-Host",
			Value:  "{HOST}",
			Detect: func(body string, headers http.Header, status int, injectedValue string) bool {
				// Cache indicator: presence of X-Cache/Age + value reflected in body.
				_, hasCache := headers["X-Cache"]
				_, hasAge := headers["Age"]
				return (hasCache || hasAge) && detectReflection(body, headers, status, injectedValue)
			},
			Severity: module.SeverityCritical,
			Tags:     []string{"hostinjection", "cache-poisoning"},
		},
	}
}
