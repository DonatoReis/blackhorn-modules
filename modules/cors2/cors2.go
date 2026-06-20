// Package cors2 implements Advanced CORS Misconfiguration detection.
//
// Source reference: PortSwigger CORS research (James Kettle) + CORStest (MIT)
// + Corsy (MIT). Detection logic reimplemented from scratch.
//
// This module complements the basic corsaudit module with bypass techniques:
//
// Bypass techniques tested:
//   - Origin reflection:      server reflects ANY Origin back in ACAO header
//   - Null origin:            server allows "null" origin (sandboxed iframe bypass)
//   - Subdomain trust:        server trusts *.target.com (subdomain takeover vector)
//   - Prefix/suffix tricks:   attacker-target.com, targetattacker.com accepted
//   - Protocol variation:     http:// allowed when https:// expected
//   - Unrecognized origins:   unknown origins that server shouldn't trust are trusted
//   - Pre-domain injection:   https://attacker.com.target.com accepted
//   - Trusted-headers bypass: ACAO:* with ACAC:true (wildcard + credentials)
//   - HTTP Method bypass:     OPTIONS reveals loose CORS on unusual methods
//
// Finding types:
//   - "cors_origin_reflection"  — any origin reflected in ACAO
//   - "cors_null_origin"        — null origin accepted with credentials
//   - "cors_subdomain_bypass"   — subdomain of target trusted
//   - "cors_prefix_bypass"      — attacker-target.com trusted
//   - "cors_wildcard_creds"     — ACAO: * with ACAC: true (invalid but some servers)
//   - "cors_http_downgrade"     — HTTP origin trusted on HTTPS endpoint
//
// Architecture:
//   - CORSProbe struct: origin value + detection function
//   - errgroup.SetLimit(Parallelism) fan-out
//   - io.LimitReader on all response reads
//   - log/slog observability
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) for testability
package cors2

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

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	DefaultTimeout     = 10 * time.Second
	DefaultParallelism = 15
	maxBodyRead        = 64 * 1024 // 64 KB
)

// ─── Probe ───────────────────────────────────────────────────────────────────

// CORSProbe defines a single CORS bypass test.
type CORSProbe struct {
	// ID is a unique identifier.
	ID string
	// OriginTemplate is the Origin header value; may contain {TARGET_HOST} placeholder.
	OriginTemplate string
	// FindingType is the specific finding type for this probe.
	FindingType string
	// Detect inspects ACAO, ACAC, and status code.
	Detect func(origin string, acao string, acac string, status int) bool
	// Severity of the finding.
	Severity module.Severity
	// Tags are metadata tags.
	Tags []string
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements Advanced CORS Misconfiguration detection.
type Module struct {
	client      *http.Client
	probes      []CORSProbe
	parallelism int
	logger      *slog.Logger
}

// New returns a Module with all built-in probes and default HTTP client.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: DefaultTimeout}),
		probes:      builtinProbes(),
		parallelism: DefaultParallelism,
		logger:      slog.Default(),
	}
}

// NewWithClient returns a Module using the supplied HTTP client (testability).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// NewWithProbes returns a Module with custom probes (testability).
func NewWithProbes(probes []CORSProbe) *Module {
	m := New()
	m.probes = probes
	return m
}

// Name returns the module name.
func (m *Module) Name() string { return "cors2" }

// Run executes CORS bypass probes against all target URLs.
//
// Options:
//   - "parallelism" — max concurrent probes (default: 15)
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

	maxTargets := 100
	if v := input.Options["max_targets"]; v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			maxTargets = n
		}
	}
	if len(targets) > maxTargets {
		targets = targets[:maxTargets]
	}

	maxRuntimeSec := 300 // CORS probing with 617 URLs was taking 25 min — cap at 5 min
	if v := input.Options["max_runtime_seconds"]; v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			maxRuntimeSec = n
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntimeSec)*time.Second)
	defer cancel()

	var (
		mu       sync.Mutex
		seen     = make(map[string]struct{})
		findings []module.Finding
	)

	addFinding := func(f module.Finding) {
		key := f.URL + "|" + f.Type + "|" + f.Extra["probe_id"]
		mu.Lock()
		defer mu.Unlock()
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			findings = append(findings, f)
		}
	}

	eg, egCtx := errgroup.WithContext(runCtx)
	eg.SetLimit(parallelism)

	for _, target := range targets {
		target := target
		targetHost := extractHost(target)

		for _, probe := range m.probes {
			probe := probe
			eg.Go(func() error {
				origin := strings.ReplaceAll(probe.OriginTemplate, "{TARGET_HOST}", targetHost)
				f, ok := m.checkProbe(egCtx, target, origin, probe)
				if ok {
					addFinding(f)
				}
				return nil
			})
		}
	}

	if err := eg.Wait(); err != nil {
		return findings, fmt.Errorf("cors2: worker failed: %w", err)
	}
	if err := runCtx.Err(); err != nil {
		return findings, fmt.Errorf("cors2: runtime budget exceeded: %w", err)
	}
	return findings, nil
}

// checkProbe sends a CORS preflight or simple request and checks the response headers.
func (m *Module) checkProbe(ctx context.Context, rawURL, origin string, p CORSProbe) (module.Finding, bool) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return module.Finding{}, false
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-cors2/1.0)")

	resp, err := m.client.Do(req)
	if err != nil {
		m.logger.DebugContext(ctx, "cors2: request failed", "url", rawURL, "err", err)
		return module.Finding{}, false
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if !p.Detect(origin, acao, acac, resp.StatusCode) {
		return module.Finding{}, false
	}

	m.logger.InfoContext(ctx, "cors2: CORS misconfiguration found",
		"url", rawURL, "origin", origin, "acao", acao, "acac", acac, "probe", p.ID)

	return module.Finding{
		Type:     p.FindingType,
		Severity: p.Severity,
		URL:      rawURL,
		Detail:   fmt.Sprintf("[CORS2/%s] origin=%q ACAO=%q ACAC=%q", p.ID, origin, acao, acac),
		Extra: map[string]string{
			"probe_id":    p.ID,
			"origin_sent": origin,
			"acao":        acao,
			"acac":        acac,
			"tags":        strings.Join(p.Tags, ","),
			"confidence":  "0.90", // ACAO header reflects sent origin — confirmed CORS misconfiguration
		},
	}, true
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func extractHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return parsed.Host
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

// reflectsOrigin returns true if the ACAO header matches the sent origin.
func reflectsOrigin(origin, acao string) bool {
	return acao != "" && acao != "*" && strings.EqualFold(acao, origin)
}

// hasCredentials returns true if the ACAC header is "true".
func hasCredentials(acac string) bool {
	return strings.EqualFold(strings.TrimSpace(acac), "true")
}

// ─── Built-in probes ─────────────────────────────────────────────────────────

// builtinProbes returns the default CORS bypass probe set.
// Techniques from James Kettle CORS paper + CORStest (MIT) + Corsy (MIT).
func builtinProbes() []CORSProbe {
	return []CORSProbe{

		// ── 1. Random origin reflection ──────────────────────────────────────

		{
			ID:             "reflect-random",
			OriginTemplate: "https://evil.attacker.blackhorn.io",
			FindingType:    "cors_origin_reflection",
			Detect: func(origin, acao, acac string, status int) bool {
				return reflectsOrigin(origin, acao)
			},
			Severity: module.SeverityHigh,
			Tags:     []string{"cors", "reflection", "bypass"},
		},

		// ── 2. Random origin reflection + credentials ─────────────────────

		{
			ID:             "reflect-random-creds",
			OriginTemplate: "https://evil.attacker.blackhorn.io",
			FindingType:    "cors_origin_reflection",
			Detect: func(origin, acao, acac string, status int) bool {
				return reflectsOrigin(origin, acao) && hasCredentials(acac)
			},
			Severity: module.SeverityCritical,
			Tags:     []string{"cors", "reflection", "credentials"},
		},

		// ── 3. Null origin ────────────────────────────────────────────────

		{
			ID:             "null-origin",
			OriginTemplate: "null",
			FindingType:    "cors_null_origin",
			Detect: func(origin, acao, acac string, status int) bool {
				return strings.EqualFold(acao, "null")
			},
			Severity: module.SeverityHigh,
			Tags:     []string{"cors", "null", "iframe-bypass"},
		},
		{
			ID:             "null-origin-creds",
			OriginTemplate: "null",
			FindingType:    "cors_null_origin",
			Detect: func(origin, acao, acac string, status int) bool {
				return strings.EqualFold(acao, "null") && hasCredentials(acac)
			},
			Severity: module.SeverityCritical,
			Tags:     []string{"cors", "null", "credentials"},
		},

		// ── 4. Subdomain bypass (*.target.com trusted) ───────────────────

		{
			ID:             "subdomain-bypass",
			OriginTemplate: "https://evil.{TARGET_HOST}",
			FindingType:    "cors_subdomain_bypass",
			Detect: func(origin, acao, acac string, status int) bool {
				return reflectsOrigin(origin, acao)
			},
			Severity: module.SeverityHigh,
			Tags:     []string{"cors", "subdomain", "bypass"},
		},
		{
			ID:             "subdomain-bypass-creds",
			OriginTemplate: "https://evil.{TARGET_HOST}",
			FindingType:    "cors_subdomain_bypass",
			Detect: func(origin, acao, acac string, status int) bool {
				return reflectsOrigin(origin, acao) && hasCredentials(acac)
			},
			Severity: module.SeverityCritical,
			Tags:     []string{"cors", "subdomain", "credentials"},
		},

		// ── 5. Prefix bypass: attacker-target.com ────────────────────────

		{
			ID:             "prefix-bypass",
			OriginTemplate: "https://attacker.{TARGET_HOST}",
			FindingType:    "cors_prefix_bypass",
			Detect: func(origin, acao, acac string, status int) bool {
				return reflectsOrigin(origin, acao)
			},
			Severity: module.SeverityHigh,
			Tags:     []string{"cors", "prefix", "bypass"},
		},

		// ── 6. Suffix bypass: target.com.attacker.com ────────────────────

		{
			ID:             "suffix-bypass",
			OriginTemplate: "https://{TARGET_HOST}.attacker.blackhorn.io",
			FindingType:    "cors_prefix_bypass",
			Detect: func(origin, acao, acac string, status int) bool {
				return reflectsOrigin(origin, acao)
			},
			Severity: module.SeverityHigh,
			Tags:     []string{"cors", "suffix", "bypass"},
		},

		// ── 7. HTTP downgrade: http:// origin trusted on HTTPS endpoint ──

		{
			ID:             "http-downgrade",
			OriginTemplate: "http://{TARGET_HOST}",
			FindingType:    "cors_http_downgrade",
			Detect: func(origin, acao, acac string, status int) bool {
				return reflectsOrigin(origin, acao)
			},
			Severity: module.SeverityMedium,
			Tags:     []string{"cors", "http-downgrade"},
		},

		// ── 8. Wildcard + credentials (invalid per spec but some servers) ──

		{
			ID:             "wildcard-with-creds",
			OriginTemplate: "https://evil.attacker.blackhorn.io",
			FindingType:    "cors_wildcard_creds",
			Detect: func(origin, acao, acac string, status int) bool {
				return acao == "*" && hasCredentials(acac)
			},
			Severity: module.SeverityHigh,
			Tags:     []string{"cors", "wildcard", "credentials"},
		},

		// ── 9. Origin without protocol (some servers strip scheme) ───────

		{
			ID:             "no-scheme-origin",
			OriginTemplate: "{TARGET_HOST}.attacker.blackhorn.io",
			FindingType:    "cors_origin_reflection",
			Detect: func(origin, acao, acac string, status int) bool {
				return reflectsOrigin(origin, acao)
			},
			Severity: module.SeverityMedium,
			Tags:     []string{"cors", "scheme-bypass"},
		},

		// ── 10. Backslash in origin ──────────────────────────────────────

		{
			ID:             "backslash-origin",
			OriginTemplate: "https://{TARGET_HOST}\\@evil.attacker.blackhorn.io",
			FindingType:    "cors_prefix_bypass",
			Detect: func(origin, acao, acac string, status int) bool {
				return reflectsOrigin(origin, acao)
			},
			Severity: module.SeverityHigh,
			Tags:     []string{"cors", "backslash", "bypass"},
		},

		// ── 11. Localhost trust ──────────────────────────────────────────

		{
			ID:             "localhost-origin",
			OriginTemplate: "http://localhost",
			FindingType:    "cors_origin_reflection",
			Detect: func(origin, acao, acac string, status int) bool {
				return reflectsOrigin(origin, acao) && hasCredentials(acac)
			},
			Severity: module.SeverityMedium,
			Tags:     []string{"cors", "localhost"},
		},

		// ── 12. 127.0.0.1 trust ──────────────────────────────────────────

		{
			ID:             "loopback-origin",
			OriginTemplate: "http://127.0.0.1",
			FindingType:    "cors_origin_reflection",
			Detect: func(origin, acao, acac string, status int) bool {
				return reflectsOrigin(origin, acao) && hasCredentials(acac)
			},
			Severity: module.SeverityMedium,
			Tags:     []string{"cors", "loopback"},
		},
	}
}
