// Package corsaudit detects CORS misconfiguration vulnerabilities.
//
// Ported from s0md3v/Corsy (GPL-3.0 — logic reimplemented independently in Go).
// Original: https://github.com/s0md3v/Corsy
// Reference used for test-case names, origin vectors, and severity — no source
// code copied. All 8 active test cases from the original are reproduced.
//
// Test cases:
//  1. Origin Reflected         — server echoes arbitrary Origin
//  2. Post-domain Wildcard     — trusts *.target.com  (attacker.target.com)
//  3. Pre-domain Wildcard      — trusts *target.com   (eviltarget.com)
//  4. Null Origin Allowed      — trusts "null" (sandboxed iframe attack)
//  5. Unrecognised Underscore  — parser bug: target_.com treated as *.target.com
//  6. Broken Parser (backtick) — parser bug: target`.com bypasses validation
//  7. Unescaped Dot in Regex   — parser bug: targetXcom matches target.com regex
//  8. HTTP Origin Allowed      — HTTPS endpoint trusts plain-HTTP origin
package corsaudit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const moduleName = "corsaudit"

// testCase describes one CORS probe — mirrors the dict structure in corsy.
type testCase struct {
	name        string
	buildOrigin func(scheme, root, apex string) string
	description string
	severity    module.Severity
}

// activeTests mirrors corsy's active_tests list (8 cases).
var activeTests = []testCase{
	{
		name: "origin_reflected",
		buildOrigin: func(scheme, _, apex string) string {
			return scheme + "://evil-" + apex
		},
		description: "Origin Reflected — server reflects any arbitrary origin",
		severity:    module.SeverityHigh,
	},
	{
		name: "post_domain_wildcard",
		buildOrigin: func(scheme, _, apex string) string {
			return scheme + "://attacker." + apex
		},
		description: "Post-domain Wildcard — any subdomain of target trusted",
		severity:    module.SeverityHigh,
	},
	{
		name: "pre_domain_wildcard",
		buildOrigin: func(scheme, _, apex string) string {
			return scheme + "://attacker" + apex
		},
		description: "Pre-domain Wildcard — prefix bypass (eviltarget.com trusted)",
		severity:    module.SeverityHigh,
	},
	{
		name:        "null_origin",
		buildOrigin: func(_, _, _ string) string { return "null" },
		description: "Null Origin Allowed — sandboxed iframe can exfiltrate data",
		severity:    module.SeverityHigh,
	},
	{
		name: "unrecognised_underscore",
		buildOrigin: func(scheme, _, apex string) string {
			return scheme + "://" + apex + "_.attacker.com"
		},
		description: "Unrecognised Underscore — parser bug treats underscore as wildcard",
		severity:    module.SeverityMedium,
	},
	{
		name: "broken_parser_backtick",
		buildOrigin: func(scheme, _, apex string) string {
			return scheme + "://" + apex + "`.attacker.com"
		},
		description: "Broken Parser (backtick) — backtick bypasses origin validation",
		severity:    module.SeverityMedium,
	},
	{
		name: "unescaped_dot_regex",
		buildOrigin: func(scheme, _, apex string) string {
			// Replace the dot separator in apex with any character (X)
			// to test whether the regex uses an unescaped dot.
			escaped := strings.Replace(apex, ".", "x", 1)
			return scheme + "://" + escaped
		},
		description: "Unescaped Dot in Regex — dot in origin validator not escaped",
		severity:    module.SeverityMedium,
	},
	{
		name: "http_origin_allowed",
		buildOrigin: func(_, _, apex string) string {
			return "http://" + apex
		},
		description: "HTTP Origin Allowed — HTTPS endpoint trusts plain-HTTP origin",
		severity:    module.SeverityMedium,
	},
}

// Module implements module.Module for CORS misconfiguration detection.
type Module struct {
	client *http.Client
}

func New() *Module                         { return &Module{client: httpclient.Default()} }
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

func (m *Module) Name() string { return moduleName }

// Run tests each URL in input.URLs (or input.Target) against all 8 CORS
// test cases. A Finding is emitted only when a misconfiguration is confirmed.
//
// Supported options:
//   - "concurrency": number of parallel probes per URL (default "4")
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	urls := input.URLs
	if len(urls) == 0 && input.Target != "" {
		urls = []string{normalizeURL(input.Target)}
	}
	if len(urls) == 0 {
		return nil, errors.New("corsaudit: no URLs provided")
	}

	maxTargets := 100
	if v := input.Options["max_targets"]; v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			maxTargets = n
		}
	}
	if len(urls) > maxTargets {
		urls = urls[:maxTargets]
	}

	maxRuntimeSec := 300
	if v := input.Options["max_runtime_seconds"]; v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			maxRuntimeSec = n
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntimeSec)*time.Second)
	defer cancel()

	slog.Debug("corsaudit: starting", "urls", len(urls), "max_runtime_s", maxRuntimeSec)

	var findings []module.Finding
	for _, u := range urls {
		if runCtx.Err() != nil {
			break
		}
		fs, err := m.probeURL(runCtx, u)
		if err != nil {
			continue
		}
		findings = append(findings, fs...)
	}
	if err := runCtx.Err(); err != nil {
		return findings, fmt.Errorf("corsaudit: runtime budget exceeded: %w", err)
	}
	return findings, nil
}

// probeURL runs all 8 test cases against a single URL using errgroup for
// bounded concurrency — never fires goroutines without a lifecycle.
func (m *Module) probeURL(ctx context.Context, target string) ([]module.Finding, error) {
	scheme, apex, err := extractSchemeApex(target)
	if err != nil || apex == "" {
		return nil, fmt.Errorf("corsaudit: cannot parse target %q", target)
	}

	root := apex // root == apex for simplicity; full TLD-split is unnecessary
	// because we only use it to construct test origins

	type result struct {
		finding *module.Finding
	}

	results := make([]result, len(activeTests))

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(4) // bounded — no unbounded goroutine fan-out

	for i, tc := range activeTests {
		i, tc := i, tc
		g.Go(func() error {
			origin := tc.buildOrigin(scheme, root, apex)
			acao, creds, probeErr := m.probe(gctx, target, origin)
			if probeErr != nil || !isVulnerable(origin, acao) {
				return nil
			}

			sev := tc.severity
			detail := tc.description
			if creds {
				sev = module.SeverityCritical
				detail += " + credentials=true (ACAO+ACAC)"
			}

			f := module.Finding{
				Type:     "cors_misconfiguration",
				URL:      target,
				Detail:   detail,
				Severity: sev,
				Extra: map[string]string{
					"test_case":                        tc.name,
					"injected_origin":                  origin,
					"access_control_allow_origin":      acao,
					"access_control_allow_credentials": fmt.Sprintf("%v", creds),
					"confidence":                       "0.95",
				},
			}
			results[i] = result{finding: &f}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	var findings []module.Finding
	for _, r := range results {
		if r.finding != nil {
			findings = append(findings, *r.finding)
		}
	}
	return findings, nil
}

// probe sends a single request with the given Origin header and returns
// the ACAO value and whether credentials are allowed.
func (m *Module) probe(ctx context.Context, target, origin string) (acao string, creds bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Origin", origin)

	resp, err := m.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	acao = resp.Header.Get("Access-Control-Allow-Origin")
	creds = strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
	return acao, creds, nil
}

// isVulnerable returns true when the ACAO header reflects or wildcards the origin.
func isVulnerable(injected, acao string) bool {
	if acao == "" {
		return false
	}
	if acao == "*" {
		return true
	}
	return strings.EqualFold(acao, injected)
}

// extractSchemeApex returns the scheme and apex domain from a URL.
func extractSchemeApex(raw string) (scheme, apex string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("invalid URL")
	}
	host := u.Hostname()
	// apex = last two labels (e.g. sub.example.com → example.com)
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		apex = strings.Join(parts[len(parts)-2:], ".")
	} else {
		apex = host
	}
	return u.Scheme, apex, nil
}

func normalizeURL(raw string) string {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "https://" + raw
	}
	return raw
}
