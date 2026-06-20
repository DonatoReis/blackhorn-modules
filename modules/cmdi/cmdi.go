// Package cmdi implements OS Command Injection detection.
//
// Source reference: commix (GPL-3.0) technique catalogue + PayloadsAllTheThings
// command injection section (MIT) — techniques are publicly documented algorithms,
// reimplemented from scratch without copying code.
//
// Techniques implemented (mirrors commix --technique):
//   - R  Results-based:  inject command that prints unique canary → detect in response
//   - T  Time-based:     inject sleep/ping -c command → detect delay
//   - OOB (future):      OOB DNS callback support (requires interactsh OOB server)
//
// Operators tested (Unix + Windows):
//   - ; (semicolon)
//   - && (and chain)
//   - || (or chain)
//   - | (pipe)
//   - ` (backtick — command substitution)
//   - $( ) (subshell — command substitution)
//   - %0a (URL-encoded newline)
//   - \n (literal newline)
//   - {cmd,} (brace injection)
//
// Windows-specific:
//   - & (Windows chain)
//   - | (Windows pipe)
//
// Architecture:
//   - Probe struct: inject string + operator + canary detection function
//   - Canary: random 8-char hex string embedded in command output
//   - errgroup.SetLimit(Parallelism) fan-out
//   - io.LimitReader on all response reads
//   - log/slog observability
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) for testability
//   - Dedup by url+param+probe_id
package cmdi

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

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	// DefaultTimeout is the per-request timeout for results-based probes.
	DefaultTimeout = 10 * time.Second

	// DefaultTimeBasedTimeout is the timeout for time-based probes (must accommodate sleep).
	DefaultTimeBasedTimeout = 30 * time.Second

	// DefaultSleepSeconds is the sleep delay injected into time-based payloads.
	DefaultSleepSeconds = 5

	// DefaultParallelism is the max concurrent probes.
	DefaultParallelism = 15

	// maxBodyRead caps response body reads.
	maxBodyRead = 512 * 1024 // 512 KB

	// timeDeltaFactor: response is "delayed" if elapsed > sleep * factor.
	timeDeltaFactor = 0.75
)

// ─── Technique flags ──────────────────────────────────────────────────────────

const (
	TechniqueResults = "R"
	TechniqueTime    = "T"
)

// ─── Probe ───────────────────────────────────────────────────────────────────

// Probe defines a single command injection test.
type Probe struct {
	// ID is a unique identifier.
	ID string
	// Technique is R (results-based) or T (time-based).
	Technique string
	// OS targets this probe: "unix", "windows", "generic".
	OS string
	// Operator is the shell operator used (&& | ; etc.).
	Operator string
	// CmdTemplate is the command format string.
	// For R: must contain {CANARY} placeholder — printed to stdout.
	// For T: must contain {SLEEP} placeholder — sleep N seconds.
	CmdTemplate string
	// Severity of a confirmed finding.
	Severity module.Severity
	// Tags are metadata tags.
	Tags []string
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements OS Command Injection detection.
type Module struct {
	client          *http.Client
	timeBasedClient *http.Client
	probes          []Probe
	parallelism     int
	sleepSeconds    int
	techniques      map[string]bool
	logger          *slog.Logger
}

// New returns a Module with all built-in probes and default HTTP client.
func New() *Module {
	c := httpclient.New(httpclient.Options{Timeout: DefaultTimeout})
	tb := httpclient.New(httpclient.Options{Timeout: DefaultTimeBasedTimeout})
	return &Module{
		client:          c,
		timeBasedClient: tb,
		probes:          builtinProbes(),
		parallelism:     DefaultParallelism,
		sleepSeconds:    DefaultSleepSeconds,
		techniques:      map[string]bool{TechniqueResults: true, TechniqueTime: true},
		logger:          slog.Default(),
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
	m.timeBasedClient = c
	return m
}

// Name returns the module name.
func (m *Module) Name() string { return "cmdi" }

// Run executes command injection probes against all target URLs.
//
// Options supported:
//   - "parallelism"   — max concurrent probes (default: 15)
//   - "techniques"    — comma-separated R,T (default: R,T)
//   - "sleep_seconds" — sleep for time-based probes (default: 5)
//   - "os"            — target OS filter: unix, windows, generic (default: all)
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

	maxTargets := 50
	if v := input.Options["max_targets"]; v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			maxTargets = n
		}
	}
	if len(targets) > maxTargets {
		targets = targets[:maxTargets]
	}

	maxRuntimeSec := 300 // 5 minutes — time-based probes can be slow
	if v := input.Options["max_runtime_seconds"]; v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			maxRuntimeSec = n
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntimeSec)*time.Second)
	defer cancel()

	sleepSecs := m.sleepSeconds
	if v := input.Options["sleep_seconds"]; v != "" {
		if s, err := parseInt(v); err == nil && s > 0 {
			sleepSecs = s
		}
	}

	techniques := m.techniques
	if v := input.Options["techniques"]; v != "" {
		techniques = parseTechniques(v)
	}

	osFilter := strings.ToLower(strings.TrimSpace(input.Options["os"]))
	probes := m.selectProbes(techniques, osFilter)

	// Generate a session canary for results-based detection.
	canary := newCanary()

	var (
		mu       sync.Mutex
		seen     = make(map[string]struct{})
		findings []module.Finding
	)

	addFinding := func(f module.Finding) {
		key := f.URL + "|" + f.Extra["param"] + "|" + f.Extra["probe_id"]
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
		params := extractParams(target)
		if len(params) == 0 {
			m.logger.DebugContext(ctx, "cmdi: no parameters found", "url", target)
			continue
		}

		for _, param := range params {
			param := param
			for _, probe := range probes {
				probe := probe
				eg.Go(func() error {
					var (
						f  module.Finding
						ok bool
					)
					switch probe.Technique {
					case TechniqueResults:
						f, ok = m.probeResults(egCtx, target, param, probe, canary)
					case TechniqueTime:
						f, ok = m.probeTime(egCtx, target, param, probe, sleepSecs)
					}
					if ok {
						addFinding(f)
					}
					return nil
				})
			}
		}
	}

	if err := eg.Wait(); err != nil {
		return findings, fmt.Errorf("cmdi: worker failed: %w", err)
	}
	if err := runCtx.Err(); err != nil {
		return findings, fmt.Errorf("cmdi: runtime budget exceeded: %w", err)
	}
	return findings, nil
}

// probeResults: inject command that echoes a canary, detect it in response.
func (m *Module) probeResults(ctx context.Context, rawURL, param string, p Probe, canary string) (module.Finding, bool) {
	cmd := strings.ReplaceAll(p.CmdTemplate, "{CANARY}", canary)
	inject := p.Operator + cmd
	injected := injectParam(rawURL, param, inject)

	req, err := http.NewRequestWithContext(ctx, "GET", injected, nil)
	if err != nil {
		return module.Finding{}, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-cmdi/1.0)")

	resp, err := m.client.Do(req)
	if err != nil {
		m.logger.DebugContext(ctx, "cmdi: request failed", "url", injected, "err", err)
		return module.Finding{}, false
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	body := string(b)

	if !strings.Contains(body, canary) {
		return module.Finding{}, false
	}

	m.logger.InfoContext(ctx, "cmdi: results-based vuln found",
		"url", rawURL, "param", param, "probe", p.ID, "canary", canary)

	return module.Finding{
		Type:     "cmdi",
		Severity: p.Severity,
		URL:      rawURL,
		Detail:   fmt.Sprintf("[CMDi/R/%s] param=%q op=%q canary=%q found in response", p.ID, param, p.Operator, canary),
		Extra: map[string]string{
			"param":      param,
			"probe_id":   p.ID,
			"technique":  TechniqueResults,
			"operator":   p.Operator,
			"os":         p.OS,
			"inject":     inject,
			"canary":     canary,
			"tags":       strings.Join(p.Tags, ","),
			"confidence": "0.95", // canary token found in response body — definitive CMDi
		},
	}, true
}

// probeTime: inject sleep command, measure delay.
func (m *Module) probeTime(ctx context.Context, rawURL, param string, p Probe, sleepSecs int) (module.Finding, bool) {
	sleep := sleepSecs
	cmd := strings.ReplaceAll(p.CmdTemplate, "{SLEEP}", fmt.Sprintf("%d", sleep))
	inject := p.Operator + cmd
	injected := injectParam(rawURL, param, inject)

	// Baseline: clean request first.
	baseURL := injectParam(rawURL, param, "1")
	_, _, err := m.doGET(ctx, baseURL, m.client)
	if err != nil {
		return module.Finding{}, false
	}

	start := time.Now()
	_, _, err = m.doGET(ctx, injected, m.timeBasedClient)
	elapsed := time.Since(start)

	if err != nil {
		if strings.Contains(err.Error(), "deadline") || strings.Contains(err.Error(), "timeout") {
			detail := fmt.Sprintf("[CMDi/T/%s] param=%q timed out (sleep=%ds)", p.ID, param, sleep)
			return m.buildFinding(rawURL, param, p, inject, detail, TechniqueTime), true
		}
		return module.Finding{}, false
	}

	threshold := time.Duration(float64(sleep) * timeDeltaFactor * float64(time.Second))
	if elapsed < threshold {
		return module.Finding{}, false
	}

	detail := fmt.Sprintf("[CMDi/T/%s] param=%q elapsed=%s threshold=%s sleep=%ds",
		p.ID, param, elapsed.Round(time.Millisecond), threshold.Round(time.Millisecond), sleep)
	return m.buildFinding(rawURL, param, p, inject, detail, TechniqueTime), true
}

func (m *Module) buildFinding(rawURL, param string, p Probe, inject, detail, technique string) module.Finding {
	m.logger.InfoContext(context.Background(), "cmdi: time-based vuln found",
		"url", rawURL, "param", param, "probe", p.ID)
	return module.Finding{
		Type:     "cmdi",
		Severity: p.Severity,
		URL:      rawURL,
		Detail:   detail,
		Extra: map[string]string{
			"param":      param,
			"probe_id":   p.ID,
			"technique":  technique,
			"operator":   p.Operator,
			"os":         p.OS,
			"inject":     inject,
			"tags":       strings.Join(p.Tags, ","),
			"confidence": "0.80", // time-delay: threshold crossed but network jitter possible
		},
	}
}

func (m *Module) doGET(ctx context.Context, rawURL string, c *http.Client) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-cmdi/1.0)")
	resp, err := c.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return string(b), resp.StatusCode, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func extractParams(rawURL string) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var params []string
	for k := range parsed.Query() {
		params = append(params, k)
	}
	return params
}

func injectParam(rawURL, param, inject string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL + inject
	}
	q := parsed.Query()
	orig := q.Get(param)
	q.Set(param, orig+inject)
	parsed.RawQuery = q.Encode()
	return parsed.String()
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

func parseTechniques(s string) map[string]bool {
	m := make(map[string]bool)
	for _, t := range strings.Split(strings.ToUpper(s), ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			m[t] = true
		}
	}
	return m
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n, err
}

func newCanary() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "BH" + strings.ToUpper(hex.EncodeToString(b))
}

func (m *Module) selectProbes(techniques map[string]bool, osFilter string) []Probe {
	var out []Probe
	for _, p := range m.probes {
		if !techniques[p.Technique] {
			continue
		}
		if osFilter != "" && osFilter != "all" {
			if p.OS != osFilter && p.OS != "generic" {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

// ─── Built-in probes ─────────────────────────────────────────────────────────

// builtinProbes returns the default set of command injection probes.
// Payloads mirror commix technique catalogue + PayloadsAllTheThings (MIT).
func builtinProbes() []Probe {

	// ── Results-based Unix ─────────────────────────────────────────────────

	unixResultsProbes := []Probe{
		// ; operator
		{ID: "unix-semi-echo", Technique: TechniqueResults, OS: "unix", Operator: ";",
			CmdTemplate: "echo {CANARY}", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "unix"}},
		// && operator
		{ID: "unix-and-echo", Technique: TechniqueResults, OS: "unix", Operator: "&&",
			CmdTemplate: "echo {CANARY}", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "unix"}},
		// || operator
		{ID: "unix-or-echo", Technique: TechniqueResults, OS: "unix", Operator: "||",
			CmdTemplate: "echo {CANARY}", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "unix"}},
		// | pipe
		{ID: "unix-pipe-echo", Technique: TechniqueResults, OS: "unix", Operator: "|",
			CmdTemplate: "echo {CANARY}", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "unix"}},
		// backtick command substitution
		{ID: "unix-backtick", Technique: TechniqueResults, OS: "unix", Operator: "`",
			CmdTemplate: "echo {CANARY}`", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "unix", "substitution"}},
		// $() subshell
		{ID: "unix-subshell", Technique: TechniqueResults, OS: "unix", Operator: "$(",
			CmdTemplate: "echo {CANARY})", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "unix", "substitution"}},
		// URL-encoded newline
		{ID: "unix-newline-echo", Technique: TechniqueResults, OS: "unix", Operator: "%0a",
			CmdTemplate: "echo {CANARY}", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "unix", "encoded"}},
		// Literal newline
		{ID: "unix-newline-literal", Technique: TechniqueResults, OS: "unix", Operator: "\n",
			CmdTemplate: "echo {CANARY}", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "unix", "encoded"}},
		// Brace expansion
		{ID: "unix-brace", Technique: TechniqueResults, OS: "unix", Operator: ";{",
			CmdTemplate: "echo,{CANARY}}", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "unix", "obfuscated"}},
		// Space-encoded with IFS
		{ID: "unix-ifs", Technique: TechniqueResults, OS: "unix", Operator: ";",
			CmdTemplate: "echo${IFS}{CANARY}", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "unix", "obfuscated"}},
	}

	// ── Results-based Windows ──────────────────────────────────────────────

	windowsResultsProbes := []Probe{
		// & chain
		{ID: "win-amp-echo", Technique: TechniqueResults, OS: "windows", Operator: "&",
			CmdTemplate: "echo {CANARY}", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "windows"}},
		// && chain
		{ID: "win-and-echo", Technique: TechniqueResults, OS: "windows", Operator: "&&",
			CmdTemplate: "echo {CANARY}", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "windows"}},
		// || chain
		{ID: "win-or-echo", Technique: TechniqueResults, OS: "windows", Operator: "||",
			CmdTemplate: "echo {CANARY}", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "windows"}},
		// | pipe
		{ID: "win-pipe-echo", Technique: TechniqueResults, OS: "windows", Operator: "|",
			CmdTemplate: "echo {CANARY}", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "windows"}},
		// %0a newline (also works on Windows cmd sometimes)
		{ID: "win-newline", Technique: TechniqueResults, OS: "windows", Operator: "%0a",
			CmdTemplate: "echo {CANARY}", Severity: module.SeverityCritical,
			Tags: []string{"cmdi", "results", "windows", "encoded"}},
	}

	// ── Time-based Unix ────────────────────────────────────────────────────

	unixTimeProbes := []Probe{
		{ID: "unix-semi-sleep", Technique: TechniqueTime, OS: "unix", Operator: ";",
			CmdTemplate: "sleep {SLEEP}", Severity: module.SeverityHigh,
			Tags: []string{"cmdi", "time", "unix"}},
		{ID: "unix-and-sleep", Technique: TechniqueTime, OS: "unix", Operator: "&&",
			CmdTemplate: "sleep {SLEEP}", Severity: module.SeverityHigh,
			Tags: []string{"cmdi", "time", "unix"}},
		{ID: "unix-or-sleep", Technique: TechniqueTime, OS: "unix", Operator: "||",
			CmdTemplate: "sleep {SLEEP}", Severity: module.SeverityHigh,
			Tags: []string{"cmdi", "time", "unix"}},
		{ID: "unix-pipe-sleep", Technique: TechniqueTime, OS: "unix", Operator: "|",
			CmdTemplate: "sleep {SLEEP}", Severity: module.SeverityHigh,
			Tags: []string{"cmdi", "time", "unix"}},
		// ping-based timing (Linux: -c, macOS: -c also works)
		{ID: "unix-ping-sleep", Technique: TechniqueTime, OS: "unix", Operator: ";",
			CmdTemplate: "ping -c {SLEEP} 127.0.0.1", Severity: module.SeverityHigh,
			Tags: []string{"cmdi", "time", "unix", "ping"}},
		{ID: "unix-newline-sleep", Technique: TechniqueTime, OS: "unix", Operator: "%0a",
			CmdTemplate: "sleep {SLEEP}", Severity: module.SeverityHigh,
			Tags: []string{"cmdi", "time", "unix", "encoded"}},
		{ID: "unix-subshell-sleep", Technique: TechniqueTime, OS: "unix", Operator: "$(",
			CmdTemplate: "sleep {SLEEP})", Severity: module.SeverityHigh,
			Tags: []string{"cmdi", "time", "unix", "substitution"}},
	}

	// ── Time-based Windows ─────────────────────────────────────────────────

	windowsTimeProbes := []Probe{
		// ping-based timing (Windows: -n is count)
		{ID: "win-ping-sleep", Technique: TechniqueTime, OS: "windows", Operator: "&",
			CmdTemplate: "ping -n {SLEEP} 127.0.0.1", Severity: module.SeverityHigh,
			Tags: []string{"cmdi", "time", "windows", "ping"}},
		// timeout command (Windows 7+)
		{ID: "win-timeout-sleep", Technique: TechniqueTime, OS: "windows", Operator: "&&",
			CmdTemplate: "timeout /T {SLEEP}", Severity: module.SeverityHigh,
			Tags: []string{"cmdi", "time", "windows"}},
		// PowerShell sleep
		{ID: "win-powershell-sleep", Technique: TechniqueTime, OS: "windows", Operator: "&",
			CmdTemplate: "powershell -c Start-Sleep -s {SLEEP}", Severity: module.SeverityHigh,
			Tags: []string{"cmdi", "time", "windows", "powershell"}},
	}

	var all []Probe
	all = append(all, unixResultsProbes...)
	all = append(all, windowsResultsProbes...)
	all = append(all, unixTimeProbes...)
	all = append(all, windowsTimeProbes...)
	return all
}
