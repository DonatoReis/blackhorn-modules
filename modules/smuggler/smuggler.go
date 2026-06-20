// Package smuggler detects HTTP Request Smuggling vulnerabilities.
//
// Source references:
//   - http2smugl (MIT): https://github.com/neex/http2smugl
//     Technique ported: h2.te smuggling detection, header injection probes.
//   - smuggler.py (MIT): https://github.com/defparam/smuggler
//     Technique ported: CL.TE and TE.CL detection using timing and differential responses.
//   - PortSwigger Web Security Academy: HTTP Request Smuggling
//     (research by James Kettle)
//
// What is implemented:
//   - CL.TE detection (Content-Length takes priority over Transfer-Encoding)
//   - TE.CL detection (Transfer-Encoding takes priority over Content-Length)
//   - TE.TE detection (duplicate/obfuscated Transfer-Encoding headers)
//   - Obfuscated TE header probes (xchunked, chunked\t, etc.)
//   - HTTP/2 downgrade probe (h2.te surface detection)
//   - Differential response detection
//   - Timeout-based detection (server hangs on ambiguous body)
//   - io.LimitReader on every body read                  (dicas.md §5)
//   - log/slog structured observability                  (dicas.md §16)
//   - context propagation and cancellation               (guia-go §9)
package smuggler

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	probeTimeout   = 5 * time.Second
	defaultThreads = 4
)

// ─── Check ───────────────────────────────────────────────────────────────────

// Check represents a single smuggling probe.
type Check struct {
	ID          string
	Name        string
	Description string
	Severity    module.Severity
	Tags        []string
	Run         func(ctx context.Context, m *Module, target string) []module.Finding
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module is the HTTP Request Smuggling scanner.
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
		logger:  slog.Default().With("module", "smuggler"),
	}
}

// NewWithClient creates a Module with a custom HTTP client.
func NewWithClient(client *http.Client) *Module {
	m := New()
	m.client = client
	return m
}

// Name implements module.Module.
func (m *Module) Name() string { return "smuggler" }

// Run implements module.Module.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	targets := input.URLs
	if len(targets) == 0 && input.Target != "" {
		targets = []string{input.Target}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("smuggler: at least one URL required")
	}

	m.logger.InfoContext(ctx, "starting request smuggling detection", "targets", len(targets))

	findingsCh := make(chan module.Finding, 64)
	eg, gctx := errgroup.WithContext(ctx)
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

// ─── Raw TCP request helper ───────────────────────────────────────────────────

// rawRequest sends a raw HTTP/1.1 request over TCP without header normalization.
// Mirrors smuggler.py's raw socket approach — needed because Go's http.Client
// normalizes headers and prevents malformed Transfer-Encoding values.
func (m *Module) rawRequest(ctx context.Context, addr string, rawData []byte, timeout time.Duration) (string, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(rawData); err != nil {
		return "", err
	}

	var buf bytes.Buffer
	lw := &limitWriter{w: &buf, rem: int64(maxBodyRead)}
	_, _ = io.Copy(lw, conn)
	return buf.String(), nil
}

// parseAddr extracts host:port from a URL.
func parseAddr(rawURL string) string {
	s := strings.TrimPrefix(rawURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	if !strings.Contains(s, ":") {
		if strings.HasPrefix(rawURL, "https://") {
			return s + ":443"
		}
		return s + ":80"
	}
	return s
}

// parsePath extracts the path+query from a URL.
func parsePath(rawURL string) string {
	for _, prefix := range []string{"https://", "http://"} {
		rawURL = strings.TrimPrefix(rawURL, prefix)
	}
	if idx := strings.Index(rawURL, "/"); idx != -1 {
		return rawURL[idx:]
	}
	return "/"
}

// parseHost extracts the Host header value.
func parseHost(rawURL string) string {
	s := strings.TrimPrefix(rawURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	return s
}

func newFinding(checkID, checkName, target string, sev module.Severity, detail string, extra map[string]string) module.Finding {
	if extra == nil {
		extra = map[string]string{}
	}
	extra["check_id"] = checkID
	extra["check_name"] = checkName
	// Confidence reflects timing/differential certainty: timing-based = 0.75, header-based = 0.85.
	if _, ok := extra["confidence"]; !ok {
		extra["confidence"] = "0.80"
	}
	return module.Finding{
		Type:     "request_smuggling",
		Severity: sev,
		URL:      target,
		Detail:   detail,
		Extra:    extra,
	}
}

// ─── Built-in checks ─────────────────────────────────────────────────────────

func builtinChecks() []Check {
	return []Check{
		// SMUG-001 — CL.TE timing probe
		{
			ID:   "SMUG-001",
			Name: "CL.TE Request Smuggling",
			Description: "Front-end uses Content-Length, back-end uses Transfer-Encoding. " +
				"Timing probe: CL=6, body='0\\r\\n\\r\\nX'. Mirrors smuggler.py CL.TE probe.",
			Severity: module.SeverityHigh,
			Tags:     []string{"smuggling", "cl-te", "cwe-444"},
			Run: func(ctx context.Context, m *Module, target string) []module.Finding {
				addr := parseAddr(target)
				host := parseHost(target)
				path := parsePath(target)

				// CL.TE: CL=6, chunked body = "0\r\n\r\n" (5 bytes) + "X" (1 byte).
				// If front-end uses CL it forwards 6 bytes; back-end uses TE,
				// reads "0\r\n\r\n" as full response and leaves "X" as start of next request.
				payload := fmt.Sprintf(
					"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
					path, host)

				start := time.Now()
				_, err := m.rawRequest(ctx, addr, []byte(payload), probeTimeout)
				elapsed := time.Since(start)

				if err != nil && elapsed >= probeTimeout-100*time.Millisecond {
					return []module.Finding{newFinding("SMUG-001", "CL.TE Smuggling", target, module.SeverityHigh,
						fmt.Sprintf("Server timed out (%dms) on CL.TE probe. Front-end may use Content-Length while back-end uses Transfer-Encoding, enabling request smuggling (CWE-444).", elapsed.Milliseconds()),
						map[string]string{"elapsed_ms": fmt.Sprintf("%d", elapsed.Milliseconds())},
					)}
				}
				return nil
			},
		},

		// SMUG-002 — TE.CL timing probe
		{
			ID:   "SMUG-002",
			Name: "TE.CL Request Smuggling",
			Description: "Front-end uses Transfer-Encoding, back-end uses Content-Length. " +
				"Mirrors smuggler.py TE.CL timing probe.",
			Severity: module.SeverityHigh,
			Tags:     []string{"smuggling", "te-cl", "cwe-444"},
			Run: func(ctx context.Context, m *Module, target string) []module.Finding {
				addr := parseAddr(target)
				host := parseHost(target)
				path := parsePath(target)

				// TE.CL: valid chunked body, CL=3. Front-end uses TE and forwards all.
				// Back-end uses CL=3, reads only "8\r\n", leaves chunk data for next request.
				payload := fmt.Sprintf(
					"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n",
					path, host)

				start := time.Now()
				_, err := m.rawRequest(ctx, addr, []byte(payload), probeTimeout)
				elapsed := time.Since(start)

				if err != nil && elapsed >= probeTimeout-100*time.Millisecond {
					return []module.Finding{newFinding("SMUG-002", "TE.CL Smuggling", target, module.SeverityHigh,
						fmt.Sprintf("Server timed out (%dms) on TE.CL probe. Front-end may use Transfer-Encoding while back-end uses Content-Length (CWE-444).", elapsed.Milliseconds()),
						map[string]string{"elapsed_ms": fmt.Sprintf("%d", elapsed.Milliseconds())},
					)}
				}
				return nil
			},
		},

		// SMUG-003 — TE.TE obfuscated Transfer-Encoding
		{
			ID:   "SMUG-003",
			Name: "TE.TE Obfuscated Transfer-Encoding",
			Description: "Duplicate or obfuscated TE headers to confuse front-end/back-end parsing. " +
				"Mirrors smuggler.py TE obfuscation variants.",
			Severity: module.SeverityHigh,
			Tags:     []string{"smuggling", "te-te", "obfuscation"},
			Run: func(ctx context.Context, m *Module, target string) []module.Finding {
				addr := parseAddr(target)
				host := parseHost(target)
				path := parsePath(target)

				variants := []struct {
					name    string
					headers string
				}{
					{"xchunked", "Transfer-Encoding: xchunked\r\nTransfer-Encoding: chunked"},
					{"chunked_space", "Transfer-Encoding: chunked\r\nTransfer-Encoding : chunked"},
					{"x_te_header", "X-Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked"},
					{"tab_prefix", "Transfer-Encoding:\tchunked"},
					{"cow_te", "Transfer-Encoding: cow\r\nTransfer-Encoding: chunked"},
				}

				for _, variant := range variants {
					payload := fmt.Sprintf(
						"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\n%s\r\nContent-Length: 4\r\n\r\n1\r\nZ\r\nQ",
						path, host, variant.headers)

					start := time.Now()
					_, err := m.rawRequest(ctx, addr, []byte(payload), probeTimeout)
					elapsed := time.Since(start)

					if err != nil && elapsed >= probeTimeout-100*time.Millisecond {
						return []module.Finding{newFinding("SMUG-003", "TE.TE Obfuscated", target, module.SeverityHigh,
							fmt.Sprintf("Server timed out (%dms) with obfuscated TE variant %q. One endpoint accepted obfuscated TE while other didn't, enabling smuggling (CWE-444).", elapsed.Milliseconds(), variant.name),
							map[string]string{"variant": variant.name},
						)}
					}
				}
				return nil
			},
		},

		// SMUG-004 — Differential response detection
		{
			ID:   "SMUG-004",
			Name: "Differential Response (Smuggling Indicator)",
			Description: "Two identical requests produce different responses, suggesting a prior smuggling " +
				"probe left data in the back-end buffer.",
			Severity: module.SeverityMedium,
			Tags:     []string{"smuggling", "differential"},
			Run: func(ctx context.Context, m *Module, target string) []module.Finding {
				req1, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				if err != nil {
					return nil
				}
				req2 := req1.Clone(ctx)

				resp1, err := m.client.Do(req1)
				if err != nil {
					return nil
				}
				defer resp1.Body.Close()
				body1, _ := io.ReadAll(io.LimitReader(resp1.Body, maxBodyRead))

				resp2, err := m.client.Do(req2)
				if err != nil {
					return nil
				}
				defer resp2.Body.Close()
				body2, _ := io.ReadAll(io.LimitReader(resp2.Body, maxBodyRead))

				lenDiff := len(body1) - len(body2)
				if lenDiff < 0 {
					lenDiff = -lenDiff
				}
				if resp1.StatusCode != resp2.StatusCode || (lenDiff > 100 && len(body1) > 0 && lenDiff > len(body1)/4) {
					return []module.Finding{newFinding("SMUG-004", "Differential Response", target, module.SeverityMedium,
						fmt.Sprintf("Two identical GET requests returned different responses: status %d vs %d, body %d vs %d bytes. May indicate prior smuggling probe poisoned back-end buffer.",
							resp1.StatusCode, resp2.StatusCode, len(body1), len(body2)),
						map[string]string{
							"status1": fmt.Sprintf("%d", resp1.StatusCode),
							"status2": fmt.Sprintf("%d", resp2.StatusCode),
							"len1":    fmt.Sprintf("%d", len(body1)),
							"len2":    fmt.Sprintf("%d", len(body2)),
						},
					)}
				}
				return nil
			},
		},

		// SMUG-005 — HTTP/2 downgrade detection (h2.te surface)
		{
			ID:   "SMUG-005",
			Name: "HTTP/2 Downgrade Probe",
			Description: "Detects HTTP/2 support. H2→HTTP/1.1 downgrade can enable h2.te and h2.cl smuggling " +
				"(neex/http2smugl technique).",
			Severity: module.SeverityMedium,
			Tags:     []string{"smuggling", "http2", "h2-te"},
			Run: func(ctx context.Context, m *Module, target string) []module.Finding {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				if err != nil {
					return nil
				}
				resp, err := m.client.Do(req)
				if err != nil {
					return nil
				}
				defer resp.Body.Close()
				io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyRead))

				if strings.HasPrefix(resp.Proto, "HTTP/2") {
					return []module.Finding{newFinding("SMUG-005", "HTTP/2 Downgrade Surface", target, module.SeverityMedium,
						fmt.Sprintf("Server responded with %s. HTTP/2 frontends that downgrade to HTTP/1.1 for back-ends are vulnerable to h2.te and h2.cl request smuggling (neex/http2smugl).", resp.Proto),
						map[string]string{"protocol": resp.Proto},
					)}
				}
				return nil
			},
		},

		// SMUG-006 — Connection header smuggling
		{
			ID:          "SMUG-006",
			Name:        "Connection Header Smuggling Probe",
			Description: "Hop-by-hop headers via Connection can smuggle Transfer-Encoding to back-end",
			Severity:    module.SeverityMedium,
			Tags:        []string{"smuggling", "connection-header", "hop-by-hop"},
			Run: func(ctx context.Context, m *Module, target string) []module.Finding {
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, target,
					strings.NewReader("0\r\n\r\n"))
				if err != nil {
					return nil
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Content-Length", "5")
				req.Header.Set("Connection", "Transfer-Encoding")
				req.Header.Set("Transfer-Encoding", "chunked")

				resp, err := m.client.Do(req)
				if err != nil {
					return nil
				}
				defer resp.Body.Close()
				io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyRead))

				if resp.StatusCode == 200 || resp.StatusCode >= 500 {
					return []module.Finding{newFinding("SMUG-006", "Connection Header Smuggling", target, module.SeverityMedium,
						fmt.Sprintf("Server returned %d to a request with Connection: Transfer-Encoding. Front-end may not be stripping the TE header, enabling hop-by-hop smuggling.", resp.StatusCode),
						map[string]string{"status": fmt.Sprintf("%d", resp.StatusCode)},
					)}
				}
				return nil
			},
		},
	}
}

// ─── limitWriter helper ───────────────────────────────────────────────────────

type limitWriter struct {
	w   io.Writer
	rem int64
}

func (lw *limitWriter) Write(p []byte) (int, error) {
	if lw.rem <= 0 {
		return len(p), nil // discard excess
	}
	if int64(len(p)) > lw.rem {
		p = p[:lw.rem]
	}
	n, err := lw.w.Write(p)
	lw.rem -= int64(n)
	return n, err
}

// ─── HTTP client ─────────────────────────────────────────────────────────────

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 3,
			ForceAttemptHTTP2:   true,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
