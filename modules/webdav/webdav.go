// Package webdav implements WebDAV misconfiguration detection.
//
// Source reference: nuclei-templates/network/webdav (MIT) +
// dalfox-webdav + WFuzz WebDAV detection techniques.
// Detection logic reimplemented from scratch.
//
// WebDAV misconfigurations allow attackers to:
//   - List directory contents (PROPFIND enabled)
//   - Upload arbitrary files (PUT enabled) — leads to RCE
//   - Delete files (DELETE enabled)
//   - Overwrite files (COPY/MOVE enabled)
//   - Access server internal structure (OPTIONS discloses DAV: header)
//
// Detection checks:
//  1. OPTIONS → check Allow: header for dangerous methods (PUT/DELETE/PROPFIND/MKCOL)
//     and DAV: header presence
//  2. PROPFIND / → check if server returns 207 Multi-Status
//  3. PUT attempt with random canary filename → 201 Created = critical
//  4. MKCOL attempt with random directory name → 201 Created = critical
//  5. Sensitive method disclosure via Allow header analysis
//
// Architecture:
//   - Check struct: ID, Method, Path, Detect func, Severity, Tags
//   - errgroup.SetLimit(Parallelism) fan-out
//   - io.LimitReader on all response reads
//   - log/slog observability
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) for testability
package webdav

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	DefaultTimeout     = 10 * time.Second
	DefaultParallelism = 10
	maxBodyRead        = 128 * 1024 // 128 KB
)

// dangerousMethods is the list of HTTP methods that indicate WebDAV misconfig.
var dangerousMethods = []string{"PUT", "DELETE", "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "PATCH"}

// ─── Check ────────────────────────────────────────────────────────────────────

// Check defines a WebDAV test.
type Check struct {
	// ID is a unique slug.
	ID string
	// Severity is the finding severity.
	Severity module.Severity
	// Tags are metadata tags.
	Tags []string
	// Run executes the check against the target URL.
	Run func(ctx context.Context, client *http.Client, rawURL string) *module.Finding
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements WebDAV misconfiguration detection.
type Module struct {
	client      *http.Client
	parallelism int
	logger      *slog.Logger
}

// New returns a Module with default settings.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: DefaultTimeout}),
		parallelism: DefaultParallelism,
		logger:      slog.Default(),
	}
}

// NewWithClient returns a Module using the supplied HTTP client.
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// Name returns the module name.
func (m *Module) Name() string { return "webdav" }

// Run tests all target URLs for WebDAV misconfigurations.
//
// Options:
//   - "parallelism" — max concurrent checks (default: 10)
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

	checks := builtinChecks(m.client, m.logger)

	var (
		mu       sync.Mutex
		seen     = make(map[string]struct{})
		findings []module.Finding
	)

	addFinding := func(f module.Finding) {
		mu.Lock()
		defer mu.Unlock()
		key := f.URL + "|" + f.Type + "|" + f.Extra["check_id"]
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			findings = append(findings, f)
		}
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(parallelism)

	for _, rawURL := range targets {
		for _, check := range checks {
			rawURL := rawURL
			check := check
			eg.Go(func() error {
				f := check.Run(egCtx, m.client, rawURL)
				if f != nil {
					f.Extra["check_id"] = check.ID
					addFinding(*f)
				}
				return nil
			})
		}
	}

	_ = eg.Wait()
	return findings, nil
}

// ─── Built-in Checks ──────────────────────────────────────────────────────────

func builtinChecks(client *http.Client, logger *slog.Logger) []Check {
	return []Check{
		{
			ID:       "options-dav-header",
			Severity: module.SeverityMedium,
			Tags:     []string{"webdav", "options", "fingerprint"},
			Run: func(ctx context.Context, c *http.Client, rawURL string) *module.Finding {
				resp, body, err := doRequest(ctx, c, "OPTIONS", rawURL, nil)
				if err != nil {
					logger.DebugContext(ctx, "webdav: OPTIONS failed", "url", rawURL, "err", err)
					return nil
				}
				dav := resp.Header.Get("DAV")
				allow := resp.Header.Get("Allow")
				if dav == "" && !strings.Contains(strings.ToUpper(allow), "PROPFIND") {
					return nil
				}
				return &module.Finding{
					Type:     "webdav_enabled",
					Severity: module.SeverityMedium,
					URL:      rawURL,
					Detail:   fmt.Sprintf("[WebDAV] DAV header present: DAV=%q Allow=%q", dav, allow),
					Extra: map[string]string{
						"dav_header":   dav,
						"allow_header": allow,
						"body_preview": bodyPreview(body),
						"tags":         "webdav,options",
						"confidence":   "0.90",
					},
				}
			},
		},
		{
			ID:       "options-dangerous-methods",
			Severity: module.SeverityHigh,
			Tags:     []string{"webdav", "options", "methods"},
			Run: func(ctx context.Context, c *http.Client, rawURL string) *module.Finding {
				resp, _, err := doRequest(ctx, c, "OPTIONS", rawURL, nil)
				if err != nil {
					return nil
				}
				allow := strings.ToUpper(resp.Header.Get("Allow"))
				var found []string
				for _, m := range dangerousMethods {
					if strings.Contains(allow, m) {
						found = append(found, m)
					}
				}
				if len(found) == 0 {
					return nil
				}
				return &module.Finding{
					Type:     "webdav_dangerous_methods",
					Severity: module.SeverityHigh,
					URL:      rawURL,
					Detail:   fmt.Sprintf("[WebDAV] Dangerous methods allowed: %s", strings.Join(found, ", ")),
					Extra: map[string]string{
						"allowed_methods": strings.Join(found, ","),
						"tags":            "webdav,dangerous-methods",
						"confidence":      "0.90",
					},
				}
			},
		},
		{
			ID:       "propfind-listing",
			Severity: module.SeverityHigh,
			Tags:     []string{"webdav", "propfind", "listing"},
			Run: func(ctx context.Context, c *http.Client, rawURL string) *module.Finding {
				body := `<?xml version="1.0" encoding="utf-8"?>
<propfind xmlns="DAV:"><allprop/></propfind>`
				headers := map[string]string{
					"Content-Type": "application/xml",
					"Depth":        "1",
				}
				resp, respBody, err := doRequestWithHeaders(ctx, c, "PROPFIND", rawURL, []byte(body), headers)
				if err != nil {
					return nil
				}
				if resp.StatusCode != 207 {
					return nil
				}
				return &module.Finding{
					Type:     "webdav_propfind_listing",
					Severity: module.SeverityHigh,
					URL:      rawURL,
					Detail:   "[WebDAV] PROPFIND returns 207 Multi-Status — directory listing enabled",
					Extra: map[string]string{
						"status":       fmt.Sprintf("%d", resp.StatusCode),
						"body_preview": bodyPreview(respBody),
						"tags":         "webdav,propfind,listing",
						"confidence":   "0.90",
					},
				}
			},
		},
		{
			ID:       "put-file-upload",
			Severity: module.SeverityCritical,
			Tags:     []string{"webdav", "put", "upload"},
			Run: func(ctx context.Context, c *http.Client, rawURL string) *module.Finding {
				canary := "bh" + newHex(4) + ".txt"
				uploadURL := strings.TrimRight(rawURL, "/") + "/" + canary
				content := []byte("blackhorn-webdav-test-" + canary)
				resp, _, err := doRequest(ctx, c, "PUT", uploadURL, content)
				if err != nil {
					return nil
				}
				if resp.StatusCode != 201 && resp.StatusCode != 204 {
					return nil
				}
				// Attempt cleanup.
				_, _, _ = doRequest(ctx, c, "DELETE", uploadURL, nil)
				return &module.Finding{
					Type:     "webdav_put_upload",
					Severity: module.SeverityCritical,
					URL:      rawURL,
					Detail:   fmt.Sprintf("[WebDAV] PUT file upload succeeded: %s → HTTP %d", uploadURL, resp.StatusCode),
					Extra: map[string]string{
						"upload_url":    uploadURL,
						"upload_status": fmt.Sprintf("%d", resp.StatusCode),
						"tags":          "webdav,put,upload,rce-potential",
						"confidence":    "0.90",
					},
				}
			},
		},
		{
			ID:       "mkcol-directory",
			Severity: module.SeverityHigh,
			Tags:     []string{"webdav", "mkcol"},
			Run: func(ctx context.Context, c *http.Client, rawURL string) *module.Finding {
				dirName := "bhdir" + newHex(4)
				mkcolURL := strings.TrimRight(rawURL, "/") + "/" + dirName + "/"
				resp, _, err := doRequest(ctx, c, "MKCOL", mkcolURL, nil)
				if err != nil {
					return nil
				}
				if resp.StatusCode != 201 {
					return nil
				}
				// Attempt cleanup.
				_, _, _ = doRequest(ctx, c, "DELETE", mkcolURL, nil)
				return &module.Finding{
					Type:     "webdav_mkcol",
					Severity: module.SeverityHigh,
					URL:      rawURL,
					Detail:   fmt.Sprintf("[WebDAV] MKCOL directory creation succeeded: %s → HTTP %d", mkcolURL, resp.StatusCode),
					Extra: map[string]string{
						"mkcol_url":  mkcolURL,
						"status":     fmt.Sprintf("%d", resp.StatusCode),
						"tags":       "webdav,mkcol",
						"confidence": "0.90",
					},
				}
			},
		},
	}
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func doRequest(ctx context.Context, c *http.Client, method, rawURL string, body []byte) (*http.Response, string, error) {
	return doRequestWithHeaders(ctx, c, method, rawURL, body, nil)
}

func doRequestWithHeaders(ctx context.Context, c *http.Client, method, rawURL string, body []byte, headers map[string]string) (*http.Response, string, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-webdav/1.0)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return resp, string(b), nil
}

func bodyPreview(body string) string {
	if len(body) > 200 {
		return body[:200] + "..."
	}
	return body
}

func newHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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
