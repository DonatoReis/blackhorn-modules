// Package tlsfinder discovers subdomains via Certificate Transparency (CT) logs
// by querying the crt.sh public API and the Certspotter API. Both services
// index TLS certificates from all major CT logs (Google, Cloudflare, DigiCert,
// Let's Encrypt, etc.) and expose them via a free REST API.
//
// Reference: projectdiscovery/tldfinder (MIT) + crt.sh (open data) +
// sslmate/certspotter (public API, no key required for basic use).
// No code is copied — only the API endpoint patterns are used.
//
// License: MIT (blackhorn-modules).
package tlsfinder

import (
	"context"
	"encoding/json"
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
	defaultTimeout = 20 * time.Second
	maxBodyBytes   = 4 * 1024 * 1024 // 4 MiB — CT responses can be large
)

// ─── module ──────────────────────────────────────────────────────────────────

// Module implements module.Module for CT-log subdomain discovery.
type Module struct {
	client *http.Client
	// Sources controls which CT sources to query.
	// Default: ["crtsh", "certspotter"]
	Sources []string
	// IncludeExpired includes subdomains from expired certificates.
	IncludeExpired bool
	// IncludeWildcard includes wildcard entries (*.example.com).
	IncludeWildcard bool

	// Overridable base URLs for testing.
	CRTSHBaseURL       string // default: "https://crt.sh"
	CertspotterBaseURL string // default: "https://api.certspotter.com"
}

// New returns a Module with production defaults.
func New() *Module {
	return &Module{
		client:  httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		Sources: []string{"crtsh", "certspotter"},
	}
}

// NewWithClient creates a Module using the provided HTTP client.
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client:          c,
		Sources:         []string{"crtsh", "certspotter"},
		IncludeWildcard: true,
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "tlsfinder" }

// Run implements module.Module.
// Input.Target: apex domain (required).
// Input.URLs: additional domains to query.
// Input.RawContent: newline-delimited domains.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	domains := collectDomains(input)
	if len(domains) == 0 {
		return nil, fmt.Errorf("tlsfinder: no domains provided")
	}

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	sources := m.Sources
	if len(sources) == 0 {
		sources = []string{"crtsh", "certspotter"}
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(len(domains) * len(sources))

	for _, domain := range domains {
		for _, source := range sources {
			domain, source := domain, source
			g.Go(func() error {
				subs, err := m.querySource(gctx, source, domain)
				if err != nil {
					slog.Debug("tlsfinder: source query failed", "source", source, "domain", domain, "err", err)
					return nil
				}
				ff := m.buildFindings(domain, source, subs)
				if len(ff) > 0 {
					mu.Lock()
					findings = append(findings, ff...)
					mu.Unlock()
				}
				return nil
			})
		}
	}

	_ = g.Wait()
	return dedupFindings(findings), nil
}

// ─── source queries ───────────────────────────────────────────────────────────

func (m *Module) querySource(ctx context.Context, source, domain string) ([]string, error) {
	switch source {
	case "crtsh":
		return m.queryCRTSH(ctx, domain)
	case "certspotter":
		return m.queryCertspotter(ctx, domain)
	default:
		return nil, fmt.Errorf("unknown source: %s", source)
	}
}

// crtshBase returns the crt.sh base URL, with fallback to production.
func (m *Module) crtshBase() string {
	if m.CRTSHBaseURL != "" {
		return m.CRTSHBaseURL
	}
	return "https://crt.sh"
}

// certspotterBase returns the Certspotter base URL, with fallback to production.
func (m *Module) certspotterBase() string {
	if m.CertspotterBaseURL != "" {
		return m.CertspotterBaseURL
	}
	return "https://api.certspotter.com"
}

// queryCRTSH queries crt.sh for SANs associated with the domain.
// API: https://crt.sh/?q=%25.domain.com&output=json
func (m *Module) queryCRTSH(ctx context.Context, domain string) ([]string, error) {
	query := "%." + domain
	apiURL := fmt.Sprintf("%s/?q=%s&output=json", m.crtshBase(), url.QueryEscape(query))
	return m.queryCRTSHFromURL(ctx, domain, apiURL)
}

// queryCRTSHFromURL is the testable implementation — accepts an explicit URL.
func (m *Module) queryCRTSHFromURL(ctx context.Context, domain, apiURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-tlsfinder/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}

	return parseCRTSHResponse(body, domain)
}

// queryCertspotter queries the Certspotter API for issuances.
// API: https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names
func (m *Module) queryCertspotter(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf(
		"%s/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names",
		m.certspotterBase(), url.QueryEscape(domain),
	)
	return m.queryCertspotterFromURL(ctx, domain, apiURL)
}

// queryCertspotterFromURL is the testable implementation — accepts an explicit URL.
func (m *Module) queryCertspotterFromURL(ctx context.Context, domain, apiURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-tlsfinder/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certspotter returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}

	return parseCertspotterResponse(body, domain)
}

// ─── response parsers ────────────────────────────────────────────────────────

type crtshEntry struct {
	NameValue string `json:"name_value"`
	NotAfter  string `json:"not_after"`
}

func parseCRTSHResponse(body []byte, apex string) ([]string, error) {
	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh JSON parse error: %w", err)
	}

	seen := make(map[string]struct{})
	var out []string
	for _, e := range entries {
		// name_value may contain multiple names separated by newlines.
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || name == apex {
				continue
			}
			if !strings.HasSuffix(name, "."+apex) && !strings.EqualFold(name, apex) {
				continue
			}
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				out = append(out, name)
			}
		}
	}
	return out, nil
}

type certspotterEntry struct {
	DNSNames []string `json:"dns_names"`
}

func parseCertspotterResponse(body []byte, apex string) ([]string, error) {
	var entries []certspotterEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("certspotter JSON parse error: %w", err)
	}

	seen := make(map[string]struct{})
	var out []string
	for _, e := range entries {
		for _, name := range e.DNSNames {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || name == apex {
				continue
			}
			if !strings.HasSuffix(name, "."+apex) {
				continue
			}
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				out = append(out, name)
			}
		}
	}
	return out, nil
}

// ─── finding builder ─────────────────────────────────────────────────────────

func (m *Module) buildFindings(apex, source string, subs []string) []module.Finding {
	findings := make([]module.Finding, 0, len(subs))
	for _, sub := range subs {
		if strings.HasPrefix(sub, "*.") && !m.IncludeWildcard {
			continue
		}
		findings = append(findings, module.Finding{
			Type:     "ct_name_reference",
			URL:      sub,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("Subdomain %s found via CT log (%s) for %s", sub, source, apex),
			Extra: map[string]string{
				"apex":               apex,
				"source":             source,
				"host":               sub,
				"validated":          "false",
				"validation_state":   "certificate_transparency_reference",
				"confidence":         "0.90",
				"promote_to_context": "false",
			},
		})
	}
	return findings
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func collectDomains(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = cleanDomain(s)
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

func cleanDomain(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	for _, b := range []byte{'/', ':', '?', '#'} {
		if i := strings.IndexByte(s, b); i >= 0 {
			s = s[:i]
		}
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

func dedupFindings(findings []module.Finding) []module.Finding {
	seen := make(map[string]struct{})
	out := findings[:0]
	for _, f := range findings {
		if _, ok := seen[f.URL]; !ok {
			seen[f.URL] = struct{}{}
			out = append(out, f)
		}
	}
	return out
}
