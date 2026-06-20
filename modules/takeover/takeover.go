// Package takeover detects subdomain takeover candidates via CNAME dangling.
//
// Reference implementation (algorithm and signatures, no code copied):
//   - orbit-core internal/modules/takeover.go (proprietary)
//   - can-i-take-over-xyz (MIT): https://github.com/EdOverflow/can-i-take-over-xyz
//
// What is implemented:
//   - 50+ service signatures (CNAME suffix → service name) sourced from
//     can-i-take-over-xyz (MIT licensed dataset)
//   - DNS CNAME resolution via stdlib net.Resolver (no binary dependency)
//   - HTTP probing: 404/410/0 + soft-404 body detection (same engine as soft404 module)
//   - Input: domain (Target), list of subdomains (URLs), or raw subdomain list (RawContent)
//   - Confidence scoring: high (hard 404) → medium (soft 200) → low (timeout/refused)
//   - io.LimitReader on every body read                   (dicas.md §5)
//   - log/slog structured observability                   (dicas.md §16)
//   - errgroup.SetLimit bounded fan-out                   (guia-go §9)
//   - context propagation and cancellation               (guia-go §9)
package takeover

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	maxBodyRead    = 16 * 1024 // 16 KiB — dicas.md §5
	defaultTimeout = 10 * time.Second
	defaultThreads = 10
)

// ─── Signatures ───────────────────────────────────────────────────────────────

// Signature maps a CNAME suffix to a cloud/SaaS service name.
// Source: can-i-take-over-xyz (MIT) — expanded with additional services.
type Signature struct {
	Suffix  string
	Service string
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module detects subdomain takeover candidates.
type Module struct {
	client     *http.Client
	resolver   *net.Resolver
	threads    int
	timeout    time.Duration
	signatures []Signature
	probeHTTP  bool
	probeHTTPS bool
}

// New creates a Module with default settings and the full built-in signature list.
func New() *Module {
	return &Module{
		client:     defaultClient(defaultTimeout),
		resolver:   net.DefaultResolver,
		threads:    defaultThreads,
		timeout:    defaultTimeout,
		signatures: builtinSignatures(),
		probeHTTP:  true,
		probeHTTPS: true,
	}
}

// NewWithClient creates a Module with a custom HTTP client (useful for tests).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// NewWithSignatures creates a Module with a custom signature list.
func NewWithSignatures(sigs []Signature) *Module {
	m := New()
	m.signatures = sigs
	return m
}

// Name satisfies module.Module.
func (m *Module) Name() string { return "takeover" }

// Run satisfies module.Module.
// Accepts:
//   - input.Target: root domain → resolves subdomains via DNS CNAME chain.
//   - input.URLs: list of subdomains to check directly.
//   - input.RawContent: newline-delimited subdomains.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	subdomains := m.collectSubdomains(input)
	if len(subdomains) == 0 {
		return nil, fmt.Errorf("takeover: no subdomains to check")
	}

	threads := optInt(input.Options, "threads", m.threads)
	slog.Debug("takeover: starting", "subdomains", len(subdomains), "sigs", len(m.signatures), "threads", threads)

	type candidate struct {
		subdomain string
		cname     string
		service   string
	}

	// Phase 1: DNS CNAME resolution → match against signatures.
	var candidates []candidate
	for _, sub := range subdomains {
		cname, ok := m.resolveCNAME(ctx, sub)
		if !ok || cname == "" {
			continue
		}
		for _, sig := range m.signatures {
			if strings.HasSuffix(cname, sig.Suffix) {
				candidates = append(candidates, candidate{
					subdomain: sub,
					cname:     cname,
					service:   sig.Service,
				})
				break
			}
		}
	}

	if len(candidates) == 0 {
		slog.Debug("takeover: no CNAME candidates found")
		return nil, nil
	}

	// Phase 2: HTTP probe each candidate.
	findingsCh := make(chan module.Finding, 64)
	var found atomic.Int64

	eg, gctx := errgroup.WithContext(ctx)
	eg.SetLimit(threads)

	for _, c := range candidates {
		c := c // capture
		eg.Go(func() error {
			code, body, headers := m.probe(gctx, c.subdomain)

			isTakeover, confidence := m.classify(code, body, headers)
			if !isTakeover {
				return nil
			}

			found.Add(1)
			detail := fmt.Sprintf(
				"Subdomain %q has a CNAME pointing to %q (%s) but the service returned HTTP %d, "+
					"indicating the resource may not be claimed. An attacker may register this resource "+
					"and take over the subdomain.",
				c.subdomain, c.cname, c.service, code,
			)
			findingsCh <- module.Finding{
				Type:     "subdomain_takeover",
				URL:      "https://" + c.subdomain,
				Detail:   detail,
				Severity: module.SeverityHigh,
				Extra: map[string]string{
					"subdomain":   c.subdomain,
					"cname":       c.cname,
					"service":     c.service,
					"http_status": fmt.Sprintf("%d", code),
					"confidence":  confidence,
					"remediation": fmt.Sprintf("Remove CNAME for %q or claim the resource on %s.", c.subdomain, c.service),
				},
			}
			return nil
		})
	}

	go func() { _ = eg.Wait(); close(findingsCh) }()

	var findings []module.Finding
	for f := range findingsCh {
		findings = append(findings, f)
	}
	if err := eg.Wait(); err != nil {
		return findings, err
	}
	slog.Debug("takeover: done", "candidates", len(candidates), "findings", found.Load())
	return findings, nil
}

// ─── DNS resolution ───────────────────────────────────────────────────────────

// resolveCNAME follows the CNAME chain and returns the final canonical name.
func (m *Module) resolveCNAME(ctx context.Context, host string) (string, bool) {
	tctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	cname, err := m.resolver.LookupCNAME(tctx, host)
	if err != nil {
		return "", false
	}
	cname = strings.TrimSuffix(strings.ToLower(cname), ".")
	return cname, cname != "" && cname != strings.ToLower(host)
}

// ─── HTTP probing ─────────────────────────────────────────────────────────────

func (m *Module) probe(ctx context.Context, subdomain string) (int, string, http.Header) {
	var code int
	var body string
	var headers http.Header

	if m.probeHTTPS {
		body, headers, code = fetchBody(ctx, m.client, "https://"+subdomain)
	}
	if code == 0 && m.probeHTTP {
		body, headers, code = fetchBody(ctx, m.client, "http://"+subdomain)
	}
	return code, body, headers
}

// classify returns (isTakeover, confidence) from the HTTP probe result.
func (m *Module) classify(code int, body string, headers http.Header) (bool, string) {
	switch {
	case code == 0:
		return true, "low" // timeout / refused — may indicate unclaimed resource
	case code == 404 || code == 410:
		return true, "high" // canonical "not found" from the service
	case code == 200:
		// Soft-404 from the service (e.g. GitHub Pages "404 There isn't a GitHub Pages site here")
		if isSoft404(body, headers) {
			return true, "medium"
		}
		return false, ""
	default:
		return false, ""
	}
}

// ─── Soft-404 detection (subset, for takeover-specific patterns) ─────────────

var takeoverBodyMarkers = []string{
	// GitHub Pages
	"there isn't a github pages site here",
	"404 there isn't a github pages site",
	// Heroku
	"no such app", "heroku | no such app",
	// AWS S3
	"nosuchbucket", "the specified bucket does not exist",
	"this xml file does not appear",
	// Azure
	"404 web site not found", "the web site you are trying to reach is not available",
	// Netlify
	"not found — looks like you've followed a broken link",
	"not found - looks like you have followed a broken link",
	// Fastly
	"fastly error: unknown domain",
	// Surge
	"project not found",
	// Ghost
	"404 page not found",
	// StatusPage
	"page not found",
	// Generic
	"domain not configured", "this domain is not configured",
	"this page is not available", "unclaimed",
	"hasn't been claimed yet",
}

func isSoft404(body string, headers http.Header) bool {
	if body == "" {
		return false
	}
	// API response? Not a takeover page.
	b := strings.TrimSpace(body)
	if strings.HasPrefix(b, "{") || strings.HasPrefix(b, "[") {
		return false
	}
	lower := strings.ToLower(body)
	for _, m := range takeoverBodyMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// ─── Subdomain collection ─────────────────────────────────────────────────────

func (m *Module) collectSubdomains(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "https://")
		s = strings.TrimPrefix(s, "http://")
		s = strings.SplitN(s, "/", 2)[0] // strip path
		if s == "" {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	if input.Target != "" {
		add(input.Target)
	}
	for _, u := range input.URLs {
		add(u)
	}
	if input.RawContent != "" {
		for _, line := range strings.Split(input.RawContent, "\n") {
			add(strings.TrimSpace(line))
		}
	}
	return out
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func fetchBody(ctx context.Context, client *http.Client, rawURL string) (string, http.Header, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", nil, 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BlackhornScanner/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, 0
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return string(b), resp.Header, resp.StatusCode
}

func defaultClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

func optInt(opts map[string]string, key string, def int) int {
	if opts == nil {
		return def
	}
	v, ok := opts[key]
	if !ok {
		return def
	}
	n := 0
	for _, c := range v {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	if n == 0 {
		return def
	}
	return n
}

// ─── Built-in signatures ──────────────────────────────────────────────────────

// builtinSignatures returns the full service signature list.
// Sources: can-i-take-over-xyz (MIT) + additional services.
func builtinSignatures() []Signature {
	return []Signature{
		// Cloud Hosting
		{"github.io", "GitHub Pages"},
		{"github.com", "GitHub"},
		{"githubusercontent.com", "GitHub Content"},
		{"herokuapp.com", "Heroku"},

		// AWS
		{"s3.amazonaws.com", "AWS S3"},
		{"s3-website-us-east-1.amazonaws.com", "AWS S3 Static (us-east-1)"},
		{"s3-website-us-west-1.amazonaws.com", "AWS S3 Static (us-west-1)"},
		{"s3-website-us-west-2.amazonaws.com", "AWS S3 Static (us-west-2)"},
		{"s3-website-eu-west-1.amazonaws.com", "AWS S3 Static (eu-west-1)"},
		{"s3-website-ap-southeast-1.amazonaws.com", "AWS S3 Static (ap-se-1)"},
		{"s3-website-ap-northeast-1.amazonaws.com", "AWS S3 Static (ap-ne-1)"},
		{"s3-website.amazonaws.com", "AWS S3 Static"},
		{"amazonaws.com", "AWS"},
		{"elasticbeanstalk.com", "AWS Elastic Beanstalk"},
		{"awsapprunner.com", "AWS App Runner"},

		// Azure
		{"azurewebsites.net", "Azure Web Apps"},
		{"cloudapp.azure.com", "Azure Cloud App"},
		{"cloudapp.net", "Azure Cloud App (legacy)"},
		{"trafficmanager.net", "Azure Traffic Manager"},
		{"blob.core.windows.net", "Azure Blob Storage"},
		{"azurefd.net", "Azure Front Door"},
		{"azureedge.net", "Azure CDN"},
		{"azure-api.net", "Azure API Management"},

		// GCP
		{"appspot.com", "Google App Engine"},
		{"storage.googleapis.com", "Google Cloud Storage"},
		{"c.storage.googleapis.com", "Google Cloud Storage (CNAME)"},
		{"a.run.app", "Google Cloud Run"},

		// Vercel / Netlify / Render
		{"vercel.app", "Vercel"},
		{"now.sh", "Vercel (now.sh)"},
		{"netlify.app", "Netlify"},
		{"netlify.com", "Netlify (legacy)"},
		{"onrender.com", "Render"},

		// Shopify / eCommerce
		{"shopify.com", "Shopify"},
		{"myshopify.com", "Shopify"},
		{"shop.app", "Shopify (shop.app)"},

		// Zendesk / Help
		{"zendesk.com", "Zendesk"},
		{"zendeskservice.com", "Zendesk Service"},

		// WordPress
		{"wordpress.com", "WordPress.com"},
		{"wordpress.org", "WordPress.org"},

		// CDN / Edge
		{"fastly.net", "Fastly"},
		{"fastly-custom-domains.net", "Fastly Custom"},
		{"pages.dev", "Cloudflare Pages"},
		{"workers.dev", "Cloudflare Workers"},

		// Static Hosting
		{"surge.sh", "Surge"},
		{"fly.dev", "Fly.io"},
		{"fly.io", "Fly.io (direct)"},

		// Blogging / CMS
		{"ghost.io", "Ghost"},
		{"cargo.site", "Cargo"},
		{"webflow.io", "Webflow"},
		{"squarespace.com", "Squarespace"},
		{"webnode.com", "Webnode"},

		// Documentation
		{"readme.io", "ReadMe"},
		{"readmeapp.com", "ReadMe App"},
		{"readthedocs.io", "Read The Docs"},
		{"gitbook.io", "GitBook"},

		// Status / Monitoring
		{"statuspage.io", "Statuspage"},
		{"instatus.com", "Instatus"},

		// Source Control
		{"bitbucket.io", "Bitbucket"},
		{"bitbucket.org", "Bitbucket Pages"},
		{"gitlab.io", "GitLab Pages"},

		// Issue Trackers / Support
		{"helpjuice.com", "HelpJuice"},
		{"helpscoutdocs.com", "HelpScout"},
		{"uservoice.com", "UserVoice"},
		{"freshdesk.com", "Freshdesk"},
		{"kayako.com", "Kayako"},

		// Marketing / Analytics
		{"hubspot.com", "HubSpot"},
		{"hubspotpagebuilder.com", "HubSpot Page Builder"},
		{"strikingly.com", "Strikingly"},
		{"wixsite.com", "Wix"},
		{"sites.google.com", "Google Sites"},

		// Email / SaaS
		{"cname.sendgrid.net", "SendGrid"},
		{"mailgun.org", "Mailgun"},

		// Firebase
		{"firebaseapp.com", "Firebase Hosting"},
		{"web.app", "Firebase Web App"},
	}
}
