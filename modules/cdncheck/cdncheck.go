// Package cdncheck detects whether a host is fronted by a CDN, WAF, or cloud
// provider by performing multi-signal analysis:
//   - IP CIDR matching against known CDN/cloud IP ranges
//   - DNS CNAME chain inspection
//   - HTTP response header fingerprinting
//
// Reference: projectdiscovery/cdncheck (MIT) — detection approach and some
// CIDR/cname lists are inspired by this tool, but all code is independently
// re-implemented. The IP ranges and CNAME suffixes used here are derived from
// publicly available documentation from the respective vendors.
//
// License: MIT (blackhorn-modules). IP ranges are public vendor documentation.
package cdncheck

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	defaultTimeout = 10 * time.Second
	defaultConc    = 12
	maxBodyBytes   = 64 * 1024
)

// ─── types ───────────────────────────────────────────────────────────────────

// ProviderKind classifies what type of service was detected.
type ProviderKind string

const (
	KindCDN   ProviderKind = "cdn"
	KindWAF   ProviderKind = "waf"
	KindCloud ProviderKind = "cloud"
)

// DetectionMethod records how the provider was detected.
type DetectionMethod string

const (
	MethodCIDR   DetectionMethod = "cidr"
	MethodCNAME  DetectionMethod = "cname"
	MethodHeader DetectionMethod = "header"
)

// ─── module ──────────────────────────────────────────────────────────────────

// Module implements module.Module for CDN/WAF/cloud detection.
type Module struct {
	client      *http.Client
	resolver    *net.Resolver
	concurrency int
}

// New returns a Module with production defaults.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		resolver:    net.DefaultResolver,
		concurrency: defaultConc,
	}
}

// NewWithClient creates a Module using the provided HTTP client (useful in tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client:      c,
		resolver:    net.DefaultResolver,
		concurrency: defaultConc,
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "cdncheck" }

// Run implements module.Module.
// Accepts Target (domain or URL), URLs (slice), or RawContent (newline-delimited).
// Each unique host is probed once. Findings carry provider name, kind, and detection method.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	hosts := collectHosts(input)
	if len(hosts) == 0 {
		return nil, fmt.Errorf("cdncheck: no hosts provided")
	}

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(m.concurrency)

	for _, host := range hosts {
		host := host
		g.Go(func() error {
			ff := m.checkHost(gctx, host)
			if len(ff) > 0 {
				mu.Lock()
				findings = append(findings, ff...)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()
	return findings, nil
}

// ─── host analysis ───────────────────────────────────────────────────────────

func (m *Module) checkHost(ctx context.Context, host string) []module.Finding {
	var findings []module.Finding

	// 1. DNS resolution: A records → IP CIDR matching.
	addrs, err := m.resolver.LookupHost(ctx, host)
	if err != nil {
		slog.Debug("cdncheck: DNS lookup failed", "host", host, "err", err)
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if provider, kind := matchIPRanges(ip); provider != "" {
			findings = append(findings, module.Finding{
				Type:     "cdn_detected",
				URL:      host,
				Severity: module.SeverityInfo,
				Detail: fmt.Sprintf(
					"Host %q resolves to %s IP (%s) — provider: %s (%s)",
					host, kind, addr, provider, MethodCIDR,
				),
				Extra: map[string]string{
					"host":       host,
					"ip":         addr,
					"provider":   provider,
					"kind":       string(kind),
					"method":     string(MethodCIDR),
					"confidence": "0.90",
				},
			})
			break // one finding per host is enough for IP
		}
	}

	// 2. CNAME chain inspection.
	cname, err := m.resolver.LookupCNAME(ctx, host)
	if err == nil && cname != "" && !strings.EqualFold(strings.TrimSuffix(cname, "."), host) {
		if provider, kind := matchCNAME(cname); provider != "" {
			findings = append(findings, module.Finding{
				Type:     "cdn_detected",
				URL:      host,
				Severity: module.SeverityInfo,
				Detail: fmt.Sprintf(
					"Host %q has CNAME %q pointing to %s provider: %s (%s)",
					host, cname, kind, provider, MethodCNAME,
				),
				Extra: map[string]string{
					"host":       host,
					"cname":      cname,
					"provider":   provider,
					"kind":       string(kind),
					"method":     string(MethodCNAME),
					"confidence": "0.90",
				},
			})
		}
	}

	// 3. HTTP header fingerprinting.
	if headerProvider, kind := m.probeHeaders(ctx, host); headerProvider != "" {
		// Only add if not already detected via CIDR/CNAME.
		already := false
		for _, f := range findings {
			if f.Extra["provider"] == headerProvider {
				already = true
				break
			}
		}
		if !already {
			findings = append(findings, module.Finding{
				Type:     "cdn_detected",
				URL:      host,
				Severity: module.SeverityInfo,
				Detail: fmt.Sprintf(
					"Host %q HTTP headers indicate %s provider: %s (%s)",
					host, kind, headerProvider, MethodHeader,
				),
				Extra: map[string]string{
					"host":       host,
					"provider":   headerProvider,
					"kind":       string(kind),
					"method":     string(MethodHeader),
					"confidence": "0.90",
				},
			})
		}
	}

	return findings
}

// probeHeaders makes an HTTP request to the host and fingerprints response headers.
func (m *Module) probeHeaders(ctx context.Context, host string) (string, ProviderKind) {
	// Try HTTPS first, fall back to HTTP.
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s/", scheme, host)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-cdncheck/1.0)")

		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
		resp.Body.Close()

		if provider, kind := matchHeaders(resp.Header); provider != "" {
			return provider, kind
		}
	}
	return "", ""
}

// ─── detection engines ───────────────────────────────────────────────────────

// matchIPRanges checks if ip falls within any known CDN/cloud CIDR.
func matchIPRanges(ip net.IP) (string, ProviderKind) {
	for _, entry := range cidrEntries {
		_, network, err := net.ParseCIDR(entry.cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return entry.provider, entry.kind
		}
	}
	return "", ""
}

// matchCNAME checks if the CNAME chain contains a known CDN/cloud suffix.
func matchCNAME(cname string) (string, ProviderKind) {
	lower := strings.ToLower(cname)
	for _, entry := range cnameEntries {
		if strings.Contains(lower, entry.suffix) {
			return entry.provider, entry.kind
		}
	}
	return "", ""
}

// matchHeaders fingerprints response headers against known CDN/WAF patterns.
func matchHeaders(headers http.Header) (string, ProviderKind) {
	for _, entry := range headerEntries {
		val := headers.Get(entry.header)
		if val == "" {
			continue
		}
		if entry.value == "" || strings.Contains(strings.ToLower(val), strings.ToLower(entry.value)) {
			return entry.provider, entry.kind
		}
	}
	return "", ""
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func collectHosts(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		h := extractHost(s)
		if h == "" {
			return
		}
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			out = append(out, h)
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

// extractHost returns the hostname from a URL or bare domain.
func extractHost(s string) string {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		host := s
		if i := strings.Index(s, "://"); i >= 0 {
			host = s[i+3:]
		}
		if i := strings.IndexByte(host, '/'); i >= 0 {
			host = host[:i]
		}
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		return strings.ToLower(host)
	}
	// Bare domain — strip port if present.
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

// ─── detection databases ─────────────────────────────────────────────────────

type cidrEntry struct {
	cidr     string
	provider string
	kind     ProviderKind
}

// cidrEntries contains known IP CIDR ranges for major CDN, cloud, and WAF providers.
// Sources: vendor documentation (public), regional IP allocation files.
// These are a representative subset; production deployments should refresh from
// vendor APIs (e.g. https://ip-ranges.amazonaws.com/ip-ranges.json).
var cidrEntries = []cidrEntry{
	// Cloudflare CDN/WAF — https://www.cloudflare.com/ips/
	{"103.21.244.0/22", "Cloudflare", KindCDN},
	{"103.22.200.0/22", "Cloudflare", KindCDN},
	{"103.31.4.0/22", "Cloudflare", KindCDN},
	{"104.16.0.0/13", "Cloudflare", KindCDN},
	{"104.24.0.0/14", "Cloudflare", KindCDN},
	{"108.162.192.0/18", "Cloudflare", KindCDN},
	{"131.0.72.0/22", "Cloudflare", KindCDN},
	{"141.101.64.0/18", "Cloudflare", KindCDN},
	{"162.158.0.0/15", "Cloudflare", KindCDN},
	{"172.64.0.0/13", "Cloudflare", KindCDN},
	{"173.245.48.0/20", "Cloudflare", KindCDN},
	{"188.114.96.0/20", "Cloudflare", KindCDN},
	{"190.93.240.0/20", "Cloudflare", KindCDN},
	{"197.234.240.0/22", "Cloudflare", KindCDN},
	{"198.41.128.0/17", "Cloudflare", KindCDN},
	// Fastly CDN — https://developer.fastly.com/reference/api/utils/public-ip-list/
	{"23.235.32.0/20", "Fastly", KindCDN},
	{"43.249.72.0/22", "Fastly", KindCDN},
	{"103.244.50.0/24", "Fastly", KindCDN},
	{"103.245.222.0/23", "Fastly", KindCDN},
	{"104.156.80.0/20", "Fastly", KindCDN},
	{"151.101.0.0/17", "Fastly", KindCDN},
	{"157.52.64.0/18", "Fastly", KindCDN},
	{"167.82.0.0/17", "Fastly", KindCDN},
	{"199.27.72.0/21", "Fastly", KindCDN},
	// Akamai Technologies — representative ranges
	{"2.16.0.0/13", "Akamai", KindCDN},
	{"23.32.0.0/11", "Akamai", KindCDN},
	{"96.16.0.0/15", "Akamai", KindCDN},
	{"96.20.0.0/14", "Akamai", KindCDN},
	// AWS CloudFront — https://ip-ranges.amazonaws.com/ip-ranges.json (CLOUDFRONT service)
	{"13.32.0.0/15", "AWS CloudFront", KindCDN},
	{"13.35.0.0/16", "AWS CloudFront", KindCDN},
	{"52.46.0.0/18", "AWS CloudFront", KindCDN},
	{"52.84.0.0/15", "AWS CloudFront", KindCDN},
	{"64.252.64.0/18", "AWS CloudFront", KindCDN},
	{"204.246.164.0/22", "AWS CloudFront", KindCDN},
	{"205.251.192.0/19", "AWS CloudFront", KindCDN},
	// AWS EC2 global (representative subnets)
	{"3.0.0.0/9", "Amazon Web Services", KindCloud},
	{"13.0.0.0/8", "Amazon Web Services", KindCloud},
	{"52.0.0.0/8", "Amazon Web Services", KindCloud},
	{"54.0.0.0/8", "Amazon Web Services", KindCloud},
	// Google Cloud Platform — https://cloud.google.com/compute/docs/faq#find_ip_range
	{"34.0.0.0/10", "Google Cloud", KindCloud},
	{"35.184.0.0/13", "Google Cloud", KindCloud},
	{"104.154.0.0/15", "Google Cloud", KindCloud},
	{"104.196.0.0/14", "Google Cloud", KindCloud},
	{"130.211.0.0/22", "Google Cloud", KindCloud},
	{"35.190.0.0/17", "Google Cloud", KindCloud},
	// Azure — https://www.microsoft.com/en-us/download/details.aspx?id=56519
	{"40.112.0.0/13", "Microsoft Azure", KindCloud},
	{"13.64.0.0/11", "Microsoft Azure", KindCloud},
	{"40.64.0.0/10", "Microsoft Azure", KindCloud},
	{"104.40.0.0/13", "Microsoft Azure", KindCloud},
	// Imperva/Incapsula WAF — https://docs.imperva.com/bundle/cloud-application-security/page/ip-range.htm
	{"45.64.64.0/22", "Imperva", KindWAF},
	{"149.126.72.0/21", "Imperva", KindWAF},
	{"192.230.64.0/18", "Imperva", KindWAF},
	{"199.83.128.0/21", "Imperva", KindWAF},
	// Sucuri WAF — https://kb.sucuri.net/firewall/Performance/Firewall-IP-Ranges
	{"66.248.200.0/22", "Sucuri", KindWAF},
	{"185.93.228.0/22", "Sucuri", KindWAF},
	// DigitalOcean
	{"159.65.0.0/16", "DigitalOcean", KindCloud},
	{"167.99.0.0/16", "DigitalOcean", KindCloud},
	{"68.183.0.0/16", "DigitalOcean", KindCloud},
}

type cnameEntry struct {
	suffix   string
	provider string
	kind     ProviderKind
}

// cnameEntries maps CNAME suffixes to known CDN/cloud/WAF providers.
var cnameEntries = []cnameEntry{
	// Cloudflare
	{".cloudflare.com", "Cloudflare", KindCDN},
	{".cloudflare.net", "Cloudflare", KindCDN},
	// Fastly
	{".fastly.net", "Fastly", KindCDN},
	{".fastlylb.net", "Fastly", KindCDN},
	{".fastly.com", "Fastly", KindCDN},
	// AWS CloudFront
	{".cloudfront.net", "AWS CloudFront", KindCDN},
	// AWS (general)
	{".amazonaws.com", "Amazon Web Services", KindCloud},
	{".awsglobalaccelerator.com", "Amazon Web Services", KindCloud},
	// Azure
	{".azureedge.net", "Azure CDN", KindCDN},
	{".windows.net", "Microsoft Azure", KindCloud},
	{".azurewebsites.net", "Microsoft Azure", KindCloud},
	{".trafficmanager.net", "Azure Traffic Manager", KindCloud},
	// GCP
	{".appspot.com", "Google Cloud", KindCloud},
	{".googleusercontent.com", "Google Cloud", KindCloud},
	{".cloudfunctions.net", "Google Cloud", KindCloud},
	{".run.app", "Google Cloud Run", KindCloud},
	// Akamai
	{".akamaiedge.net", "Akamai", KindCDN},
	{".akamaized.net", "Akamai", KindCDN},
	{".akamaitechnologies.com", "Akamai", KindCDN},
	{".akamai.net", "Akamai", KindCDN},
	// Incapsula/Imperva WAF
	{".incapdns.net", "Imperva", KindWAF},
	{".impervadns.net", "Imperva", KindWAF},
	// Sucuri WAF
	{".sucuri.net", "Sucuri", KindWAF},
	// Vercel
	{".vercel.app", "Vercel", KindCDN},
	{".now.sh", "Vercel", KindCDN},
	// Netlify
	{".netlify.app", "Netlify", KindCDN},
	{".netlify.com", "Netlify", KindCDN},
	// GitHub Pages
	{".github.io", "GitHub Pages", KindCDN},
	// Heroku
	{".herokuapp.com", "Heroku", KindCloud},
	{".herokudns.com", "Heroku", KindCloud},
	// Render
	{".onrender.com", "Render", KindCloud},
	// Fly.io
	{".fly.dev", "Fly.io", KindCloud},
	// Shopify
	{".myshopify.com", "Shopify", KindCloud},
	{".shopifycdn.com", "Shopify", KindCDN},
	// StackPath / MaxCDN
	{".stackpathdns.com", "StackPath", KindCDN},
	{".wp.com", "WordPress.com / Automattic", KindCDN},
	// BunnyCDN
	{".b-cdn.net", "BunnyCDN", KindCDN},
	// Cachefly
	{".cachefly.net", "CacheFly", KindCDN},
	// Edgecast / Verizon
	{".edgecastcdn.net", "Edgecast", KindCDN},
	// Limelight
	{".llnwd.net", "Limelight", KindCDN},
}

type headerEntry struct {
	header   string
	value    string // if empty, presence alone is a match
	provider string
	kind     ProviderKind
}

// headerEntries maps HTTP response headers to CDN/WAF providers.
var headerEntries = []headerEntry{
	// Cloudflare
	{"cf-ray", "", "Cloudflare", KindCDN},
	{"cf-cache-status", "", "Cloudflare", KindCDN},
	{"cf-mitigated", "", "Cloudflare", KindWAF},
	// Akamai
	{"x-akamai-transformed", "", "Akamai", KindCDN},
	{"x-check-cacheable", "", "Akamai", KindCDN},
	{"akamai-x-cache", "", "Akamai", KindCDN},
	// Fastly
	{"x-served-by", "cache", "Fastly", KindCDN},
	{"fastly-restarts", "", "Fastly", KindCDN},
	{"x-cache", "hit", "Fastly", KindCDN},
	// Varnish (generic CDN/cache)
	{"x-varnish", "", "Varnish", KindCDN},
	{"x-age", "", "Varnish", KindCDN},
	// AWS CloudFront
	{"x-amz-cf-id", "", "AWS CloudFront", KindCDN},
	{"x-amz-cf-pop", "", "AWS CloudFront", KindCDN},
	// Azure CDN
	{"x-ms-request-id", "", "Microsoft Azure", KindCloud},
	{"x-azure-ref", "", "Azure CDN", KindCDN},
	// Imperva/Incapsula WAF
	{"x-cdn", "incapsula", "Imperva", KindWAF},
	{"x-iinfo", "", "Imperva", KindWAF},
	// Sucuri WAF
	{"x-sucuri-id", "", "Sucuri", KindWAF},
	{"x-sucuri-cache", "", "Sucuri", KindWAF},
	// Vercel
	{"x-vercel-id", "", "Vercel", KindCDN},
	{"x-vercel-cache", "", "Vercel", KindCDN},
	// Netlify
	{"x-nf-request-id", "", "Netlify", KindCDN},
	// Fly.io
	{"fly-request-id", "", "Fly.io", KindCloud},
	// BunnyCDN
	{"cdn-pullzone", "", "BunnyCDN", KindCDN},
	{"cdn-cache", "", "BunnyCDN", KindCDN},
}
