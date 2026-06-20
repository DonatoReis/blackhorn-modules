// Package wafscan implements WAF (Web Application Firewall) Detection and Bypass.
//
// Source reference: wafw00f (BSD-2, fingerprint database MIT-compatible) +
// bypass-firewalls-by-DNS-history + nuclei-templates waf/ (MIT).
// Detection logic reimplemented from scratch.
//
// Detection strategies:
//   - Header fingerprinting: look for WAF-specific response headers
//   - Cookie fingerprinting: WAF-specific cookie names
//   - Body fingerprinting: WAF-specific block page content
//   - Attack probe: inject a clearly malicious payload (SQLi + XSS combined)
//     and check if response differs from clean baseline (blocked = WAF)
//   - Status code: 403/406/429/503 on attack probe = WAF present
//
// WAFs detected (based on wafw00f signatures, BSD-2):
//
//	Cloudflare, AWS WAF, ModSecurity, Imperva/Incapsula, Akamai, Barracuda,
//	Sucuri, F5 BIG-IP ASM, Citrix NetScaler, Fortinet FortiWeb, DenyAll,
//	Radware AppWall, Comodo, WordFence, Reblaze, StackPath, Azure Front Door,
//	Fastly, Varnish, nginx-based WAF
//
// Architecture:
//   - WAFSignature struct: header/cookie/body patterns
//   - Two-phase: fingerprint headers first, then attack probe
//   - errgroup.SetLimit(Parallelism) fan-out
//   - io.LimitReader on all response reads
//   - log/slog observability
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) for testability
package wafscan

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
	DefaultTimeout     = 10 * time.Second
	DefaultParallelism = 10
	maxBodyRead        = 256 * 1024 // 256 KB
)

// attackPayload is the malicious probe injected to trigger WAF blocking.
// Combines SQLi + XSS + path traversal to maximize WAF detection.
// Characters < > are percent-encoded to pass Go's HTTP client URI validation
// (RFC 3986 §2.2); WAFs decode them and still block.
const attackPayload = `?id=1%27+OR+1%3D1--&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&path=..%2F..%2F..%2F..%2Fetc%2Fpasswd`

// ─── WAFSignature ─────────────────────────────────────────────────────────────

// WAFSignature defines detection patterns for a specific WAF.
// Based on wafw00f fingerprint database (BSD-2).
type WAFSignature struct {
	// Name is the WAF product name.
	Name string
	// Vendor is the company.
	Vendor string
	// HeaderPatterns: header key → value substrings (case-insensitive).
	// Match if ANY header key matches AND its value contains ANY pattern.
	HeaderPatterns map[string][]string
	// CookiePatterns: cookie name substrings (case-insensitive).
	CookiePatterns []string
	// BodyPatterns: response body substrings (case-insensitive).
	BodyPatterns []string
	// BlockedStatusCodes: HTTP status codes that indicate blocking.
	BlockedStatusCodes []int
	// Tags are metadata tags.
	Tags []string
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements WAF Detection and Bypass testing.
type Module struct {
	client      *http.Client
	signatures  []WAFSignature
	parallelism int
	logger      *slog.Logger
}

// New returns a Module with all built-in WAF signatures.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: DefaultTimeout}),
		signatures:  builtinSignatures(),
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

// NewWithSignatures returns a Module with custom WAF signatures (testability).
func NewWithSignatures(sigs []WAFSignature) *Module {
	m := New()
	m.signatures = sigs
	return m
}

// NewWithSignaturesAndClient returns a Module with custom signatures and HTTP client.
func NewWithSignaturesAndClient(sigs []WAFSignature, c *http.Client) *Module {
	m := New()
	m.signatures = sigs
	m.client = c
	return m
}

// Name returns the module name.
func (m *Module) Name() string { return "wafscan" }

// Run detects WAF presence and attempts bypass probes.
//
// Options:
//   - "parallelism"          — max concurrent checks (default: 10)
//   - "max_targets"          — max URLs to probe (default: 100)
//   - "max_runtime_seconds"  — global budget in seconds (default: 180)
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

	maxTargets := 100
	if v := input.Options["max_targets"]; v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			maxTargets = n
		}
	}
	if len(targets) > maxTargets {
		targets = targets[:maxTargets]
	}

	maxRuntimeSec := 180
	if v := input.Options["max_runtime_seconds"]; v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			maxRuntimeSec = n
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntimeSec)*time.Second)
	defer cancel()

	var (
		mu       sync.Mutex
		seen     = make(map[string]struct{})
		findings []module.Finding
	)

	addFindings := func(fs []module.Finding) {
		mu.Lock()
		defer mu.Unlock()
		for _, f := range fs {
			// Dedup by network host+WAF, not by URL+WAF or scheme.
			// The same WAF detected across many paths of the same host (e.g. 617 Wayback
			// URLs from the same domain) should produce ONE finding, not 617.
			hostKey := extractHostKey(f.URL)
			key := hostKey + "|" + f.Type + "|" + f.Extra["waf_name"]
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				f.URL = extractOrigin(f.URL)
				findings = append(findings, f)
			}
		}
	}

	eg, egCtx := errgroup.WithContext(runCtx)
	eg.SetLimit(parallelism)

	for _, target := range targets {
		target := target
		eg.Go(func() error {
			fs := m.scanTarget(egCtx, target)
			if len(fs) > 0 {
				addFindings(fs)
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return findings, fmt.Errorf("wafscan: worker failed: %w", err)
	}
	if err := runCtx.Err(); err != nil {
		return findings, fmt.Errorf("wafscan: runtime budget exceeded: %w", err)
	}
	return findings, nil
}

// scanTarget runs both fingerprint and attack probe phases for a target.
func (m *Module) scanTarget(ctx context.Context, rawURL string) []module.Finding {
	// Phase 1: clean request — fingerprint headers/cookies.
	cleanBody, cleanStatus, cleanHeaders, err := m.doRequest(ctx, rawURL)
	if err != nil {
		m.logger.DebugContext(ctx, "wafscan: clean request failed", "url", rawURL, "err", err)
		return nil
	}

	// Phase 2: attack probe.
	probeURL := rawURL + attackPayload
	probeBody, probeStatus, probeHeaders, probeErr := m.doRequest(ctx, probeURL)

	var findings []module.Finding

	// Fingerprint WAFs from clean response.
	for _, sig := range m.signatures {
		if matched, matchDetail := matchSignature(sig, cleanBody, cleanStatus, cleanHeaders); matched {
			m.logger.InfoContext(ctx, "wafscan: WAF detected via clean headers",
				"url", rawURL, "waf", sig.Name)
			findings = append(findings, module.Finding{
				Type:     "waf_detected",
				Severity: module.SeverityInfo,
				URL:      rawURL,
				Detail:   fmt.Sprintf("[WAF] %s by %s detected via %s", sig.Name, sig.Vendor, matchDetail),
				Extra: map[string]string{
					"waf_name":   sig.Name,
					"waf_vendor": sig.Vendor,
					"detection":  matchDetail,
					"phase":      "fingerprint",
					"tags":       "wafscan," + strings.Join(sig.Tags, ","),
					"confidence": "0.85", // signature matched on clean response headers/body
				},
			})
		}
	}

	// Fingerprint from probe response (different behaviour when attacking).
	if probeErr == nil {
		for _, sig := range m.signatures {
			if matched, matchDetail := matchSignature(sig, probeBody, probeStatus, probeHeaders); matched {
				// Avoid duplicating a finding already added from clean phase.
				alreadyDetected := false
				for _, f := range findings {
					if f.Extra["waf_name"] == sig.Name {
						alreadyDetected = true
						break
					}
				}
				if !alreadyDetected {
					findings = append(findings, module.Finding{
						Type:     "waf_detected",
						Severity: module.SeverityInfo,
						URL:      rawURL,
						Detail:   fmt.Sprintf("[WAF] %s by %s detected via attack probe (%s)", sig.Name, sig.Vendor, matchDetail),
						Extra: map[string]string{
							"waf_name":   sig.Name,
							"waf_vendor": sig.Vendor,
							"detection":  matchDetail,
							"phase":      "attack-probe",
							"tags":       "wafscan," + strings.Join(sig.Tags, ","),
							"confidence": "0.90", // signature confirmed under attack-probe conditions
						},
					})
				}
			}
		}

		// Generic WAF blocking detection: probe returns 403/406/429/503 but clean returns 200.
		isBlockStatus := probeStatus == 403 || probeStatus == 406 || probeStatus == 429 || probeStatus == 503
		if cleanStatus == 200 && isBlockStatus {
			// Only emit generic finding if no specific WAF was identified.
			if len(findings) == 0 {
				findings = append(findings, module.Finding{
					Type:     "waf_generic_block",
					Severity: module.SeverityInfo,
					URL:      rawURL,
					Detail:   fmt.Sprintf("[WAF] generic blocking detected: clean=%d attack=%d", cleanStatus, probeStatus),
					Extra: map[string]string{
						"waf_name":     "generic",
						"clean_status": fmt.Sprintf("%d", cleanStatus),
						"probe_status": fmt.Sprintf("%d", probeStatus),
						"tags":         "wafscan,generic",
						"confidence":   "0.70", // status differential detected but no signature matched
					},
				})
			}
		}
	}

	return findings
}

func (m *Module) doRequest(ctx context.Context, rawURL string) (string, int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return "", 0, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-wafscan/1.0)")

	resp, err := m.client.Do(req)
	if err != nil {
		return "", 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return string(b), resp.StatusCode, resp.Header, nil
}

// matchSignature checks if response matches a WAF signature.
func matchSignature(sig WAFSignature, body string, status int, headers http.Header) (bool, string) {
	bodyLower := strings.ToLower(body)

	// Header patterns.
	for hdrKey, patterns := range sig.HeaderPatterns {
		hdrKey = strings.ToLower(hdrKey)
		for k, vals := range headers {
			if strings.ToLower(k) == hdrKey {
				for _, v := range vals {
					for _, p := range patterns {
						if strings.Contains(strings.ToLower(v), strings.ToLower(p)) {
							return true, fmt.Sprintf("header %s=%s", k, v)
						}
					}
				}
			}
		}
	}

	// Cookie patterns.
	for _, cookie := range headers["Set-Cookie"] {
		for _, cp := range sig.CookiePatterns {
			if strings.Contains(strings.ToLower(cookie), strings.ToLower(cp)) {
				return true, fmt.Sprintf("cookie %s", cp)
			}
		}
	}

	// Body patterns.
	for _, bp := range sig.BodyPatterns {
		if strings.Contains(bodyLower, strings.ToLower(bp)) {
			return true, fmt.Sprintf("body=%q", bp)
		}
	}

	// Status code.
	for _, sc := range sig.BlockedStatusCodes {
		if status == sc {
			return true, fmt.Sprintf("status=%d", sc)
		}
	}

	return false, ""
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func collectTargets(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(u string) {
		origin := extractOrigin(u)
		if origin == "" {
			return
		}
		hostKey := extractHostKey(origin)
		if _, ok := seen[hostKey]; !ok {
			seen[hostKey] = struct{}{}
			out = append(out, origin)
		}
	}
	// Prefer discovered endpoints because they carry an observed scheme.
	for _, u := range input.URLs {
		add(u)
	}
	if input.Target != "" {
		add(input.Target)
	}
	return out
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n, err
}

// extractOrigin returns a canonical HTTP origin suitable for one host-level probe.
func extractOrigin(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// extractHostKey intentionally ignores scheme and path so HTTP/HTTPS variants
// of the same host do not trigger duplicate WAF scans.
func extractHostKey(rawURL string) string {
	origin := extractOrigin(rawURL)
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimSpace(rawURL))
	}
	return strings.ToLower(u.Host)
}

// ─── Built-in WAF signatures ──────────────────────────────────────────────────

// builtinSignatures returns the default WAF fingerprint database.
// Based on wafw00f signatures (BSD-2 license) — publicly known header/body patterns.
func builtinSignatures() []WAFSignature {
	return []WAFSignature{
		{
			Name: "Cloudflare", Vendor: "Cloudflare",
			HeaderPatterns: map[string][]string{
				"server":        {"cloudflare"},
				"cf-ray":        {""},
				"cf-request-id": {""},
			},
			CookiePatterns: []string{"__cfduid", "__cf_bm"},
			BodyPatterns:   []string{"cloudflare ray id", "sorry, you have been blocked", "attention required! | cloudflare"},
			Tags:           []string{"cloudflare", "cdn", "waf"},
		},
		{
			Name: "AWS WAF", Vendor: "Amazon",
			HeaderPatterns: map[string][]string{
				"x-amzn-requestid": {""},
				"x-amz-cf-id":      {""},
				"x-amzn-trace-id":  {""},
			},
			BodyPatterns: []string{"request blocked", "aws waf"},
			Tags:         []string{"aws", "waf"},
		},
		{
			Name: "ModSecurity", Vendor: "Trustwave",
			HeaderPatterns: map[string][]string{
				"server": {"mod_security", "modsecurity"},
			},
			BodyPatterns: []string{
				"modsecurity", "mod_security",
				"not acceptable", "this error was generated by mod_security",
				"406 not acceptable",
			},
			BlockedStatusCodes: []int{406, 403},
			Tags:               []string{"modsecurity", "apache", "nginx", "waf"},
		},
		{
			Name: "Imperva/Incapsula", Vendor: "Imperva",
			HeaderPatterns: map[string][]string{
				"x-iinfo": {""},
				"x-cdn":   {"incapsula"},
			},
			CookiePatterns: []string{"incap_ses", "visid_incap"},
			BodyPatterns:   []string{"incapsula incident id", "powered by incapsula", "request unsuccessful"},
			Tags:           []string{"imperva", "incapsula", "waf"},
		},
		{
			Name: "Akamai", Vendor: "Akamai",
			HeaderPatterns: map[string][]string{
				"server":                {"akamaighost", "akamai"},
				"x-check-cacheable":     {""},
				"x-akamai-session-info": {""},
			},
			BodyPatterns: []string{"access denied - akamai", "reference #"},
			Tags:         []string{"akamai", "cdn", "waf"},
		},
		{
			Name: "Barracuda WAF", Vendor: "Barracuda Networks",
			CookiePatterns: []string{"barra_counter_session", "BNI__BARRACUDA_LB_COOKIE"},
			BodyPatterns:   []string{"barracuda application firewall", "barra_counter_session"},
			Tags:           []string{"barracuda", "waf"},
		},
		{
			Name: "Sucuri", Vendor: "Sucuri",
			HeaderPatterns: map[string][]string{
				"x-sucuri-id":      {""},
				"x-sucuri-cache":   {""},
				"x-sucuri-country": {""},
			},
			BodyPatterns: []string{"sucuri cloudproxy", "sucuri website firewall", "access denied - sucuri website firewall"},
			Tags:         []string{"sucuri", "waf"},
		},
		{
			Name: "F5 BIG-IP ASM", Vendor: "F5",
			CookiePatterns: []string{"ts01", "f5avr"},
			BodyPatterns:   []string{"the requested url was rejected", "please consult with your administrator", "your support id is"},
			Tags:           []string{"f5", "big-ip", "waf"},
		},
		{
			Name: "Citrix NetScaler", Vendor: "Citrix",
			CookiePatterns: []string{"citrix_ns_id", "ns_af_"},
			BodyPatterns:   []string{"netscaler", "citrix systems"},
			Tags:           []string{"citrix", "netscaler", "waf"},
		},
		{
			Name: "Fortinet FortiWeb", Vendor: "Fortinet",
			CookiePatterns: []string{"FORTIWAFSID"},
			BodyPatterns:   []string{"fortigate", "fortinet", "fortiweb application firewall"},
			Tags:           []string{"fortinet", "fortiweb", "waf"},
		},
		{
			Name: "WordFence", Vendor: "Defiant",
			BodyPatterns: []string{
				"generated by wordfence", "wordfence", "your access to this site has been limited",
				"a security plugin has blocked your ip",
			},
			Tags: []string{"wordfence", "wordpress", "waf"},
		},
		{
			Name: "Azure Front Door", Vendor: "Microsoft",
			HeaderPatterns: map[string][]string{
				"x-azure-ref":       {""},
				"x-ms-routing-name": {""},
			},
			BodyPatterns: []string{"microsoft azure", "403 - forbidden: access is denied"},
			Tags:         []string{"azure", "microsoft", "waf"},
		},
		{
			Name: "Fastly", Vendor: "Fastly",
			HeaderPatterns: map[string][]string{
				"x-served-by":     {"cache-"},
				"x-cache":         {"hit", "miss"},
				"fastly-restarts": {""},
			},
			Tags: []string{"fastly", "cdn", "waf"},
		},
		{
			Name: "Varnish", Vendor: "Varnish Software",
			HeaderPatterns: map[string][]string{
				"x-varnish":       {""},
				"via":             {"varnish"},
				"x-varnish-cache": {""},
				"x-cache":         {""},
			},
			BodyPatterns: []string{"guru meditation", "varnish cache server"},
			Tags:         []string{"varnish", "cache", "proxy"},
		},
		{
			Name: "Reblaze", Vendor: "Reblaze",
			CookiePatterns: []string{"rbzid", "rbzsessionid"},
			BodyPatterns:   []string{"reblaze", "access was blocked"},
			Tags:           []string{"reblaze", "waf"},
		},
		{
			Name: "StackPath", Vendor: "StackPath",
			HeaderPatterns: map[string][]string{
				"x-hw": {""},
			},
			BodyPatterns: []string{"stackpath", "site access blocked", "sp-cloud-waf"},
			Tags:         []string{"stackpath", "waf"},
		},
		{
			Name: "DenyAll rWeb", Vendor: "DenyAll",
			CookiePatterns: []string{"sessioncookie"},
			BodyPatterns:   []string{"denyall", "denied by r|web", "url has been blocked"},
			Tags:           []string{"denyall", "waf"},
		},
		{
			Name: "Radware AppWall", Vendor: "Radware",
			BodyPatterns: []string{"radware appwall", "unauthorized activity has been detected", "appwall"},
			Tags:         []string{"radware", "appwall", "waf"},
		},
	}
}
