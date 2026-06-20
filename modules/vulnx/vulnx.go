// Package vulnx performs vulnerability scanning by combining technology
// fingerprinting with known CVE/exploit databases. It detects the tech stack
// of a target and correlates it with a built-in vulnerability dataset covering
// the most impactful CVEs across web frameworks, CMS, servers, and containers.
//
// Reference: shodan-labs/vulnx (MIT) + NVD CVE data (public domain).
// No source code copied — only the vulnerability matching concept is used.
// License: MIT (blackhorn-modules).
package vulnx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	defaultTimeout = 20 * time.Second
	maxBodyBytes   = 2 * 1024 * 1024 // 2 MiB
)

// ─── vulnerability database ───────────────────────────────────────────────────

// VulnEntry describes a known vulnerability for a specific technology.
type VulnEntry struct {
	CVE         string
	Technology  string // matched against fingerprinted tech names
	VersionRe   string // regex to match affected version strings (empty = all versions)
	Severity    module.Severity
	CVSS        float64
	Description string
	References  []string

	compiledRe *regexp.Regexp
}

// builtinVulns is the built-in vulnerability database.
// Entries are matched against fingerprinted technologies at runtime.
var builtinVulns = []VulnEntry{
	// ─── Apache HTTP Server ──────────────────────────────────────────────────
	{CVE: "CVE-2021-41773", Technology: "apache", VersionRe: `2\.4\.49`,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "Path traversal and RCE via mod_cgi in Apache 2.4.49",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-41773"}},
	{CVE: "CVE-2021-42013", Technology: "apache", VersionRe: `2\.4\.(49|50)`,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "Path traversal and RCE bypass in Apache 2.4.49/2.4.50",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-42013"}},
	{CVE: "CVE-2017-7679", Technology: "apache", VersionRe: `2\.(2\.|4\.[01])`,
		Severity: module.SeverityHigh, CVSS: 9.8,
		Description: "Buffer overflow in mod_mime (Apache <2.2.34, <2.4.26)"},
	{CVE: "CVE-2024-38472", Technology: "apache", VersionRe: ``,
		Severity: module.SeverityHigh, CVSS: 7.5,
		Description: "Server-Side Request Forgery in Apache HTTP Server on Windows"},

	// ─── Nginx ───────────────────────────────────────────────────────────────
	{CVE: "CVE-2013-4547", Technology: "nginx", VersionRe: `0\.(7|8)\.|1\.[0-4]\.`,
		Severity: module.SeverityHigh, CVSS: 7.5,
		Description: "nginx file name confusion with uninitialized memory"},
	// CVE-2021-23017 affects nginx < 1.20.2 and 1.21.x < 1.21.1.
	// nginx 1.20.2+ (stable) and 1.21.1+ (mainline) are patched.
	// Regex matches: 0.x, 1.0-1.19.x, 1.20.0, 1.20.1 (not 1.20.2+), 1.21.0 (not 1.21.1+).
	{CVE: "CVE-2021-23017", Technology: "nginx",
		VersionRe: `^(0\.|1\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19)\.|1\.20\.[01][^0-9]|1\.20\.[01]$|1\.21\.0[^0-9]|1\.21\.0$)`,
		Severity:  module.SeverityHigh, CVSS: 7.7,
		Description: "1-byte memory overwrite in nginx resolver (nginx < 1.20.2)"},

	// ─── WordPress ───────────────────────────────────────────────────────────
	{CVE: "CVE-2022-21661", Technology: "wordpress", VersionRe: ``,
		Severity: module.SeverityHigh, CVSS: 8.8,
		Description: "WordPress SQL injection via WP_Query"},
	{CVE: "CVE-2022-21664", Technology: "wordpress", VersionRe: ``,
		Severity: module.SeverityHigh, CVSS: 8.8,
		Description: "WordPress SQL injection via core WP_Meta_Query"},
	{CVE: "CVE-2023-39999", Technology: "wordpress", VersionRe: ``,
		Severity: module.SeverityMedium, CVSS: 6.5,
		Description: "WordPress information disclosure via REST API"},
	{CVE: "CVE-2024-6386", Technology: "wordpress", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 9.9,
		Description: "SSTI RCE in WPML plugin for WordPress"},

	// ─── Drupal ──────────────────────────────────────────────────────────────
	{CVE: "CVE-2018-7600", Technology: "drupal", VersionRe: `7\.|8\.`,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "Drupalgeddon2: RCE via Form API (Drupal 7/8)"},
	{CVE: "CVE-2018-7602", Technology: "drupal", VersionRe: `7\.`,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "Drupalgeddon3: RCE via deletion forms (Drupal 7)"},
	{CVE: "CVE-2019-6340", Technology: "drupal", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "RCE via REST API in Drupal 8.5.x < 8.5.11"},

	// ─── Joomla ──────────────────────────────────────────────────────────────
	{CVE: "CVE-2015-8562", Technology: "joomla", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 10.0,
		Description: "Joomla! RCE via object injection in PHP session handler"},
	{CVE: "CVE-2023-23752", Technology: "joomla", VersionRe: ``,
		Severity: module.SeverityMedium, CVSS: 5.3,
		Description: "Joomla! improper access check in web service API"},

	// ─── Laravel ─────────────────────────────────────────────────────────────
	{CVE: "CVE-2021-3129", Technology: "laravel", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "RCE via ignition log file when APP_DEBUG=true"},
	{CVE: "CVE-2018-15133", Technology: "laravel", VersionRe: `5\.[56]\.`,
		Severity: module.SeverityHigh, CVSS: 8.1,
		Description: "Laravel RCE via unserialize() in cache driver"},

	// ─── Spring Boot / Spring Framework ──────────────────────────────────────
	{CVE: "CVE-2022-22965", Technology: "spring", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "Spring4Shell: RCE via data binding (JDK >= 9)"},
	{CVE: "CVE-2022-22963", Technology: "spring", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "Spring Cloud Function SPEL expression injection"},
	{CVE: "CVE-2017-8046", Technology: "spring", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "Spring Data REST PATCH RCE via SpEL injection"},

	// ─── Log4j ───────────────────────────────────────────────────────────────
	{CVE: "CVE-2021-44228", Technology: "log4j", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 10.0,
		Description: "Log4Shell: JNDI injection RCE in Log4j 2.x"},
	{CVE: "CVE-2021-45046", Technology: "log4j", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 9.0,
		Description: "Log4j DoS/RCE bypass (Log4j 2.15.0)"},
	{CVE: "CVE-2021-44832", Technology: "log4j", VersionRe: ``,
		Severity: module.SeverityMedium, CVSS: 6.6,
		Description: "Log4j RCE via JDBC appender with attacker-controlled config"},

	// ─── Struts ──────────────────────────────────────────────────────────────
	{CVE: "CVE-2017-5638", Technology: "struts", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 10.0,
		Description: "Apache Struts2 Content-Type OGNL injection RCE (Equifax breach)"},
	{CVE: "CVE-2018-11776", Technology: "struts", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 10.0,
		Description: "Apache Struts2 namespace RCE"},

	// ─── Jenkins ─────────────────────────────────────────────────────────────
	{CVE: "CVE-2019-1003000", Technology: "jenkins", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 8.8,
		Description: "Jenkins Sandbox Bypass RCE via Script Security"},
	{CVE: "CVE-2018-1000861", Technology: "jenkins", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "Jenkins unauthenticated RCE via Stapler web framework"},
	{CVE: "CVE-2024-23897", Technology: "jenkins", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "Jenkins arbitrary file read via CLI parser (2024)"},

	// ─── GitLab ──────────────────────────────────────────────────────────────
	{CVE: "CVE-2021-22205", Technology: "gitlab", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 10.0,
		Description: "GitLab RCE via ExifTool upload parsing"},
	{CVE: "CVE-2023-7028", Technology: "gitlab", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 10.0,
		Description: "GitLab account takeover via password reset email"},

	// ─── Docker / Kubernetes ──────────────────────────────────────────────────
	{CVE: "CVE-2019-5736", Technology: "docker", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 8.6,
		Description: "runc container escape via /proc/self/exe overwrite"},
	{CVE: "CVE-2020-15257", Technology: "docker", VersionRe: ``,
		Severity: module.SeverityHigh, CVSS: 8.8,
		Description: "containerd API exposure via host networking"},
	{CVE: "CVE-2018-1002105", Technology: "kubernetes", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "Kubernetes API server privilege escalation"},

	// ─── OpenSSL ──────────────────────────────────────────────────────────────
	{CVE: "CVE-2022-0778", Technology: "openssl", VersionRe: ``,
		Severity: module.SeverityHigh, CVSS: 7.5,
		Description: "OpenSSL infinite loop via certificate parsing DoS"},
	{CVE: "CVE-2014-0160", Technology: "openssl", VersionRe: `1\.0\.[01]`,
		Severity: module.SeverityHigh, CVSS: 7.5,
		Description: "Heartbleed: OpenSSL memory leak via TLS heartbeat"},

	// ─── PHP ──────────────────────────────────────────────────────────────────
	{CVE: "CVE-2024-4577", Technology: "php", VersionRe: `8\.[23]`,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "PHP CGI argument injection RCE on Windows"},
	{CVE: "CVE-2019-11043", Technology: "php", VersionRe: `7\.[01234]`,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "PHP-FPM buffer underflow RCE via nginx misconfiguration"},

	// ─── Elasticsearch ───────────────────────────────────────────────────────
	{CVE: "CVE-2015-1427", Technology: "elasticsearch", VersionRe: `1\.[0-3]\.`,
		Severity: module.SeverityCritical, CVSS: 10.0,
		Description: "Elasticsearch Groovy sandbox escape RCE (Shodan vulnerable hosts)"},
	{CVE: "CVE-2021-22146", Technology: "elasticsearch", VersionRe: ``,
		Severity: module.SeverityHigh, CVSS: 7.5,
		Description: "Elasticsearch sensitive info in API response"},

	// ─── Redis ───────────────────────────────────────────────────────────────
	{CVE: "CVE-2022-0543", Technology: "redis", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 10.0,
		Description: "Redis Lua sandbox escape RCE (Debian/Ubuntu packaging)"},
	{CVE: "CVE-2023-28425", Technology: "redis", VersionRe: `7\.0`,
		Severity: module.SeverityMedium, CVSS: 5.5,
		Description: "Redis denial-of-service via malformed SRANDMEMBER command"},

	// ─── Node.js / npm ───────────────────────────────────────────────────────
	{CVE: "CVE-2022-32213", Technology: "node", VersionRe: ``,
		Severity: module.SeverityMedium, CVSS: 6.5,
		Description: "Node.js HTTP request smuggling via invalid chunk extension"},
	{CVE: "CVE-2023-30590", Technology: "node", VersionRe: ``,
		Severity: module.SeverityHigh, CVSS: 7.5,
		Description: "Node.js crypto.randomBytes() insecure fallback"},

	// ─── Confluence ──────────────────────────────────────────────────────────
	{CVE: "CVE-2022-26134", Technology: "confluence", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "Confluence Server/Data Center OGNL injection RCE"},
	{CVE: "CVE-2023-22527", Technology: "confluence", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 10.0,
		Description: "Confluence SSTI/RCE via template injection (2024)"},

	// ─── Exchange / OWA ──────────────────────────────────────────────────────
	{CVE: "CVE-2021-26855", Technology: "exchange", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "ProxyLogon: Exchange Server SSRF + auth bypass"},
	{CVE: "CVE-2021-34473", Technology: "exchange", VersionRe: ``,
		Severity: module.SeverityCritical, CVSS: 9.8,
		Description: "ProxyShell: Exchange Server URL rewrite RCE"},
}

// ─── fingerprinting hints ─────────────────────────────────────────────────────

// fingerprintHints maps HTTP response signals to technology names that match
// entries in builtinVulns. These are lightweight checks — for full fingerprinting
// use the modules/fingerprint module.
var fingerprintHints = []struct {
	header  string // header name (lowercase)
	pattern string // regex pattern to match header value
	tech    string // technology name for vuln lookup
}{
	{"server", `(?i)apache`, "apache"},
	{"server", `(?i)nginx`, "nginx"},
	{"x-powered-by", `(?i)php`, "php"},
	{"x-powered-by", `(?i)express`, "node"},
	{"x-powered-by", `(?i)asp\.net`, "iis"},
	{"x-generator", `(?i)wordpress`, "wordpress"},
	{"x-generator", `(?i)drupal`, "drupal"},
	{"x-powered-by", `(?i)struts`, "struts"},
	{"via", `(?i)varnish`, "varnish"},
	{"x-jenkins", ``, "jenkins"},
	{"x-gitlab-meta", ``, "gitlab"},
}

// bodyHints are checked against the response body.
var bodyHints = []struct {
	pattern string
	tech    string
}{
	{`(?i)wp-content|wp-includes`, "wordpress"},
	{`(?i)joomla`, "joomla"},
	{`(?i)drupal\.settings`, "drupal"},
	{`(?i)laravel_session|csrf_token.*laravel`, "laravel"},
	{`(?i)spring framework`, "spring"},
	{`(?i)log4j`, "log4j"},
	{`(?i)struts`, "struts"},
	{`(?i)elastic.*kibana|kibana`, "elasticsearch"},
	{`(?i)confluence`, "confluence"},
	{`(?i)<title>.*gitlab`, "gitlab"},
	{`(?i)<title>.*jenkins`, "jenkins"},
	{`(?i)docker-desktop|docker daemon`, "docker"},
	{`(?i)kubernetes dashboard`, "kubernetes"},
}

// ─── module ──────────────────────────────────────────────────────────────────

// Module identifies technologies and correlates them with known vulnerabilities.
type Module struct {
	client *http.Client
	// ExtraVulns extends the built-in vulnerability database.
	ExtraVulns []VulnEntry
	// TechOverride skips fingerprinting and uses a fixed technology list.
	TechOverride []string
	// MinCVSS filters findings below this CVSS score (default: 0.0 = no filter).
	MinCVSS float64
	// EnableNVDLookup enables live NVD CVE API lookup for additional details.
	EnableNVDLookup bool
	// NVDBaseURL overrides the NVD API URL (for testing).
	NVDBaseURL string
}

// New returns a Module with production defaults.
func New() *Module {
	return &Module{
		client: httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
	}
}

// NewWithClient creates a Module using the provided HTTP client.
func NewWithClient(c *http.Client) *Module {
	return &Module{client: c}
}

// Name implements module.Module.
func (m *Module) Name() string { return "vulnx" }

// Run implements module.Module.
// Input.Target: URL to fingerprint and scan.
// Input.URLs: additional URLs to scan.
// Input.Options:
//   - "tech": comma-separated tech override (skips fingerprinting)
//   - "min_cvss": minimum CVSS to include (default: 0.0)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	targets := collectTargets(input)
	if len(targets) == 0 {
		return nil, fmt.Errorf("vulnx: no targets provided")
	}

	// Compile vuln regex.
	allVulns := append(builtinVulns, m.ExtraVulns...)
	for i := range allVulns {
		if allVulns[i].VersionRe != "" {
			re, err := regexp.Compile(allVulns[i].VersionRe)
			if err != nil {
				return nil, fmt.Errorf("vulnx: invalid VersionRe for %s: %w", allVulns[i].CVE, err)
			}
			allVulns[i].compiledRe = re
		}
	}

	minCVSS := m.MinCVSS
	if v := input.Options["min_cvss"]; v != "" {
		fmt.Sscanf(v, "%f", &minCVSS)
	}

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(len(targets))

	for _, target := range targets {
		target := target
		g.Go(func() error {
			ff, err := m.scanTarget(gctx, target, input.Options, allVulns, minCVSS)
			if err != nil {
				slog.Warn("vulnx: target scan failed", "target", target, "err", err)
				return nil
			}
			if len(ff) > 0 {
				mu.Lock()
				findings = append(findings, ff...)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()
	return dedupFindings(findings), nil
}

// ─── target scanning ──────────────────────────────────────────────────────────

func (m *Module) scanTarget(ctx context.Context, target string, opts map[string]string, vulns []VulnEntry, minCVSS float64) ([]module.Finding, error) {
	// Determine technologies.
	var techs []string
	if m.TechOverride != nil {
		techs = m.TechOverride
	} else if opts != nil && opts["tech"] != "" {
		for _, t := range strings.Split(opts["tech"], ",") {
			techs = append(techs, strings.TrimSpace(strings.ToLower(t)))
		}
	} else {
		var err error
		techs, err = m.fingerprint(ctx, target)
		if err != nil {
			slog.Debug("vulnx: fingerprint failed", "target", target, "err", err)
			// Continue with empty tech list — no vuln matches.
		}
	}

	if len(techs) == 0 {
		return nil, nil
	}

	// Match vulnerabilities.
	var findings []module.Finding
	for _, vuln := range vulns {
		if vuln.CVSS < minCVSS {
			continue
		}
		for _, tech := range techs {
			// Match technology name.
			if !techMatches(tech, vuln.Technology) {
				continue
			}
			// Check version constraint.
			// TODO: version is embedded in tech string as "apache/2.4.49"
			version := extractVersion(tech, vuln.Technology)
			if vuln.compiledRe != nil && version != "" && !vuln.compiledRe.MatchString(version) {
				continue
			}
			findings = append(findings, module.Finding{
				Type:     "known_cve",
				URL:      target,
				Severity: vuln.Severity,
				Detail:   fmt.Sprintf("%s: %s", vuln.CVE, vuln.Description),
				Extra: map[string]string{
					"cve":         vuln.CVE,
					"technology":  tech,
					"cvss":        fmt.Sprintf("%.1f", vuln.CVSS),
					"description": vuln.Description,
					"target":      target,
					"confidence":  "0.70",
				},
			})
			break // one match per vuln entry per target
		}
	}

	// Optionally enrich with NVD API.
	if m.EnableNVDLookup {
		for i := range findings {
			if cve := findings[i].Extra["cve"]; cve != "" {
				if detail := m.lookupNVD(ctx, cve); detail != "" {
					findings[i].Extra["nvd_detail"] = detail
				}
			}
		}
	}

	return findings, nil
}

// ─── fingerprinting ───────────────────────────────────────────────────────────

// fingerprint fetches target and extracts technology hints from headers + body.
func (m *Module) fingerprint(ctx context.Context, target string) ([]string, error) {
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-vulnx/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))

	var techs []string
	seen := make(map[string]struct{})
	add := func(t string) {
		t = strings.ToLower(t)
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			techs = append(techs, t)
		}
	}

	// Header-based hints.
	for _, hint := range fingerprintHints {
		val := resp.Header.Get(hint.header)
		if val == "" {
			continue
		}
		if hint.pattern == "" {
			add(hint.tech)
			continue
		}
		if matched, _ := regexp.MatchString(hint.pattern, val); matched {
			// Try to include version from header value.
			ver := extractVersionFromString(val)
			if ver != "" {
				add(hint.tech + "/" + ver)
			} else {
				add(hint.tech)
			}
		}
	}

	// Body-based hints.
	bodyStr := string(body)
	for _, hint := range bodyHints {
		if matched, _ := regexp.MatchString(hint.pattern, bodyStr); matched {
			add(hint.tech)
		}
	}

	return techs, nil
}

// ─── NVD API lookup (optional enrichment) ─────────────────────────────────────

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func (m *Module) nvdBase() string {
	if m.NVDBaseURL != "" {
		return m.NVDBaseURL
	}
	return "https://services.nvd.nist.gov/rest/json/cves/2.0"
}

func (m *Module) lookupNVD(ctx context.Context, cve string) string {
	apiURL := fmt.Sprintf("%s?cveId=%s", m.nvdBase(), cve)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "blackhorn-vulnx/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))

	var nvd nvdResponse
	if err := json.Unmarshal(body, &nvd); err != nil {
		return ""
	}
	for _, v := range nvd.Vulnerabilities {
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				return d.Value
			}
		}
	}
	return ""
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func techMatches(detected, vulnTech string) bool {
	// "apache/2.4.49" matches "apache".
	base := strings.ToLower(strings.SplitN(detected, "/", 2)[0])
	return base == strings.ToLower(vulnTech)
}

func extractVersion(tech, _ string) string {
	parts := strings.SplitN(tech, "/", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

var reVersion = regexp.MustCompile(`(\d+\.\d+[\.\d]*)`)

func extractVersionFromString(s string) string {
	if m := reVersion.FindString(s); m != "" {
		return m
	}
	return ""
}

func collectTargets(input module.Input) []string {
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

func dedupFindings(findings []module.Finding) []module.Finding {
	seen := make(map[string]struct{})
	out := findings[:0]
	for _, f := range findings {
		key := f.Extra["cve"] + "|" + f.URL
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, f)
		}
	}
	return out
}
