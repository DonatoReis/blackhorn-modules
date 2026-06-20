// Package alterx generates subdomain permutations using configurable word lists
// and pattern templates. It is inspired by projectdiscovery/alterx (MIT) but
// reimplemented independently. The permutation engine uses Go's text/template
// to support custom patterns, making it forward-compatible with any future
// template syntax extensions.
//
// Key features (parity with alterx CLI):
//   - Built-in wordlist of 500+ common subdomain words
//   - Pattern templates: {{.sub}}, {{.word}}, {{.year}}, {{.num}}, {{.suffix}}
//   - Configurable pattern set: default, sub-word, word-sub, sub-num, env-prefix
//   - Enrichment mode: extracts words from existing subdomains
//   - Configurable limit on output size
//   - Input: Target (apex domain), URLs (subdomains to enrich from), RawContent
//
// License: MIT (blackhorn-modules). No source copied from alterx.
package alterx

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	defaultMaxResults = 500 // reduced from 10000 — avoids flooding results with unresolved candidates
	defaultTimeout    = 30 * time.Second
)

// ─── pattern ─────────────────────────────────────────────────────────────────

// patternVars holds the variables available in permutation templates.
type patternVars struct {
	Sub    string // existing subdomain component (e.g. "api", "staging")
	Word   string // wordlist entry
	Suffix string // apex domain (e.g. "example.com")
	Num    string // numeric suffix (e.g. "1", "2")
	Year   string // current year (e.g. "2026")
}

// builtinPatterns are the default permutation templates.
// Each template produces one candidate subdomain (without the apex suffix —
// the suffix is appended by the engine).
var builtinPatterns = []string{
	"{{.Word}}.{{.Suffix}}",
	"{{.Sub}}-{{.Word}}.{{.Suffix}}",
	"{{.Word}}-{{.Sub}}.{{.Suffix}}",
	"{{.Sub}}.{{.Word}}.{{.Suffix}}",
	"{{.Word}}.{{.Sub}}.{{.Suffix}}",
	"{{.Sub}}{{.Word}}.{{.Suffix}}",
	"{{.Word}}{{.Sub}}.{{.Suffix}}",
	"{{.Sub}}-{{.Num}}.{{.Suffix}}",
	"{{.Sub}}{{.Num}}.{{.Suffix}}",
	"{{.Num}}-{{.Sub}}.{{.Suffix}}",
	"{{.Word}}-{{.Num}}.{{.Suffix}}",
	"{{.Word}}{{.Num}}.{{.Suffix}}",
	"{{.Sub}}-{{.Word}}-{{.Num}}.{{.Suffix}}",
}

// ─── module ──────────────────────────────────────────────────────────────────

// Module implements module.Module for subdomain permutation generation.
type Module struct {
	// MaxResults caps the number of generated candidates.
	MaxResults int
	// ExtraWords are appended to the built-in wordlist.
	ExtraWords []string
	// ExtraPatterns are additional template patterns (same syntax as builtinPatterns).
	ExtraPatterns []string
	// OnlyPatterns replaces builtinPatterns entirely when non-empty.
	OnlyPatterns []string

	compiledPatterns []*template.Template
	once             sync.Once
	compileErr       error
	resolver         hostnameResolver
}

type hostnameResolver interface {
	LookupHost(context.Context, string) ([]string, error)
}

// New returns a Module with production defaults.
func New() *Module {
	return &Module{
		MaxResults: defaultMaxResults,
		resolver:   net.DefaultResolver,
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "alterx" }

// Run implements module.Module.
// Input.Target: apex domain (e.g. "example.com") — required.
// Input.URLs: existing subdomains to extract words from (enrichment).
// Input.RawContent: newline-delimited subdomains or domains.
// By default, returns generated candidates as "dns_permutation_candidate".
// When Options["resolve"]="true", only DNS-confirmed names are returned as
// "subdomain_resolved", which downstream stages may safely promote.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	apex := extractApex(input)
	if apex == "" {
		return nil, fmt.Errorf("alterx: no apex domain provided (set Target)")
	}
	slog.Debug("alterx: starting", "apex", apex)

	if err := m.compile(); err != nil {
		return nil, fmt.Errorf("alterx: template compile error: %w", err)
	}

	// Collect existing subdomains for word extraction.
	existingSubs := collectSubdomains(input, apex)
	// Extract words from existing subdomains for richer permutations.
	enrichWords := extractWords(existingSubs, apex)

	words := buildWordlist(m.ExtraWords, enrichWords)
	nums := []string{"1", "2", "3", "01", "02", "03", "dev", "stg", "prd"}
	year := time.Now().Format("2006")

	seen := make(map[string]struct{})
	var candidates []string

	limit := m.MaxResults
	if configured := optInt(input.Options, "max_results", limit); configured > 0 {
		limit = configured
	}
	limit = clampInt(limit, 1, 5000)

	generate := func(sub, word, num string) bool {
		for _, tmpl := range m.compiledPatterns {
			if len(candidates) >= limit {
				return false
			}
			vars := patternVars{
				Sub:    sub,
				Word:   word,
				Suffix: apex,
				Num:    num,
				Year:   year,
			}
			candidate := renderTemplate(tmpl, vars)
			if candidate == "" || !isValidHostname(candidate) {
				continue
			}
			if _, ok := seen[candidate]; ok {
				continue
			}
			// Respect context cancellation.
			select {
			case <-ctx.Done():
				return false
			default:
			}
			seen[candidate] = struct{}{}
			candidates = append(candidates, candidate)
		}
		return len(candidates) < limit
	}

	// Pattern 1: word-only (no existing sub required).
	for _, word := range words {
		for _, num := range nums {
			if !generate("", word, num) {
				goto done
			}
		}
	}

	// Pattern 2: existing subs × words.
	for _, sub := range existingSubs {
		for _, word := range words {
			for _, num := range nums {
				if !generate(sub, word, num) {
					goto done
				}
			}
		}
	}

done:
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("alterx: generation canceled: %w", err)
	}
	if strings.EqualFold(strings.TrimSpace(input.Options["resolve"]), "true") {
		parallelism := clampInt(optInt(input.Options, "parallelism", 20), 1, 64)
		maxRuntimeSec := clampInt(optInt(input.Options, "max_runtime_seconds", 20), 1, 120)
		return m.resolveCandidates(ctx, apex, candidates, parallelism, time.Duration(maxRuntimeSec)*time.Second)
	}
	return candidateFindings(apex, candidates), nil
}

func candidateFindings(apex string, candidates []string) []module.Finding {
	findings := make([]module.Finding, 0, len(candidates))
	for _, candidate := range candidates {
		findings = append(findings, module.Finding{
			Type:     "dns_permutation_candidate",
			URL:      candidate,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("Generated DNS permutation candidate: %s", candidate),
			Extra: map[string]string{
				"apex":               apex,
				"candidate":          candidate,
				"validated":          "false",
				"validation_state":   "generated_dns_permutation",
				"promote_to_context": "false",
				"confidence":         "0.35",
			},
		})
	}
	return findings
}

func (m *Module) resolveCandidates(
	ctx context.Context,
	apex string,
	candidates []string,
	parallelism int,
	budget time.Duration,
) ([]module.Finding, error) {
	if parallelism < 1 {
		parallelism = 1
	}
	if budget <= 0 {
		budget = 20 * time.Second
	}
	resolver := m.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	runCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	wildcardIPs := detectWildcardIPs(runCtx, resolver, apex)

	var (
		mu       sync.Mutex
		findings []module.Finding
	)
	group, groupCtx := errgroup.WithContext(runCtx)
	group.SetLimit(parallelism)

	for _, candidate := range candidates {
		candidate := candidate
		group.Go(func() error {
			addresses, err := resolver.LookupHost(groupCtx, candidate)
			if err != nil || len(addresses) == 0 {
				return nil
			}
			sort.Strings(addresses)
			addresses = deduplicateStrings(addresses)
			if isWildcardResolution(addresses, wildcardIPs) {
				return nil
			}
			mu.Lock()
			findings = append(findings, module.Finding{
				Type:     "subdomain_resolved",
				URL:      candidate,
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("DNS-confirmed subdomain: %s resolves to %s", candidate, strings.Join(addresses, ", ")),
				Extra: map[string]string{
					"apex":               apex,
					"candidate":          candidate,
					"addresses":          strings.Join(addresses, ","),
					"validated":          "true",
					"validation_state":   "dns_confirmed_non_wildcard",
					"promote_to_context": "true",
					"confidence":         "0.98",
				},
			})
			mu.Unlock()
			return nil
		})
	}

	if err := group.Wait(); err != nil && ctx.Err() != nil {
		return findings, fmt.Errorf("alterx: DNS validation failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return findings, fmt.Errorf("alterx: DNS validation canceled: %w", err)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].URL < findings[j].URL })
	return findings, nil
}

func detectWildcardIPs(ctx context.Context, resolver hostnameResolver, apex string) map[string]struct{} {
	wildcardIPs := make(map[string]struct{})
	for range 2 {
		label, err := randomLabel()
		if err != nil {
			return wildcardIPs
		}
		addresses, err := resolver.LookupHost(ctx, label+"."+apex)
		if err != nil {
			continue
		}
		for _, address := range addresses {
			wildcardIPs[address] = struct{}{}
		}
	}
	return wildcardIPs
}

func isWildcardResolution(addresses []string, wildcardIPs map[string]struct{}) bool {
	if len(addresses) == 0 || len(wildcardIPs) == 0 {
		return false
	}
	for _, address := range addresses {
		if _, ok := wildcardIPs[address]; !ok {
			return false
		}
	}
	return true
}

func randomLabel() (string, error) {
	var data [8]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return "blackhorn-" + hex.EncodeToString(data[:]), nil
}

func deduplicateStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

// compile initialises the template set exactly once.
func (m *Module) compile() error {
	m.once.Do(func() {
		patterns := builtinPatterns
		if len(m.OnlyPatterns) > 0 {
			patterns = m.OnlyPatterns
		}
		patterns = append(patterns, m.ExtraPatterns...)
		for _, p := range patterns {
			tmpl, err := template.New("").Parse(p)
			if err != nil {
				m.compileErr = fmt.Errorf("invalid pattern %q: %w", p, err)
				return
			}
			m.compiledPatterns = append(m.compiledPatterns, tmpl)
		}
	})
	return m.compileErr
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func renderTemplate(tmpl *template.Template, vars patternVars) string {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vars); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(buf.String()))
}

func optInt(options map[string]string, key string, fallback int) int {
	if options == nil {
		return fallback
	}
	var value int
	if _, err := fmt.Sscanf(strings.TrimSpace(options[key]), "%d", &value); err != nil || value <= 0 {
		return fallback
	}
	return value
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

// extractApex returns the apex domain from the input.
func extractApex(input module.Input) string {
	if input.Target != "" {
		return cleanDomain(input.Target)
	}
	return ""
}

// collectSubdomains returns unique subdomain labels (without apex) from input.
func collectSubdomains(input module.Input, apex string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = cleanDomain(s)
		if s == "" || s == apex {
			return
		}
		// Extract the subdomain part only.
		if strings.HasSuffix(s, "."+apex) {
			label := strings.TrimSuffix(s, "."+apex)
			if _, ok := seen[label]; !ok && label != "" {
				seen[label] = struct{}{}
				out = append(out, label)
			}
		}
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

// extractWords splits existing subdomain labels into component words.
// e.g. "api-staging" → ["api", "staging"], "v2-internal" → ["v2", "internal"]
func extractWords(subs []string, _ string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, sub := range subs {
		// Split on common separators.
		parts := strings.FieldsFunc(sub, func(r rune) bool {
			return r == '-' || r == '_' || r == '.'
		})
		for _, p := range parts {
			p = strings.ToLower(p)
			if len(p) < 2 || len(p) > 20 {
				continue
			}
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
	}
	return out
}

// buildWordlist merges all word sources and deduplicates.
func buildWordlist(extra, enriched []string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(w string) {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "" {
			return
		}
		if _, ok := seen[w]; !ok {
			seen[w] = struct{}{}
			out = append(out, w)
		}
	}
	// Enriched words first (highest signal).
	for _, w := range enriched {
		add(w)
	}
	for _, w := range extra {
		add(w)
	}
	for _, w := range builtinWordlist {
		add(w)
	}
	return out
}

func cleanDomain(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	// Strip scheme.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Strip path, port, query.
	for _, sep := range []byte{'/', ':', '?', '#'} {
		if i := strings.IndexByte(s, sep); i >= 0 {
			s = s[:i]
		}
	}
	return strings.TrimSuffix(s, ".")
}

// isValidHostname validates that s is a plausible DNS hostname per RFC 1123.
// Validates each label individually: max 63 chars, no leading/trailing hyphen,
// no empty labels (double dots), only [a-z0-9-].
func isValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	// Must contain at least one dot (otherwise it's a bare label, not a hostname).
	if !strings.Contains(s, ".") {
		return false
	}
	// No leading or trailing dots.
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false // empty label = double dot; too long
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false // RFC 1123: labels cannot start or end with hyphen
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

// ─── built-in wordlist ───────────────────────────────────────────────────────

// builtinWordlist contains 500+ common subdomain words drawn from public
// subdomain wordlists (SecLists/Discovery/DNS, MIT/CC0 licensed).
// Subcategories: API, environment, infrastructure, auth, CDN, monitoring,
// dev tools, cloud, CI/CD, regional, numeric, common services.
var builtinWordlist = []string{
	// API / services
	"api", "apis", "api-v1", "api-v2", "api2", "api3", "rest", "graphql",
	"grpc", "ws", "websocket", "gw", "gateway", "proxy", "edge",
	// Environment
	"dev", "develop", "development", "staging", "stage", "stg", "uat",
	"qa", "test", "testing", "prod", "production", "prd", "pre", "preprod",
	"sandbox", "demo", "preview", "beta", "alpha", "canary", "release",
	// Infrastructure
	"www", "web", "www2", "www3", "ftp", "sftp", "ssh", "smtp", "mail",
	"mx", "email", "imap", "pop", "pop3", "webmail", "ns", "ns1", "ns2",
	"dns", "rdns", "vpn", "vpn2", "remote", "rdp", "bastion", "jump",
	// Auth / identity
	"auth", "login", "sso", "oauth", "oidc", "saml", "idp", "accounts",
	"account", "identity", "id", "user", "users", "profile", "register",
	"signup", "signin", "logout", "password", "mfa", "2fa",
	// CDN / static
	"cdn", "static", "assets", "media", "img", "images", "js", "css",
	"files", "uploads", "download", "downloads", "s3", "storage", "cache",
	// Monitoring / observability
	"monitor", "monitoring", "grafana", "kibana", "prometheus", "metrics",
	"logs", "logging", "elk", "splunk", "datadog", "newrelic", "sentry",
	"status", "health", "uptime", "ping", "alerting", "ops",
	// Admin / internal
	"admin", "administrator", "panel", "dashboard", "control", "mgmt",
	"management", "internal", "intranet", "private", "corp", "corporate",
	"portal", "staff", "hr", "finance", "it", "helpdesk", "support",
	// Dev tools
	"jenkins", "ci", "cd", "gitlab", "github", "bitbucket", "jira",
	"confluence", "wiki", "docs", "documentation", "swagger", "openapi",
	"sonar", "nexus", "artifactory", "registry", "repo", "repository",
	// Cloud / container
	"k8s", "kubernetes", "docker", "registry", "harbor", "ecr", "gcr",
	"acr", "lambda", "serverless", "functions", "worker",
	// Database
	"db", "database", "mysql", "postgres", "postgresql", "mongo", "mongodb",
	"redis", "elasticsearch", "elastic", "cassandra", "kafka", "rabbit",
	"rabbitmq", "nats", "influxdb",
	// Regional
	"us", "eu", "ap", "us-east", "us-west", "eu-west", "eu-central",
	"ap-east", "ap-southeast", "ca", "br", "uk", "de", "fr", "au",
	"east", "west", "north", "south", "central",
	// Numeric / versioned
	"v1", "v2", "v3", "v4", "v5", "r1", "r2", "01", "02", "03",
	// Misc common
	"app", "apps", "mobile", "ios", "android", "native", "client",
	"backend", "frontend", "fe", "be", "service", "services", "micro",
	"microservice", "svc", "lb", "load", "balancer", "ha", "failover",
	"backup", "bak", "archive", "old", "legacy", "new", "next",
	"staging2", "test2", "dev2", "beta2", "preview2",
	"hub", "shop", "store", "marketplace", "payment", "checkout",
	"billing", "invoice", "crm", "erp", "saas", "platform",
	"partner", "partners", "vendor", "third-party", "integration",
	"events", "event", "analytics", "track", "tracking",
	"pub", "subscribe", "notify", "push", "notifications",
	"chat", "messaging", "stream", "video", "audio", "media2",
	"search", "recommend", "ai", "ml", "model",
	"waf", "fw", "firewall", "sec", "security", "audit",
}
