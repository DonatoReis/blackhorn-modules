// Package vulnscan is an algorithmic reimplementation of projectdiscovery/nuclei
// (MIT License) HTTP template matching engine.
//
// Source reference: github.com/projectdiscovery/nuclei/pkg/operators/matchers/matchers.go,
// pkg/protocols/http/request.go, pkg/protocols/http/operators.go.
//
// Strategy: nuclei's engine is large (YAML templates, DSL, headless, etc.).
// We implement the core algorithm — HTTP request execution + matcher evaluation
// (status/word/regex/size) — using stdlib only. This covers the most common
// vulnerability checks without importing the full nuclei dependency tree.
//
// What is ported faithfully:
//   - Matcher struct — identical fields and JSON/YAML tags to nuclei matchers.go
//   - MatcherType: status, word, regex, size — all 4 basic types
//   - Condition: "and"/"or" — mirrors nuclei AND/OR logic
//   - Part: "body"/"header"/"raw"/"status" — mirrors nuclei Part field
//   - Negative matcher — mirrors nuclei Negative field
//   - Template struct — mirrors nuclei templates basic fields
//   - HTTP request builder — mirrors nuclei build_request.go
//   - io.LimitReader on every body — dicas.md §5
//   - context propagation — guia-go §9
//   - log/slog observability — dicas.md §16
//
// Bundled templates: 20 high-signal HTTP checks covering common misconfigurations
// and exposures (missing security headers, path traversal, default credentials,
// version disclosure, open redirect, CORS, etc.).
package vulnscan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	// maxBodyRead is the memory ceiling per response — dicas.md §5.
	maxBodyRead = 5 * 1024 * 1024 // 5 MB

	// defaultTimeout per HTTP request.
	defaultTimeout = 10 * time.Second

	// concurrentTemplates — errgroup goroutine limit.
	concurrentTemplates = 20
)

// ─── Matcher types — mirrors nuclei matchers/matchers_types.go ───────────────

type MatcherType string

const (
	StatusMatcher MatcherType = "status"
	WordMatcher   MatcherType = "word"
	RegexMatcher  MatcherType = "regex"
	SizeMatcher   MatcherType = "size"
)

// Matcher mirrors nuclei operators/matchers/matchers.go Matcher struct.
// Fields use the same YAML/JSON tags.
type Matcher struct {
	// Type of the matcher — status | word | regex | size.
	Type MatcherType `yaml:"type" json:"type"`
	// Condition between matcher variables — "and" | "or" (default: "or").
	Condition string `yaml:"condition,omitempty" json:"condition,omitempty"`
	// Part of the response to match — "body" | "header" | "raw" | "status".
	Part string `yaml:"part,omitempty" json:"part,omitempty"`
	// Negative reverses the match — true = match only if condition NOT met.
	Negative bool `yaml:"negative,omitempty" json:"negative,omitempty"`
	// Status codes to match (for StatusMatcher).
	Status []int `yaml:"status,omitempty" json:"status,omitempty"`
	// Words to match (for WordMatcher).
	Words []string `yaml:"words,omitempty" json:"words,omitempty"`
	// Regex patterns to match (for RegexMatcher).
	Regex []string `yaml:"regex,omitempty" json:"regex,omitempty"`
	// Size values to match (for SizeMatcher).
	Size []int `yaml:"size,omitempty" json:"size,omitempty"`

	// compiled regexps — populated at load time.
	compiled []*regexp.Regexp
}

// compile precompiles all regex patterns.
func (m *Matcher) compile() error {
	if m.Type != RegexMatcher {
		return nil
	}
	m.compiled = make([]*regexp.Regexp, 0, len(m.Regex))
	for _, pat := range m.Regex {
		re, err := regexp.Compile(pat)
		if err != nil {
			return fmt.Errorf("compile regex %q: %w", pat, err)
		}
		m.compiled = append(m.compiled, re)
	}
	return nil
}

// ─── Template — mirrors nuclei templates/template.go ─────────────────────────

// Template mirrors the essential fields of a nuclei YAML template for HTTP checks.
type Template struct {
	// ID is the unique template identifier.
	ID string `yaml:"id" json:"id"`
	// Name is the human-readable name.
	Name string `yaml:"name" json:"name"`
	// Severity mirrors nuclei info.severity.
	Severity module.Severity `yaml:"severity" json:"severity"`
	// Description is a human-readable explanation.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Tags mirrors nuclei info.tags.
	Tags []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	// Path is the URL path to request (appended to the target URL).
	Path string `yaml:"path" json:"path"`
	// Method is the HTTP method (default: GET).
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
	// Headers are additional request headers.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	// Body is the optional HTTP request body (for POST/PUT templates).
	Body string `yaml:"body,omitempty" json:"body,omitempty"`
	// Matchers are evaluated against the response — all must match (AND at template level).
	Matchers []Matcher `yaml:"matchers" json:"matchers"`
	// MatchersCondition is the condition between all matchers — "and"/"or" (default: "and").
	MatchersCondition string `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"`
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements module.Module for vulnerability scanning via HTTP templates.
type Module struct {
	logger    *slog.Logger
	client    *http.Client
	templates []Template
}

// New returns a Module with the built-in template set.
func New() *Module {
	m := &Module{
		logger: slog.Default().With("module", "vulnscan"),
		client: &http.Client{
			Timeout: defaultTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec
					MinVersion:         tls.VersionTLS10,
				},
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		templates: builtinTemplates(),
	}
	// Pre-compile all regex matchers.
	for i := range m.templates {
		for j := range m.templates[i].Matchers {
			_ = m.templates[i].Matchers[j].compile()
		}
	}
	return m
}

// NewWithTemplates returns a Module with a custom template set (for tests).
func NewWithTemplates(templates []Template) *Module {
	m := &Module{
		logger:    slog.Default().With("module", "vulnscan"),
		client:    &http.Client{Timeout: 5 * time.Second},
		templates: templates,
	}
	for i := range m.templates {
		for j := range m.templates[i].Matchers {
			_ = m.templates[i].Matchers[j].compile()
		}
	}
	return m
}

// NewWithClient returns a Module with an injected http.Client (for tests).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// Name satisfies module.Module.
func (m *Module) Name() string { return "vulnscan" }

// Run satisfies module.Module.
// Input.Target or Input.URLs are the base URLs to scan.
//
// Options:
//
//	"tags"     — comma-separated template tags to run (default: all)
//	"ids"      — comma-separated template IDs to run (default: all)
//	"timeout"  — per-request timeout in seconds (default: 10)
//	"threads"  — concurrent template executions (default: 20)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	baseURLs := collectTargets(input)
	if len(baseURLs) == 0 {
		return nil, fmt.Errorf("vulnscan: no target provided")
	}

	// Per-run timeout.
	if ts, ok := input.Options["timeout"]; ok {
		if secs, err := strconv.Atoi(ts); err == nil {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(secs)*time.Second)
			defer cancel()
		}
	}

	// Thread count.
	threads := concurrentTemplates
	if t, ok := input.Options["threads"]; ok {
		if n, err := strconv.Atoi(t); err == nil && n > 0 {
			threads = n
		}
	}

	// Filter templates.
	templates := m.filterTemplates(input.Options)
	m.logger.InfoContext(ctx, "starting vuln scan",
		"targets", len(baseURLs), "templates", len(templates))

	eg, gctx := errgroup.WithContext(ctx)
	eg.SetLimit(threads)

	findingsCh := make(chan module.Finding, 64)

	for _, base := range baseURLs {
		for _, tmpl := range templates {
			base, tmpl := base, tmpl
			eg.Go(func() error {
				f, matched := m.executeTemplate(gctx, base, tmpl)
				if matched {
					select {
					case findingsCh <- f:
					case <-gctx.Done():
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

	var findings []module.Finding
	for f := range findingsCh {
		findings = append(findings, f)
	}

	if err := eg.Wait(); err != nil {
		return findings, err
	}

	m.logger.InfoContext(ctx, "scan complete", "findings", len(findings))
	return findings, nil
}

// ─── Template execution ───────────────────────────────────────────────────────

// executeTemplate sends the HTTP request and evaluates all matchers.
// Mirrors nuclei Request.ExecuteWithResults().
func (m *Module) executeTemplate(ctx context.Context, baseURL string, tmpl Template) (module.Finding, bool) {
	method := tmpl.Method
	if method == "" {
		method = http.MethodGet
	}

	targetURL := strings.TrimRight(baseURL, "/") + tmpl.Path

	var bodyReader io.Reader
	if tmpl.Body != "" {
		bodyReader = strings.NewReader(tmpl.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		m.logger.WarnContext(ctx, "build request failed", "template", tmpl.ID, "err", err)
		return module.Finding{}, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-vulnscan/1.0)")
	for k, v := range tmpl.Headers {
		req.Header.Set(k, v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return module.Finding{}, false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))

	// Build raw response string — mirrors nuclei "raw" part.
	var rawBuilder strings.Builder
	rawBuilder.WriteString(fmt.Sprintf("HTTP/1.1 %d\n", resp.StatusCode))
	for k, vs := range resp.Header {
		for _, v := range vs {
			rawBuilder.WriteString(k + ": " + v + "\n")
		}
	}
	rawBuilder.WriteString("\n")
	rawBuilder.Write(body)
	rawStr := rawBuilder.String()

	// Header string for "header" part.
	var headerBuilder strings.Builder
	for k, vs := range resp.Header {
		for _, v := range vs {
			headerBuilder.WriteString(k + ": " + v + "\n")
		}
	}
	headerStr := headerBuilder.String()

	// Evaluate all matchers — mirrors nuclei operators.go Matches().
	matched, matchedCount := evaluateMatchersWithCount(tmpl, resp.StatusCode, string(body), headerStr, rawStr)
	if !matched {
		return module.Finding{}, false
	}

	m.logger.InfoContext(ctx, "template matched",
		"template", tmpl.ID, "url", targetURL, "severity", tmpl.Severity,
		"matchers_satisfied", matchedCount)

	return module.Finding{
		Type:     "vuln_match",
		Severity: tmpl.Severity,
		URL:      targetURL,
		Detail: fmt.Sprintf("[%s] %s — %s",
			tmpl.ID, tmpl.Name, tmpl.Description),
		Extra: map[string]string{
			"template_id":        tmpl.ID,
			"template_name":      tmpl.Name,
			"severity":           string(tmpl.Severity),
			"tags":               strings.Join(tmpl.Tags, ","),
			"status_code":        strconv.Itoa(resp.StatusCode),
			"matchers_satisfied": strconv.Itoa(matchedCount),
			"matchers_total":     strconv.Itoa(len(tmpl.Matchers)),
			"confidence":         vulnscanConfidence(tmpl, matchedCount),
		},
	}, true
}

// evaluateMatchersWithCount evaluates all matchers and returns (matched, count of satisfied matchers).
// Per dicas.md §4: count feeds confidence score — more matchers satisfied = higher confidence.
func evaluateMatchersWithCount(tmpl Template, statusCode int, body, headers, raw string) (bool, int) {
	condition := strings.ToLower(tmpl.MatchersCondition)
	if condition == "" {
		condition = "and"
	}

	results := make([]bool, len(tmpl.Matchers))
	for i, matcher := range tmpl.Matchers {
		results[i] = evaluateMatcher(matcher, statusCode, body, headers, raw)
	}

	satisfied := 0
	for _, r := range results {
		if r {
			satisfied++
		}
	}

	switch condition {
	case "or":
		return satisfied > 0, satisfied
	default: // "and"
		return satisfied == len(tmpl.Matchers), satisfied
	}
}

// evaluateMatchers is the original boolean-only form, kept for callers that don't need the count.
func evaluateMatchers(tmpl Template, statusCode int, body, headers, raw string) bool {
	matched, _ := evaluateMatchersWithCount(tmpl, statusCode, body, headers, raw)
	return matched
}

// vulnscanConfidence computes confidence per dicas.md §4.
// AND condition + multiple matchers satisfied = highest confidence.
// OR condition (any one match) = lower confidence.
// Single matcher = moderate confidence.
func vulnscanConfidence(tmpl Template, satisfied int) string {
	total := len(tmpl.Matchers)
	condition := strings.ToLower(tmpl.MatchersCondition)
	if condition == "" {
		condition = "and"
	}
	switch {
	case total == 0 || satisfied == 0:
		return "0.70"
	case condition == "and" && satisfied >= 3:
		return "0.95" // all matchers required + 3+ checks satisfied
	case condition == "and" && satisfied == 2:
		return "0.90"
	case condition == "and" && satisfied == 1:
		return "0.85"
	case condition == "or" && satisfied >= 2:
		return "0.85" // OR but multiple paths matched
	default: // or, single match
		return "0.78"
	}
}

// evaluateMatcher evaluates a single Matcher — mirrors nuclei match.go MatchStatus/MatchWords/…
func evaluateMatcher(m Matcher, statusCode int, body, headers, raw string) bool {
	part := strings.ToLower(m.Part)
	if part == "" {
		part = "body"
	}

	var target string
	switch part {
	case "status":
		target = strconv.Itoa(statusCode)
	case "header", "headers":
		target = headers
	case "raw":
		target = raw
	default: // "body"
		target = body
	}

	var result bool

	switch m.Type {
	case StatusMatcher:
		cond := strings.ToLower(m.Condition)
		if cond == "" {
			cond = "or"
		}
		for _, s := range m.Status {
			if s == statusCode {
				if cond == "and" {
					// Continue checking — for AND all must match (but status list is usually OR).
					result = true
				} else {
					result = true
					break
				}
			}
		}
		// If AND condition and none matched, result stays false.

	case WordMatcher:
		cond := strings.ToLower(m.Condition)
		if cond == "" {
			cond = "or"
		}
		switch cond {
		case "and":
			result = true
			for _, w := range m.Words {
				if !strings.Contains(target, w) {
					result = false
					break
				}
			}
		default: // "or"
			for _, w := range m.Words {
				if strings.Contains(target, w) {
					result = true
					break
				}
			}
		}

	case RegexMatcher:
		cond := strings.ToLower(m.Condition)
		if cond == "" {
			cond = "or"
		}
		switch cond {
		case "and":
			result = true
			for _, re := range m.compiled {
				if !re.MatchString(target) {
					result = false
					break
				}
			}
		default: // "or"
			for _, re := range m.compiled {
				if re.MatchString(target) {
					result = true
					break
				}
			}
		}

	case SizeMatcher:
		size := len([]byte(target))
		for _, s := range m.Size {
			if s == size {
				result = true
				break
			}
		}
	}

	if m.Negative {
		return !result
	}
	return result
}

// ─── Template filtering ───────────────────────────────────────────────────────

func (m *Module) filterTemplates(opts map[string]string) []Template {
	// Build filter sets.
	tagSet := map[string]bool{}
	idSet := map[string]bool{}
	if raw, ok := opts["tags"]; ok {
		for _, t := range strings.Split(raw, ",") {
			tagSet[strings.TrimSpace(t)] = true
		}
	}
	if raw, ok := opts["ids"]; ok {
		for _, id := range strings.Split(raw, ",") {
			idSet[strings.TrimSpace(id)] = true
		}
	}

	if len(tagSet) == 0 && len(idSet) == 0 {
		return m.templates
	}

	var filtered []Template
	for _, tmpl := range m.templates {
		if idSet[tmpl.ID] {
			filtered = append(filtered, tmpl)
			continue
		}
		for _, tag := range tmpl.Tags {
			if tagSet[tag] {
				filtered = append(filtered, tmpl)
				break
			}
		}
	}
	return filtered
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func collectTargets(input module.Input) []string {
	var out []string
	if input.Target != "" {
		t := input.Target
		if !strings.HasPrefix(t, "http") {
			t = "https://" + t
		}
		out = append(out, t)
	}
	for _, u := range input.URLs {
		if !strings.HasPrefix(u, "http") {
			u = "https://" + u
		}
		out = append(out, u)
	}
	return out
}

// ─── Built-in templates ───────────────────────────────────────────────────────

// builtinTemplates returns the bundled set of HTTP vulnerability templates.
// These mirror common nuclei community templates for misconfigurations and
// exposures — no CVE-specific payloads.
func builtinTemplates() []Template {
	return []Template{
		// ── Security header checks ─────────────────────────────────────────
		{
			ID:                "missing-hsts",
			Name:              "Missing HSTS Header",
			Severity:          module.SeverityMedium,
			Description:       "Strict-Transport-Security header is not present",
			Tags:              []string{"headers", "misconfiguration"},
			Path:              "/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200, 301, 302, 304}},
				{Type: WordMatcher, Part: "header", Negative: true,
					Words: []string{"strict-transport-security", "Strict-Transport-Security"}},
			},
		},
		{
			ID:                "missing-xcto",
			Name:              "Missing X-Content-Type-Options Header",
			Severity:          module.SeverityLow,
			Description:       "X-Content-Type-Options: nosniff is not set",
			Tags:              []string{"headers", "misconfiguration"},
			Path:              "/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "header", Negative: true,
					Words: []string{"x-content-type-options", "X-Content-Type-Options"}},
			},
		},
		{
			ID:                "missing-xfo",
			Name:              "Missing X-Frame-Options Header",
			Severity:          module.SeverityMedium,
			Description:       "X-Frame-Options header is not present — possible clickjacking",
			Tags:              []string{"headers", "misconfiguration"},
			Path:              "/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "header", Negative: true,
					Words: []string{"x-frame-options", "X-Frame-Options"}},
			},
		},
		// ── Version disclosure ─────────────────────────────────────────────
		{
			ID:                "server-version-disclosure",
			Name:              "Server Version Disclosure",
			Severity:          module.SeverityLow,
			Description:       "Server header reveals version information",
			Tags:              []string{"disclosure", "headers"},
			Path:              "/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200, 301, 302, 304, 404, 403}},
				{Type: RegexMatcher, Part: "header",
					Regex: []string{`(?i)(apache|nginx|iis|lighttpd|tomcat|jetty|gunicorn|uvicorn)/[\d.]+`}},
			},
		},
		{
			ID:                "php-version-disclosure",
			Name:              "PHP Version Disclosure",
			Severity:          module.SeverityLow,
			Description:       "X-Powered-By header discloses PHP version",
			Tags:              []string{"disclosure", "headers", "php"},
			Path:              "/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: RegexMatcher, Part: "header",
					Regex: []string{`(?i)X-Powered-By: PHP/[\d.]+`}},
			},
		},
		// ── Default / exposed files ────────────────────────────────────────
		{
			ID:                "exposed-git-directory",
			Name:              "Exposed Git Directory",
			Severity:          module.SeverityHigh,
			Description:       ".git/config is publicly accessible",
			Tags:              []string{"exposure", "git", "config"},
			Path:              "/.git/config",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "body", Words: []string{"[core]"}},
			},
		},
		{
			ID:                "exposed-env-file",
			Name:              "Exposed .env File",
			Severity:          module.SeverityCritical,
			Description:       ".env file leaks environment variables including secrets",
			Tags:              []string{"exposure", "secrets", "env"},
			Path:              "/.env",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(APP_KEY|DB_PASSWORD|AWS_SECRET|SECRET_KEY|API_KEY)\s*=`}},
			},
		},
		{
			ID:                "exposed-phpinfo",
			Name:              "PHP Info Disclosure",
			Severity:          module.SeverityMedium,
			Description:       "phpinfo() page is publicly accessible",
			Tags:              []string{"exposure", "php"},
			Path:              "/phpinfo.php",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "body", Words: []string{"PHP Version", "phpinfo()"}},
			},
		},
		{
			ID:                "exposed-wp-config-bak",
			Name:              "WordPress Config Backup",
			Severity:          module.SeverityCritical,
			Description:       "wp-config.php backup is accessible",
			Tags:              []string{"exposure", "wordpress", "config"},
			Path:              "/wp-config.php.bak",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "body",
					Words: []string{"DB_PASSWORD", "DB_NAME", "DB_USER"}},
			},
		},
		{
			ID:                "exposed-ds-store",
			Name:              "Exposed .DS_Store File",
			Severity:          module.SeverityMedium,
			Description:       "macOS .DS_Store file leaks directory structure",
			Tags:              []string{"exposure", "information-disclosure"},
			Path:              "/.DS_Store",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				// .DS_Store magic bytes: 0000 0001 4200 6f6f6d
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`Bud1`}},
			},
		},
		// ── Default credentials / admin panels ────────────────────────────
		{
			ID:                "default-apache-page",
			Name:              "Apache Default Page",
			Severity:          module.SeverityLow,
			Description:       "Apache default welcome page is accessible",
			Tags:              []string{"misconfiguration", "apache"},
			Path:              "/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "body",
					Words:     []string{"It works!", "Apache HTTP Server"},
					Condition: "or"},
			},
		},
		{
			ID:                "exposed-phpmyadmin",
			Name:              "phpMyAdmin Accessible",
			Severity:          module.SeverityMedium,
			Description:       "phpMyAdmin login page is exposed",
			Tags:              []string{"panel", "database"},
			Path:              "/phpmyadmin/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "body",
					Words: []string{"phpMyAdmin"}},
			},
		},
		// ── CORS misconfiguration ──────────────────────────────────────────
		{
			ID:                "cors-wildcard",
			Name:              "CORS Wildcard Origin",
			Severity:          module.SeverityMedium,
			Description:       "Access-Control-Allow-Origin: * allows any origin",
			Tags:              []string{"cors", "misconfiguration"},
			Path:              "/",
			Method:            "GET",
			Headers:           map[string]string{"Origin": "https://evil.example.com"},
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: WordMatcher, Part: "header",
					Words: []string{"Access-Control-Allow-Origin: *"}},
			},
		},
		// ── Robots.txt / sitemap exposure ─────────────────────────────────
		{
			ID:                "robots-txt-found",
			Name:              "Robots.txt Found",
			Severity:          module.SeverityInfo,
			Description:       "robots.txt may disclose sensitive paths",
			Tags:              []string{"disclosure", "robots"},
			Path:              "/robots.txt",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "body",
					Words:     []string{"User-agent:", "Disallow:", "Allow:"},
					Condition: "or"},
			},
		},
		// ── Directory listing ──────────────────────────────────────────────
		{
			ID:                "directory-listing",
			Name:              "Directory Listing Enabled",
			Severity:          module.SeverityMedium,
			Description:       "Server returns a directory listing exposing file structure",
			Tags:              []string{"exposure", "misconfiguration"},
			Path:              "/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "body",
					Words:     []string{"Index of /", "Parent Directory", "[DIR]"},
					Condition: "or"},
			},
		},
		// ── Open redirect ─────────────────────────────────────────────────
		{
			ID:                "open-redirect-test",
			Name:              "Potential Open Redirect",
			Severity:          module.SeverityMedium,
			Description:       "Common open redirect parameter triggers redirect to external URL",
			Tags:              []string{"redirect", "misconfiguration"},
			Path:              "/?url=https://evil.example.com&redirect=https://evil.example.com&next=https://evil.example.com",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{301, 302, 303, 307, 308}},
				{Type: WordMatcher, Part: "header",
					Words: []string{"evil.example.com"}},
			},
		},
		// ── Admin panel exposure ───────────────────────────────────────────
		{
			ID:                "exposed-admin-panel",
			Name:              "Admin Panel Exposed",
			Severity:          module.SeverityHigh,
			Description:       "Common admin panel path is accessible without authentication",
			Tags:              []string{"panel", "exposure"},
			Path:              "/admin/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "body",
					Words:     []string{"dashboard", "admin", "login", "password"},
					Condition: "or"},
			},
		},
		// ── Backup files ──────────────────────────────────────────────────
		{
			ID:                "exposed-backup-files",
			Name:              "Exposed Backup Files",
			Severity:          module.SeverityHigh,
			Description:       "Common backup file names are accessible",
			Tags:              []string{"exposure", "backup"},
			Path:              "/backup.zip",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "header",
					Words:     []string{"application/zip", "application/octet-stream"},
					Condition: "or"},
			},
		},
		// ── Miscellaneous ──────────────────────────────────────────────────
		{
			ID:                "server-error-disclosure",
			Name:              "Server Error Disclosure",
			Severity:          module.SeverityLow,
			Description:       "Server returns 500 with stack trace or framework details",
			Tags:              []string{"disclosure", "error"},
			Path:              "/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{500}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(stack\s*trace|exception|traceback|django|laravel|rails|symfony)`}},
			},
		},

		// ── Cloud / Infrastructure exposure ──────────────────────────────────
		{
			ID:                "aws-metadata-ssrf",
			Name:              "AWS Metadata SSRF Indicator",
			Severity:          module.SeverityCritical,
			Description:       "Response contains AWS IMDSv1 metadata content, possible SSRF",
			Tags:              []string{"ssrf", "aws", "cloud"},
			Path:              "/",
			Method:            "GET",
			MatchersCondition: "or",
			Matchers: []Matcher{
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`ami-[0-9a-f]{8,17}`, `"instanceId"\s*:\s*"i-[0-9a-f]{17}"`, `169\.254\.169\.254`}},
			},
		},
		{
			ID:                "exposed-actuator",
			Name:              "Spring Boot Actuator Exposed",
			Severity:          module.SeverityHigh,
			Description:       "Spring Boot Actuator endpoints are publicly accessible",
			Tags:              []string{"exposure", "spring", "java"},
			Path:              "/actuator",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"_links"\s*:\s*\{`}},
			},
		},
		{
			ID:                "exposed-actuator-env",
			Name:              "Spring Boot Actuator /env Exposed",
			Severity:          module.SeverityCritical,
			Description:       "/actuator/env exposes environment variables including secrets",
			Tags:              []string{"exposure", "spring", "java", "secrets"},
			Path:              "/actuator/env",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"activeProfiles"|"propertySources"`}},
			},
		},
		{
			ID:                "exposed-swagger-ui",
			Name:              "Swagger UI Exposed",
			Severity:          module.SeverityMedium,
			Description:       "Swagger UI / OpenAPI documentation is publicly accessible",
			Tags:              []string{"exposure", "api", "documentation"},
			Path:              "/swagger-ui.html",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "body",
					Words:     []string{"swagger-ui", "Swagger UI", "openapi"},
					Condition: "or"},
			},
		},
		{
			ID:                "exposed-swagger-json",
			Name:              "OpenAPI/Swagger JSON Exposed",
			Severity:          module.SeverityMedium,
			Description:       "OpenAPI specification JSON is publicly accessible",
			Tags:              []string{"exposure", "api", "documentation"},
			Path:              "/openapi.json",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"openapi"\s*:\s*"[23]\.\d+\.\d+"`}},
			},
		},
		{
			ID:                "exposed-graphql-playground",
			Name:              "GraphQL Playground Exposed",
			Severity:          module.SeverityLow,
			Description:       "GraphQL Playground IDE is publicly accessible",
			Tags:              []string{"exposure", "graphql"},
			Path:              "/graphql",
			Method:            "GET",
			MatchersCondition: "or",
			Matchers: []Matcher{
				{Type: WordMatcher, Part: "body",
					Words: []string{"GraphQL Playground", "GraphiQL"}},
			},
		},
		{
			ID:                "exposed-kubernetes-api",
			Name:              "Kubernetes API Server Exposed",
			Severity:          module.SeverityCritical,
			Description:       "Kubernetes API server is accessible without authentication",
			Tags:              []string{"exposure", "kubernetes", "cloud"},
			Path:              "/api/v1/namespaces",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"kind"\s*:\s*"NamespaceList"`}},
			},
		},
		{
			ID:                "exposed-docker-api",
			Name:              "Docker Remote API Exposed",
			Severity:          module.SeverityCritical,
			Description:       "Docker Remote API is accessible without authentication",
			Tags:              []string{"exposure", "docker", "cloud"},
			Path:              "/v1.41/info",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"Containers"\s*:\s*\d+`}},
			},
		},
		{
			ID:                "exposed-prometheus-metrics",
			Name:              "Prometheus Metrics Exposed",
			Severity:          module.SeverityMedium,
			Description:       "Prometheus /metrics endpoint is publicly accessible",
			Tags:              []string{"exposure", "monitoring"},
			Path:              "/metrics",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`# HELP |# TYPE `}},
			},
		},
		{
			ID:                "exposed-grafana-anon",
			Name:              "Grafana Anonymous Access",
			Severity:          module.SeverityHigh,
			Description:       "Grafana dashboard accessible without authentication",
			Tags:              []string{"exposure", "monitoring", "panel"},
			Path:              "/api/dashboards/home",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"dashboard"\s*:\s*\{`}},
			},
		},
		{
			ID:                "exposed-kibana",
			Name:              "Kibana Dashboard Exposed",
			Severity:          module.SeverityMedium,
			Description:       "Kibana dashboard is publicly accessible",
			Tags:              []string{"exposure", "monitoring", "panel"},
			Path:              "/app/kibana",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "body",
					Words: []string{"kibana"}},
			},
		},

		// ── Sensitive file exposure (additional) ──────────────────────────────
		{
			ID:                "exposed-dockerfile",
			Name:              "Exposed Dockerfile",
			Severity:          module.SeverityMedium,
			Description:       "Dockerfile is publicly accessible, may reveal infra details",
			Tags:              []string{"exposure", "docker"},
			Path:              "/Dockerfile",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)FROM\s+\w`}},
			},
		},
		{
			ID:                "exposed-docker-compose",
			Name:              "Exposed docker-compose.yml",
			Severity:          module.SeverityHigh,
			Description:       "docker-compose.yml reveals service config and possible secrets",
			Tags:              []string{"exposure", "docker", "secrets"},
			Path:              "/docker-compose.yml",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`services\s*:`}},
			},
		},
		{
			ID:                "exposed-package-json",
			Name:              "Exposed package.json",
			Severity:          module.SeverityLow,
			Description:       "package.json reveals Node.js dependencies and project metadata",
			Tags:              []string{"exposure", "node"},
			Path:              "/package.json",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"dependencies"\s*:\s*\{`}},
			},
		},
		{
			ID:                "exposed-composer-json",
			Name:              "Exposed composer.json",
			Severity:          module.SeverityLow,
			Description:       "composer.json reveals PHP dependencies",
			Tags:              []string{"exposure", "php"},
			Path:              "/composer.json",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"require"\s*:\s*\{`}},
			},
		},
		{
			ID:                "exposed-aws-credentials",
			Name:              "Exposed AWS Credentials File",
			Severity:          module.SeverityCritical,
			Description:       ".aws/credentials file is publicly accessible",
			Tags:              []string{"exposure", "aws", "secrets"},
			Path:              "/.aws/credentials",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`aws_access_key_id`}},
			},
		},
		{
			ID:                "exposed-ssh-private-key",
			Name:              "Exposed SSH Private Key",
			Severity:          module.SeverityCritical,
			Description:       "SSH private key file is publicly accessible",
			Tags:              []string{"exposure", "ssh", "crypto"},
			Path:              "/.ssh/id_rsa",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "body",
					Words:     []string{"BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"},
					Condition: "or"},
			},
		},
		{
			ID:                "exposed-htpasswd",
			Name:              "Exposed .htpasswd File",
			Severity:          module.SeverityCritical,
			Description:       ".htpasswd credential file is publicly accessible",
			Tags:              []string{"exposure", "credentials"},
			Path:              "/.htpasswd",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`\w+:\$(?:apr1|2y|1)\$`}},
			},
		},
		{
			ID:                "exposed-web-config",
			Name:              "Exposed web.config",
			Severity:          module.SeverityHigh,
			Description:       "ASP.NET web.config is publicly accessible",
			Tags:              []string{"exposure", "dotnet", "iis"},
			Path:              "/web.config",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`<configuration>`}},
			},
		},

		// ── CVE / Named vulnerabilities ───────────────────────────────────────
		{
			ID:                "cve-2021-44228-log4shell",
			Name:              "Log4Shell (CVE-2021-44228) Indicator",
			Severity:          module.SeverityCritical,
			Description:       "Server reflects JNDI patterns, may be vulnerable to Log4Shell",
			Tags:              []string{"cve", "log4j", "rce"},
			Path:              "/",
			Method:            "GET",
			Headers:           map[string]string{"X-Api-Version": "${jndi:ldap://127.0.0.1/a}"},
			MatchersCondition: "or",
			Matchers: []Matcher{
				{Type: WordMatcher, Part: "body",
					Words: []string{"jndi:ldap://"}},
				{Type: StatusMatcher, Status: []int{500}},
			},
		},
		{
			ID:                "cve-2022-22965-spring4shell",
			Name:              "Spring4Shell (CVE-2022-22965) Indicator",
			Severity:          module.SeverityCritical,
			Description:       "Spring MVC endpoint may be vulnerable to RCE via data binding",
			Tags:              []string{"cve", "spring", "rce"},
			Path:              "/?class.module.classLoader.urls[0]=0",
			Method:            "GET",
			MatchersCondition: "or",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{400}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)bad request`}},
			},
		},
		{
			ID:                "cve-2023-44487-http2",
			Name:              "HTTP/2 Server Exposure",
			Severity:          module.SeverityMedium,
			Description:       "Server supports HTTP/2 — check patch status for CVE-2023-44487",
			Tags:              []string{"cve", "http2"},
			Path:              "/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200, 301, 302}},
				{Type: RegexMatcher, Part: "header",
					Regex: []string{`(?i)upgrade:\s*h2c|alt-svc:\s*h2=`}},
			},
		},

		// ── Panel / Admin paths ───────────────────────────────────────────────
		{
			ID:                "exposed-jenkins",
			Name:              "Jenkins Dashboard Exposed",
			Severity:          module.SeverityHigh,
			Description:       "Jenkins CI/CD dashboard is publicly accessible",
			Tags:              []string{"panel", "ci-cd"},
			Path:              "/jenkins/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200, 403}},
				{Type: WordMatcher, Part: "body",
					Words:     []string{"Jenkins", "Build History"},
					Condition: "or"},
			},
		},
		{
			ID:                "exposed-gitlab",
			Name:              "GitLab Login Exposed",
			Severity:          module.SeverityMedium,
			Description:       "GitLab login page is accessible (self-hosted instance)",
			Tags:              []string{"panel", "vcs"},
			Path:              "/users/sign_in",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "body",
					Words: []string{"GitLab"}},
			},
		},
		{
			ID:                "exposed-portainer",
			Name:              "Portainer Dashboard Exposed",
			Severity:          module.SeverityHigh,
			Description:       "Portainer Docker management UI is publicly accessible",
			Tags:              []string{"panel", "docker"},
			Path:              "/api/status",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"Version"\s*:\s*"[\d.]+"`}},
			},
		},
		{
			ID:                "exposed-grafana-login",
			Name:              "Grafana Login Exposed",
			Severity:          module.SeverityMedium,
			Description:       "Grafana login page is accessible",
			Tags:              []string{"panel", "monitoring"},
			Path:              "/login",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "body",
					Words: []string{"Grafana"}},
			},
		},

		// ── Spring Boot Actuator (extended) ───────────────────────────────────
		{
			ID:                "exposed-actuator-health",
			Name:              "Spring Boot Actuator Health Exposed",
			Severity:          module.SeverityLow,
			Description:       "Spring Boot /actuator/health endpoint leaks application status",
			Tags:              []string{"exposure", "spring", "actuator"},
			Path:              "/actuator/health",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"`}},
			},
		},
		{
			ID:                "exposed-actuator-beans",
			Name:              "Spring Boot Actuator Beans Exposed",
			Severity:          module.SeverityHigh,
			Description:       "Spring Boot /actuator/beans leaks all application beans",
			Tags:              []string{"exposure", "spring", "actuator"},
			Path:              "/actuator/beans",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"beans"\s*:\s*\{`}},
			},
		},
		{
			ID:                "exposed-actuator-mappings",
			Name:              "Spring Boot Actuator Mappings Exposed",
			Severity:          module.SeverityMedium,
			Description:       "Spring Boot /actuator/mappings leaks all HTTP routes",
			Tags:              []string{"exposure", "spring", "actuator"},
			Path:              "/actuator/mappings",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"mappings"\s*:\s*\{`}},
			},
		},
		{
			ID:                "exposed-actuator-loggers",
			Name:              "Spring Boot Actuator Loggers Exposed",
			Severity:          module.SeverityMedium,
			Description:       "Spring Boot /actuator/loggers can change log levels at runtime",
			Tags:              []string{"exposure", "spring", "actuator"},
			Path:              "/actuator/loggers",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"loggers"\s*:\s*\{`}},
			},
		},

		// ── Kubernetes & Container infrastructure ─────────────────────────────
		{
			ID:                "exposed-k8s-metrics-server",
			Name:              "Kubernetes Metrics Server Exposed",
			Severity:          module.SeverityHigh,
			Description:       "Kubernetes metrics-server API is accessible without authentication",
			Tags:              []string{"kubernetes", "cloud", "exposure"},
			Path:              "/apis/metrics.k8s.io/v1beta1",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: WordMatcher, Part: "body",
					Words: []string{"metrics.k8s.io"}},
			},
		},
		{
			ID:                "exposed-k8s-dashboard",
			Name:              "Kubernetes Dashboard Exposed",
			Severity:          module.SeverityCritical,
			Description:       "Kubernetes dashboard UI is publicly accessible",
			Tags:              []string{"kubernetes", "panel", "exposure"},
			Path:              "/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/",
			Method:            "GET",
			MatchersCondition: "or",
			Matchers: []Matcher{
				{Type: WordMatcher, Part: "body",
					Words: []string{"kubernetes-dashboard", "Kubernetes Dashboard"}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)kubernetes.*dashboard`}},
			},
		},
		{
			ID:                "exposed-docker-swarm-api",
			Name:              "Docker Swarm API Exposed",
			Severity:          module.SeverityCritical,
			Description:       "Docker Swarm management API is accessible without authentication",
			Tags:              []string{"docker", "cloud", "exposure"},
			Path:              "/v1.40/swarm",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"JoinTokens"\s*:\s*\{`}},
			},
		},
		{
			ID:                "exposed-containerd-api",
			Name:              "containerd gRPC API Exposed",
			Severity:          module.SeverityCritical,
			Description:       "containerd API is accessible, full container management possible",
			Tags:              []string{"docker", "cloud", "exposure"},
			Path:              "/v1.0.0/namespaces",
			Method:            "GET",
			MatchersCondition: "or",
			Matchers: []Matcher{
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"namespaces"\s*:\s*\[`}},
				{Type: WordMatcher, Part: "body",
					Words: []string{"containerd", "moby"}},
			},
		},

		// ── Database / Cache exposure ─────────────────────────────────────────
		{
			ID:                "exposed-redis-info",
			Name:              "Redis INFO Endpoint Exposed",
			Severity:          module.SeverityCritical,
			Description:       "Redis server is accessible without authentication (HTTP interface)",
			Tags:              []string{"database", "redis", "exposure"},
			Path:              "/info",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`redis_version:|# Server|aof_enabled:`}},
			},
		},
		{
			ID:                "exposed-mongodb-restapi",
			Name:              "MongoDB REST API Exposed",
			Severity:          module.SeverityCritical,
			Description:       "MongoDB REST API is accessible, database enumeration possible",
			Tags:              []string{"database", "mongodb", "exposure"},
			Path:              "/_api/v1/database",
			Method:            "GET",
			MatchersCondition: "or",
			Matchers: []Matcher{
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"databases"\s*:\s*\[`}},
				{Type: WordMatcher, Part: "body",
					Words: []string{"mongodb", "collection"}},
			},
		},
		{
			ID:                "exposed-elasticsearch",
			Name:              "Elasticsearch Cluster Exposed",
			Severity:          module.SeverityCritical,
			Description:       "Elasticsearch node is accessible without authentication",
			Tags:              []string{"database", "elasticsearch", "exposure"},
			Path:              "/_cluster/health",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"cluster_name"\s*:\s*"[^"]+"`}},
			},
		},
		{
			ID:                "exposed-elasticsearch-indices",
			Name:              "Elasticsearch Indices Listed",
			Severity:          module.SeverityCritical,
			Description:       "Elasticsearch indices are publicly enumerable",
			Tags:              []string{"database", "elasticsearch", "exposure"},
			Path:              "/_cat/indices?v",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`health\s+status\s+index|yellow|green.*index`}},
			},
		},

		// ── CI/CD Exposure ────────────────────────────────────────────────────
		{
			ID:                "exposed-jenkins-script-console",
			Name:              "Jenkins Script Console Exposed",
			Severity:          module.SeverityCritical,
			Description:       "Jenkins script console allows arbitrary Groovy code execution",
			Tags:              []string{"panel", "ci-cd", "rce"},
			Path:              "/script",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)script\s+console|groovy\s+script|jenkins.*script`}},
			},
		},
		{
			ID:                "exposed-jenkins-api",
			Name:              "Jenkins REST API Exposed",
			Severity:          module.SeverityHigh,
			Description:       "Jenkins REST API is accessible without authentication",
			Tags:              []string{"panel", "ci-cd", "exposure"},
			Path:              "/api/json",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"jobs"\s*:\s*\[`}},
			},
		},
		{
			ID:                "exposed-circleci-api",
			Name:              "CircleCI API Accessible",
			Severity:          module.SeverityHigh,
			Description:       "CircleCI API endpoint is accessible without credentials",
			Tags:              []string{"ci-cd", "exposure"},
			Path:              "/api/v1.1/me",
			Method:            "GET",
			MatchersCondition: "or",
			Matchers: []Matcher{
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"login"\s*:\s*"[^"]+"`}},
				{Type: WordMatcher, Part: "body",
					Words: []string{"circleci", "circle_ci"}},
			},
		},
		{
			ID:                "exposed-sonarqube",
			Name:              "SonarQube Web UI Exposed",
			Severity:          module.SeverityMedium,
			Description:       "SonarQube instance is accessible without authentication",
			Tags:              []string{"panel", "ci-cd", "exposure"},
			Path:              "/api/system/status",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"status"\s*:\s*"(UP|STARTING|RESTARTING|DB_MIGRATION_NEEDED|DB_MIGRATION_RUNNING)"`}},
			},
		},
		{
			ID:                "exposed-nexus-repository",
			Name:              "Nexus Repository Manager Exposed",
			Severity:          module.SeverityHigh,
			Description:       "Nexus Repository Manager admin interface is publicly accessible",
			Tags:              []string{"panel", "ci-cd", "exposure"},
			Path:              "/service/rest/v1/status",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)"edition"\s*:\s*"(OSS|PRO|Community)"`}},
			},
		},

		// ── CVE / Named vulnerabilities (additional) ──────────────────────────
		{
			ID:                "cve-2022-1388-bigip-authbypass",
			Name:              "CVE-2022-1388 F5 BIG-IP Auth Bypass",
			Severity:          module.SeverityCritical,
			Description:       "F5 BIG-IP authentication bypass via X-F5-Auth-Token header (CVE-2022-1388)",
			Tags:              []string{"cve", "f5", "auth-bypass", "rce"},
			Path:              "/mgmt/tm/util/bash",
			Method:            "POST",
			Body:              `{"command":"run","utilCmdArgs":"-c id"}`,
			Headers:           map[string]string{"X-F5-Auth-Token": "x", "Content-Type": "application/json", "Connection": "keep-alive, X-F5-Auth-Token"},
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"commandResult"\s*:\s*"uid=`}},
			},
		},
		{
			ID:                "cve-2021-26855-proxylogon",
			Name:              "CVE-2021-26855 ProxyLogon SSRF",
			Severity:          module.SeverityCritical,
			Description:       "Microsoft Exchange Server SSRF vulnerability (ProxyLogon, CVE-2021-26855)",
			Tags:              []string{"cve", "exchange", "ssrf"},
			Path:              "/owa/auth/x.js",
			Method:            "GET",
			Headers:           map[string]string{"X-AnonResource": "true", "X-AnonResource-Backend": "localhost:444/ecp/default.flt?~3", "X-BEResource": "localhost:444/owa/auth/logon.aspx?~3"},
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200, 302}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(exchange|owa|outlook\s*web|ecp)`}},
			},
		},
		{
			ID:                "cve-2021-41773-apache-path-traversal",
			Name:              "CVE-2021-41773 Apache Path Traversal",
			Severity:          module.SeverityCritical,
			Description:       "Apache HTTP Server 2.4.49 path traversal vulnerability (CVE-2021-41773)",
			Tags:              []string{"cve", "apache", "path-traversal", "rce"},
			Path:              "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
			Method:            "POST",
			Body:              "echo Content-Type: text/plain; echo; id",
			Headers:           map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`uid=\d+\(\w+\)`}},
			},
		},
		{
			ID:                "cve-2023-23397-outlook-ntlm",
			Name:              "CVE-2023-23397 Outlook NTLM Leak Indicator",
			Severity:          module.SeverityHigh,
			Description:       "Microsoft Outlook NTLM credential leak vulnerability indicator (CVE-2023-23397)",
			Tags:              []string{"cve", "outlook", "ntlm"},
			Path:              "/autodiscover/autodiscover.xml",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200, 401}},
				{Type: RegexMatcher, Part: "header",
					Regex: []string{`(?i)WWW-Authenticate:\s*NTLM`}},
			},
		},
		{
			ID:                "cve-2022-47966-zoho-rce",
			Name:              "CVE-2022-47966 Zoho ManageEngine RCE",
			Severity:          module.SeverityCritical,
			Description:       "Zoho ManageEngine unauthenticated remote code execution (CVE-2022-47966)",
			Tags:              []string{"cve", "zoho", "rce"},
			Path:              "/api/json/v2/ServerData",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(manageengine|servicedesk|helpdesk)`}},
			},
		},
		{
			ID:                "cve-2023-34362-moveit-sqli",
			Name:              "CVE-2023-34362 MOVEit Transfer SQLi",
			Severity:          module.SeverityCritical,
			Description:       "MOVEit Transfer SQL injection vulnerability (CVE-2023-34362)",
			Tags:              []string{"cve", "moveit", "sqli"},
			Path:              "/api/v1/token",
			Method:            "POST",
			Body:              `grant_type=password&username=admin'--&password=x`,
			Headers:           map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200, 500}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(sql|syntax|moveit|transfer)`}},
			},
		},
		{
			ID:                "cve-2023-44487-rapid-reset",
			Name:              "CVE-2023-44487 HTTP/2 Rapid Reset Indicator",
			Severity:          module.SeverityHigh,
			Description:       "Server may be vulnerable to HTTP/2 Rapid Reset DDoS (CVE-2023-44487)",
			Tags:              []string{"cve", "http2", "dos"},
			Path:              "/",
			Method:            "GET",
			Headers:           map[string]string{"Upgrade": "h2c", "HTTP2-Settings": "AAMAAABkAAQAAP__"},
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{101, 200}},
				{Type: RegexMatcher, Part: "header",
					Regex: []string{`(?i)(upgrade:\s*h2|HTTP/2)`}},
			},
		},

		// ── Cloud Storage Misconfiguration ────────────────────────────────────
		{
			ID:                "exposed-s3-bucket-listing",
			Name:              "AWS S3 Bucket Public Listing",
			Severity:          module.SeverityHigh,
			Description:       "S3 bucket allows public object listing",
			Tags:              []string{"cloud", "aws", "s3", "exposure"},
			Path:              "/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`<ListBucketResult|<Key>[^<]+</Key>`}},
			},
		},
		{
			ID:                "exposed-azure-blob-listing",
			Name:              "Azure Blob Storage Public Listing",
			Severity:          module.SeverityHigh,
			Description:       "Azure Blob container allows public enumeration",
			Tags:              []string{"cloud", "azure", "storage", "exposure"},
			Path:              "/?restype=container&comp=list",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`<EnumerationResults|<Blob>\s*<Name>`}},
			},
		},
		{
			ID:                "exposed-gcs-bucket",
			Name:              "GCS Bucket Public Access",
			Severity:          module.SeverityHigh,
			Description:       "Google Cloud Storage bucket is publicly accessible",
			Tags:              []string{"cloud", "gcp", "storage", "exposure"},
			Path:              "/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"kind"\s*:\s*"storage#objects"|<ListBucketResult`}},
			},
		},

		// ── CMS / Application Panels ──────────────────────────────────────────
		{
			ID:                "exposed-wordpress-xmlrpc",
			Name:              "WordPress XML-RPC Enabled",
			Severity:          module.SeverityMedium,
			Description:       "WordPress xmlrpc.php is enabled; can be abused for brute-force or SSRF",
			Tags:              []string{"cms", "wordpress", "exposure"},
			Path:              "/xmlrpc.php",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200, 405}},
				{Type: WordMatcher, Part: "body",
					Words: []string{"XML-RPC server accepts POST requests only"}},
			},
		},
		{
			ID:                "exposed-wordpress-debug",
			Name:              "WordPress Debug Mode Active",
			Severity:          module.SeverityMedium,
			Description:       "WordPress debug log file is publicly accessible",
			Tags:              []string{"cms", "wordpress", "exposure"},
			Path:              "/wp-content/debug.log",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(PHP \w+ Error|WordPress database error|wp-content)`}},
			},
		},
		{
			ID:                "exposed-drupal-status",
			Name:              "Drupal Status Report Exposed",
			Severity:          module.SeverityMedium,
			Description:       "Drupal admin status report is publicly accessible",
			Tags:              []string{"cms", "drupal", "exposure"},
			Path:              "/admin/reports/status",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(Drupal|drupal_version|cron.php)`}},
			},
		},
		{
			ID:                "exposed-joomla-config",
			Name:              "Joomla Configuration Exposed",
			Severity:          module.SeverityHigh,
			Description:       "Joomla configuration.php backup is publicly accessible",
			Tags:              []string{"cms", "joomla", "exposure"},
			Path:              "/configuration.php.bak",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(joomla|secret|password|db_name|db_user)`}},
			},
		},

		// ── Observability / Metrics endpoints ────────────────────────────────
		{
			ID:                "exposed-jaeger-ui",
			Name:              "Jaeger Tracing UI Exposed",
			Severity:          module.SeverityMedium,
			Description:       "Jaeger distributed tracing UI is publicly accessible",
			Tags:              []string{"exposure", "observability"},
			Path:              "/api/services",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"data"\s*:\s*\[.*\].*"errors"\s*:\s*null`}},
			},
		},
		{
			ID:                "exposed-zipkin",
			Name:              "Zipkin Tracing Exposed",
			Severity:          module.SeverityMedium,
			Description:       "Zipkin distributed tracing server is publicly accessible",
			Tags:              []string{"exposure", "observability"},
			Path:              "/api/v2/services",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`^\s*\[(\s*"[^"]+"\s*,?\s*)+\]\s*$`}},
			},
		},
		{
			ID:                "exposed-influxdb",
			Name:              "InfluxDB API Exposed",
			Severity:          module.SeverityCritical,
			Description:       "InfluxDB API is accessible without authentication",
			Tags:              []string{"database", "exposure", "observability"},
			Path:              "/query?q=SHOW+DATABASES",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"results"\s*:\s*\[.*"series"\s*:\s*\[`}},
			},
		},

		// ── Source code / secret file exposure ───────────────────────────────
		{
			ID:                "exposed-env-secrets",
			Name:              "Exposed .env File With Secrets",
			Severity:          module.SeverityCritical,
			Description:       ".env file with high-value secret variables is publicly accessible",
			Tags:              []string{"exposure", "secrets"},
			Path:              "/.env",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(DB_PASSWORD|APP_KEY|SECRET_KEY|AWS_SECRET|STRIPE_SECRET|API_KEY)\s*=`}},
			},
		},
		{
			ID:                "exposed-env-local",
			Name:              "Exposed .env.local File",
			Severity:          module.SeverityCritical,
			Description:       ".env.local file is publicly accessible",
			Tags:              []string{"exposure", "secrets"},
			Path:              "/.env.local",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(PASSWORD|SECRET|KEY|TOKEN)\s*=`}},
			},
		},
		{
			ID:                "exposed-env-prod",
			Name:              "Exposed .env.production File",
			Severity:          module.SeverityCritical,
			Description:       ".env.production file is publicly accessible",
			Tags:              []string{"exposure", "secrets"},
			Path:              "/.env.production",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(PASSWORD|SECRET|KEY|TOKEN)\s*=`}},
			},
		},
		{
			ID:                "exposed-laravel-env",
			Name:              "Exposed Laravel .env File",
			Severity:          module.SeverityCritical,
			Description:       "Laravel .env file with database credentials is publicly accessible",
			Tags:              []string{"exposure", "secrets", "laravel"},
			Path:              "/.env",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`APP_KEY=base64:`}},
			},
		},
		{
			ID:                "exposed-symfony-env",
			Name:              "Exposed Symfony .env File",
			Severity:          module.SeverityCritical,
			Description:       "Symfony environment file is publicly accessible",
			Tags:              []string{"exposure", "secrets", "symfony"},
			Path:              "/.env.local.php",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(database_url|secret|app_secret)`}},
			},
		},
		{
			ID:                "exposed-git-config",
			Name:              "Exposed .git/config File",
			Severity:          module.SeverityHigh,
			Description:       ".git/config file exposes remote repository URL and credentials",
			Tags:              []string{"exposure", "vcs"},
			Path:              "/.git/config",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`\[core\]|\[remote`}},
			},
		},

		// ── API / Swagger / OpenAPI Exposure ──────────────────────────────────
		{
			ID:                "exposed-openapi-json",
			Name:              "OpenAPI Specification Exposed (JSON)",
			Severity:          module.SeverityMedium,
			Description:       "OpenAPI/Swagger JSON spec is publicly accessible, leaks API structure",
			Tags:              []string{"exposure", "api", "swagger"},
			Path:              "/openapi.json",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`"openapi"\s*:\s*"[0-9]|"swagger"\s*:\s*"[0-9]`}},
			},
		},
		{
			ID:                "exposed-openapi-yaml",
			Name:              "OpenAPI Specification Exposed (YAML)",
			Severity:          module.SeverityMedium,
			Description:       "OpenAPI/Swagger YAML spec is publicly accessible",
			Tags:              []string{"exposure", "api", "swagger"},
			Path:              "/openapi.yaml",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?m)^openapi:\s+[0-9]|^swagger:\s+"?[0-9]`}},
			},
		},
		{
			ID:                "exposed-graphql-voyager",
			Name:              "GraphQL Voyager Explorer Exposed",
			Severity:          module.SeverityMedium,
			Description:       "GraphQL Voyager interactive schema explorer is publicly accessible",
			Tags:              []string{"exposure", "api", "graphql"},
			Path:              "/voyager",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(graphql.*voyager|voyager.*graphql|GraphQL Voyager)`}},
			},
		},
		{
			ID:                "exposed-api-docs",
			Name:              "API Documentation Exposed",
			Severity:          module.SeverityLow,
			Description:       "API documentation page is publicly accessible",
			Tags:              []string{"exposure", "api"},
			Path:              "/api-docs",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(swagger|redoc|api.reference|api.documentation)`}},
			},
		},

		// ── Misconfigured Services ────────────────────────────────────────────
		{
			ID:                "exposed-phpmyadmin-root",
			Name:              "phpMyAdmin at Root Path Exposed",
			Severity:          module.SeverityHigh,
			Description:       "phpMyAdmin accessible at /phpmyadmin/ (common default path)",
			Tags:              []string{"panel", "database", "exposure"},
			Path:              "/phpmyadmin/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(phpMyAdmin|phpmyadmin)`}},
			},
		},
		{
			ID:                "exposed-adminer",
			Name:              "Adminer Database Tool Exposed",
			Severity:          module.SeverityHigh,
			Description:       "Adminer database management tool is publicly accessible",
			Tags:              []string{"panel", "database", "exposure"},
			Path:              "/adminer.php",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(adminer|Adminer \d)`}},
			},
		},
		{
			ID:                "exposed-hashicorp-vault-ui",
			Name:              "HashiCorp Vault UI Exposed",
			Severity:          module.SeverityHigh,
			Description:       "HashiCorp Vault web UI is publicly accessible",
			Tags:              []string{"panel", "secrets", "exposure"},
			Path:              "/ui/vault/auth",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(Vault|hashicorp|vault-ui)`}},
			},
		},
		{
			ID:                "exposed-consul-ui",
			Name:              "Consul Service Mesh UI Exposed",
			Severity:          module.SeverityHigh,
			Description:       "HashiCorp Consul UI is publicly accessible, leaks service topology",
			Tags:              []string{"panel", "cloud", "exposure"},
			Path:              "/ui/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(consul|HashiCorp)`}},
			},
		},
		{
			ID:                "exposed-minio-console",
			Name:              "MinIO Storage Console Exposed",
			Severity:          module.SeverityHigh,
			Description:       "MinIO object storage console is publicly accessible",
			Tags:              []string{"panel", "storage", "exposure"},
			Path:              "/minio/health/live",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				// Require MinIO-specific content — avoids SPA wildcard-200 false positives.
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(minio|MinIO)`}},
			},
		},

		// ── Information Disclosure ────────────────────────────────────────────
		{
			ID:                "exposed-server-info-php",
			Name:              "PHP Server Info Exposed",
			Severity:          module.SeverityMedium,
			Description:       "phpinfo() or server-status page leaks server configuration",
			Tags:              []string{"exposure", "php", "disclosure"},
			Path:              "/info.php",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`<title>phpinfo\(\)|PHP Version`}},
			},
		},
		{
			ID:                "exposed-nginx-status",
			Name:              "Nginx Status Page Exposed",
			Severity:          module.SeverityLow,
			Description:       "Nginx stub_status module is enabled and publicly accessible",
			Tags:              []string{"exposure", "nginx", "disclosure"},
			Path:              "/nginx_status",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`Active connections:\s*\d+`}},
			},
		},
		{
			ID:                "exposed-apache-server-status",
			Name:              "Apache Server Status Exposed",
			Severity:          module.SeverityLow,
			Description:       "Apache mod_status is enabled and publicly accessible",
			Tags:              []string{"exposure", "apache", "disclosure"},
			Path:              "/server-status",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`Apache Server Status|Server Version:`}},
			},
		},
		{
			ID:                "exposed-iis-short-name",
			Name:              "IIS Short Name Disclosure",
			Severity:          module.SeverityLow,
			Description:       "IIS server discloses 8.3 short file names via HTTP methods",
			Tags:              []string{"exposure", "iis", "disclosure"},
			Path:              "/*~1*/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{400, 404}},
				{Type: RegexMatcher, Part: "header",
					Regex: []string{`(?i)Microsoft-IIS/[0-9]`}},
			},
		},
		{
			ID:                "exposed-trace-method",
			Name:              "HTTP TRACE Method Enabled",
			Severity:          module.SeverityMedium,
			Description:       "HTTP TRACE method is enabled, allowing Cross-Site Tracing (XST) attacks",
			Tags:              []string{"misconfiguration", "xst"},
			Path:              "/",
			Method:            "TRACE",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)TRACE\s+/`}},
			},
		},

		// ── File upload / WebShell indicators ────────────────────────────────
		{
			ID:                "webshell-indicator-php",
			Name:              "PHP Webshell Indicator",
			Severity:          module.SeverityCritical,
			Description:       "Response pattern matches known PHP webshell signatures",
			Tags:              []string{"webshell", "malware", "backdoor"},
			Path:              "/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(c99shell|r57shell|b374k|phpspy|wso\s*shell|WSO\s*\d+\.\d+|FilesMan|eval\(base64_decode\()`}},
			},
		},
		{
			ID:                "webshell-indicator-jsp",
			Name:              "JSP Webshell Indicator",
			Severity:          module.SeverityCritical,
			Description:       "Response pattern matches known JSP webshell signatures",
			Tags:              []string{"webshell", "malware", "backdoor"},
			Path:              "/",
			Method:            "GET",
			MatchersCondition: "and",
			Matchers: []Matcher{
				{Type: StatusMatcher, Status: []int{200}},
				{Type: RegexMatcher, Part: "body",
					Regex: []string{`(?i)(jspspy|rebeyond|behinder|godzilla.*runtime|Runtime\.exec)`}},
			},
		},
	}
}
