// Package paramspider mines URLs with parameters from the Wayback Machine CDX
// API and returns them with parameter values replaced by a configurable
// placeholder.
//
// Ported from devanshbatham/ParamSpider (MIT License).
// Original: https://github.com/devanshbatham/ParamSpider
// Core functions (fetch_and_clean_urls, clean_url, has_extension, clean_urls)
// translated directly to Go with the blackhorn-modules Module interface,
// context cancellation, log/slog observability, and io.LimitReader.
package paramspider

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/urlutil"
)

const moduleName = "paramspider"

// maxBodyRead — 4 MB ceiling for CDX responses (dicas.md §5).
const maxBodyRead = 4 << 20

const (
	defaultMaxResults     = 500
	defaultMaxSourceURLs  = 10000
	defaultRuntimeSeconds = 45
)

// hardcodedExtensions mirrors ParamSpider's HARDCODED_EXTENSIONS list exactly.
var hardcodedExtensions = []string{
	".jpg", ".jpeg", ".png", ".gif", ".pdf", ".svg", ".json",
	".css", ".js", ".webp", ".woff", ".woff2", ".eot", ".ttf",
	".otf", ".mp4", ".txt",
}

// Module implements module.Module for parameter URL mining.
type Module struct {
	client *http.Client
	logger *slog.Logger
}

func New() *Module {
	return &Module{
		client: httpclient.Default(),
		logger: slog.Default(),
	}
}

func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

func (m *Module) Name() string { return moduleName }

// Run fetches and cleans URLs for input.Target from the Wayback Machine.
// Returns one Finding per unique URL that contains at least one parameter,
// with parameter values replaced by the placeholder.
//
// Supported options:
//   - "placeholder": string to replace param values (default "FUZZ")
//   - "extensions":  comma-separated extensions to also drop (merged with defaults)
//   - "save":        "true" to write results to ./results/<domain>.txt (default "false")
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	domain := input.Target
	if domain == "" && len(input.URLs) > 0 {
		domain = input.URLs[0]
	}
	domain = urlutil.NormalizeDomain(domain)
	if domain == "" {
		return nil, errors.New("paramspider: target domain required")
	}

	placeholder := optStr(input.Options, "placeholder", "FUZZ")
	save := optBool(input.Options, "save", false)
	maxResults := clampInt(optInt(input.Options, "max_results", defaultMaxResults), 1, 5000)
	maxSourceURLs := clampInt(optInt(input.Options, "max_source_urls", defaultMaxSourceURLs), maxResults, 50000)
	maxRuntime := clampInt(optInt(input.Options, "max_runtime_seconds", defaultRuntimeSeconds), 1, 180)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntime)*time.Second)
	defer cancel()

	extensions := append([]string(nil), hardcodedExtensions...)
	if extra := optStr(input.Options, "extensions", ""); extra != "" {
		for _, e := range strings.Split(extra, ",") {
			e = strings.TrimSpace(strings.ToLower(e))
			if e != "" && !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			extensions = append(extensions, e)
		}
	}

	m.logger.Info("paramspider: fetching URLs", "domain", domain)
	rawURLs, err := m.fetchURLs(runCtx, domain, maxSourceURLs)
	if err != nil {
		return nil, fmt.Errorf("paramspider: CDX fetch failed: %w", err)
	}
	m.logger.Info("paramspider: CDX returned", "domain", domain, "count", len(rawURLs))

	cleaned := cleanURLs(rawURLs, extensions, placeholder, domain, maxResults)
	m.logger.Info("paramspider: after cleaning", "domain", domain, "count", len(cleaned))

	if save {
		if err := saveResults(domain, cleaned); err != nil {
			m.logger.Warn("paramspider: save failed", "domain", domain, "err", err)
		}
	}

	findings := make([]module.Finding, 0, len(cleaned))
	for _, u := range cleaned {
		findings = append(findings, module.Finding{
			Type:     "historical_parameter_url_candidate",
			URL:      u,
			Detail:   fmt.Sprintf("Historical parameterized URL reference for %s", domain),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"domain":                 domain,
				"placeholder":            placeholder,
				"source":                 "wayback_cdx",
				"confidence":             "0.65",
				"validated":              "false",
				"validation_state":       "public_archive_reference",
				"promote_to_context":     "false",
				"source_validated":       "true",
				"target_scope_validated": "true",
			},
		})
	}
	return findings, nil
}

// fetchURLs queries the Wayback CDX API — mirrors fetch_and_clean_urls() exactly.
func (m *Module) fetchURLs(ctx context.Context, domain string, maxURLs int) ([]string, error) {
	query := url.Values{
		"url":      {domain + "/*"},
		"output":   {"txt"},
		"collapse": {"urlkey"},
		"fl":       {"original"},
	}
	waybackURI := "https://web.archive.org/cdx/search/cdx?" + query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, waybackURI, nil)
	if err != nil {
		return nil, err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("wayback CDX returned HTTP %d", resp.StatusCode)
	}

	// io.LimitReader — guia §8, dicas.md §5
	var urls []string
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxBodyRead))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			urls = append(urls, line)
			if len(urls) >= maxURLs {
				break
			}
		}
	}
	return urls, sc.Err()
}

// cleanURLs mirrors ParamSpider's clean_urls() exactly:
//  1. Drop URLs with matching file extensions.
//  2. Clean redundant port information (clean_url).
//  3. Replace all param values with the placeholder.
//  4. Keep only URLs that have at least one parameter ("?" in URL).
//  5. Deduplicate.
func cleanURLs(rawURLs []string, extensions []string, placeholder, domain string, maxResults int) []string {
	seen := make(map[string]bool, len(rawURLs))
	var out []string

	for _, raw := range rawURLs {
		cleaned := cleanURL(raw)
		canonical, ok := urlutil.CanonicalHTTP(cleaned)
		if !ok || !urlutil.InDomainScope(canonical, domain) {
			continue
		}
		if hasExtension(canonical, extensions) {
			continue
		}
		u, err := url.Parse(canonical)
		if err != nil || u.RawQuery == "" {
			continue
		}
		// Replace all param values with placeholder
		q := u.Query()
		newQ := make(url.Values, len(q))
		for k := range q {
			newQ[k] = []string{placeholder}
		}
		u.RawQuery = newQ.Encode()
		final := u.String()

		if !seen[final] {
			seen[final] = true
			out = append(out, final)
			if len(out) >= maxResults {
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// cleanURL removes redundant port information for HTTP/HTTPS URLs
// — mirrors ParamSpider's clean_url() exactly.
func cleanURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	port := u.Port()
	if (port == "80" && u.Scheme == "http") || (port == "443" && u.Scheme == "https") {
		// Strip the redundant port
		host := u.Hostname()
		u.Host = host
	}
	return u.String()
}

// hasExtension mirrors ParamSpider's has_extension() exactly.
func hasExtension(rawURL string, extensions []string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	ext := filepath.Ext(path)
	for _, e := range extensions {
		if ext == e {
			return true
		}
	}
	return false
}

// saveResults writes cleaned URLs to ./results/<domain>.txt — mirrors ParamSpider.
func saveResults(domain string, urls []string) error {
	if err := os.MkdirAll("results", 0755); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join("results", domain+".txt"))
	if err != nil {
		return err
	}
	defer f.Close()
	for _, u := range urls {
		_, _ = fmt.Fprintln(f, u)
	}
	return nil
}

func optStr(opts map[string]string, key, def string) string {
	if opts == nil {
		return def
	}
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

func optBool(opts map[string]string, key string, def bool) bool {
	if opts == nil {
		return def
	}
	v, ok := opts[key]
	if !ok {
		return def
	}
	return strings.ToLower(v) != "false"
}

func optInt(opts map[string]string, key string, fallback int) int {
	if opts == nil {
		return fallback
	}
	value, err := strconv.Atoi(strings.TrimSpace(opts[key]))
	if err != nil {
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
