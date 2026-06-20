// Package googledork performs Google Dorking (advanced search queries) using
// multiple search APIs to discover exposed information about a target.
//
// Search engines supported:
//   - SerpAPI        — Google results via API (key required, most reliable)
//   - Bing API       — Microsoft Bing Search v7 (key required)
//   - DuckDuckGo     — DDG HTML scraping, no key, rate-limited
//   - Brave Search   — Brave Search API (key optional)
//
// Built-in dork categories:
//   - sensitive_files: robots.txt, sitemap.xml, backup files, .git, .env
//   - login_panels:    admin pages, login forms, phpMyAdmin
//   - tech_stack:      exposed version strings, error pages, stack traces
//   - data_exposure:   spreadsheets, PDFs, database dumps
//   - cameras:         exposed webcams, IP cameras
//   - brasil:          CPF forms, CNPJ lookup pages, Nota Fiscal, eSocial
//   - cloud:           exposed S3/Azure/GCP endpoints
//   - credentials:     password files, config files with secrets
//
// Each dork generates a structured query: "site:{target} {dork_query}"
//
// Usage:
//
//	m := googledork.New()
//	findings, err := m.Run(ctx, module.Input{
//	    Target:  "example.com",
//	    Options: map[string]string{
//	        "sources":       "serpapi,bing",
//	        "serpapi_key":   "<key>",
//	        "bing_key":      "<key>",
//	        "categories":    "sensitive_files,credentials",
//	        "max_results":   "10",
//	        "site_operator": "true",  // prefix with site:target
//	    },
//	})
package googledork

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	maxBodyDork = 512 * 1024 // 512 KB per search result page
	maxParallel = 4
	rateSleep   = 2 * time.Second // between dork queries per engine
)

// Dork describes a single Google dork query.
type Dork struct {
	Name       string
	Category   string
	Query      string
	Severity   module.Severity
	Confidence float64
}

// BuiltinDorks returns the built-in dork list.
func BuiltinDorks() []Dork { return builtinDorks }

var builtinDorks = []Dork{
	// ── sensitive_files ──────────────────────────────────────────────────────
	{Name: "env_file", Category: "sensitive_files",
		Query: `".env" "DB_PASSWORD" OR "SECRET_KEY"`, Severity: module.SeverityHigh, Confidence: 0.90},
	{Name: "git_config", Category: "sensitive_files",
		Query: `"/.git/config"`, Severity: module.SeverityHigh, Confidence: 0.88},
	{Name: "backup_files", Category: "sensitive_files",
		Query: `ext:bak OR ext:backup OR ext:old "index"`, Severity: module.SeverityMedium, Confidence: 0.78},
	{Name: "exposed_logs", Category: "sensitive_files",
		Query: `ext:log "error" OR "exception" OR "password"`, Severity: module.SeverityMedium, Confidence: 0.75},
	{Name: "config_files", Category: "sensitive_files",
		Query: `ext:xml OR ext:conf OR ext:ini "password" OR "secret"`, Severity: module.SeverityHigh, Confidence: 0.82},
	{Name: "sql_files", Category: "sensitive_files",
		Query: `ext:sql "INSERT INTO" OR "CREATE TABLE"`, Severity: module.SeverityHigh, Confidence: 0.87},
	// ── login_panels ─────────────────────────────────────────────────────────
	{Name: "admin_panel", Category: "login_panels",
		Query: `inurl:admin OR inurl:administrator OR inurl:wp-admin`, Severity: module.SeverityMedium, Confidence: 0.72},
	{Name: "phpmyadmin", Category: "login_panels",
		Query: `inurl:phpmyadmin`, Severity: module.SeverityHigh, Confidence: 0.85},
	{Name: "login_pages", Category: "login_panels",
		Query: `inurl:login OR inurl:signin "username" "password"`, Severity: module.SeverityLow, Confidence: 0.68},
	{Name: "cpanel", Category: "login_panels",
		Query: `inurl:2082 OR inurl:2083 OR inurl:cpanel`, Severity: module.SeverityMedium, Confidence: 0.80},
	// ── tech_stack ───────────────────────────────────────────────────────────
	{Name: "error_pages", Category: "tech_stack",
		Query: `"PHP Parse error" OR "Fatal error" OR "Stack trace"`, Severity: module.SeverityMedium, Confidence: 0.82},
	{Name: "version_disclosure", Category: "tech_stack",
		Query: `"Powered by" OR "Running on" intitle:"index of"`, Severity: module.SeverityLow, Confidence: 0.70},
	{Name: "directory_listing", Category: "tech_stack",
		Query: `intitle:"Index of /" OR intitle:"Directory listing"`, Severity: module.SeverityHigh, Confidence: 0.90},
	// ── data_exposure ────────────────────────────────────────────────────────
	{Name: "spreadsheets", Category: "data_exposure",
		Query: `ext:xlsx OR ext:xls OR ext:csv "email" OR "phone" OR "cpf"`, Severity: module.SeverityHigh, Confidence: 0.80},
	{Name: "exposed_db", Category: "data_exposure",
		Query: `inurl:db_dump OR inurl:database_backup ext:sql`, Severity: module.SeverityCritical, Confidence: 0.92},
	{Name: "pdf_documents", Category: "data_exposure",
		Query: `ext:pdf "confidential" OR "internal use only" OR "não divulgar"`, Severity: module.SeverityMedium, Confidence: 0.72},
	// ── credentials ──────────────────────────────────────────────────────────
	{Name: "password_file", Category: "credentials",
		Query: `inurl:password OR inurl:passwd ext:txt OR ext:log`, Severity: module.SeverityHigh, Confidence: 0.85},
	{Name: "aws_keys", Category: "credentials",
		Query: `"AKIAIOSFODNN7EXAMPLE" OR "AKIA" ext:txt OR ext:env`, Severity: module.SeverityCritical, Confidence: 0.93},
	{Name: "private_keys", Category: "credentials",
		Query: `"BEGIN RSA PRIVATE KEY" OR "BEGIN PRIVATE KEY"`, Severity: module.SeverityCritical, Confidence: 0.95},
	// ── brasil ───────────────────────────────────────────────────────────────
	{Name: "cpf_forms", Category: "brasil",
		Query: `"CPF" "Digite seu CPF" OR "informe o CPF"`, Severity: module.SeverityLow, Confidence: 0.68},
	{Name: "cnpj_exposed", Category: "brasil",
		Query: `"CNPJ" ext:xml OR ext:csv "Razão Social"`, Severity: module.SeverityMedium, Confidence: 0.75},
	{Name: "nota_fiscal", Category: "brasil",
		Query: `"Nota Fiscal" "chave de acesso" ext:xml`, Severity: module.SeverityMedium, Confidence: 0.78},
	{Name: "dados_pessoais", Category: "brasil",
		Query: `"dados pessoais" OR "LGPD" "vazamento" OR "incidente"`, Severity: module.SeverityMedium, Confidence: 0.70},
	// ── cloud ─────────────────────────────────────────────────────────────────
	{Name: "s3_exposed", Category: "cloud",
		Query: `"s3.amazonaws.com" OR "s3-us-east-1.amazonaws.com" intitle:"index"`, Severity: module.SeverityHigh, Confidence: 0.85},
	{Name: "azure_blob", Category: "cloud",
		Query: `"blob.core.windows.net" intitle:"index"`, Severity: module.SeverityHigh, Confidence: 0.83},
	{Name: "gcp_storage", Category: "cloud",
		Query: `"storage.googleapis.com" intitle:"index"`, Severity: module.SeverityHigh, Confidence: 0.83},
	// ── cameras ───────────────────────────────────────────────────────────────
	{Name: "webcams", Category: "cameras",
		Query: `inurl:view.shtml OR inurl:viewerframe?mode=motion`, Severity: module.SeverityHigh, Confidence: 0.88},
}

// Module implements module.Module for search-engine dorking.
type Module struct {
	client *http.Client
	dorks  []Dork
}

// New returns a Module with built-in dorks and default HTTP client.
func New() *Module { return NewWithDorks(defaultClient(), builtinDorks) }

// NewWithClient injects a custom HTTP client.
func NewWithClient(c *http.Client) *Module { return NewWithDorks(c, builtinDorks) }

// NewWithDorks injects a client and custom dork list.
func NewWithDorks(c *http.Client, dorks []Dork) *Module { return &Module{client: c, dorks: dorks} }

// Name returns the canonical module identifier.
func (m *Module) Name() string { return "googledork" }

// Run executes dork queries against configured search engines.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("googledork: target vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	sourcesFilter := opts["sources"]
	categoriesFilter := opts["categories"]
	maxResults := optInt(opts, "max_results", 10)
	siteOp := optBool(opts, "site_operator", true)

	// Select active dorks
	active := m.filterDorks(categoriesFilter)
	if len(active) == 0 {
		return nil, fmt.Errorf("googledork: nenhum dork ativo com categorias '%s'", categoriesFilter)
	}

	slog.InfoContext(ctx, "googledork.Run iniciado",
		"target", target,
		"sources", sourcesFilter,
		"dorks_active", len(active),
		"categories", categoriesFilter,
	)

	type sourceFunc struct {
		name string
		fn   func(context.Context, string, string, map[string]string, int) ([]module.Finding, error)
	}

	sources := []sourceFunc{
		{"serpapi", m.querySerpAPI},
		{"bing", m.queryBing},
		{"ddg", m.queryDDG},
		{"brave", m.queryBrave},
	}

	var mu sync.Mutex
	var all []module.Finding

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxParallel)

	for _, s := range sources {
		s := s
		if !isWanted(sourcesFilter, s.name) {
			continue
		}
		g.Go(func() error {
			for _, dork := range active {
				dork := dork
				query := buildQuery(target, dork.Query, siteOp)
				slog.DebugContext(gctx, "googledork: executando dork",
					"engine", s.name, "dork", dork.Name, "query", query)

				findings, err := s.fn(gctx, query, dork.Name, opts, maxResults)
				if err != nil {
					slog.WarnContext(gctx, "googledork: dork com erro",
						"engine", s.name, "dork", dork.Name, "err", err)
				} else {
					// Enrich findings with dork metadata
					for i := range findings {
						findings[i].Severity = dork.Severity
						if findings[i].Extra == nil {
							findings[i].Extra = map[string]string{}
						}
						findings[i].Extra["dork_name"] = dork.Name
						findings[i].Extra["dork_category"] = dork.Category
						findings[i].Extra["dork_query"] = query
						if findings[i].Extra["confidence"] == "" {
							findings[i].Extra["confidence"] = fmt.Sprintf("%.2f", dork.Confidence)
						}
					}
					mu.Lock()
					all = append(all, findings...)
					mu.Unlock()
				}

				// Rate limit between queries
				select {
				case <-gctx.Done():
					return nil
				case <-time.After(rateSleep):
				}
			}
			return nil
		})
	}
	_ = g.Wait()

	result := dedup(all)
	slog.InfoContext(ctx, "googledork.Run concluído",
		"target", target,
		"findings", len(result),
	)
	return result, nil
}

// ─── SerpAPI ──────────────────────────────────────────────────────────────────

type serpResult struct {
	OrganicResults []struct {
		Title   string `json:"title"`
		Link    string `json:"link"`
		Snippet string `json:"snippet"`
	} `json:"organic_results"`
	SearchMetadata struct {
		Status string `json:"status"`
	} `json:"search_metadata"`
}

func (m *Module) querySerpAPI(ctx context.Context, query, dorkName string, opts map[string]string, maxResults int) ([]module.Finding, error) {
	apiKey := opts["serpapi_key"]
	if apiKey == "" {
		return nil, fmt.Errorf("serpapi: serpapi_key não configurado")
	}

	u := fmt.Sprintf("https://serpapi.com/search.json?q=%s&num=%d&api_key=%s",
		url.QueryEscape(query), min(maxResults, 10), apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-googledork/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("serpapi: API key inválida")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("serpapi: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyDork))
	if err != nil {
		return nil, err
	}

	var result serpResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("serpapi: parse: %w", err)
	}

	var findings []module.Finding
	for _, r := range result.OrganicResults {
		findings = append(findings, module.Finding{
			Type:   "dork_result",
			URL:    r.Link,
			Detail: fmt.Sprintf("Dork '%s' via Google/SerpAPI: [%s] %s", dorkName, r.Title, truncate(r.Snippet, 200)),
			Extra: map[string]string{
				"title":   r.Title,
				"snippet": truncate(r.Snippet, 300),
				"engine":  "google",
				"source":  "serpapi",
			},
		})
	}
	return findings, nil
}

// ─── Bing Search API ──────────────────────────────────────────────────────────

type bingResult struct {
	WebPages struct {
		Value []struct {
			Name    string `json:"name"`
			URL     string `json:"url"`
			Snippet string `json:"snippet"`
		} `json:"value"`
	} `json:"webPages"`
}

func (m *Module) queryBing(ctx context.Context, query, dorkName string, opts map[string]string, maxResults int) ([]module.Finding, error) {
	apiKey := opts["bing_key"]
	if apiKey == "" {
		return nil, fmt.Errorf("bing: bing_key não configurado")
	}

	u := fmt.Sprintf("https://api.bing.microsoft.com/v7.0/search?q=%s&count=%d",
		url.QueryEscape(query), min(maxResults, 50))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Ocp-Apim-Subscription-Key", apiKey)
	req.Header.Set("User-Agent", "blackhorn-googledork/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("bing: API key inválida")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bing: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyDork))
	if err != nil {
		return nil, err
	}

	var result bingResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("bing: parse: %w", err)
	}

	var findings []module.Finding
	for _, r := range result.WebPages.Value {
		findings = append(findings, module.Finding{
			Type:   "dork_result",
			URL:    r.URL,
			Detail: fmt.Sprintf("Dork '%s' via Bing: [%s] %s", dorkName, r.Name, truncate(r.Snippet, 200)),
			Extra: map[string]string{
				"title":   r.Name,
				"snippet": truncate(r.Snippet, 300),
				"engine":  "bing",
				"source":  "bing",
			},
		})
	}
	return findings, nil
}

// ─── DuckDuckGo ───────────────────────────────────────────────────────────────

type ddgResult struct {
	RelatedTopics []struct {
		Text     string `json:"Text"`
		FirstURL string `json:"FirstURL"`
	} `json:"RelatedTopics"`
	Results []struct {
		Text     string `json:"Text"`
		FirstURL string `json:"FirstURL"`
	} `json:"Results"`
}

func (m *Module) queryDDG(ctx context.Context, query, dorkName string, opts map[string]string, maxResults int) ([]module.Finding, error) {
	// DDG Instant Answer API (free, no key, limited results)
	u := fmt.Sprintf("https://api.duckduckgo.com/?q=%s&format=json&no_redirect=1&no_html=1",
		url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-googledork/1.0 (OSINT)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ddg: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyDork))
	if err != nil {
		return nil, err
	}

	var result ddgResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, nil // DDG sometimes returns non-JSON
	}

	var findings []module.Finding
	count := 0

	for _, r := range result.Results {
		if count >= maxResults {
			break
		}
		if r.FirstURL == "" {
			continue
		}
		findings = append(findings, module.Finding{
			Type:   "dork_result",
			URL:    r.FirstURL,
			Detail: fmt.Sprintf("Dork '%s' via DuckDuckGo: %s", dorkName, truncate(r.Text, 200)),
			Extra: map[string]string{
				"snippet": truncate(r.Text, 300),
				"engine":  "duckduckgo",
				"source":  "ddg",
			},
		})
		count++
	}

	return findings, nil
}

// ─── Brave Search ─────────────────────────────────────────────────────────────

type braveResult struct {
	Web struct {
		Results []struct {
			Title       string `json:"title"`
			URL         string `json:"url"`
			Description string `json:"description"`
		} `json:"results"`
	} `json:"web"`
}

func (m *Module) queryBrave(ctx context.Context, query, dorkName string, opts map[string]string, maxResults int) ([]module.Finding, error) {
	apiKey := opts["brave_key"]
	if apiKey == "" {
		return nil, fmt.Errorf("brave: brave_key não configurado")
	}

	u := fmt.Sprintf("https://api.search.brave.com/res/v1/web/search?q=%s&count=%d",
		url.QueryEscape(query), min(maxResults, 20))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Subscription-Token", apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "blackhorn-googledork/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("brave: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyDork))
	if err != nil {
		return nil, err
	}

	var result braveResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("brave: parse: %w", err)
	}

	var findings []module.Finding
	for _, r := range result.Web.Results {
		findings = append(findings, module.Finding{
			Type:   "dork_result",
			URL:    r.URL,
			Detail: fmt.Sprintf("Dork '%s' via Brave Search: [%s] %s", dorkName, r.Title, truncate(r.Description, 200)),
			Extra: map[string]string{
				"title":   r.Title,
				"snippet": truncate(r.Description, 300),
				"engine":  "brave",
				"source":  "brave",
			},
		})
	}
	return findings, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func buildQuery(target, dorkQuery string, siteOp bool) string {
	if siteOp {
		return fmt.Sprintf("site:%s %s", target, dorkQuery)
	}
	return fmt.Sprintf("%s %s", target, dorkQuery)
}

func (m *Module) filterDorks(categoriesFilter string) []Dork {
	if categoriesFilter == "" {
		return m.dorks
	}
	wanted := map[string]bool{}
	for _, c := range strings.Split(categoriesFilter, ",") {
		wanted[strings.TrimSpace(c)] = true
	}
	var out []Dork
	for _, d := range m.dorks {
		if wanted[d.Category] || wanted[d.Name] {
			out = append(out, d)
		}
	}
	return out
}

func isWanted(filter, name string) bool {
	if filter == "" {
		return true
	}
	for _, s := range strings.Split(filter, ",") {
		if strings.TrimSpace(s) == name {
			return true
		}
	}
	return false
}

func optInt(opts map[string]string, key string, def int) int {
	v, ok := opts[key]
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func optBool(opts map[string]string, key string, def bool) bool {
	v, ok := opts[key]
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func defaultClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     60 * time.Second,
		},
	}
}

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	out := make([]module.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.URL + "|" + f.Extra["dork_name"] + "|" + f.Extra["source"]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
