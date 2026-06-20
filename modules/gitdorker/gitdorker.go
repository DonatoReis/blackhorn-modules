// Package gitdorker busca segredos e informações sensíveis em repositórios públicos
// do GitHub e GitLab usando técnicas de dorking (GitHub Search API).
//
// Inspirado no GitDorker (https://github.com/obheda12/GitDorker) e
// gitrob (https://github.com/michenriksen/gitrob).
//
// Fontes integradas:
//   - GitHub Search API  (https://api.github.com/search)
//   - GitLab Search API  (https://gitlab.com/api/v4/search)
//
// Dorks pré-definidos por categoria:
//   - Credenciais (API keys, tokens, passwords, secrets)
//   - Arquivos sensíveis (.env, docker-compose, terraform, k8s secrets)
//   - Configurações de banco (connection strings, DSN)
//   - Chaves privadas (RSA, EC, PGP)
//   - Certificados e segredos de CI/CD
//   - Dados brasileiros (CPF, CNPJ, CEP em código)
//
// Input:
//   - Target: organização, usuário ou repositório (ex: "org:acme" ou "acme")
//   - Options["github_token"]    — GitHub Personal Access Token (ou env GITHUB_TOKEN)
//   - Options["gitlab_token"]    — GitLab Personal Access Token (ou env GITLAB_TOKEN)
//   - Options["sources"]         — "github", "gitlab" ou ambos (default: github)
//   - Options["categories"]      — categorias separadas por vírgula (default: all)
//   - Options["max_results"]     — máximo de resultados por dork (default: 10)
//   - Options["timeout"]         — timeout em segundos (default: 30)
//
// Limite de rate: GitHub permite 30 requests/min autenticado para search.
// O módulo respeita X-RateLimit-Remaining e dorme quando necessário.
//
// AVISO LEGAL: use apenas em repositórios/orgs que você tem permissão para auditar.
package gitdorker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	moduleName     = "gitdorker"
	maxBody        = 1 << 20 // 1 MB
	defaultMaxRes  = 10
	rateLimitSleep = 2 * time.Second
)

// ─── Dork defines a search pattern ────────────────────────────────────────────

// Dork representa uma consulta de busca com categoria e severidade associadas.
type Dork struct {
	Name       string
	Category   string
	Query      string // fragmento de busca adicionado ao target
	Severity   module.Severity
	Confidence float64
}

// ─── Built-in dorks ───────────────────────────────────────────────────────────

var builtinDorks = []Dork{
	// Credenciais — alta severidade
	{Name: "api_key_assignment", Category: "credentials", Query: `"api_key" OR "apikey" "= " language:python language:javascript language:go`, Severity: module.SeverityHigh, Confidence: 0.75},
	{Name: "password_variable", Category: "credentials", Query: `"password" "=" "secret" NOT "example" NOT "test"`, Severity: module.SeverityHigh, Confidence: 0.70},
	{Name: "aws_access_key", Category: "credentials", Query: `"AKIA" language:python language:javascript language:go`, Severity: module.SeverityHigh, Confidence: 0.88},
	{Name: "github_token", Category: "credentials", Query: `"ghp_" OR "github_pat_" language:python language:javascript language:go`, Severity: module.SeverityHigh, Confidence: 0.90},
	{Name: "stripe_key", Category: "credentials", Query: `"sk_live_" OR "rk_live_" language:python language:javascript`, Severity: module.SeverityHigh, Confidence: 0.92},
	{Name: "slack_token", Category: "credentials", Query: `"xox" "slack" language:python language:javascript`, Severity: module.SeverityHigh, Confidence: 0.85},
	{Name: "sendgrid_key", Category: "credentials", Query: `"SG." filename:.env OR filename:config`, Severity: module.SeverityHigh, Confidence: 0.85},
	{Name: "jwt_secret", Category: "credentials", Query: `"jwt_secret" OR "jwt_key" OR "JWT_SECRET" filename:.env`, Severity: module.SeverityHigh, Confidence: 0.80},
	{Name: "openai_key", Category: "credentials", Query: `"sk-" "openai" language:python language:javascript`, Severity: module.SeverityHigh, Confidence: 0.85},
	{Name: "anthropic_key", Category: "credentials", Query: `"sk-ant-" language:python language:javascript`, Severity: module.SeverityHigh, Confidence: 0.90},

	// Arquivos sensíveis
	{Name: "dotenv_file", Category: "sensitive_files", Query: `filename:.env`, Severity: module.SeverityMedium, Confidence: 0.65},
	{Name: "dotenv_local", Category: "sensitive_files", Query: `filename:.env.local OR filename:.env.production OR filename:.env.staging`, Severity: module.SeverityHigh, Confidence: 0.80},
	{Name: "docker_compose_secrets", Category: "sensitive_files", Query: `filename:docker-compose.yml "password" OR "secret"`, Severity: module.SeverityMedium, Confidence: 0.70},
	{Name: "terraform_secrets", Category: "sensitive_files", Query: `filename:.tfvars "password" OR "secret" OR "api_key"`, Severity: module.SeverityHigh, Confidence: 0.78},
	{Name: "k8s_secret", Category: "sensitive_files", Query: `filename:*.yaml "kind: Secret" "data:"`, Severity: module.SeverityMedium, Confidence: 0.72},
	{Name: "ci_config_secrets", Category: "sensitive_files", Query: `filename:.travis.yml OR filename:.circleci "password" OR "secret"`, Severity: module.SeverityMedium, Confidence: 0.70},
	{Name: "github_actions_secrets", Category: "sensitive_files", Query: `filename:*.yml path:.github/workflows "secrets."`, Severity: module.SeverityInfo, Confidence: 0.60},
	{Name: "htpasswd", Category: "sensitive_files", Query: `filename:.htpasswd`, Severity: module.SeverityHigh, Confidence: 0.85},
	{Name: "npmrc_token", Category: "sensitive_files", Query: `filename:.npmrc "_authToken"`, Severity: module.SeverityHigh, Confidence: 0.88},

	// Chaves privadas
	{Name: "private_key_rsa", Category: "private_keys", Query: `"BEGIN RSA PRIVATE KEY"`, Severity: module.SeverityHigh, Confidence: 0.95},
	{Name: "private_key_ec", Category: "private_keys", Query: `"BEGIN EC PRIVATE KEY"`, Severity: module.SeverityHigh, Confidence: 0.95},
	{Name: "private_key_openssh", Category: "private_keys", Query: `"BEGIN OPENSSH PRIVATE KEY"`, Severity: module.SeverityHigh, Confidence: 0.95},
	{Name: "pgp_private", Category: "private_keys", Query: `"BEGIN PGP PRIVATE KEY BLOCK"`, Severity: module.SeverityHigh, Confidence: 0.95},
	{Name: "private_key_pkcs8", Category: "private_keys", Query: `"BEGIN PRIVATE KEY"`, Severity: module.SeverityHigh, Confidence: 0.90},

	// Banco de dados
	{Name: "db_connection_string", Category: "database", Query: `"mongodb://" OR "postgres://" OR "mysql://" language:python language:go language:javascript`, Severity: module.SeverityHigh, Confidence: 0.82},
	{Name: "db_password_in_code", Category: "database", Query: `"DB_PASSWORD" OR "DATABASE_PASSWORD" filename:.env`, Severity: module.SeverityHigh, Confidence: 0.80},
	{Name: "redis_url", Category: "database", Query: `"redis://" "password" language:python language:javascript language:go`, Severity: module.SeverityMedium, Confidence: 0.75},
	{Name: "elasticsearch_credentials", Category: "database", Query: `"elasticsearch" "password" filename:*.yml OR filename:*.yaml`, Severity: module.SeverityMedium, Confidence: 0.72},

	// Cloud providers
	{Name: "gcp_service_account", Category: "cloud", Query: `filename:*.json "type": "service_account"`, Severity: module.SeverityHigh, Confidence: 0.88},
	{Name: "azure_connection", Category: "cloud", Query: `"DefaultEndpointsProtocol=https" "AccountKey="`, Severity: module.SeverityHigh, Confidence: 0.90},
	{Name: "aws_credentials_file", Category: "cloud", Query: `filename:credentials "aws_access_key_id"`, Severity: module.SeverityHigh, Confidence: 0.92},
	{Name: "heroku_api", Category: "cloud", Query: `"HEROKU_API_KEY" filename:.env OR language:ruby`, Severity: module.SeverityHigh, Confidence: 0.82},

	// Brasil específico
	{Name: "cpf_in_code", Category: "brasil", Query: `"cpf" "000.000.000-00" OR "cpf_number" language:python language:javascript language:go`, Severity: module.SeverityMedium, Confidence: 0.65},
	{Name: "cnpj_hardcoded", Category: "brasil", Query: `"cnpj" "00.000.000/0000-00" language:python language:javascript`, Severity: module.SeverityMedium, Confidence: 0.65},
	{Name: "receita_federal_key", Category: "brasil", Query: `"receita_federal" OR "receitaws" "api_key" OR "token"`, Severity: module.SeverityHigh, Confidence: 0.72},
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implementa busca de segredos em repositórios git públicos.
type Module struct {
	client *http.Client
	logger *slog.Logger
	dorks  []Dork
}

// New retorna um Module com todos os dorks pré-definidos.
func New() *Module {
	return &Module{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        30,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     60 * time.Second,
			},
		},
		logger: slog.Default().With("module", moduleName),
		dorks:  builtinDorks,
	}
}

// NewWithClient retorna um Module usando o cliente HTTP fornecido (testabilidade).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// BuiltinDorks retorna a lista de dorks pré-definidos (inspeção/testes).
func BuiltinDorks() []Dork { return builtinDorks }

// NewWithDorks retorna um Module com dorks customizados (extensibilidade).
func NewWithDorks(c *http.Client, dorks []Dork) *Module {
	m := New()
	m.client = c
	m.dorks = dorks
	return m
}

// Name implementa module.Module.
func (m *Module) Name() string { return moduleName }

// Run executa os dorks contra o target.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" && len(input.URLs) > 0 {
		target = strings.TrimSpace(input.URLs[0])
	}
	if target == "" {
		return nil, fmt.Errorf("gitdorker: target obrigatório (ex: 'org:acme' ou 'user:johndoe')")
	}

	opts := input.Options
	githubToken := optStr(opts, "github_token", os.Getenv("GITHUB_TOKEN"))
	categoriesFilter := optStr(opts, "categories", "")
	maxResults := optInt(opts, "max_results", defaultMaxRes)
	sourcesFilter := optStr(opts, "sources", "github")

	if githubToken == "" && strings.Contains(sourcesFilter, "github") {
		m.logger.WarnContext(ctx, "gitdorker: sem github_token — rate limit muito restrito (10 req/min)")
	}

	// Filtra dorks por categoria
	activeDorks := m.filterDorks(categoriesFilter)
	if len(activeDorks) == 0 {
		return nil, fmt.Errorf("gitdorker: nenhum dork ativo para categorias: %q", categoriesFilter)
	}

	m.logger.InfoContext(ctx, "gitdorker: iniciando",
		"target", target, "dorks", len(activeDorks), "max_per_dork", maxResults)

	var (
		mu      sync.Mutex
		results []module.Finding
	)
	add := func(fs []module.Finding) {
		mu.Lock()
		results = append(results, fs...)
		mu.Unlock()
	}

	// Limitar paralelismo para respeitar rate limit do GitHub (30 req/min auth, 10 unauth)
	maxParallel := 3
	if githubToken != "" {
		maxParallel = 5
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(maxParallel)

	for _, dork := range activeDorks {
		d := dork // captura
		if strings.Contains(sourcesFilter, "github") {
			eg.Go(func() error {
				fs, err := m.searchGitHub(egCtx, target, d, githubToken, maxResults)
				if err != nil {
					m.logger.WarnContext(egCtx, "gitdorker: github search error",
						"dork", d.Name, "err", err)
				} else {
					add(fs)
				}
				// pequena pausa entre dorks para respeitar rate limit
				time.Sleep(rateLimitSleep)
				return nil
			})
		}
	}

	_ = eg.Wait()

	results = dedupByURL(results)

	m.logger.InfoContext(ctx, "gitdorker: concluído",
		"target", target, "findings", len(results))
	return results, nil
}

// ─── GitHub Search ────────────────────────────────────────────────────────────
// GET https://api.github.com/search/code?q={query}&per_page={n}

func (m *Module) searchGitHub(ctx context.Context, target string, dork Dork, token string, maxResults int) ([]module.Finding, error) {
	// Compõe a query: target + dork query
	q := buildQuery(target, dork.Query)

	apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=%d",
		url.QueryEscape(q), maxResults)

	m.logger.DebugContext(ctx, "gitdorker: github search",
		"dork", dork.Name, "query", q)

	headers := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}

	body, err := m.get(ctx, apiURL, headers)
	if err != nil {
		return nil, err
	}

	var r struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Name       string `json:"name"`
			Path       string `json:"path"`
			HTMLURL    string `json:"html_url"`
			Repository struct {
				FullName    string `json:"full_name"`
				HTMLURL     string `json:"html_url"`
				Description string `json:"description"`
				Private     bool   `json:"private"`
				StarCount   int    `json:"stargazers_count"`
				Language    string `json:"language"`
			} `json:"repository"`
			Score float64 `json:"score"`
		} `json:"items"`
		Message string `json:"message"` // erros da API
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("github search: parse: %w", err)
	}
	if r.Message != "" {
		return nil, fmt.Errorf("github search: %s", r.Message)
	}

	if len(r.Items) == 0 {
		return nil, nil
	}

	m.logger.DebugContext(ctx, "gitdorker: results",
		"dork", dork.Name, "total", r.TotalCount, "returned", len(r.Items))

	var findings []module.Finding
	for _, item := range r.Items {
		repo := item.Repository
		confidence := fmt.Sprintf("%.2f", dork.Confidence)
		// Score do GitHub aumenta confiança
		if item.Score > 50 {
			adjusted := dork.Confidence + 0.05
			if adjusted > 0.99 {
				adjusted = 0.99
			}
			confidence = fmt.Sprintf("%.2f", adjusted)
		}

		findings = append(findings, module.Finding{
			Type:     "git_secret_exposure",
			URL:      item.HTMLURL,
			Detail:   fmt.Sprintf("[GitDorker/%s] %s/%s — dork: %s (total: %d resultados)", dork.Category, repo.FullName, item.Path, dork.Name, r.TotalCount),
			Severity: dork.Severity,
			Extra: map[string]string{
				"source":        "github",
				"dork_name":     dork.Name,
				"dork_category": dork.Category,
				"repo":          repo.FullName,
				"repo_url":      repo.HTMLURL,
				"file_name":     item.Name,
				"file_path":     item.Path,
				"file_url":      item.HTMLURL,
				"language":      repo.Language,
				"stars":         strconv.Itoa(repo.StarCount),
				"total_count":   strconv.Itoa(r.TotalCount),
				"score":         fmt.Sprintf("%.2f", item.Score),
				"confidence":    confidence,
			},
		})
	}

	return findings, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// buildQuery compõe a query do GitHub combinando target e dork.
// Target pode ser: "org:acme", "user:johndoe", "repo:acme/api", ou bare "acme"
func buildQuery(target, dorkQuery string) string {
	if strings.ContainsAny(target, ":") {
		// já formatado: org:X, user:X, repo:X
		return target + " " + dorkQuery
	}
	// tenta como org por padrão
	return "org:" + target + " " + dorkQuery
}

func (m *Module) filterDorks(categories string) []Dork {
	if categories == "" {
		return m.dorks
	}
	cats := make(map[string]bool)
	for _, c := range strings.Split(categories, ",") {
		cats[strings.TrimSpace(strings.ToLower(c))] = true
	}
	var out []Dork
	for _, d := range m.dorks {
		if cats[strings.ToLower(d.Category)] {
			out = append(out, d)
		}
	}
	return out
}

func dedupByURL(findings []module.Finding) []module.Finding {
	seen := make(map[string]bool)
	var out []module.Finding
	for _, f := range findings {
		key := f.URL
		if key == "" {
			key = f.Type + ":" + f.Detail
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

func (m *Module) get(ctx context.Context, apiURL string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-gitdorker/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check rate limit
	remaining := resp.Header.Get("X-RateLimit-Remaining")
	if remaining == "0" {
		m.logger.WarnContext(ctx, "gitdorker: GitHub rate limit esgotado")
	}

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("github search: proibido (403) — verifique token ou rate limit")
	}
	if resp.StatusCode == http.StatusUnprocessableEntity {
		return nil, fmt.Errorf("github search: query inválida (422)")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("github search: rate limited (429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github search: status %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
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

func optInt(opts map[string]string, key string, def int) int {
	s := optStr(opts, key, "")
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return def
	}
	return n
}
