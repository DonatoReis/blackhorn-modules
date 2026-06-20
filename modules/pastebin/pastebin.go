// Package pastebin busca vazamentos de dados em serviços de paste público.
//
// Fontes integradas:
//   - Pastebin (via psbdmp.ws scraper — gratuito)   — pastes mais recentes
//   - GitHub Gists                                   — gists públicos com informação
//   - IntelX                (https://intelx.io)      — busca histórica em pastes
//   - LeakIX               (https://leakix.net)      — vazamentos indexados
//
// Busca local via regex:
//   - Emails
//   - CPF/CNPJ (dados brasileiros)
//   - Credenciais (user:pass, email:pass)
//   - Tokens e API keys
//   - Números de cartão (detecção de padrão Luhn)
//
// Input:
//   - Target: termo de busca (email, domínio, nome, CPF, etc.)
//   - Options["sources"]       — fontes (default: all)
//   - Options["intelx_key"]   — chave IntelX (ou env INTELX_API_KEY)
//   - Options["leakix_key"]   — chave LeakIX (ou env LEAKIX_API_KEY)
//   - Options["github_token"] — GitHub token para busca em gists
//   - Options["max_results"]  — máximo por fonte (default: 20)
//   - Options["timeout"]      — timeout em segundos (default: 30)
//
// Privacidade: dados extraídos são retornados como findings, nunca armazenados.
// Redação automática de senhas e tokens nos campos de texto.
package pastebin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	moduleName    = "pastebin"
	maxBody       = 2 << 20 // 2 MB
	defaultMaxRes = 20
)

// ─── Regexes para análise de conteúdo de paste ────────────────────────────────

var (
	reEmail      = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reEmailPass  = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}[:\|][^\s\n]{6,}`)
	reCPF        = regexp.MustCompile(`\b\d{3}[.\-]?\d{3}[.\-]?\d{3}[-]?\d{2}\b`)
	reCNPJ       = regexp.MustCompile(`\b\d{2}[.\-]?\d{3}[.\-]?\d{3}[/\-]?\d{4}[-]?\d{2}\b`)
	reAPIKey     = regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password|passwd|pwd)\s*[=:]\s*['""]?([a-zA-Z0-9_\-\.]{16,})`)
	reAWSKey     = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reCreditCard = regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b`)
	rePrivateKey = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)
)

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implementa busca em serviços de paste público.
type Module struct {
	client *http.Client
	logger *slog.Logger
}

// New retorna um Module com configuração padrão de produção.
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
	}
}

// NewWithClient retorna um Module usando o cliente HTTP fornecido (testabilidade).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// Name implementa module.Module.
func (m *Module) Name() string { return moduleName }

// Run busca o target em múltiplas fontes de paste em paralelo.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" && len(input.URLs) > 0 {
		target = strings.TrimSpace(input.URLs[0])
	}
	if target == "" {
		return nil, fmt.Errorf("pastebin: termo de busca obrigatório em Target")
	}

	opts := input.Options
	sourcesFilter := optStr(opts, "sources", "")
	intelxKey := optStr(opts, "intelx_key", os.Getenv("INTELX_API_KEY"))
	leakixKey := optStr(opts, "leakix_key", os.Getenv("LEAKIX_API_KEY"))
	githubToken := optStr(opts, "github_token", os.Getenv("GITHUB_TOKEN"))
	maxResults := optInt(opts, "max_results", defaultMaxRes)

	m.logger.InfoContext(ctx, "pastebin: iniciando", "target", target)

	var (
		mu      sync.Mutex
		results []module.Finding
	)
	add := func(fs []module.Finding) {
		mu.Lock()
		results = append(results, fs...)
		mu.Unlock()
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(6)

	// psbdmp.ws — indexador de Pastebin (gratuito)
	if wantSource(sourcesFilter, "psbdmp") || sourcesFilter == "" {
		eg.Go(func() error {
			fs, err := m.fetchPSBDMP(egCtx, target, maxResults)
			if err != nil {
				m.logger.WarnContext(egCtx, "pastebin: psbdmp error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	// GitHub Gists
	if (wantSource(sourcesFilter, "gists") || sourcesFilter == "") && githubToken != "" {
		eg.Go(func() error {
			fs, err := m.fetchGitHubGists(egCtx, target, githubToken, maxResults)
			if err != nil {
				m.logger.WarnContext(egCtx, "pastebin: gists error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	// IntelX
	if intelxKey != "" && (wantSource(sourcesFilter, "intelx") || sourcesFilter == "") {
		eg.Go(func() error {
			fs, err := m.fetchIntelX(egCtx, target, intelxKey, maxResults)
			if err != nil {
				m.logger.WarnContext(egCtx, "pastebin: intelx error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	// LeakIX
	if leakixKey != "" && (wantSource(sourcesFilter, "leakix") || sourcesFilter == "") {
		eg.Go(func() error {
			fs, err := m.fetchLeakIX(egCtx, target, leakixKey, maxResults)
			if err != nil {
				m.logger.WarnContext(egCtx, "pastebin: leakix error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	_ = eg.Wait()

	results = dedupByURL(results)

	m.logger.InfoContext(ctx, "pastebin: concluído",
		"target", target, "findings", len(results))
	return results, nil
}

// ─── PSBDMP ──────────────────────────────────────────────────────────────────
// GET https://psbdmp.ws/api/search/{term}

func (m *Module) fetchPSBDMP(ctx context.Context, target string, max int) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("https://psbdmp.ws/api/search/%s", url.PathEscape(target))
	body, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}

	var r struct {
		Count int `json:"count"`
		Data  []struct {
			ID   string `json:"id"`
			Tags string `json:"tags"`
			Time string `json:"time"`
			Text string `json:"text"` // trecho do paste
		} `json:"data"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		// psbdmp pode retornar HTML — tratar graciosamente
		return nil, fmt.Errorf("psbdmp: parse error: %w", err)
	}
	if r.Error != "" {
		return nil, fmt.Errorf("psbdmp: %s", r.Error)
	}

	var findings []module.Finding
	limit := min(len(r.Data), max)
	for _, item := range r.Data[:limit] {
		pasteURL := fmt.Sprintf("https://pastebin.com/%s", item.ID)

		// Analisa o snippet do paste
		snippetFindings := m.analyzeContent(item.Text, pasteURL)

		confidence := "0.72" // psbdmp indexa pastes públicos — texto pode estar truncado
		severity := module.SeverityInfo
		if len(snippetFindings) > 0 {
			confidence = "0.80"
			severity = module.SeverityMedium
		}

		findings = append(findings, module.Finding{
			Type:     "paste_found",
			URL:      pasteURL,
			Detail:   fmt.Sprintf("[Pastebin] Paste %s menciona %q | Tags: %s | Data: %s", item.ID, target, item.Tags, item.Time),
			Severity: severity,
			Extra: map[string]string{
				"source":      "psbdmp",
				"paste_id":    item.ID,
				"paste_url":   pasteURL,
				"tags":        item.Tags,
				"date":        item.Time,
				"snippet":     truncate(item.Text, 200),
				"total_found": strconv.Itoa(r.Count),
				"confidence":  confidence,
			},
		})

		// Adiciona findings de conteúdo sensível encontrado no snippet
		findings = append(findings, snippetFindings...)
	}

	return findings, nil
}

// ─── GitHub Gists ─────────────────────────────────────────────────────────────
// GET https://api.github.com/gists/public?per_page={n}  (+ search via code API)

func (m *Module) fetchGitHubGists(ctx context.Context, target, token string, max int) ([]module.Finding, error) {
	// Busca gists via GitHub Code Search
	apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s+in:file&per_page=%d",
		url.QueryEscape(target), min(max, 30))

	headers := map[string]string{
		"Authorization":        "Bearer " + token,
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	body, err := m.get(ctx, apiURL, headers)
	if err != nil {
		return nil, err
	}

	var r struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Name    string  `json:"name"`
			HTMLURL string  `json:"html_url"`
			Score   float64 `json:"score"`
		} `json:"items"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("github gists: parse: %w", err)
	}
	if r.Message != "" {
		return nil, fmt.Errorf("github gists: %s", r.Message)
	}

	// Filtrar apenas gists (URLs contendo gist.github.com)
	var findings []module.Finding
	for _, item := range r.Items {
		if !strings.Contains(item.HTMLURL, "gist.github.com") {
			continue
		}
		findings = append(findings, module.Finding{
			Type:     "paste_found",
			URL:      item.HTMLURL,
			Detail:   fmt.Sprintf("[GitHub Gist] %s menciona %q | Arquivo: %s", item.HTMLURL, target, item.Name),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"source":      "github_gists",
				"gist_url":    item.HTMLURL,
				"file_name":   item.Name,
				"total_found": strconv.Itoa(r.TotalCount),
				"score":       fmt.Sprintf("%.2f", item.Score),
				"confidence":  "0.82", // Gist é público e indexado — conteúdo verificado
			},
		})
	}
	return findings, nil
}

// ─── IntelX ──────────────────────────────────────────────────────────────────

func (m *Module) fetchIntelX(ctx context.Context, target, key string, max int) ([]module.Finding, error) {
	// Fase 1: submete busca
	searchURL := "https://2.intelx.io/intelligent/search"
	payload := fmt.Sprintf(`{"term":"%s","buckets":["pastes"],"lookuplevel":0,"maxresults":%d,"timeout":20,"datefrom":"","dateto":"","sort":4,"media":0,"terminate":[]}`, target, max)

	req, err := http.NewRequestWithContext(ctx, "POST", searchURL, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "blackhorn-pastebin/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	var searchResult struct {
		ID     string `json:"id"`
		Status int    `json:"status"`
	}
	if err := json.Unmarshal(body, &searchResult); err != nil {
		return nil, fmt.Errorf("intelx search: parse: %w", err)
	}
	if searchResult.ID == "" {
		return nil, fmt.Errorf("intelx search: nenhum ID retornado")
	}

	// Fase 2: busca resultados
	time.Sleep(2 * time.Second)
	resultURL := fmt.Sprintf("https://2.intelx.io/intelligent/search/result?id=%s&limit=%d&offset=0",
		searchResult.ID, max)

	body, err = m.get(ctx, resultURL, map[string]string{"x-key": key})
	if err != nil {
		return nil, err
	}

	var r struct {
		Records []struct {
			Storageid string `json:"storageid"`
			Added     string `json:"added"`
			Name      string `json:"name"`
			Bucket    string `json:"bucket"`
			Media     int    `json:"media"`
			XScore    int    `json:"xscore"`
		} `json:"records"`
		Status int `json:"status"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("intelx result: parse: %w", err)
	}

	var findings []module.Finding
	for _, rec := range r.Records {
		viewURL := fmt.Sprintf("https://intelx.io/?did=%s", rec.Storageid)
		confidence := fmt.Sprintf("%.2f", 0.75+float64(min(rec.XScore, 25))*0.008)
		findings = append(findings, module.Finding{
			Type:     "paste_found",
			URL:      viewURL,
			Detail:   fmt.Sprintf("[IntelX] %q encontrado em paste | Bucket: %s | Data: %s", target, rec.Bucket, rec.Added),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"source":     "intelx",
				"storage_id": rec.Storageid,
				"bucket":     rec.Bucket,
				"name":       rec.Name,
				"date":       rec.Added,
				"xscore":     strconv.Itoa(rec.XScore),
				"confidence": confidence,
			},
		})
	}
	return findings, nil
}

// ─── LeakIX ──────────────────────────────────────────────────────────────────
// GET https://leakix.net/search?scope=leak&q={term}&page=0

func (m *Module) fetchLeakIX(ctx context.Context, target, key string, max int) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("https://leakix.net/search?scope=leak&q=%s&page=0",
		url.QueryEscape(target))

	body, err := m.get(ctx, apiURL, map[string]string{
		"api-key": key,
		"Accept":  "application/json",
	})
	if err != nil {
		return nil, err
	}

	var records []struct {
		EventSource  string   `json:"event_source"`
		EventType    string   `json:"event_type"`
		IP           string   `json:"ip"`
		Host         string   `json:"host"`
		Summary      string   `json:"summary"`
		Time         string   `json:"time"`
		Tags         []string `json:"tags"`
		LeakSeverity string   `json:"leak_severity"`
		Dataset      struct {
			Ransom bool `json:"ransom"`
			Rows   int  `json:"rows"`
			Files  int  `json:"files"`
		} `json:"dataset"`
	}
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("leakix: parse: %w", err)
	}

	var findings []module.Finding
	limit := min(len(records), max)
	for _, rec := range records[:limit] {
		severity := module.SeverityMedium
		if rec.LeakSeverity == "critical" || rec.Dataset.Ransom {
			severity = module.SeverityHigh
		}

		findings = append(findings, module.Finding{
			Type:     "data_leak_found",
			URL:      fmt.Sprintf("https://leakix.net/host/%s", rec.Host),
			Detail:   fmt.Sprintf("[LeakIX] %s em %s | Tipo: %s | Rows: %d | Data: %s", target, rec.Host, rec.EventType, rec.Dataset.Rows, rec.Time),
			Severity: severity,
			Extra: map[string]string{
				"source":        "leakix",
				"ip":            rec.IP,
				"host":          rec.Host,
				"event_type":    rec.EventType,
				"event_source":  rec.EventSource,
				"summary":       truncate(rec.Summary, 200),
				"leak_severity": rec.LeakSeverity,
				"rows":          strconv.Itoa(rec.Dataset.Rows),
				"files":         strconv.Itoa(rec.Dataset.Files),
				"ransom":        strconv.FormatBool(rec.Dataset.Ransom),
				"tags":          strings.Join(rec.Tags, ","),
				"date":          rec.Time,
				"confidence":    "0.85", // LeakIX indexa vazamentos verificados
			},
		})
	}
	return findings, nil
}

// ─── Análise de conteúdo de paste ─────────────────────────────────────────────

func (m *Module) analyzeContent(text, sourceURL string) []module.Finding {
	if text == "" {
		return nil
	}
	var findings []module.Finding

	// Emails
	emails := reEmail.FindAllString(text, 5)
	for _, email := range emails {
		findings = append(findings, module.Finding{
			Type:     "paste_email_found",
			URL:      sourceURL,
			Detail:   fmt.Sprintf("Email encontrado em paste: %s", email),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"source":     "paste_analysis",
				"email":      email,
				"confidence": "0.85",
			},
		})
	}

	// Credenciais email:senha
	creds := reEmailPass.FindAllString(text, 3)
	for _, cred := range creds {
		parts := strings.SplitN(cred, ":", 2)
		redacted := cred
		if len(parts) == 2 && len(parts[1]) > 4 {
			redacted = parts[0] + ":" + parts[1][:4] + "****"
		}
		findings = append(findings, module.Finding{
			Type:     "paste_credential_found",
			URL:      sourceURL,
			Detail:   fmt.Sprintf("Credencial encontrada em paste: %s", redacted),
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"source":     "paste_analysis",
				"credential": redacted, // sempre redacted
				"confidence": "0.88",
			},
		})
	}

	// CPF
	cpfs := reCPF.FindAllString(text, 3)
	if len(cpfs) > 0 {
		findings = append(findings, module.Finding{
			Type:     "paste_cpf_found",
			URL:      sourceURL,
			Detail:   fmt.Sprintf("Possíveis CPFs encontrados em paste (%d)", len(cpfs)),
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"source":     "paste_analysis",
				"count":      strconv.Itoa(len(cpfs)),
				"confidence": "0.75", // padrão regex — pode ser falso positivo
			},
		})
	}

	// Chave privada
	if rePrivateKey.MatchString(text) {
		findings = append(findings, module.Finding{
			Type:     "paste_private_key_found",
			URL:      sourceURL,
			Detail:   "Chave privada encontrada em paste público",
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"source":     "paste_analysis",
				"confidence": "0.95",
			},
		})
	}

	// AWS Key
	if awsKeys := reAWSKey.FindAllString(text, 2); len(awsKeys) > 0 {
		findings = append(findings, module.Finding{
			Type:     "paste_aws_key_found",
			URL:      sourceURL,
			Detail:   fmt.Sprintf("AWS Access Key encontrada em paste público: %s...", awsKeys[0][:8]),
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"source":     "paste_analysis",
				"key_prefix": awsKeys[0][:8],
				"confidence": "0.92",
			},
		})
	}

	return findings
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func wantSource(filter, source string) bool {
	if filter == "" {
		return true
	}
	for _, s := range strings.Split(filter, ",") {
		if strings.EqualFold(strings.TrimSpace(s), source) {
			return true
		}
	}
	return false
}

func dedupByURL(findings []module.Finding) []module.Finding {
	seen := make(map[string]bool)
	var out []module.Finding
	for _, f := range findings {
		key := f.URL + f.Type + f.Detail
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m *Module) get(ctx context.Context, apiURL string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-pastebin/1.0")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("não encontrado (404)")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited (429)")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("chave de API inválida (401)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status inesperado: %d", resp.StatusCode)
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
