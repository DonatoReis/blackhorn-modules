// Package darkweb monitora menções a um alvo em fontes OSINT de dark web e
// serviços de inteligência sobre ameaças que indexam conteúdo onion.
//
// AVISO LEGAL: Este módulo usa APENAS APIs e motores de busca OSINT públicos
// que indexam conteúdo da dark web. Ele NÃO acessa a rede Tor diretamente.
// Nenhuma conexão é feita a endereços .onion. Use apenas para fins legítimos
// de monitoramento defensivo (threat intel, brand protection, investigação
// forense com autorização).
//
// Fontes integradas:
//   - Ahmia         (https://ahmia.fi)       — motor de busca onion (gratuito)
//   - IntelX Paste  (https://intelx.io)      — busca histórica dark web
//   - TorBot/OnionSearch — via Ahmia JSON API
//   - DarkSearch    (https://darksearch.io)   — indexador dark web (gratuito)
//
// Todas as buscas são feitas via clearnet. Nenhum dado sensível é transmitido
// além do termo de busca. Resultados são retornados como findings com URL
// do cache/proxy, nunca do .onion direto.
//
// Input:
//   - Target: termo de busca (email, domínio, CPF, nome, hash, etc.)
//   - Options["sources"]       — fontes separadas por vírgula (default: all)
//   - Options["intelx_key"]   — chave IntelX (ou env INTELX_API_KEY)
//   - Options["max_results"]  — máximo por fonte (default: 10)
//   - Options["timeout"]      — timeout em segundos (default: 30)
package darkweb

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
	moduleName    = "darkweb"
	maxBody       = 1 << 20 // 1 MB
	defaultMaxRes = 10
)

// reOnion detecta links .onion em texto
var reOnion = regexp.MustCompile(`[a-z2-7]{16,56}\.onion`)

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implementa monitoramento OSINT de dark web.
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
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 5,
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

// Run executa a busca OSINT dark web para o target.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" && len(input.URLs) > 0 {
		target = strings.TrimSpace(input.URLs[0])
	}
	if target == "" {
		return nil, fmt.Errorf("darkweb: termo de busca obrigatório em Target")
	}

	opts := input.Options
	sourcesFilter := optStr(opts, "sources", "")
	intelxKey := optStr(opts, "intelx_key", os.Getenv("INTELX_API_KEY"))
	maxResults := optInt(opts, "max_results", defaultMaxRes)

	m.logger.InfoContext(ctx, "darkweb: iniciando",
		"target", target,
		"note", "usando OSINT clearnet — nenhuma conexão Tor direta")

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
	eg.SetLimit(5)

	// Ahmia (gratuito, sem autenticação)
	if wantSource(sourcesFilter, "ahmia") || sourcesFilter == "" {
		eg.Go(func() error {
			fs, err := m.fetchAhmia(egCtx, target, maxResults)
			if err != nil {
				m.logger.WarnContext(egCtx, "darkweb: ahmia error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	// DarkSearch (gratuito, sem autenticação)
	if wantSource(sourcesFilter, "darksearch") || sourcesFilter == "" {
		eg.Go(func() error {
			fs, err := m.fetchDarkSearch(egCtx, target)
			if err != nil {
				m.logger.WarnContext(egCtx, "darkweb: darksearch error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	// IntelX dark web buckets
	if intelxKey != "" && (wantSource(sourcesFilter, "intelx") || sourcesFilter == "") {
		eg.Go(func() error {
			fs, err := m.fetchIntelXDarkWeb(egCtx, target, intelxKey, maxResults)
			if err != nil {
				m.logger.WarnContext(egCtx, "darkweb: intelx error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	_ = eg.Wait()

	results = dedupByURL(results)

	m.logger.InfoContext(ctx, "darkweb: concluído",
		"target", target, "findings", len(results))
	return results, nil
}

// ─── Ahmia ───────────────────────────────────────────────────────────────────
// GET https://ahmia.fi/search/?q={term}  (scraping JSON alternativo)
// Ahmia não tem API JSON oficial, usa scraping do HTML ou o RSS feed

func (m *Module) fetchAhmia(ctx context.Context, target string, max int) ([]module.Finding, error) {
	// Ahmia fornece RSS que é parseável
	rssURL := fmt.Sprintf("https://ahmia.fi/search/?q=%s&format=rss", url.QueryEscape(target))
	body, err := m.get(ctx, rssURL, map[string]string{
		"Accept": "application/rss+xml, application/xml, text/xml",
	})
	if err != nil {
		return nil, err
	}

	// Parse RSS simples sem biblioteca externa — extrai links e títulos
	findings := m.parseAhmiaRSS(string(body), target, max)
	return findings, nil
}

func (m *Module) parseAhmiaRSS(rss, target string, max int) []module.Finding {
	// Extração simples de <item> do RSS com regex
	reItem := regexp.MustCompile(`(?s)<item>(.*?)</item>`)
	reTitle := regexp.MustCompile(`<title>(?:<!\\[CDATA\\[)?(.*?)(?:\\]\\]>)?</title>`)
	reLink := regexp.MustCompile(`<link>(.*?)</link>`)
	reDesc := regexp.MustCompile(`<description>(?:<!\\[CDATA\\[)?(.*?)(?:\\]\\]>)?</description>`)

	items := reItem.FindAllString(rss, max)
	var findings []module.Finding

	for _, item := range items {
		title := ""
		if m := reTitle.FindStringSubmatch(item); len(m) > 1 {
			title = strings.TrimSpace(m[1])
		}
		link := ""
		if m := reLink.FindStringSubmatch(item); len(m) > 1 {
			link = strings.TrimSpace(m[1])
		}
		desc := ""
		if m := reDesc.FindStringSubmatch(item); len(m) > 1 {
			desc = strings.TrimSpace(m[1])
			if len(desc) > 200 {
				desc = desc[:200] + "..."
			}
		}

		if link == "" && title == "" {
			continue
		}

		// Extrai possível endereço onion da URL/texto
		onionAddr := ""
		if onions := reOnion.FindAllString(link+" "+desc, 1); len(onions) > 0 {
			onionAddr = onions[0]
		}

		// URL do cache Ahmia (clearnet, seguro)
		cacheURL := fmt.Sprintf("https://ahmia.fi/search/?q=%s", url.QueryEscape(target))
		if link != "" {
			cacheURL = link
		}

		severity := module.SeverityMedium
		confidence := "0.70" // Ahmia indexa, mas relevância pode variar

		findings = append(findings, module.Finding{
			Type:     "darkweb_mention",
			URL:      cacheURL,
			Detail:   fmt.Sprintf("[Ahmia] %q encontrado | Título: %s | Onion: %s", target, title, onionAddr),
			Severity: severity,
			Extra: map[string]string{
				"source":      "ahmia",
				"title":       title,
				"onion_addr":  onionAddr,
				"description": desc,
				"confidence":  confidence,
			},
		})
	}
	return findings
}

// ─── DarkSearch ──────────────────────────────────────────────────────────────
// GET https://darksearch.io/api/search?query={term}&page=1

func (m *Module) fetchDarkSearch(ctx context.Context, target string) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("https://darksearch.io/api/search?query=%s&page=1",
		url.QueryEscape(target))

	body, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}

	var r struct {
		Total       int `json:"total"`
		PerPage     int `json:"per_page"`
		CurrentPage int `json:"current_page"`
		LastPage    int `json:"last_page"`
		Data        []struct {
			Title       string `json:"title"`
			Link        string `json:"link"`
			Description string `json:"description"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("darksearch: parse: %w", err)
	}

	var findings []module.Finding
	for _, item := range r.Data {
		onionAddr := ""
		combined := item.Link + " " + item.Description
		if onions := reOnion.FindAllString(combined, 1); len(onions) > 0 {
			onionAddr = onions[0]
		}

		desc := strings.TrimSpace(item.Description)
		if len(desc) > 200 {
			desc = desc[:200] + "..."
		}

		findings = append(findings, module.Finding{
			Type:     "darkweb_mention",
			URL:      fmt.Sprintf("https://darksearch.io/search?query=%s", url.QueryEscape(target)),
			Detail:   fmt.Sprintf("[DarkSearch] %q encontrado | Título: %s | Onion: %s", target, item.Title, onionAddr),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"source":      "darksearch",
				"title":       item.Title,
				"onion_addr":  onionAddr,
				"description": desc,
				"total_found": strconv.Itoa(r.Total),
				"confidence":  "0.68", // DarkSearch indexa mas tem cobertura menor que Ahmia
			},
		})
	}
	return findings, nil
}

// ─── IntelX Dark Web ─────────────────────────────────────────────────────────

func (m *Module) fetchIntelXDarkWeb(ctx context.Context, target, key string, max int) ([]module.Finding, error) {
	// IntelX busca em buckets darknet/tor
	searchURL := "https://2.intelx.io/intelligent/search"
	payload := fmt.Sprintf(`{"term":"%s","buckets":["darknet","tor"],"lookuplevel":0,"maxresults":%d,"timeout":20,"datefrom":"","dateto":"","sort":4,"media":0,"terminate":[]}`,
		target, max)

	req, err := http.NewRequestWithContext(ctx, "POST", searchURL, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "blackhorn-darkweb/1.0")

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
		return nil, fmt.Errorf("intelx darkweb: parse search: %w", err)
	}
	if searchResult.ID == "" {
		return nil, fmt.Errorf("intelx darkweb: nenhum ID retornado")
	}

	time.Sleep(3 * time.Second)

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
			XScore    int    `json:"xscore"`
		} `json:"records"`
		Status int `json:"status"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("intelx darkweb result: parse: %w", err)
	}

	var findings []module.Finding
	for _, rec := range r.Records {
		viewURL := fmt.Sprintf("https://intelx.io/?did=%s", rec.Storageid)
		confidence := fmt.Sprintf("%.2f", 0.78+float64(min(rec.XScore, 22))*0.01)

		findings = append(findings, module.Finding{
			Type:     "darkweb_mention",
			URL:      viewURL,
			Detail:   fmt.Sprintf("[IntelX DarkWeb] %q em %s | Bucket: %s | Data: %s", target, rec.Name, rec.Bucket, rec.Added),
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"source":     "intelx_darkweb",
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
	req.Header.Set("User-Agent", "blackhorn-darkweb/1.0")
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
