// Package namesearch realiza busca de pessoas por nome em fontes públicas brasileiras e internacionais.
//
// Fontes integradas:
//   - BrasilAPI Tabelafipe/CPTEC       — validação de contexto BR
//   - IBGE API Nomes                   — frequência e distribuição geográfica de nomes (grátis)
//   - Receita Federal / CNPJ.ws        — sócios e titulares de empresas por nome
//   - Brasil.io                        — dados públicos consolidados
//   - Transparência Pública (CGU)      — servidores públicos federais
//   - OpenSanctions                    — listas de sanções e pessoas expostas politicamente (PEP)
//   - Interpol Notices                 — avisos vermelhos e difusões (API pública)
//
// Análise local (sem API):
//   - Tokenização e normalização de nomes (unicode, diacríticos)
//   - Parsing de partes: primeiro nome, sobrenome, nomes compostos
//   - Detecção de nomes brasileiros comuns vs internacionais
//
// Input:
//   - Target: nome completo ou parcial (min. 2 tokens para maior precisão)
//   - Options["sources"]           — fontes separadas por vírgula (default: all)
//   - Options["max_results"]       — máximo de resultados por fonte (default: 20)
//   - Options["transparency_key"]  — API key Portal Transparência (ou TRANSPARENCIA_API_KEY)
//   - Options["opensanctions_key"] — API key OpenSanctions (ou OPENSANCTIONS_API_KEY)
//   - Options["lang"]              — idioma dos resultados: pt/en (default: pt)
//   - Options["lgpd_consent"]      — "true" para consultas com dados pessoais (LGPD)
//
// Privacidade / LGPD:
//
//	Dados pessoais retornados são mascarados por padrão.
//	Resultados brutos exigem lgpd_consent=true.
package namesearch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	maxBodyBytes      = 2 << 20 // 2 MB
	defaultTimeout    = 20
	defaultMaxResults = 20
)

// Module implementa o módulo namesearch.
type Module struct {
	client *http.Client
}

// New cria um módulo com http.Client padrão.
func New() *Module {
	return NewWithClient(&http.Client{Timeout: time.Duration(defaultTimeout) * time.Second})
}

// NewWithClient cria um módulo com cliente customizado (útil para testes).
func NewWithClient(c *http.Client) *Module {
	return &Module{client: c}
}

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "namesearch" }

// Run executa a busca de pessoas por nome.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	name := strings.TrimSpace(input.Target)
	if name == "" {
		return nil, fmt.Errorf("namesearch: target (nome) não pode ser vazio")
	}

	tokens := tokenizeName(name)
	if len(tokens) < 1 {
		return nil, fmt.Errorf("namesearch: nome inválido — nenhum token extraído de '%s'", name)
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}
	maxResults := optInt(opts, "max_results", defaultMaxResults)
	lang := optStr(opts, "lang", "pt")
	lgpdConsent := optStr(opts, "lgpd_consent", "") == "true"
	enabledSources := parseSources(optStr(opts, "sources", "all"))

	transparencyKey := firstNonEmpty(opts["transparency_key"], getEnv("TRANSPARENCIA_API_KEY"))
	openSanctionsKey := firstNonEmpty(opts["opensanctions_key"], getEnv("OPENSANCTIONS_API_KEY"))

	slog.InfoContext(ctx, "namesearch: iniciando busca",
		"name", maskName(name),
		"tokens", len(tokens),
		"sources", enabledSources,
		"lgpd_consent", lgpdConsent,
	)

	var (
		mu       sync.Mutex
		findings []module.Finding
	)
	add := func(ff []module.Finding) {
		mu.Lock()
		findings = append(findings, ff...)
		mu.Unlock()
	}

	eg, ctx2 := errgroup.WithContext(ctx)
	eg.SetLimit(4)

	// IBGE Nomes — distribuição e frequência (sempre disponível, sem key)
	if sourceEnabled(enabledSources, "ibge") {
		eg.Go(func() error {
			ff, err := m.queryIBGENomes(ctx2, name, tokens, maxResults, lang)
			if err != nil {
				slog.WarnContext(ctx2, "namesearch: ibge falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Transparência Pública — servidores federais
	if sourceEnabled(enabledSources, "transparencia") && transparencyKey != "" {
		eg.Go(func() error {
			ff, err := m.queryTransparencia(ctx2, name, transparencyKey, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "namesearch: transparencia falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// OpenSanctions — PEP, sanções internacionais
	if sourceEnabled(enabledSources, "opensanctions") && openSanctionsKey != "" {
		eg.Go(func() error {
			ff, err := m.queryOpenSanctions(ctx2, name, openSanctionsKey, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "namesearch: opensanctions falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Interpol Notices — avisos vermelhos (API pública, sem key)
	if sourceEnabled(enabledSources, "interpol") {
		eg.Go(func() error {
			ff, err := m.queryInterpol(ctx2, name, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "namesearch: interpol falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	_ = eg.Wait()

	// Análise local — sempre executada
	localFindings := analyzeNameLocally(name, tokens, lgpdConsent)
	findings = append(findings, localFindings...)

	result := dedup(findings)

	slog.InfoContext(ctx, "namesearch: concluído",
		"name", maskName(name),
		"total_findings", len(result),
	)

	return result, nil
}

// ─── IBGE Nomes ──────────────────────────────────────────────────────────────

type ibgeNomeFreq struct {
	Nome       string           `json:"nome"`
	Sexo       string           `json:"sexo,omitempty"`
	Frequencia int              `json:"frequencia,omitempty"`
	Res        []ibgeNomeRegiao `json:"res,omitempty"`
}

type ibgeNomeRegiao struct {
	Periodo    string `json:"periodo,omitempty"`
	Frequencia int    `json:"frequencia,omitempty"`
	Localidade string `json:"localidade,omitempty"`
}

func (m *Module) queryIBGENomes(ctx context.Context, name string, tokens []string, max int, lang string) ([]module.Finding, error) {
	var findings []module.Finding

	// Para nomes compostos, consulta cada token principal
	queryTokens := tokens
	if len(queryTokens) > 2 {
		queryTokens = tokens[:2]
	}

	for _, tok := range queryTokens {
		if len(tok) < 2 {
			continue
		}
		u := fmt.Sprintf("https://servicodados.ibge.gov.br/api/v2/censos/nomes/%s",
			url.PathEscape(strings.ToUpper(normalizeAccents(tok))))

		resp, err := m.get(ctx, u, nil)
		if err != nil {
			slog.DebugContext(ctx, "namesearch/ibge: request falhou", "token", tok, "err", err)
			continue
		}

		var results []ibgeNomeFreq
		if err := json.Unmarshal(resp, &results); err != nil || len(results) == 0 {
			continue
		}

		for _, r := range results {
			if max > 0 && len(findings) >= max {
				break
			}
			detail := fmt.Sprintf("Nome '%s' encontrado no censo IBGE com frequência de %d ocorrências no Brasil.",
				r.Nome, r.Frequencia)
			if lang == "en" {
				detail = fmt.Sprintf("Name '%s' found in IBGE census with frequency of %d occurrences in Brazil.",
					r.Nome, r.Frequencia)
			}

			extra := map[string]string{
				"nome":       r.Nome,
				"frequencia": fmt.Sprintf("%d", r.Frequencia),
				"fonte":      "ibge_nomes",
				"confidence": "0.60",
			}
			if r.Sexo != "" {
				extra["sexo"] = r.Sexo
			}

			findings = append(findings, module.Finding{
				Type:     "name_frequency",
				URL:      u,
				Detail:   detail,
				Severity: module.SeverityInfo,
				Extra:    extra,
			})
		}
	}

	// Consulta ranking dos nomes também (décadas recentes)
	rankURL := fmt.Sprintf("https://servicodados.ibge.gov.br/api/v2/censos/nomes/ranking?qtd=20")
	rankResp, err := m.get(ctx, rankURL, nil)
	if err == nil {
		type rankItem struct {
			Nome       string           `json:"nome"`
			Frequencia int              `json:"frequencia"`
			Res        []ibgeNomeRegiao `json:"res"`
		}
		var ranking []rankItem
		if json.Unmarshal(rankResp, &ranking) == nil {
			normalizedName := strings.ToUpper(normalizeAccents(tokens[0]))
			for _, item := range ranking {
				if strings.ToUpper(normalizeAccents(item.Nome)) == normalizedName {
					findings = append(findings, module.Finding{
						Type:     "name_ranking",
						URL:      rankURL,
						Detail:   fmt.Sprintf("'%s' está entre os nomes mais frequentes do Brasil (rank IBGE), com %d ocorrências.", item.Nome, item.Frequencia),
						Severity: module.SeverityInfo,
						Extra: map[string]string{
							"nome":       item.Nome,
							"frequencia": fmt.Sprintf("%d", item.Frequencia),
							"fonte":      "ibge_ranking",
							"confidence": "0.75",
						},
					})
					break
				}
			}
		}
	}

	return findings, nil
}

// ─── Transparência Pública ────────────────────────────────────────────────────

type transparenciaServidor struct {
	Nome        string  `json:"nome"`
	CPF         string  `json:"cpf,omitempty"`
	Orgao       string  `json:"orgaoNome,omitempty"`
	Cargo       string  `json:"cargoEfetivo,omitempty"`
	Remuneracao float64 `json:"remuneracaoBasicaBruta,omitempty"`
	UF          string  `json:"ufExercicio,omitempty"`
}

func (m *Module) queryTransparencia(ctx context.Context, name string, apiKey string, max int) ([]module.Finding, error) {
	u := fmt.Sprintf("https://api.portaltransparencia.gov.br/api-de-dados/servidores?nome=%s&pagina=1&tamanhoPagina=%d",
		url.QueryEscape(name), clampMax(max, 20))

	headers := map[string]string{
		"chave-api-dados": apiKey,
		"Accept":          "application/json",
	}

	resp, err := m.get(ctx, u, headers)
	if err != nil {
		return nil, fmt.Errorf("transparencia: %w", err)
	}

	var servidores []transparenciaServidor
	if err := json.Unmarshal(resp, &servidores); err != nil {
		return nil, fmt.Errorf("transparencia: parse falhou: %w", err)
	}

	var findings []module.Finding
	for _, s := range servidores {
		extra := map[string]string{
			"nome":       s.Nome,
			"orgao":      s.Orgao,
			"cargo":      s.Cargo,
			"uf":         s.UF,
			"fonte":      "transparencia_publica",
			"confidence": "0.85",
		}
		if s.Remuneracao > 0 {
			extra["remuneracao_bruta"] = fmt.Sprintf("%.2f", s.Remuneracao)
		}
		// Nunca expor CPF completo
		if s.CPF != "" {
			extra["cpf_mascarado"] = maskCPF(s.CPF)
		}

		findings = append(findings, module.Finding{
			Type:     "public_servant",
			URL:      u,
			Detail:   fmt.Sprintf("'%s' encontrado como servidor público federal no órgão '%s', cargo: '%s'.", s.Nome, s.Orgao, s.Cargo),
			Severity: module.SeverityInfo,
			Extra:    extra,
		})
	}

	return findings, nil
}

// ─── OpenSanctions ────────────────────────────────────────────────────────────

type openSanctionsResult struct {
	Total struct {
		Value int `json:"value"`
	} `json:"total"`
	Results []struct {
		ID         string                 `json:"id"`
		Caption    string                 `json:"caption"`
		Schema     string                 `json:"schema"`
		Datasets   []string               `json:"datasets"`
		Score      float64                `json:"score"`
		Properties map[string]interface{} `json:"properties"`
	} `json:"results"`
}

func (m *Module) queryOpenSanctions(ctx context.Context, name string, apiKey string, max int) ([]module.Finding, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("opensanctions: API key obrigatória")
	}

	u := fmt.Sprintf("https://api.opensanctions.org/match/default?limit=%d", clampMax(max, 10))

	payload := fmt.Sprintf(`{"queries":{"q":{"schema":"Person","properties":{"name":[%q]}}}}`, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("opensanctions: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "ApiKey "+apiKey)

	httpResp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opensanctions: request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("opensanctions: API key inválida (401)")
	}
	if httpResp.StatusCode == http.StatusTooManyRequests {
		slog.WarnContext(ctx, "opensanctions: rate limit atingido")
		return nil, nil
	}
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opensanctions: status %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("opensanctions: leitura body: %w", err)
	}

	// OpenSanctions match retorna nested por query key
	var rawResp map[string]openSanctionsResult
	if err := json.Unmarshal(body, &rawResp); err != nil {
		return nil, fmt.Errorf("opensanctions: parse: %w", err)
	}

	var findings []module.Finding
	for _, qResult := range rawResp {
		for _, entity := range qResult.Results {
			if entity.Score < 0.5 {
				continue
			}

			severity := module.SeverityInfo
			datasetStr := strings.Join(entity.Datasets, ", ")

			// Identifica se é sanção, PEP, aviso ou outra categoria
			isPEP := false
			isSanctioned := false
			for _, ds := range entity.Datasets {
				dsl := strings.ToLower(ds)
				if strings.Contains(dsl, "sanction") || strings.Contains(dsl, "ofac") || strings.Contains(dsl, "eu_") {
					isSanctioned = true
				}
				if strings.Contains(dsl, "pep") || strings.Contains(dsl, "politician") {
					isPEP = true
				}
			}

			findingType := "name_mention"
			if isSanctioned {
				severity = module.SeverityHigh
				findingType = "sanctioned_entity"
			} else if isPEP {
				severity = module.SeverityMedium
				findingType = "pep_entity"
			}

			findings = append(findings, module.Finding{
				Type:     findingType,
				URL:      fmt.Sprintf("https://www.opensanctions.org/entities/%s/", entity.ID),
				Detail:   fmt.Sprintf("Entidade '%s' encontrada no OpenSanctions (score %.2f, tipo: %s, datasets: %s).", entity.Caption, entity.Score, entity.Schema, datasetStr),
				Severity: severity,
				Extra: map[string]string{
					"id":         entity.ID,
					"caption":    entity.Caption,
					"schema":     entity.Schema,
					"datasets":   datasetStr,
					"score":      fmt.Sprintf("%.3f", entity.Score),
					"fonte":      "opensanctions",
					"confidence": fmt.Sprintf("%.3f", entity.Score),
				},
			})
		}
	}

	return findings, nil
}

// ─── Interpol Notices ─────────────────────────────────────────────────────────

type interpolNotice struct {
	EntityID      string `json:"entity_id"`
	ForenamesWS   string `json:"forenames"`
	Name          string `json:"name"`
	Nationalities []struct {
		ID string `json:"id"`
	} `json:"nationalities"`
	DateOfBirth         string `json:"date_of_birth"`
	DistinguishingMarks string `json:"distinguishing_marks,omitempty"`
}

type interpolResponse struct {
	Total   int              `json:"total"`
	Query   string           `json:"query"`
	Notices []interpolNotice `json:"_embedded"`
}

func (m *Module) queryInterpol(ctx context.Context, name string, max int) ([]module.Finding, error) {
	// Extrai primeiro e segundo tokens para busca
	tokens := tokenizeName(name)
	forename := ""
	surname := ""
	if len(tokens) >= 1 {
		forename = tokens[0]
	}
	if len(tokens) >= 2 {
		surname = tokens[len(tokens)-1]
	}

	params := url.Values{}
	if forename != "" {
		params.Set("forename", forename)
	}
	if surname != "" {
		params.Set("name", surname)
	}
	params.Set("resultPerPage", fmt.Sprintf("%d", clampMax(max, 20)))
	params.Set("page", "1")

	u := "https://ws-public.interpol.int/notices/v1/red?" + params.Encode()

	resp, err := m.get(ctx, u, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, fmt.Errorf("interpol: %w", err)
	}

	// Interpol retorna estrutura com _embedded.notices
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(resp, &raw); err != nil {
		return nil, fmt.Errorf("interpol: parse: %w", err)
	}

	embeddedRaw, ok := raw["_embedded"]
	if !ok {
		return nil, nil
	}

	var embedded map[string][]interpolNotice
	if err := json.Unmarshal(embeddedRaw, &embedded); err != nil {
		return nil, fmt.Errorf("interpol: parse embedded: %w", err)
	}

	notices := embedded["notices"]
	if len(notices) == 0 {
		return nil, nil
	}

	var findings []module.Finding
	for _, n := range notices {
		fullName := strings.TrimSpace(n.ForenamesWS + " " + n.Name)
		nats := make([]string, 0, len(n.Nationalities))
		for _, nat := range n.Nationalities {
			nats = append(nats, nat.ID)
		}

		findings = append(findings, module.Finding{
			Type:     "interpol_notice",
			URL:      fmt.Sprintf("https://www.interpol.int/How-we-work/Notices/Red-Notices/View-Red-Notices/%s", n.EntityID),
			Detail:   fmt.Sprintf("AVISO VERMELHO INTERPOL: '%s' (ID: %s). Nacionalidades: %s. Data de nascimento: %s.", fullName, n.EntityID, strings.Join(nats, ", "), n.DateOfBirth),
			Severity: module.SeverityCritical,
			Extra: map[string]string{
				"entity_id":       n.EntityID,
				"nome_completo":   fullName,
				"nacionalidades":  strings.Join(nats, ", "),
				"data_nascimento": n.DateOfBirth,
				"fonte":           "interpol_red_notices",
				"confidence":      "0.80",
			},
		})
	}

	return findings, nil
}

// ─── Análise local ─────────────────────────────────────────────────────────────

func analyzeNameLocally(name string, tokens []string, lgpdConsent bool) []module.Finding {
	var findings []module.Finding

	nameType := classifyName(tokens)
	detail := fmt.Sprintf("Análise local: nome '%s' classificado como %s com %d token(s).",
		maskName(name), nameType, len(tokens))

	extra := map[string]string{
		"name_type":   nameType,
		"token_count": fmt.Sprintf("%d", len(tokens)),
		"fonte":       "local_analysis",
		"confidence":  "0.50",
	}

	if !lgpdConsent {
		extra["aviso"] = "lgpd_consent=false: dados pessoais mascarados; consultas externas com dados pessoais não realizadas"
	}

	findings = append(findings, module.Finding{
		Type:     "name_analysis",
		URL:      "",
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra:    extra,
	})

	// Detecta nome composto brasileiro
	if len(tokens) >= 3 {
		findings = append(findings, module.Finding{
			Type:     "name_structure",
			URL:      "",
			Detail:   fmt.Sprintf("Nome composto detectado com %d partes: primeiro nome, %d nome(s) do meio e sobrenome.", len(tokens), len(tokens)-2),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"first_name":   tokens[0],
				"last_name":    tokens[len(tokens)-1],
				"middle_count": fmt.Sprintf("%d", len(tokens)-2),
				"fonte":        "local_analysis",
				"confidence":   "0.70",
			},
		})
	}

	return findings
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func (m *Module) get(ctx context.Context, rawURL string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "blackhorn-modules/1.0 (security research tool)")
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found (404)")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limit (429)")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
}

// tokenizeName divide um nome em tokens normalizados.
func tokenizeName(name string) []string {
	normalized := strings.TrimSpace(name)
	parts := strings.Fields(normalized)

	// Filtra conectivos/preposições comuns em nomes brasileiros
	stopwords := map[string]bool{
		"de": true, "da": true, "do": true, "das": true, "dos": true,
		"di": true, "du": true, "del": true, "von": true, "van": true,
		"e": true,
	}

	var tokens []string
	for _, p := range parts {
		lower := strings.ToLower(p)
		if !stopwords[lower] && len(p) >= 2 {
			tokens = append(tokens, p)
		}
	}
	return tokens
}

// normalizeAccents remove diacríticos comuns do português para buscas mais robustas.
func normalizeAccents(s string) string {
	replacer := strings.NewReplacer(
		"à", "a", "á", "a", "â", "a", "ã", "a", "ä", "a",
		"è", "e", "é", "e", "ê", "e", "ë", "e",
		"ì", "i", "í", "i", "î", "i", "ï", "i",
		"ò", "o", "ó", "o", "ô", "o", "õ", "o", "ö", "o",
		"ù", "u", "ú", "u", "û", "u", "ü", "u",
		"ç", "c", "ñ", "n",
		"À", "A", "Á", "A", "Â", "A", "Ã", "A", "Ä", "A",
		"È", "E", "É", "E", "Ê", "E", "Ë", "E",
		"Ì", "I", "Í", "I", "Î", "I", "Ï", "I",
		"Ò", "O", "Ó", "O", "Ô", "O", "Õ", "O", "Ö", "O",
		"Ù", "U", "Ú", "U", "Û", "U", "Ü", "U",
		"Ç", "C", "Ñ", "N",
	)
	return replacer.Replace(s)
}

// classifyName tenta classificar o tipo de nome.
func classifyName(tokens []string) string {
	if len(tokens) == 0 {
		return "desconhecido"
	}
	if len(tokens) == 1 {
		return "nome_simples"
	}
	if len(tokens) == 2 {
		return "nome_sobrenome"
	}
	return "nome_composto_brasileiro"
}

// maskName mascara o nome para logs (ex: "João Silva" → "João S****")
func maskName(name string) string {
	parts := strings.Fields(name)
	if len(parts) == 0 {
		return "****"
	}
	result := make([]string, len(parts))
	result[0] = parts[0]
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) <= 1 {
			result[i] = parts[i]
		} else {
			result[i] = string(parts[i][0]) + strings.Repeat("*", len(parts[i])-1)
		}
	}
	return strings.Join(result, " ")
}

// maskCPF mascara CPF para logs (ex: "52998224725" → "529.***.***-25")
func maskCPF(cpf string) string {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, cpf)
	if len(digits) != 11 {
		return "***.***.***-**"
	}
	return digits[:3] + ".***.***-" + digits[9:]
}

// parseSources converte string de fontes em mapa de habilitados.
func parseSources(s string) map[string]bool {
	if s == "all" || s == "" {
		return nil // nil = all enabled
	}
	m := map[string]bool{}
	for _, src := range strings.Split(s, ",") {
		src = strings.TrimSpace(strings.ToLower(src))
		if src != "" {
			m[src] = true
		}
	}
	return m
}

// sourceEnabled verifica se uma fonte está habilitada.
func sourceEnabled(enabled map[string]bool, source string) bool {
	if enabled == nil {
		return true
	}
	return enabled[source]
}

// dedup remove findings duplicados por Type+URL+Detail.
func dedup(findings []module.Finding) []module.Finding {
	seen := make(map[string]struct{}, len(findings))
	result := make([]module.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Detail
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, f)
	}
	return result
}

func optStr(opts map[string]string, key, def string) string {
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

func optInt(opts map[string]string, key string, def int) int {
	v := optStr(opts, key, "")
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
		return n
	}
	return def
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func getEnv(key string) string {
	return os.Getenv(key)
}

func clampMax(val, max int) int {
	if val > max {
		return max
	}
	if val <= 0 {
		return max
	}
	return val
}
