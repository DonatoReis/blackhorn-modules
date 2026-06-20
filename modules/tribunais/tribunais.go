// Package tribunais consulta processos judiciais em bases públicas brasileiras.
//
// Fontes integradas:
//   - DataJud (CNJ) /api/v2/pesquisa/documentos — mandatório (API pública)
//   - Portal CNJ BNMP (Banco Nacional de Mandados de Prisão) — grátis
//   - JusBrasil API Search — enriquecimento (API key opcional)
//   - Escavador API — processos por CPF/CNPJ/nome (API key obrigatória)
//
// Tipos de consulta:
//   - Por CPF (11 dígitos) — processos onde pessoa é parte
//   - Por CNPJ (14 dígitos) — processos onde empresa é parte
//   - Por número de processo (CNJ) — detalhes de processo específico
//   - Por nome — busca textual nos tribunais
//
// Input:
//   - Target: CPF, CNPJ, número CNJ de processo ou nome
//   - Options["datajud_key"]    — API key DataJud (x-api-key)
//   - Options["escavador_key"]  — API key Escavador (Bearer)
//   - Options["jusbrasil_key"]  — API key JusBrasil (Bearer)
//   - Options["tribunal"]       — filtro de tribunal (ex: "TJSP", "TRF1")
//   - Options["max_results"]    — máximo de resultados (default: 20)
//   - Options["lgpd_consent"]   — "true" para busca por CPF de pessoa física
//
// Privacidade / LGPD:
//
//	Busca por CPF de pessoa física requer lgpd_consent=true.
//	Nomes de partes são parcialmente mascarados nos findings por padrão.
package tribunais

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	maxBodyBytes   = 2 << 20
	defaultTimeout = 25
	defaultMax     = 20
)

var (
	reCNPJDigits  = regexp.MustCompile(`^\d{14}$`)
	reCPFDigits   = regexp.MustCompile(`^\d{11}$`)
	reProcessoCNJ = regexp.MustCompile(`^\d{7}-\d{2}\.\d{4}\.\d\.\d{2}\.\d{4}$`)
	reDigitsOnly  = regexp.MustCompile(`\D`)
)

// TargetType classifica o tipo de target da consulta.
type TargetType string

const (
	TargetCNPJ     TargetType = "cnpj"
	TargetCPF      TargetType = "cpf"
	TargetProcesso TargetType = "processo"
	TargetNome     TargetType = "nome"
)

// Module implementa o módulo tribunais.
type Module struct {
	client *http.Client
}

// New cria um módulo com cliente padrão.
func New() *Module {
	return NewWithClient(&http.Client{Timeout: time.Duration(defaultTimeout) * time.Second})
}

// NewWithClient cria um módulo com cliente customizado.
func NewWithClient(c *http.Client) *Module {
	return &Module{client: c}
}

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "tribunais" }

// Run executa a consulta de processos judiciais.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("tribunais: target não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	lgpdConsent := optStr(opts, "lgpd_consent", "") == "true"
	maxResults := optInt(opts, "max_results", defaultMax)
	datajudKey := firstNonEmpty(opts["datajud_key"], os.Getenv("DATAJUD_API_KEY"))
	escavadorKey := firstNonEmpty(opts["escavador_key"], os.Getenv("ESCAVADOR_API_KEY"))
	jusbrasil := firstNonEmpty(opts["jusbrasil_key"], os.Getenv("JUSBRASIL_API_KEY"))
	tribunal := optStr(opts, "tribunal", "")

	targetType, cleanTarget := detectTargetType(target)

	if targetType == TargetCPF && !lgpdConsent {
		return nil, fmt.Errorf("tribunais: busca por CPF requer lgpd_consent=true")
	}

	slog.InfoContext(ctx, "tribunais: iniciando consulta",
		"target_type", string(targetType),
		"has_datajud_key", datajudKey != "",
		"has_escavador_key", escavadorKey != "",
		"has_lgpd_consent", lgpdConsent,
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

	// DataJud (CNJ) — mandatório quando key disponível
	if datajudKey != "" {
		eg.Go(func() error {
			ff, err := m.queryDataJud(ctx2, target, cleanTarget, targetType, datajudKey, tribunal, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "tribunais: datajud falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// BNMP (Banco Nacional de Mandados de Prisão) — grátis, por nome ou CPF
	if targetType == TargetCPF || targetType == TargetNome {
		eg.Go(func() error {
			ff, err := m.queryBNMP(ctx2, target, cleanTarget, targetType, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "tribunais: bnmp falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Escavador — por CPF, CNPJ ou nome
	if escavadorKey != "" {
		eg.Go(func() error {
			ff, err := m.queryEscavador(ctx2, target, cleanTarget, targetType, escavadorKey, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "tribunais: escavador falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// JusBrasil — busca textual por nome ou número de processo
	if jusbrasil != "" && (targetType == TargetNome || targetType == TargetProcesso) {
		eg.Go(func() error {
			ff, err := m.queryJusBrasil(ctx2, target, jusbrasil, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "tribunais: jusbrasil falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	_ = eg.Wait()

	result := dedup(findings)

	slog.InfoContext(ctx, "tribunais: concluído",
		"total_findings", len(result),
	)

	return result, nil
}

// ─── DataJud (CNJ) ────────────────────────────────────────────────────────────

// datajudQuery é o payload de busca da API DataJud.
type datajudQuery struct {
	Query struct {
		BoolQuery struct {
			Must []interface{} `json:"must"`
		} `json:"bool"`
	} `json:"query"`
	Size int `json:"size"`
	From int `json:"from"`
}

func (m *Module) queryDataJud(ctx context.Context, rawTarget, cleanTarget string, targetType TargetType, apiKey, tribunal string, max int) ([]module.Finding, error) {
	// Monta filtro de busca dependendo do tipo
	var must []interface{}

	switch targetType {
	case TargetCNPJ:
		must = append(must, map[string]interface{}{
			"match": map[string]interface{}{
				"partes.documento": cleanTarget,
			},
		})
	case TargetCPF:
		must = append(must, map[string]interface{}{
			"match": map[string]interface{}{
				"partes.documento": cleanTarget,
			},
		})
	case TargetProcesso:
		must = append(must, map[string]interface{}{
			"match": map[string]interface{}{
				"numeroProcesso": cleanTarget,
			},
		})
	default:
		must = append(must, map[string]interface{}{
			"multi_match": map[string]interface{}{
				"query":  rawTarget,
				"fields": []string{"partes.nome", "assuntos.nome"},
			},
		})
	}

	if tribunal != "" {
		must = append(must, map[string]interface{}{
			"match": map[string]interface{}{
				"tribunal": strings.ToUpper(tribunal),
			},
		})
	}

	payload := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		},
		"size": clampSize(max, 100),
		"from": 0,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("datajud: marshal: %w", err)
	}

	// DataJud permite busca em todos os tribunais ou em tribunal específico
	endpoint := "https://api-publica.datajud.cnj.jus.br/api_publica_tjsp/_search"
	if tribunal != "" {
		endpoint = fmt.Sprintf("https://api-publica.datajud.cnj.jus.br/api_publica_%s/_search",
			strings.ToLower(tribunal))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("datajud: request: %w", err)
	}
	req.Header.Set("Authorization", "ApiKey "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("datajud: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("datajud: API key inválida")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("datajud: status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("datajud: read: %w", err)
	}

	var result struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source struct {
					NumeroProcesso  string `json:"numeroProcesso"`
					Tribunal        string `json:"tribunal"`
					DataAjuizamento string `json:"dataAjuizamento"`
					Classe          struct {
						Nome string `json:"nome"`
					} `json:"classe"`
					Assuntos []struct {
						Nome string `json:"nome"`
					} `json:"assuntos"`
					Partes []struct {
						Nome      string `json:"nome"`
						Tipo      string `json:"tipo"`
						Documento string `json:"documento"`
					} `json:"partes"`
					GrauRecurso string `json:"grauRecurso"`
					Orgao       struct {
						Nome string `json:"nome"`
					} `json:"orgaoJulgador"`
				} `json:"_source"`
				Score float64 `json:"_score"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("datajud: parse: %w", err)
	}

	var findings []module.Finding

	total := result.Hits.Total.Value
	if total > 0 {
		findings = append(findings, module.Finding{
			Type:     "judicial_summary",
			URL:      endpoint,
			Detail:   fmt.Sprintf("Encontrados %d processo(s) judicial(ais) via DataJud (CNJ).", total),
			Severity: severityByCount(total),
			Extra: map[string]string{
				"total_processos": fmt.Sprintf("%d", total),
				"tribunal":        tribunal,
				"fonte":           "datajud",
				"confidence":      "0.92",
			},
		})
	}

	for _, hit := range result.Hits.Hits {
		src := hit.Source

		assuntos := make([]string, 0, len(src.Assuntos))
		for _, a := range src.Assuntos {
			assuntos = append(assuntos, a.Nome)
		}
		assuntosStr := strings.Join(assuntos, ", ")

		parteNomes := make([]string, 0)
		for _, p := range src.Partes {
			parteNomes = append(parteNomes, fmt.Sprintf("%s (%s)", maskName(p.Nome), p.Tipo))
		}

		detail := fmt.Sprintf("Processo %s — Tribunal: %s. Classe: %s. Assunto(s): %s. Ajuizado em: %s.",
			src.NumeroProcesso, src.Tribunal, src.Classe.Nome, assuntosStr, src.DataAjuizamento)

		findings = append(findings, module.Finding{
			Type:     "judicial_process",
			URL:      fmt.Sprintf("https://processos.cnj.jus.br/details/%s", url.PathEscape(src.NumeroProcesso)),
			Detail:   detail,
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"numero_processo":  src.NumeroProcesso,
				"tribunal":         src.Tribunal,
				"classe":           src.Classe.Nome,
				"assuntos":         assuntosStr,
				"data_ajuizamento": src.DataAjuizamento,
				"partes":           strings.Join(parteNomes, " | "),
				"orgao":            src.Orgao.Nome,
				"grau":             src.GrauRecurso,
				"fonte":            "datajud",
				"confidence":       "0.92",
			},
		})
	}

	return findings, nil
}

// ─── BNMP (Banco Nacional de Mandados de Prisão) ──────────────────────────────

func (m *Module) queryBNMP(ctx context.Context, rawTarget, cleanTarget string, targetType TargetType, max int) ([]module.Finding, error) {
	var searchURL string
	switch targetType {
	case TargetCPF:
		searchURL = fmt.Sprintf("https://portalbnmp.cnj.jus.br/bnmpportal/api/certidao/preso/pesquisar?cpf=%s&size=%d",
			url.QueryEscape(cleanTarget), clampSize(max, 50))
	default:
		searchURL = fmt.Sprintf("https://portalbnmp.cnj.jus.br/bnmpportal/api/certidao/preso/pesquisar?nomePreso=%s&size=%d",
			url.QueryEscape(rawTarget), clampSize(max, 50))
	}

	respBody, err := m.get(ctx, searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("bnmp: %w", err)
	}

	var result struct {
		Content []struct {
			NomePreso       string `json:"nomePreso"`
			NumeroMandado   string `json:"numeroMandado"`
			TipoMandado     string `json:"tipoMandado"`
			DataExpedicao   string `json:"dataExpedicao"`
			Tribunal        string `json:"tribunalExpedidor"`
			SituacaoMandado string `json:"situacaoMandado"`
			Orgao           string `json:"orgaoExpedidor"`
		} `json:"content"`
		TotalElements int `json:"totalElements"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("bnmp: parse: %w", err)
	}

	if result.TotalElements == 0 {
		return nil, nil
	}

	var findings []module.Finding

	findings = append(findings, module.Finding{
		Type:     "warrant_summary",
		URL:      searchURL,
		Detail:   fmt.Sprintf("Encontrado(s) %d mandado(s) de prisão no BNMP (CNJ).", result.TotalElements),
		Severity: module.SeverityCritical,
		Extra: map[string]string{
			"total_mandados": fmt.Sprintf("%d", result.TotalElements),
			"fonte":          "bnmp",
			"confidence":     "0.95",
		},
	})

	for _, w := range result.Content {
		findings = append(findings, module.Finding{
			Type: "arrest_warrant",
			URL:  fmt.Sprintf("https://portalbnmp.cnj.jus.br/#/mandado/%s", url.PathEscape(w.NumeroMandado)),
			Detail: fmt.Sprintf("Mandado de prisão para '%s' — Tipo: %s. Expedido em %s por %s (%s). Situação: %s.",
				maskName(w.NomePreso), w.TipoMandado, w.DataExpedicao, w.Tribunal, w.Orgao, w.SituacaoMandado),
			Severity: module.SeverityCritical,
			Extra: map[string]string{
				"nome_mascarado": maskName(w.NomePreso),
				"numero_mandado": w.NumeroMandado,
				"tipo_mandado":   w.TipoMandado,
				"data_expedicao": w.DataExpedicao,
				"tribunal":       w.Tribunal,
				"situacao":       w.SituacaoMandado,
				"fonte":          "bnmp",
				"confidence":     "0.95",
			},
		})
	}

	return findings, nil
}

// ─── Escavador ───────────────────────────────────────────────────────────────

func (m *Module) queryEscavador(ctx context.Context, rawTarget, cleanTarget string, targetType TargetType, apiKey string, max int) ([]module.Finding, error) {
	var searchURL string
	switch targetType {
	case TargetCNPJ:
		searchURL = fmt.Sprintf("https://api.escavador.com/api/v2/processos/busca?cnpj=%s&por_pagina=%d",
			url.QueryEscape(cleanTarget), clampSize(max, 100))
	case TargetCPF:
		searchURL = fmt.Sprintf("https://api.escavador.com/api/v2/processos/busca?cpf=%s&por_pagina=%d",
			url.QueryEscape(cleanTarget), clampSize(max, 100))
	default:
		searchURL = fmt.Sprintf("https://api.escavador.com/api/v2/processos/busca?envolvido=%s&por_pagina=%d",
			url.QueryEscape(rawTarget), clampSize(max, 100))
	}

	respBody, err := m.get(ctx, searchURL, map[string]string{
		"Authorization": "Bearer " + apiKey,
	})
	if err != nil {
		return nil, fmt.Errorf("escavador: %w", err)
	}

	var result struct {
		Items []struct {
			NumeroProcesso string `json:"numero_unico"`
			Tribunal       string `json:"tribunal_sigla"`
			Assunto        string `json:"assunto_principal_normalizado"`
			DataUltimoMov  string `json:"data_ultima_movimentacao"`
			Envolvidos     []struct {
				Nome string `json:"nome"`
				Tipo string `json:"tipo_parte"`
			} `json:"envolvidos"`
			TipoAcao string `json:"tipo_acao"`
		} `json:"items"`
		Total int `json:"total"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("escavador: parse: %w", err)
	}

	if result.Total == 0 {
		return nil, nil
	}

	var findings []module.Finding

	findings = append(findings, module.Finding{
		Type:     "judicial_summary",
		URL:      searchURL,
		Detail:   fmt.Sprintf("Escavador: %d processo(s) encontrado(s).", result.Total),
		Severity: severityByCount(result.Total),
		Extra: map[string]string{
			"total_processos": fmt.Sprintf("%d", result.Total),
			"fonte":           "escavador",
			"confidence":      "0.88",
		},
	})

	for _, item := range result.Items {
		envolvidos := make([]string, 0, len(item.Envolvidos))
		for _, e := range item.Envolvidos {
			envolvidos = append(envolvidos, fmt.Sprintf("%s (%s)", maskName(e.Nome), e.Tipo))
		}

		findings = append(findings, module.Finding{
			Type: "judicial_process",
			URL:  fmt.Sprintf("https://www.escavador.com/processos/%s", url.PathEscape(item.NumeroProcesso)),
			Detail: fmt.Sprintf("Processo %s — Tribunal: %s. Assunto: %s. Última movimentação: %s.",
				item.NumeroProcesso, item.Tribunal, item.Assunto, item.DataUltimoMov),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"numero_processo": item.NumeroProcesso,
				"tribunal":        item.Tribunal,
				"assunto":         item.Assunto,
				"data_ultima_mov": item.DataUltimoMov,
				"tipo_acao":       item.TipoAcao,
				"envolvidos":      strings.Join(envolvidos, " | "),
				"fonte":           "escavador",
				"confidence":      "0.88",
			},
		})
	}

	return findings, nil
}

// ─── JusBrasil ───────────────────────────────────────────────────────────────

func (m *Module) queryJusBrasil(ctx context.Context, query, apiKey string, max int) ([]module.Finding, error) {
	u := fmt.Sprintf("https://api.jusbrasil.com.br/processos/v1/search?query=%s&limit=%d",
		url.QueryEscape(query), clampSize(max, 50))

	respBody, err := m.get(ctx, u, map[string]string{
		"Authorization": "Bearer " + apiKey,
	})
	if err != nil {
		return nil, fmt.Errorf("jusbrasil: %w", err)
	}

	var result struct {
		Data []struct {
			ID         string `json:"id"`
			Titulo     string `json:"titulo"`
			Tribunal   string `json:"tribunal"`
			Resumo     string `json:"resumo"`
			DataInicio string `json:"data_inicio"`
			URL        string `json:"url"`
		} `json:"data"`
		Total int `json:"total"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("jusbrasil: parse: %w", err)
	}

	if result.Total == 0 {
		return nil, nil
	}

	var findings []module.Finding

	for _, item := range result.Data {
		findings = append(findings, module.Finding{
			Type: "judicial_process",
			URL:  item.URL,
			Detail: fmt.Sprintf("JusBrasil: '%s' — Tribunal: %s. Iniciado em: %s. Resumo: %s.",
				item.Titulo, item.Tribunal, item.DataInicio, truncate(item.Resumo, 200)),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"id":          item.ID,
				"tribunal":    item.Tribunal,
				"data_inicio": item.DataInicio,
				"fonte":       "jusbrasil",
				"confidence":  "0.82",
			},
		})
	}

	return findings, nil
}

// ─── detectTargetType ─────────────────────────────────────────────────────────

func detectTargetType(target string) (TargetType, string) {
	// Verifica número de processo CNJ antes de tirar caracteres não-dígitos
	// Formato: 0000000-00.0000.0.00.0000
	cleanForProcess := strings.TrimSpace(target)
	if reProcessoCNJ.MatchString(cleanForProcess) {
		return TargetProcesso, cleanForProcess
	}

	digits := reDigitsOnly.ReplaceAllString(target, "")
	if len(digits) == 14 && reCNPJDigits.MatchString(digits) {
		return TargetCNPJ, digits
	}
	if len(digits) == 11 && reCPFDigits.MatchString(digits) {
		return TargetCPF, digits
	}
	return TargetNome, target
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, fmt.Errorf("not found (404)")
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("não autorizado (401)")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("rate limit (429)")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
}

func maskName(name string) string {
	if name == "" {
		return ""
	}
	parts := strings.Fields(name)
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return name
	}
	// Mantém primeiro nome; mascara os outros
	masked := make([]string, len(parts))
	masked[0] = parts[0]
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) <= 2 {
			masked[i] = parts[i]
		} else {
			masked[i] = parts[i][:1] + strings.Repeat("*", len(parts[i])-1)
		}
	}
	return strings.Join(masked, " ")
}

func severityByCount(count int) module.Severity {
	switch {
	case count >= 10:
		return module.SeverityHigh
	case count >= 3:
		return module.SeverityMedium
	default:
		return module.SeverityLow
	}
}

func clampSize(val, max int) int {
	if val <= 0 {
		return defaultMax
	}
	if val > max {
		return max
	}
	return val
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
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
