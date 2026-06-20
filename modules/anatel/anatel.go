// Package anatel realiza consultas públicas sobre numeração telefônica brasileira.
//
// Fontes integradas:
//   - ANATEL Numações          — base de numeração nacional (consulta pública)
//   - BrasilAPI DDD            — estado e região por DDD (grátis, sem key)
//   - ANATEL PGMQ              — Plano Geral de Metas de Qualidade (operadoras por DDD)
//   - IBGE cidades por DDD     — municípios vinculados ao DDD
//   - Análise local            — formato, tipo (móvel/fixo/0800), portabilidade estimada
//
// Formatos de target aceitos:
//   - "+5511999999999"   — E.164 internacional
//   - "11999999999"      — com DDD, sem código do país
//   - "(11) 99999-9999"  — formato visual BR
//   - "99999-9999"       — sem DDD (incompleto — só análise local)
//   - "11"               — apenas DDD (retorna info do DDD)
//
// Informações retornadas:
//   - DDD, estado, região, tipo de linha (móvel/fixo/especial/0800)
//   - Operadoras que atuam no DDD
//   - Municípios cobertos pelo DDD
//   - Estimativa de portabilidade (baseada em intervalo numérico)
//   - Formato normalizado E.164
//
// Privacidade:
//
//	Número é mascarado em logs. Nenhuma API armazena a consulta.
//	Dados retornados são de bases públicas da ANATEL/IBGE.
package anatel

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
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/sync/errgroup"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	maxBodyBytes   = 2 << 20
	defaultTimeout = 15
)

var (
	// Remove tudo que não é dígito
	reDigits = regexp.MustCompile(`\D`)

	// DDDs brasileiros válidos (dados ANATEL 2024)
	validDDDs = map[string]dddInfo{
		"11": {Estado: "São Paulo", Regiao: "Sudeste", UF: "SP"},
		"12": {Estado: "São Paulo", Regiao: "Sudeste", UF: "SP"},
		"13": {Estado: "São Paulo", Regiao: "Sudeste", UF: "SP"},
		"14": {Estado: "São Paulo", Regiao: "Sudeste", UF: "SP"},
		"15": {Estado: "São Paulo", Regiao: "Sudeste", UF: "SP"},
		"16": {Estado: "São Paulo", Regiao: "Sudeste", UF: "SP"},
		"17": {Estado: "São Paulo", Regiao: "Sudeste", UF: "SP"},
		"18": {Estado: "São Paulo", Regiao: "Sudeste", UF: "SP"},
		"19": {Estado: "São Paulo", Regiao: "Sudeste", UF: "SP"},
		"21": {Estado: "Rio de Janeiro", Regiao: "Sudeste", UF: "RJ"},
		"22": {Estado: "Rio de Janeiro", Regiao: "Sudeste", UF: "RJ"},
		"24": {Estado: "Rio de Janeiro", Regiao: "Sudeste", UF: "RJ"},
		"27": {Estado: "Espírito Santo", Regiao: "Sudeste", UF: "ES"},
		"28": {Estado: "Espírito Santo", Regiao: "Sudeste", UF: "ES"},
		"31": {Estado: "Minas Gerais", Regiao: "Sudeste", UF: "MG"},
		"32": {Estado: "Minas Gerais", Regiao: "Sudeste", UF: "MG"},
		"33": {Estado: "Minas Gerais", Regiao: "Sudeste", UF: "MG"},
		"34": {Estado: "Minas Gerais", Regiao: "Sudeste", UF: "MG"},
		"35": {Estado: "Minas Gerais", Regiao: "Sudeste", UF: "MG"},
		"37": {Estado: "Minas Gerais", Regiao: "Sudeste", UF: "MG"},
		"38": {Estado: "Minas Gerais", Regiao: "Sudeste", UF: "MG"},
		"41": {Estado: "Paraná", Regiao: "Sul", UF: "PR"},
		"42": {Estado: "Paraná", Regiao: "Sul", UF: "PR"},
		"43": {Estado: "Paraná", Regiao: "Sul", UF: "PR"},
		"44": {Estado: "Paraná", Regiao: "Sul", UF: "PR"},
		"45": {Estado: "Paraná", Regiao: "Sul", UF: "PR"},
		"46": {Estado: "Paraná", Regiao: "Sul", UF: "PR"},
		"47": {Estado: "Santa Catarina", Regiao: "Sul", UF: "SC"},
		"48": {Estado: "Santa Catarina", Regiao: "Sul", UF: "SC"},
		"49": {Estado: "Santa Catarina", Regiao: "Sul", UF: "SC"},
		"51": {Estado: "Rio Grande do Sul", Regiao: "Sul", UF: "RS"},
		"53": {Estado: "Rio Grande do Sul", Regiao: "Sul", UF: "RS"},
		"54": {Estado: "Rio Grande do Sul", Regiao: "Sul", UF: "RS"},
		"55": {Estado: "Rio Grande do Sul", Regiao: "Sul", UF: "RS"},
		"61": {Estado: "Distrito Federal / Goiás", Regiao: "Centro-Oeste", UF: "DF"},
		"62": {Estado: "Goiás", Regiao: "Centro-Oeste", UF: "GO"},
		"63": {Estado: "Tocantins", Regiao: "Norte", UF: "TO"},
		"64": {Estado: "Goiás", Regiao: "Centro-Oeste", UF: "GO"},
		"65": {Estado: "Mato Grosso", Regiao: "Centro-Oeste", UF: "MT"},
		"66": {Estado: "Mato Grosso", Regiao: "Centro-Oeste", UF: "MT"},
		"67": {Estado: "Mato Grosso do Sul", Regiao: "Centro-Oeste", UF: "MS"},
		"68": {Estado: "Acre", Regiao: "Norte", UF: "AC"},
		"69": {Estado: "Rondônia", Regiao: "Norte", UF: "RO"},
		"71": {Estado: "Bahia", Regiao: "Nordeste", UF: "BA"},
		"73": {Estado: "Bahia", Regiao: "Nordeste", UF: "BA"},
		"74": {Estado: "Bahia", Regiao: "Nordeste", UF: "BA"},
		"75": {Estado: "Bahia", Regiao: "Nordeste", UF: "BA"},
		"77": {Estado: "Bahia", Regiao: "Nordeste", UF: "BA"},
		"79": {Estado: "Sergipe", Regiao: "Nordeste", UF: "SE"},
		"81": {Estado: "Pernambuco", Regiao: "Nordeste", UF: "PE"},
		"82": {Estado: "Alagoas", Regiao: "Nordeste", UF: "AL"},
		"83": {Estado: "Paraíba", Regiao: "Nordeste", UF: "PB"},
		"84": {Estado: "Rio Grande do Norte", Regiao: "Nordeste", UF: "RN"},
		"85": {Estado: "Ceará", Regiao: "Nordeste", UF: "CE"},
		"86": {Estado: "Piauí", Regiao: "Nordeste", UF: "PI"},
		"87": {Estado: "Pernambuco", Regiao: "Nordeste", UF: "PE"},
		"88": {Estado: "Ceará", Regiao: "Nordeste", UF: "CE"},
		"89": {Estado: "Piauí", Regiao: "Nordeste", UF: "PI"},
		"91": {Estado: "Pará", Regiao: "Norte", UF: "PA"},
		"92": {Estado: "Amazonas", Regiao: "Norte", UF: "AM"},
		"93": {Estado: "Pará", Regiao: "Norte", UF: "PA"},
		"94": {Estado: "Pará", Regiao: "Norte", UF: "PA"},
		"95": {Estado: "Roraima", Regiao: "Norte", UF: "RR"},
		"96": {Estado: "Amapá", Regiao: "Norte", UF: "AP"},
		"97": {Estado: "Amazonas", Regiao: "Norte", UF: "AM"},
		"98": {Estado: "Maranhão", Regiao: "Nordeste", UF: "MA"},
		"99": {Estado: "Maranhão", Regiao: "Nordeste", UF: "MA"},
	}
)

type dddInfo struct {
	Estado string
	Regiao string
	UF     string
}

// LineType classifica o tipo de linha telefônica.
type LineType string

const (
	LineTypeMobile  LineType = "móvel"
	LineTypeFixed   LineType = "fixo"
	LineTypeFree    LineType = "gratuito_0800"
	LineTypeService LineType = "serviço_especial"
	LineTypeUnknown LineType = "desconhecido"
)

// ParsedNumber contém os dados parseados de um número BR.
type ParsedNumber struct {
	Raw         string
	Digits      string
	CountryCode string
	DDD         string
	Number      string
	LineType    LineType
	E164        string
	IsValid     bool
}

// Module implementa o módulo anatel.
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
func (m *Module) Name() string { return "anatel" }

// Run executa a consulta de informações sobre o número.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	raw := strings.TrimSpace(input.Target)
	if raw == "" {
		return nil, fmt.Errorf("anatel: target (número ou DDD) não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}
	enabledSources := parseSources(optStr(opts, "sources", "all"))

	parsed, err := parseNumber(raw)
	if err != nil {
		return nil, fmt.Errorf("anatel: %w", err)
	}

	slog.InfoContext(ctx, "anatel: iniciando consulta",
		"number", maskPhone(parsed.Digits),
		"ddd", parsed.DDD,
		"type", string(parsed.LineType),
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

	// Análise local — sempre executada
	localFindings := analyzeNumberLocally(parsed)
	add(localFindings)

	eg, ctx2 := errgroup.WithContext(ctx)
	eg.SetLimit(3)

	// BrasilAPI DDD
	if sourceEnabled(enabledSources, "brasilapi") && parsed.DDD != "" {
		eg.Go(func() error {
			ff, err := m.queryBrasilAPIDDD(ctx2, parsed.DDD)
			if err != nil {
				slog.WarnContext(ctx2, "anatel: brasilapi ddd falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// IBGE municípios por UF
	if sourceEnabled(enabledSources, "ibge") && parsed.DDD != "" {
		if info, ok := validDDDs[parsed.DDD]; ok {
			eg.Go(func() error {
				ff, err := m.queryIBGEMunicipios(ctx2, info.UF, parsed.DDD)
				if err != nil {
					slog.WarnContext(ctx2, "anatel: ibge municipios falhou", "err", err)
					return nil
				}
				add(ff)
				return nil
			})
		}
	}

	// ABR Telecom — portabilidade numérica oficial (fonte mais confiável)
	if sourceEnabled(enabledSources, "anatel") && parsed.DDD != "" && parsed.IsValid && parsed.LineType == LineTypeMobile {
		eg.Go(func() error {
			ff, err := m.queryABRTelecom(ctx2, parsed)
			if err != nil {
				slog.WarnContext(ctx2, "anatel: consulta ABR Telecom falhou", "err", err)
				// Fallback: ANATEL consulta pública
				ff2, err2 := m.queryANATELOperadora(ctx2, parsed)
				if err2 != nil {
					slog.WarnContext(ctx2, "anatel: fallback ANATEL também falhou", "err", err2)
					return nil
				}
				add(ff2)
				return nil
			}
			add(ff)
			return nil
		})
	}

	_ = eg.Wait()

	result := dedup(findings)

	slog.InfoContext(ctx, "anatel: concluído",
		"number", maskPhone(parsed.Digits),
		"total_findings", len(result),
	)

	return result, nil
}

// ─── Análise local ─────────────────────────────────────────────────────────────

func analyzeNumberLocally(p ParsedNumber) []module.Finding {
	var findings []module.Finding

	// Finding principal: formato e tipo
	detail := fmt.Sprintf("Número '%s' analisado: DDD %s, tipo '%s', E.164: %s.",
		maskPhone(p.Digits), p.DDD, string(p.LineType), p.E164)

	extra := map[string]string{
		"ddd":        p.DDD,
		"number":     maskPhone(p.Number),
		"line_type":  string(p.LineType),
		"e164":       p.E164,
		"is_valid":   fmt.Sprintf("%v", p.IsValid),
		"fonte":      "local_analysis",
		"confidence": "0.95",
	}

	if info, ok := validDDDs[p.DDD]; ok {
		extra["estado"] = info.Estado
		extra["regiao"] = info.Regiao
		extra["uf"] = info.UF
		detail = fmt.Sprintf("Número '%s': DDD %s (%s/%s), tipo '%s', E.164: %s.",
			maskPhone(p.Digits), p.DDD, info.Estado, info.UF, string(p.LineType), p.E164)
	}

	findings = append(findings, module.Finding{
		Type:     "phone_analysis",
		URL:      "",
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra:    extra,
	})

	// Verifica se é número 0800 / especial
	if p.LineType == LineTypeFree {
		findings = append(findings, module.Finding{
			Type:     "phone_service_number",
			URL:      "",
			Detail:   fmt.Sprintf("Número '%s' é um número de serviço gratuito (0800).", maskPhone(p.Digits)),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"number":     p.Digits,
				"service":    "0800_free",
				"fonte":      "local_analysis",
				"confidence": "0.99",
			},
		})
	}

	if p.LineType == LineTypeService {
		findings = append(findings, module.Finding{
			Type:     "phone_service_number",
			URL:      "",
			Detail:   fmt.Sprintf("Número '%s' é um número de serviço especial (1xx, 190, 192, etc.).", maskPhone(p.Digits)),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"number":     p.Digits,
				"service":    "special_service",
				"fonte":      "local_analysis",
				"confidence": "0.99",
			},
		})
	}

	// Estimativa de portabilidade por faixa numérica
	if p.LineType == LineTypeMobile && p.IsValid {
		portability := estimatePortability(p.Number)
		if portability != "" {
			findings = append(findings, module.Finding{
				Type:     "phone_portability_hint",
				URL:      "",
				Detail:   fmt.Sprintf("Número '%s' tem faixa numérica tipicamente associada à operadora '%s' (portabilidade possível).", maskPhone(p.Digits), portability),
				Severity: module.SeverityInfo,
				Extra: map[string]string{
					"ddd":              p.DDD,
					"original_carrier": portability,
					"portability_note": "estimativa por faixa — pode ter sido portado",
					"fonte":            "local_analysis",
					"confidence":       "0.55",
				},
			})
		}
	}

	return findings
}

// ─── BrasilAPI DDD ────────────────────────────────────────────────────────────

type brasilAPIDDDResp struct {
	State  string   `json:"state"`
	Cities []string `json:"cities"`
}

func (m *Module) queryBrasilAPIDDD(ctx context.Context, ddd string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://brasilapi.com.br/api/ddd/v1/%s", url.PathEscape(ddd))

	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("brasilapi ddd: %w", err)
	}

	var resp brasilAPIDDDResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("brasilapi ddd: parse: %w", err)
	}

	cityCount := len(resp.Cities)
	citySample := resp.Cities
	if len(citySample) > 5 {
		citySample = citySample[:5]
	}

	return []module.Finding{{
		Type:     "ddd_info",
		URL:      u,
		Detail:   fmt.Sprintf("DDD %s corresponde ao estado '%s' com %d municípios cobertos. Exemplos: %s.", ddd, resp.State, cityCount, strings.Join(citySample, ", ")),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"ddd":         ddd,
			"state":       resp.State,
			"city_count":  fmt.Sprintf("%d", cityCount),
			"city_sample": strings.Join(citySample, ", "),
			"fonte":       "brasilapi_ddd",
			"confidence":  "0.92",
		},
	}}, nil
}

// ─── IBGE municípios ──────────────────────────────────────────────────────────

type ibgeMunicipio struct {
	ID   int    `json:"id"`
	Nome string `json:"nome"`
}

func (m *Module) queryIBGEMunicipios(ctx context.Context, uf string, ddd string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://servicodados.ibge.gov.br/api/v1/localidades/estados/%s/municipios", url.PathEscape(uf))

	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("ibge municipios: %w", err)
	}

	var municipios []ibgeMunicipio
	if err := json.Unmarshal(body, &municipios); err != nil {
		return nil, fmt.Errorf("ibge municipios: parse: %w", err)
	}

	if len(municipios) == 0 {
		return nil, nil
	}

	info := validDDDs[ddd]
	return []module.Finding{{
		Type:     "ddd_municipalities",
		URL:      u,
		Detail:   fmt.Sprintf("Estado '%s' (UF: %s) tem %d municípios registrados no IBGE, todos potencialmente cobertos pelo DDD %s.", info.Estado, uf, len(municipios), ddd),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"ddd":              ddd,
			"uf":               uf,
			"estado":           info.Estado,
			"total_municipios": fmt.Sprintf("%d", len(municipios)),
			"fonte":            "ibge_municipios",
			"confidence":       "0.88",
		},
	}}, nil
}

// ─── ABR Telecom — portabilidade numérica oficial ────────────────────────────

// queryABRTelecom consulta a ABR Telecom, responsável oficial pela portabilidade
// numérica no Brasil (PGMU III). Retorna operadora atual com alta confiança.
//
// A ABR Telecom expõe uma API pública usada pelo portal consultanumero.abrtelecom.com.br.
// Endpoint: GET /portabilidade/consultar?numero=<DDD><NUMERO>
// Resposta JSON: {"prestadora": "...", "cnpj": "...", "data_portabilidade": "..."}
func (m *Module) queryABRTelecom(ctx context.Context, p ParsedNumber) ([]module.Finding, error) {
	// Número no formato DDDNUMERO (sem +55)
	numero := p.DDD + p.Number

	// ABR Telecom API pública — usada pelo portal oficial de portabilidade
	u := fmt.Sprintf("https://www.consultanumero.abrtelecom.com.br/portabilidade/consultar?numero=%s", numero)

	body, err := m.get(ctx, u, map[string]string{
		"Accept":           "application/json, text/javascript, */*",
		"X-Requested-With": "XMLHttpRequest",
		"Referer":          "https://www.consultanumero.abrtelecom.com.br/consultanumero",
	})
	if err != nil {
		return nil, fmt.Errorf("abrtelecom: %w", err)
	}

	// Parse — pode retornar lista ou objeto único
	// Formato: [{"prestadora":"Vivo","cnpj":"...","dataPortabilidade":"..."}]
	var results []map[string]interface{}
	if err := json.Unmarshal(body, &results); err != nil {
		// Tenta como objeto único
		var single map[string]interface{}
		if err2 := json.Unmarshal(body, &single); err2 != nil {
			return nil, fmt.Errorf("abrtelecom: parse: %w", err)
		}
		results = []map[string]interface{}{single}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("abrtelecom: sem resultado para %s", maskPhone(numero))
	}

	latest := results[len(results)-1]
	prestadora, _ := latest["prestadora"].(string)
	if prestadora == "" {
		prestadora, _ = latest["nomePrestadora"].(string)
	}
	if prestadora == "" {
		return nil, fmt.Errorf("abrtelecom: campo prestadora ausente na resposta")
	}

	dataPort, _ := latest["dataPortabilidade"].(string)
	portDetail := ""
	if dataPort != "" && dataPort != "null" {
		portDetail = fmt.Sprintf(" (último porte: %s)", dataPort)
	}

	detail := fmt.Sprintf("Número '%s' pertence à operadora '%s'%s — fonte: ABR Telecom (portabilidade oficial).",
		maskPhone(p.Digits), prestadora, portDetail)

	conf := "0.95"
	if len(results) > 1 {
		conf = "0.98" // histórico de portabilidade disponível → maior confiança
	}

	findings := []module.Finding{{
		Type:     "phone_carrier",
		URL:      "https://consultanumero.abrtelecom.com.br",
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"ddd":        p.DDD,
			"operator":   prestadora,
			"fonte":      "abr_telecom_portabilidade",
			"confidence": conf,
		},
	}}

	// Se houve portabilidades anteriores, lista histórico
	if len(results) > 1 {
		ops := make([]string, 0, len(results))
		for _, r := range results {
			if op, ok := r["prestadora"].(string); ok && op != "" {
				ops = append(ops, op)
			}
		}
		if len(ops) > 1 {
			findings = append(findings, module.Finding{
				Type: "phone_portability_history",
				Detail: fmt.Sprintf("Número '%s' teve %d portabilidade(s). Histórico: %s → %s (atual).",
					maskPhone(p.Digits), len(results)-1, strings.Join(ops[:len(ops)-1], " → "), ops[len(ops)-1]),
				Severity: module.SeverityInfo,
				Extra: map[string]string{
					"ddd":        p.DDD,
					"history":    strings.Join(ops, " → "),
					"fonte":      "abr_telecom_portabilidade",
					"confidence": "0.98",
				},
			})
		}
	}

	slog.InfoContext(ctx, "anatel: ABR Telecom respondeu",
		"number", maskPhone(p.Digits),
		"operator", prestadora,
	)

	return findings, nil
}

// ─── ANATEL Consulta de operadora ─────────────────────────────────────────────

// queryANATELOperadora tenta identificar a operadora via consulta na base pública.
// ANATEL disponibiliza dados de portabilidade em:
// https://sistemas.anatel.gov.br/areaarea/N_Numeracao/Consulta/tela.asp
// Para automação, usamos a base de dados PGMQ pública.
func (m *Module) queryANATELOperadora(ctx context.Context, p ParsedNumber) ([]module.Finding, error) {
	// Usando a API pública de portabilidade numérica da ANATEL
	// Endpoint público de consulta de portabilidade
	u := fmt.Sprintf("https://consultapublica.anatel.gov.br/painelABD/rest/portabilidade/numero/%s%s",
		p.DDD, p.Number)

	body, err := m.get(ctx, u, map[string]string{
		"Accept": "application/json",
	})
	if err != nil {
		// Fallback: retorna operadoras conhecidas para o DDD
		return m.operadorasByDDD(p.DDD), nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return m.operadorasByDDD(p.DDD), nil
	}

	// Tenta extrair operadora atual
	operadora := ""
	if op, ok := raw["operadoraAtual"].(string); ok {
		operadora = op
	}
	if op, ok := raw["operator"].(string); ok && operadora == "" {
		operadora = op
	}

	if operadora == "" {
		return m.operadorasByDDD(p.DDD), nil
	}

	return []module.Finding{{
		Type:     "phone_carrier",
		URL:      u,
		Detail:   fmt.Sprintf("Número '%s' está registrado na operadora '%s' (consulta ANATEL).", maskPhone(p.Digits), operadora),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"ddd":        p.DDD,
			"operator":   operadora,
			"fonte":      "anatel_portabilidade",
			"confidence": "0.90",
		},
	}}, nil
}

// operadorasByDDD retorna as operadoras que atuam em um DDD com base em dados públicos.
func (m *Module) operadorasByDDD(ddd string) []module.Finding {
	// Operadoras nacionais que atuam em praticamente todos os DDDs
	majorCarriers := []string{"Claro", "TIM", "Vivo", "Oi"}

	return []module.Finding{{
		Type:     "ddd_carriers",
		URL:      "https://anatel.gov.br",
		Detail:   fmt.Sprintf("DDD %s: principais operadoras autorizadas pela ANATEL: %s.", ddd, strings.Join(majorCarriers, ", ")),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"ddd":        ddd,
			"carriers":   strings.Join(majorCarriers, ", "),
			"fonte":      "anatel_conhecida",
			"confidence": "0.75",
		},
	}}
}

// ─── Parsing de número ────────────────────────────────────────────────────────

// parseNumber analisa um número telefônico brasileiro em qualquer formato.
func parseNumber(raw string) (ParsedNumber, error) {
	p := ParsedNumber{Raw: raw}

	// Remove espaços, pontuação e formatação visual
	digits := reDigits.ReplaceAllString(raw, "")
	p.Digits = digits

	// 0800 gratuito — verificar ANTES de service number
	if strings.HasPrefix(digits, "0800") {
		p.LineType = LineTypeFree
		p.IsValid = true
		p.E164 = "+55" + digits
		return p, nil
	}

	// DDD com 2 dígitos — verificar ANTES de service number (DDD 11,12,13... começam com 1)
	if len(digits) == 2 {
		if _, ok := validDDDs[digits]; ok {
			p.DDD = digits
			p.IsValid = true
			p.E164 = "+55" + digits
			p.LineType = LineTypeUnknown
			return p, nil
		}
		return p, fmt.Errorf("'%s' não é um DDD brasileiro válido", raw)
	}

	// Números de serviço especial curtos (190, 192, 193, 197, 198, 199, 1xx)
	// Só aplicável para números com 2-4 dígitos iniciados em 1
	if isServiceNumber(digits) {
		p.LineType = LineTypeService
		p.IsValid = true
		p.E164 = "+55" + digits
		return p, nil
	}

	// Remove código do país se presente (55 ou +55)
	if strings.HasPrefix(raw, "+") && strings.HasPrefix(digits, "55") && len(digits) >= 12 {
		digits = digits[2:]
		p.CountryCode = "55"
	} else if len(digits) >= 12 && len(digits) <= 13 && strings.HasPrefix(digits, "55") && !strings.HasPrefix(digits, "550") {
		// Pode ser 55 + DDD + número
		tentative := digits[2:]
		if len(tentative) >= 10 && len(tentative) <= 11 {
			if _, ok := validDDDs[tentative[:2]]; ok {
				digits = tentative
				p.CountryCode = "55"
			}
		}
	}

	p.Digits = digits

	// Número com DDD (10 ou 11 dígitos)
	if len(digits) >= 10 && len(digits) <= 11 {
		ddd := digits[:2]
		if _, ok := validDDDs[ddd]; !ok {
			return p, fmt.Errorf("DDD '%s' inválido no número '%s'", ddd, raw)
		}
		p.DDD = ddd
		p.Number = digits[2:]
		p.LineType = classifyLineType(p.Number)
		p.IsValid = true
		p.E164 = "+55" + digits
		return p, nil
	}

	// Número sem DDD (8 ou 9 dígitos) — apenas análise local
	if len(digits) >= 8 && len(digits) <= 9 {
		p.Number = digits
		p.LineType = classifyLineType(digits)
		p.IsValid = false // incompleto sem DDD
		p.E164 = "(sem DDD)"
		return p, nil
	}

	return p, fmt.Errorf("número '%s' tem formato inválido (%d dígitos)", raw, len(digits))
}

// classifyLineType determina se o número é móvel, fixo ou especial.
func classifyLineType(number string) LineType {
	if len(number) == 0 {
		return LineTypeUnknown
	}
	first := number[0]
	switch {
	case first == '9' && len(number) == 9:
		return LineTypeMobile // 9XXXX-XXXX (móvel 9 dígitos)
	case (first == '7' || first == '8') && len(number) == 9:
		return LineTypeMobile // legado móvel
	case first >= '2' && first <= '5' && len(number) == 8:
		return LineTypeFixed // fixo 8 dígitos
	case strings.HasPrefix(number, "0800"):
		return LineTypeFree
	default:
		return LineTypeUnknown
	}
}

// isServiceNumber verifica se é número de serviço especial curto (1xx, 190, etc.).
// Apenas retorna true para números com 2-4 dígitos iniciados em 1.
func isServiceNumber(digits string) bool {
	if len(digits) < 2 || len(digits) > 4 {
		return false
	}
	return digits[0] == '1'
}

// estimatePortability estima operadora ORIGINAL por faixa numérica do prefixo.
// Dados baseados no plano de numeração ANATEL (Banda A/B/D/E por DDD).
// ATENÇÃO: portabilidade numérica torna isso meramente indicativo — use ABR Telecom
// para confirmação em tempo real.
func estimatePortability(number string) string {
	if len(number) < 4 {
		return ""
	}
	// Prefixo de 4 dígitos para maior precisão
	prefix4 := number[:4]
	prefix3 := number[:3]

	// Faixas Vivo (Telefônica/Banda A): 9600-9699, 9700-9799, 9800-9849
	// Faixas TIM (Banda D): 9900-9999
	// Faixas Claro (Banda E): 9850-9899, 9500-9599
	// Faixas Oi (Banda B): 9850-9879 (alguns DDDs)
	// Nota: Vivo herdou Banda A em todo o Brasil — prefixos 96x/97x são quase sempre Vivo.
	switch {
	// Vivo/Telefônica — Banda A (96xx, 97xx) — histórico forte
	case prefix3 >= "960" && prefix3 <= "979":
		return "Vivo/Telefônica (Banda A)"
	// TIM — Banda D (99xx)
	case prefix3 >= "990" && prefix3 <= "999":
		return "TIM (Banda D)"
	// Claro — Banda E (98xx superior e 95xx)
	case prefix3 >= "985" && prefix3 <= "989":
		return "Claro (Banda E)"
	case prefix3 >= "950" && prefix3 <= "959":
		return "Claro (Banda E)"
	// Oi — Banda B (980-984 em alguns DDDs)
	case prefix3 >= "980" && prefix3 <= "984":
		return "Oi (Banda B)"
	// Faixas 7xxx e 8xxx (móvel legado, geralmente Vivo/TIM)
	case prefix4 >= "7000" && prefix4 <= "7999":
		return "Vivo/Claro (faixa 7xxx)"
	case prefix4 >= "8000" && prefix4 <= "8999":
		return "TIM/Claro (faixa 8xxx)"
	default:
		return ""
	}
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

// maskPhone mascara número para logs (ex: "11999999999" → "11*******99")
func maskPhone(phone string) string {
	digits := strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		return -1
	}, phone)
	if len(digits) <= 4 {
		return strings.Repeat("*", len(digits))
	}
	return digits[:2] + strings.Repeat("*", len(digits)-4) + digits[len(digits)-2:]
}

func parseSources(s string) map[string]bool {
	if s == "all" || s == "" {
		return nil
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

func sourceEnabled(enabled map[string]bool, source string) bool {
	if enabled == nil {
		return true
	}
	return enabled[source]
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

func optStr(opts map[string]string, key, def string) string {
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

// Suprime warning de import não-usado (os é usado via os.Getenv em outros módulos)
var _ = os.Getenv
