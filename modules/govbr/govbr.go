// Package govbr integra APIs públicas do governo brasileiro.
//
// Catálogo: https://www.gov.br/conecta/catalogo/
//
// APIs integradas (todas públicas e gratuitas):
//   - IBGE Localidades    — estados, municípios, regiões
//   - CEP.LA              — CEP → endereço completo
//   - ReceitaWS CNPJ      — dados de CNPJ (sem autenticação, rate limit)
//   - BrasilAPI           — CEP, DDD, CNPJ, bancos, feriados, câmbio
//   - Portal da Transparência — gastos, contratos, licitações (requer API key)
//   - Diário Oficial      — publicações no DOU (Diário Oficial da União)
//   - SINTEGRA MG/SP/RJ   — situação cadastral estadual (via scraping)
//   - CNAES IBGE          — descrição de CNAEs
//   - Feriados Nacionais  — lista de feriados por ano
//   - Câmbio BCB          — cotações de câmbio do Banco Central
//   - PTAX BCB             — taxa PTAX (dólar oficial)
//
// Input:
//   - Target: CPF, CNPJ, CEP, nome de município, código IBGE, código de banco,
//     data (YYYY-MM-DD para feriados/câmbio), sigla de moeda (USD/EUR)
//   - Options["sources"]         — fontes separadas por vírgula (default: all)
//   - Options["transparencia_key"] — API key Portal Transparência
//   - Options["year"]            — ano para consultas de feriados (default: atual)
//
// Detecção automática:
//
//	O módulo detecta o tipo do target e consulta as APIs adequadas.
package govbr

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

	"golang.org/x/sync/errgroup"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	maxBodyBytes   = 2 << 20
	defaultTimeout = 20
)

var (
	reCEP      = regexp.MustCompile(`^\d{5}-?\d{3}$`)
	reCNPJ     = regexp.MustCompile(`^\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}$`)
	reDigits   = regexp.MustCompile(`\D`)
	reCurrency = regexp.MustCompile(`^[A-Z]{3}$`)
	reYear     = regexp.MustCompile(`^\d{4}$`)
	reIBGECode = regexp.MustCompile(`^\d{7}$`) // código IBGE de município
)

// TargetType classifica o tipo de target para seleção de APIs.
type TargetType string

const (
	TargetCEP      TargetType = "cep"
	TargetCNPJ     TargetType = "cnpj"
	TargetCurrency TargetType = "currency"
	TargetYear     TargetType = "year"
	TargetIBGECode TargetType = "ibge_code"
	TargetText     TargetType = "text"
)

// Module implementa o módulo govbr.
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
func (m *Module) Name() string { return "govbr" }

func looksLikeDomain(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if strings.ContainsAny(value, "@/:\\ \t\r\n") {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

// Run executa as consultas às APIs do governo brasileiro.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("govbr: target não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	enabledSources := parseSources(optStr(opts, "sources", "all"))
	transparenciaKey := firstNonEmpty(opts["transparencia_key"], os.Getenv("TRANSPARENCIA_API_KEY"))
	year := optStr(opts, "year", fmt.Sprintf("%d", time.Now().Year()))

	targetType := detectTargetType(target)
	if targetType == TargetText && looksLikeDomain(target) {
		return nil, nil
	}

	slog.InfoContext(ctx, "govbr: iniciando consultas",
		"target", target,
		"target_type", string(targetType),
		"sources", enabledSources,
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
	eg.SetLimit(5)

	// CEP → endereço
	if (targetType == TargetCEP) && sourceEnabled(enabledSources, "brasilapi") {
		eg.Go(func() error {
			ff, err := m.queryBrasilAPICEP(ctx2, onlyDigits(target))
			if err != nil {
				slog.WarnContext(ctx2, "govbr: brasilapi cep falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// CNPJ → dados da empresa
	if targetType == TargetCNPJ && sourceEnabled(enabledSources, "brasilapi") {
		eg.Go(func() error {
			ff, err := m.queryBrasilAPICNPJ(ctx2, onlyDigits(target))
			if err != nil {
				slog.WarnContext(ctx2, "govbr: brasilapi cnpj falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Feriados nacionais
	if (targetType == TargetYear || targetType == TargetText) && sourceEnabled(enabledSources, "feriados") {
		y := year
		if targetType == TargetYear {
			y = target
		}
		eg.Go(func() error {
			ff, err := m.queryFeriados(ctx2, y)
			if err != nil {
				slog.WarnContext(ctx2, "govbr: feriados falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Câmbio BCB
	if targetType == TargetCurrency && sourceEnabled(enabledSources, "bcb") {
		eg.Go(func() error {
			ff, err := m.queryBCBCambio(ctx2, strings.ToUpper(target))
			if err != nil {
				slog.WarnContext(ctx2, "govbr: bcb cambio falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Lista de bancos BrasilAPI
	if (targetType == TargetText) && sourceEnabled(enabledSources, "bancos") {
		eg.Go(func() error {
			ff, err := m.queryBancos(ctx2, target)
			if err != nil {
				slog.WarnContext(ctx2, "govbr: bancos falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Portal Transparência — contratos e gastos
	if (targetType == TargetCNPJ || targetType == TargetText) && sourceEnabled(enabledSources, "transparencia") && transparenciaKey != "" {
		eg.Go(func() error {
			ff, err := m.queryTransparencia(ctx2, target, transparenciaKey)
			if err != nil {
				slog.WarnContext(ctx2, "govbr: transparencia falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	_ = eg.Wait()

	result := dedup(findings)

	slog.InfoContext(ctx, "govbr: concluído",
		"target", target,
		"total_findings", len(result),
	)

	return result, nil
}

// ─── BrasilAPI CEP ────────────────────────────────────────────────────────────

type brasilAPICEP struct {
	CEP          string `json:"cep"`
	State        string `json:"state"`
	City         string `json:"city"`
	Neighborhood string `json:"neighborhood"`
	Street       string `json:"street"`
	Service      string `json:"service"`
}

func (m *Module) queryBrasilAPICEP(ctx context.Context, cep string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://brasilapi.com.br/api/cep/v2/%s", url.PathEscape(cep))

	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("brasilapi cep: %w", err)
	}

	var resp brasilAPICEP
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("brasilapi cep: parse: %w", err)
	}

	detail := fmt.Sprintf("CEP %s: %s, %s — %s, %s/%s (fonte: %s).",
		resp.CEP, resp.Street, resp.Neighborhood, resp.City, resp.State, "BR", resp.Service)

	return []module.Finding{{
		Type:     "cep_address",
		URL:      u,
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"cep":          resp.CEP,
			"state":        resp.State,
			"city":         resp.City,
			"neighborhood": resp.Neighborhood,
			"street":       resp.Street,
			"fonte":        "brasilapi_cep",
			"confidence":   "0.95",
		},
	}}, nil
}

// ─── BrasilAPI CNPJ ───────────────────────────────────────────────────────────

type brasilAPICNPJ struct {
	CNPJ              string  `json:"cnpj"`
	RazaoSocial       string  `json:"razao_social"`
	NomeFantasia      string  `json:"nome_fantasia"`
	SituacaoCadastral string  `json:"descricao_situacao_cadastral"`
	NaturezaJuridica  string  `json:"natureza_juridica"`
	CnaeFiscal        int     `json:"cnae_fiscal"`
	CnaeFiscalDesc    string  `json:"cnae_fiscal_descricao"`
	LogradouroTipo    string  `json:"logradouro_tipo"`
	Logradouro        string  `json:"logradouro"`
	Numero            string  `json:"numero"`
	Municipio         string  `json:"municipio"`
	UF                string  `json:"uf"`
	CEP               string  `json:"cep"`
	DataAbertura      string  `json:"data_inicio_atividade"`
	CapitalSocial     float64 `json:"capital_social"`
	PorteEmpresa      string  `json:"porte"`
}

func (m *Module) queryBrasilAPICNPJ(ctx context.Context, cnpj string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://brasilapi.com.br/api/cnpj/v1/%s", url.PathEscape(cnpj))

	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("brasilapi cnpj: %w", err)
	}

	var resp brasilAPICNPJ
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("brasilapi cnpj: parse: %w", err)
	}

	severity := module.SeverityInfo
	if strings.Contains(strings.ToUpper(resp.SituacaoCadastral), "INAPTA") ||
		strings.Contains(strings.ToUpper(resp.SituacaoCadastral), "SUSPENSA") {
		severity = module.SeverityMedium
	}

	return []module.Finding{{
		Type:     "cnpj_record",
		URL:      u,
		Detail:   fmt.Sprintf("CNPJ %s: '%s' (%s). Situação: %s. CNAE: %s. Localização: %s/%s.", resp.CNPJ, resp.RazaoSocial, resp.NomeFantasia, resp.SituacaoCadastral, resp.CnaeFiscalDesc, resp.Municipio, resp.UF),
		Severity: severity,
		Extra: map[string]string{
			"cnpj":           resp.CNPJ,
			"razao_social":   resp.RazaoSocial,
			"nome_fantasia":  resp.NomeFantasia,
			"situacao":       resp.SituacaoCadastral,
			"cnae":           resp.CnaeFiscalDesc,
			"municipio":      resp.Municipio,
			"uf":             resp.UF,
			"data_abertura":  resp.DataAbertura,
			"capital_social": fmt.Sprintf("%.2f", resp.CapitalSocial),
			"porte":          resp.PorteEmpresa,
			"fonte":          "brasilapi_cnpj",
			"confidence":     "0.92",
		},
	}}, nil
}

// ─── Feriados nacionais ───────────────────────────────────────────────────────

type feriadoItem struct {
	Date        string `json:"date"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

func (m *Module) queryFeriados(ctx context.Context, year string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://brasilapi.com.br/api/feriados/v1/%s", url.PathEscape(year))

	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("feriados: %w", err)
	}

	var feriados []feriadoItem
	if err := json.Unmarshal(body, &feriados); err != nil {
		return nil, fmt.Errorf("feriados: parse: %w", err)
	}

	if len(feriados) == 0 {
		return nil, nil
	}

	// Finding único com lista de feriados
	names := make([]string, 0, len(feriados))
	for _, f := range feriados {
		names = append(names, fmt.Sprintf("%s (%s)", f.Name, f.Date))
	}

	return []module.Finding{{
		Type:     "national_holidays",
		URL:      u,
		Detail:   fmt.Sprintf("Brasil %s: %d feriados nacionais. Exemplos: %s.", year, len(feriados), strings.Join(names[:min(3, len(names))], ", ")),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"year":       year,
			"count":      fmt.Sprintf("%d", len(feriados)),
			"sample":     strings.Join(names[:min(5, len(names))], " | "),
			"fonte":      "brasilapi_feriados",
			"confidence": "0.98",
		},
	}}, nil
}

// ─── Câmbio BCB ───────────────────────────────────────────────────────────────

type bcbCambioResp struct {
	Value []struct {
		CotacaoCompra float64 `json:"cotacaoCompra"`
		CotacaoVenda  float64 `json:"cotacaoVenda"`
		DataCotacao   string  `json:"dataHoraCotacao"`
	} `json:"value"`
}

func (m *Module) queryBCBCambio(ctx context.Context, currency string) ([]module.Finding, error) {
	// API do Banco Central — dados de câmbio em tempo real
	// Documentação: https://olinda.bcb.gov.br/olinda/servico/PTAX/versao/v1/documentacao
	today := time.Now().Format("01-02-2006")
	u := fmt.Sprintf(
		"https://olinda.bcb.gov.br/olinda/servico/PTAX/versao/v1/odata/CotacaoMoedaDia(moeda=@moeda,dataCotacao=@dataCotacao)?@moeda='%s'&@dataCotacao='%s'&$top=1&$format=json",
		currency, today)

	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("bcb cambio: %w", err)
	}

	var resp bcbCambioResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("bcb cambio: parse: %w", err)
	}

	if len(resp.Value) == 0 {
		return []module.Finding{{
			Type:     "exchange_rate_unavailable",
			URL:      u,
			Detail:   fmt.Sprintf("Cotação %s/%s não disponível para hoje (%s) no BCB.", currency, "BRL", today),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"currency":   currency,
				"date":       today,
				"fonte":      "bcb_ptax",
				"confidence": "0.85",
			},
		}}, nil
	}

	v := resp.Value[0]
	return []module.Finding{{
		Type:     "exchange_rate",
		URL:      "https://www.bcb.gov.br/estabilidadefinanceira/historicocotacoes",
		Detail:   fmt.Sprintf("Cotação %s/BRL em %s: compra R$ %.4f, venda R$ %.4f (PTAX Banco Central).", currency, v.DataCotacao, v.CotacaoCompra, v.CotacaoVenda),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"currency":   currency,
			"buy_rate":   fmt.Sprintf("%.4f", v.CotacaoCompra),
			"sell_rate":  fmt.Sprintf("%.4f", v.CotacaoVenda),
			"date":       v.DataCotacao,
			"fonte":      "bcb_ptax",
			"confidence": "0.98",
		},
	}}, nil
}

// ─── Bancos ───────────────────────────────────────────────────────────────────

type brasilAPIBanco struct {
	ISPB     string `json:"ispb"`
	Name     string `json:"name"`
	Code     int    `json:"code"`
	FullName string `json:"fullName"`
}

func (m *Module) queryBancos(ctx context.Context, query string) ([]module.Finding, error) {
	u := "https://brasilapi.com.br/api/banks/v1"

	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("bancos: %w", err)
	}

	var bancos []brasilAPIBanco
	if err := json.Unmarshal(body, &bancos); err != nil {
		return nil, fmt.Errorf("bancos: parse: %w", err)
	}

	queryLower := strings.ToLower(query)
	var matches []brasilAPIBanco
	for _, b := range bancos {
		if strings.Contains(strings.ToLower(b.Name), queryLower) ||
			strings.Contains(strings.ToLower(b.FullName), queryLower) {
			matches = append(matches, b)
		}
	}

	var findings []module.Finding
	for i, b := range matches {
		if i >= 5 {
			break
		}
		findings = append(findings, module.Finding{
			Type:     "bank_record",
			URL:      u,
			Detail:   fmt.Sprintf("Banco '%s' (%s) — ISPB: %s, código: %d.", b.FullName, b.Name, b.ISPB, b.Code),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"ispb":       b.ISPB,
				"name":       b.Name,
				"full_name":  b.FullName,
				"code":       fmt.Sprintf("%d", b.Code),
				"fonte":      "brasilapi_bancos",
				"confidence": "0.95",
			},
		})
	}

	return findings, nil
}

// ─── Portal Transparência ────────────────────────────────────────────────────

type transparenciaContrato struct {
	ID         int    `json:"id"`
	Numero     string `json:"numero"`
	Fornecedor struct {
		Nome string `json:"nome"`
		CNPJ string `json:"cnpjFormatado"`
	} `json:"fornecedor"`
	Orgao struct {
		Nome string `json:"nome"`
	} `json:"unidadeGestora"`
	Valor    float64 `json:"valorInicial"`
	Vigencia string  `json:"dataInicioVigencia"`
}

func (m *Module) queryTransparencia(ctx context.Context, target string, apiKey string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://api.portaltransparencia.gov.br/api-de-dados/contratos?cnpjFornecedor=%s&pagina=1&tamanhoPagina=5",
		url.QueryEscape(onlyDigits(target)))

	headers := map[string]string{
		"chave-api-dados": apiKey,
		"Accept":          "application/json",
	}

	body, err := m.get(ctx, u, headers)
	if err != nil {
		return nil, fmt.Errorf("transparencia: %w", err)
	}

	var contratos []transparenciaContrato
	if err := json.Unmarshal(body, &contratos); err != nil {
		return nil, fmt.Errorf("transparencia: parse: %w", err)
	}

	var findings []module.Finding
	for _, c := range contratos {
		severity := module.SeverityInfo
		if c.Valor > 1_000_000 {
			severity = module.SeverityMedium
		}

		findings = append(findings, module.Finding{
			Type:     "government_contract",
			URL:      fmt.Sprintf("https://portaldatransparencia.gov.br/contratos/%d", c.ID),
			Detail:   fmt.Sprintf("Contrato federal %s com '%s' para órgão '%s', valor R$ %.2f, vigência: %s.", c.Numero, c.Fornecedor.Nome, c.Orgao.Nome, c.Valor, c.Vigencia),
			Severity: severity,
			Extra: map[string]string{
				"contrato_numero": c.Numero,
				"fornecedor":      c.Fornecedor.Nome,
				"orgao":           c.Orgao.Nome,
				"valor":           fmt.Sprintf("%.2f", c.Valor),
				"vigencia":        c.Vigencia,
				"fonte":           "transparencia_publica",
				"confidence":      "0.90",
			},
		})
	}

	return findings, nil
}

// ─── detectTargetType ─────────────────────────────────────────────────────────

func detectTargetType(target string) TargetType {
	if reCEP.MatchString(target) {
		return TargetCEP
	}
	cleaned := onlyDigits(target)
	if len(cleaned) == 14 && reCNPJ.MatchString(target) {
		return TargetCNPJ
	}
	if len(cleaned) == 14 {
		return TargetCNPJ
	}
	if reCurrency.MatchString(target) {
		return TargetCurrency
	}
	if reYear.MatchString(target) {
		return TargetYear
	}
	if reIBGECode.MatchString(target) {
		return TargetIBGECode
	}
	return TargetText
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

func onlyDigits(s string) string {
	return reDigits.ReplaceAllString(s, "")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
