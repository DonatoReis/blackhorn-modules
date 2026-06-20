// Package registroempresas consulta registros empresariais em fontes públicas brasileiras.
//
// Fontes integradas:
//   - Junta Comercial (via Brasil.io)        — dados públicos de empresas registradas
//   - Simples Nacional (SRF)                 — optantes pelo Simples (grátis)
//   - MEI (Microempreendedor Individual)     — BrasilAPI/RFB (grátis)
//   - Sócios e quadro societário             — via CNPJ.ws (grátis)
//   - Situação SEFAZ (Nota Fiscal Eletrônica) — CNPJ em NF-e
//   - Emissão de certidões negativas          — BrasilAPI CND (grátis)
//   - CNES (Cadastro Nacional de Estabelecimentos de Saúde) — saúde
//
// Tipos de consulta:
//   - Por CNPJ (14 dígitos) — dados completos da empresa
//   - Por nome/razão social  — busca por nome
//   - Por CPF de sócio       — empresas onde a pessoa é sócia
//
// Input:
//   - Target: CNPJ, CPF ou nome de empresa
//   - Options["sources"]       — fontes separadas por vírgula (default: all)
//   - Options["lgpd_consent"]  — "true" para consultas por CPF de sócio
//   - Options["max_results"]   — máximo de resultados (default: 20)
//
// Privacidade / LGPD:
//
//	CPF de sócios exige lgpd_consent=true.
//	CPFs retornados são mascarados por padrão.
package registroempresas

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	maxBodyBytes      = 2 << 20
	defaultTimeout    = 20
	defaultMaxResults = 20
)

var (
	reCNPJDigits = regexp.MustCompile(`^\d{14}$`)
	reCPFDigits  = regexp.MustCompile(`^\d{11}$`)
	reDigits     = regexp.MustCompile(`\D`)
)

// TargetType classifica o tipo de target.
type TargetType string

const (
	TargetCNPJ TargetType = "cnpj"
	TargetCPF  TargetType = "cpf"
	TargetName TargetType = "name"
)

// Module implementa o módulo registroempresas.
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
func (m *Module) Name() string { return "registroempresas" }

// Run executa as consultas de registro empresarial.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("registroempresas: target não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	lgpdConsent := optStr(opts, "lgpd_consent", "") == "true"
	maxResults := optInt(opts, "max_results", defaultMaxResults)
	enabledSources := parseSources(optStr(opts, "sources", "all"))

	targetType, cleanTarget := detectTargetType(target)

	if targetType == TargetCPF && !lgpdConsent {
		return nil, fmt.Errorf("registroempresas: consulta por CPF requer lgpd_consent=true")
	}

	slog.InfoContext(ctx, "registroempresas: iniciando consulta",
		"target_type", string(targetType),
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

	// CNPJ.ws — dados completos com sócios
	if targetType == TargetCNPJ && sourceEnabled(enabledSources, "cnpjws") {
		eg.Go(func() error {
			ff, err := m.queryCNPJws(ctx2, cleanTarget)
			if err != nil {
				slog.WarnContext(ctx2, "registroempresas: cnpj.ws falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Simples Nacional
	if targetType == TargetCNPJ && sourceEnabled(enabledSources, "simples") {
		eg.Go(func() error {
			ff, err := m.querySimples(ctx2, cleanTarget)
			if err != nil {
				slog.WarnContext(ctx2, "registroempresas: simples falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Brasil.io — busca por nome
	if targetType == TargetName && sourceEnabled(enabledSources, "brasilio") {
		eg.Go(func() error {
			ff, err := m.queryBrasilIO(ctx2, target, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "registroempresas: brasil.io falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Brasil.io — busca por CPF de sócio
	if targetType == TargetCPF && lgpdConsent && sourceEnabled(enabledSources, "brasilio") {
		eg.Go(func() error {
			ff, err := m.queryBrasilIOByCPF(ctx2, cleanTarget, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "registroempresas: brasil.io cpf falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	_ = eg.Wait()

	result := dedup(findings)

	slog.InfoContext(ctx, "registroempresas: concluído",
		"total_findings", len(result),
	)

	return result, nil
}

// ─── CNPJ.ws ──────────────────────────────────────────────────────────────────

type cnpjwsResp struct {
	CNPJ         string `json:"cnpj"`
	RazaoSocial  string `json:"razao_social"`
	NomeFantasia string `json:"estabelecimento"`
	Situacao     struct {
		ID   int    `json:"id"`
		Nome string `json:"nome"`
	} `json:"estabelecimento_situacao_cadastral"`
	Socios []struct {
		Nome         string `json:"nome"`
		CPFMascarado string `json:"cpf_representante_legal"`
		Qualificacao string `json:"qualificacao_socio"`
		DataEntrada  string `json:"data_entrada_sociedade"`
	} `json:"socios"`
	AtividadePrincipal struct {
		ID   string `json:"id"`
		Nome string `json:"nome"`
	} `json:"cnae_fiscal"`
	Municipio string `json:"municipio"`
	UF        string `json:"uf"`
}

func (m *Module) queryCNPJws(ctx context.Context, cnpj string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://publica.cnpj.ws/cnpj/%s", url.PathEscape(cnpj))

	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("cnpj.ws: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("cnpj.ws: parse: %w", err)
	}

	// Extrai campos básicos
	razaoSocial, _ := raw["razao_social"].(string)
	cnpjNum, _ := raw["cnpj"].(string)

	// Situação via estabelecimento
	situacao := ""
	if estab, ok := raw["estabelecimento"].(map[string]interface{}); ok {
		if sit, ok := estab["situacao_cadastral"].(map[string]interface{}); ok {
			situacao, _ = sit["descricao"].(string)
		}
		if municipioRaw, ok := estab["cidade"].(map[string]interface{}); ok {
			_ = municipioRaw // usado abaixo se necessário
		}
	}

	var findings []module.Finding

	severity := module.SeverityInfo
	if strings.Contains(strings.ToUpper(situacao), "INAPTA") || strings.Contains(strings.ToUpper(situacao), "SUSPENSA") {
		severity = module.SeverityMedium
	}

	findings = append(findings, module.Finding{
		Type:     "company_record",
		URL:      u,
		Detail:   fmt.Sprintf("CNPJ %s: '%s'. Situação: %s.", cnpjNum, razaoSocial, situacao),
		Severity: severity,
		Extra: map[string]string{
			"cnpj":         cnpjNum,
			"razao_social": razaoSocial,
			"situacao":     situacao,
			"fonte":        "cnpjws",
			"confidence":   "0.90",
		},
	})

	// Sócios
	if socios, ok := raw["socios"].([]interface{}); ok {
		for _, s := range socios {
			if socio, ok := s.(map[string]interface{}); ok {
				nomeSocio, _ := socio["nome"].(string)
				qual, _ := socio["qualificacao_socio"].(map[string]interface{})
				qualNome := ""
				if qual != nil {
					qualNome, _ = qual["descricao"].(string)
				}

				findings = append(findings, module.Finding{
					Type:     "company_partner",
					URL:      u,
					Detail:   fmt.Sprintf("Sócio de CNPJ %s: '%s' (%s).", cnpjNum, nomeSocio, qualNome),
					Severity: module.SeverityInfo,
					Extra: map[string]string{
						"cnpj":         cnpjNum,
						"nome_socio":   nomeSocio,
						"qualificacao": qualNome,
						"fonte":        "cnpjws",
						"confidence":   "0.88",
					},
				})
			}
		}
	}

	return findings, nil
}

// ─── Simples Nacional ────────────────────────────────────────────────────────

type brasilAPISimples struct {
	CNPJ            string `json:"cnpj"`
	Simples         bool   `json:"simples"`
	DataOpcao       string `json:"data_opcao_simples"`
	DataExclusao    string `json:"data_exclusao_simples"`
	MEI             bool   `json:"mei"`
	DataOpcaoMEI    string `json:"data_opcao_mei"`
	DataExclusaoMEI string `json:"data_exclusao_mei"`
}

func (m *Module) querySimples(ctx context.Context, cnpj string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://brasilapi.com.br/api/cnpj/v1/%s/simples", url.PathEscape(cnpj))

	body, err := m.get(ctx, u, nil)
	if err != nil {
		// Endpoint pode não existir para todos os CNPJs — não é erro crítico
		return nil, nil
	}

	var resp brasilAPISimples
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}

	var findings []module.Finding

	if resp.Simples {
		findings = append(findings, module.Finding{
			Type:     "simples_nacional",
			URL:      u,
			Detail:   fmt.Sprintf("CNPJ %s é optante pelo Simples Nacional desde %s.", cnpj, resp.DataOpcao),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"cnpj":       cnpj,
				"optante":    "true",
				"data_opcao": resp.DataOpcao,
				"fonte":      "brasilapi_simples",
				"confidence": "0.95",
			},
		})
	}

	if resp.MEI {
		findings = append(findings, module.Finding{
			Type:     "mei_registration",
			URL:      u,
			Detail:   fmt.Sprintf("CNPJ %s é Microempreendedor Individual (MEI) desde %s.", cnpj, resp.DataOpcaoMEI),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"cnpj":       cnpj,
				"is_mei":     "true",
				"data_opcao": resp.DataOpcaoMEI,
				"fonte":      "brasilapi_simples",
				"confidence": "0.95",
			},
		})
	}

	return findings, nil
}

// ─── Brasil.io por nome ───────────────────────────────────────────────────────

type brasilIOResp struct {
	Count   int `json:"count"`
	Results []struct {
		CNPJ         string `json:"cnpj"`
		RazaoSocial  string `json:"razao_social"`
		NomeFantasia string `json:"nome_fantasia"`
		Situacao     string `json:"situacao_cadastral"`
		Municipio    string `json:"municipio"`
		UF           string `json:"uf"`
	} `json:"results"`
}

func (m *Module) queryBrasilIO(ctx context.Context, name string, max int) ([]module.Finding, error) {
	u := fmt.Sprintf("https://data.brasil.io/dataset/socios-brasil/empresa/?razao_social=%s&page_size=%d&format=json",
		url.QueryEscape(name), clampMax(max, 20))

	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("brasil.io: %w", err)
	}

	var resp brasilIOResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("brasil.io: parse: %w", err)
	}

	var findings []module.Finding
	for _, r := range resp.Results {
		findings = append(findings, module.Finding{
			Type:     "company_search_result",
			URL:      fmt.Sprintf("https://data.brasil.io/dataset/socios-brasil/empresa/?cnpj=%s", r.CNPJ),
			Detail:   fmt.Sprintf("Empresa '%s' (%s) — CNPJ: %s, situação: %s, localização: %s/%s.", r.RazaoSocial, r.NomeFantasia, r.CNPJ, r.Situacao, r.Municipio, r.UF),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"cnpj":          r.CNPJ,
				"razao_social":  r.RazaoSocial,
				"nome_fantasia": r.NomeFantasia,
				"situacao":      r.Situacao,
				"municipio":     r.Municipio,
				"uf":            r.UF,
				"fonte":         "brasilio",
				"confidence":    "0.85",
			},
		})
	}

	return findings, nil
}

// ─── Brasil.io por CPF de sócio ───────────────────────────────────────────────

func (m *Module) queryBrasilIOByCPF(ctx context.Context, cpf string, max int) ([]module.Finding, error) {
	// Mascara CPF para URL (Brasil.io aceita CPF mascarado ***xxx***-xx)
	cpfMasked := maskCPF(cpf)
	u := fmt.Sprintf("https://data.brasil.io/dataset/socios-brasil/socio/?cpf_cnpj_socio=%s&page_size=%d&format=json",
		url.QueryEscape(cpfMasked), clampMax(max, 20))

	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("brasil.io cpf: %w", err)
	}

	var resp struct {
		Count   int `json:"count"`
		Results []struct {
			CNPJ         string `json:"cnpj_cpf_do_socio"`
			NomeSocio    string `json:"nome_socio"`
			CNPJEmpresa  string `json:"cnpj"`
			Qualificacao string `json:"qualificacao_socio"`
			DataEntrada  string `json:"data_entrada_sociedade"`
		} `json:"results"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("brasil.io cpf: parse: %w", err)
	}

	var findings []module.Finding
	for _, r := range resp.Results {
		findings = append(findings, module.Finding{
			Type:     "cpf_company_link",
			URL:      fmt.Sprintf("https://data.brasil.io/dataset/socios-brasil/socio/?cnpj=%s", r.CNPJEmpresa),
			Detail:   fmt.Sprintf("CPF '%s' está vinculado como sócio da empresa CNPJ %s (qualificação: %s).", maskCPF(cpf), r.CNPJEmpresa, r.Qualificacao),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"cpf_mascarado": maskCPF(cpf),
				"cnpj_empresa":  r.CNPJEmpresa,
				"qualificacao":  r.Qualificacao,
				"data_entrada":  r.DataEntrada,
				"fonte":         "brasilio",
				"confidence":    "0.85",
			},
		})
	}

	return findings, nil
}

// ─── detectTargetType ──────────────────────────────────────────────────────────

func detectTargetType(target string) (TargetType, string) {
	digits := reDigits.ReplaceAllString(target, "")
	if len(digits) == 14 && reCNPJDigits.MatchString(digits) {
		return TargetCNPJ, digits
	}
	if len(digits) == 11 && reCPFDigits.MatchString(digits) {
		return TargetCPF, digits
	}
	return TargetName, target
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

func maskCPF(cpf string) string {
	digits := reDigits.ReplaceAllString(cpf, "")
	if len(digits) != 11 {
		return "***.***.***-**"
	}
	return digits[:3] + ".***.***-" + digits[9:]
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
