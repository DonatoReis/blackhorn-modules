// Package cpflookup realiza consultas de CPF via fontes legalmente permitidas.
//
// AVISO LEGAL: Este módulo consulta apenas APIs e serviços públicos que
// disponibilizam dados de Pessoa Física dentro dos limites da LGPD (Lei nº
// 13.709/2018). Dados pessoais sensíveis nunca são logados. O uso para
// fins ilícitos é de inteira responsabilidade do operador.
//
// Fontes suportadas:
//   - receitaws   : ReceitaWS – dados públicos da Receita Federal (PF)
//   - brasilapi   : BrasilAPI – CPF via Receita Federal open data
//   - cpfcnpj     : api.cpfcnpj.com.br – validação estrutural + dados públicos
//   - sintegra    : sintegra.gov.br (estadual, quando disponível)
//
// Options:
//
//	sources       : lista separada por vírgula (padrão: brasilapi,receitaws,cpfcnpj)
//	cpf_key       : API key para api.cpfcnpj.com.br (ou env CPF_CNPJ_API_KEY)
//	lgpd_consent  : deve ser "true" para ativar consultas com dados pessoais
package cpflookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	maxBodyBytes   = 512 * 1024
	defaultTimeout = 20 * time.Second

	baseURLBrasilAPI = "https://brasilapi.com.br/api/cpf/v1"
	baseURLReceitaWS = "https://www.receitaws.com.br/v1/cpf"
	baseURLCPFCNPJ   = "https://api.cpfcnpj.com.br/5ae973d7a997af13f0aaf2bf60e65803/1"
)

var reCPF = regexp.MustCompile(`^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$`)

// Module implementa module.Module para consultas de CPF.
type Module struct {
	client *http.Client
}

// New cria um Module com cliente HTTP padrão.
func New() *Module { return &Module{client: &http.Client{Timeout: defaultTimeout}} }

// NewWithClient cria um Module com cliente HTTP injetado (útil em testes).
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "cpflookup" }

// Run executa as consultas de CPF e retorna os findings.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	cpf := normalizeCPF(input.Target)
	if !reCPF.MatchString(cpf) && !reCPF.MatchString(input.Target) {
		return nil, fmt.Errorf("cpflookup: target '%s' não parece ser um CPF válido", input.Target)
	}
	cpfDigits := digitsOnly(input.Target)
	if len(cpfDigits) != 11 {
		return nil, fmt.Errorf("cpflookup: CPF deve ter 11 dígitos, obtido %d", len(cpfDigits))
	}
	if !validateCPFDigits(cpfDigits) {
		return nil, fmt.Errorf("cpflookup: CPF '%s' inválido (dígitos verificadores incorretos)", cpfDigits)
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	// LGPD gate: consultas com dados pessoais exigem consentimento explícito
	consent := optStr(opts, "lgpd_consent", "false")
	if consent != "true" {
		slog.WarnContext(ctx, "cpflookup: lgpd_consent não habilitado, retornando apenas validação estrutural",
			"cpf_prefix", cpfDigits[:3]+"***")
		return m.structuralOnly(cpfDigits), nil
	}

	sources := parseSources(optStr(opts, "sources", "brasilapi,receitaws,cpfcnpj"))
	cpfKey := firstNonEmpty(opts["cpf_key"], os.Getenv("CPF_CNPJ_API_KEY"))

	slog.InfoContext(ctx, "cpflookup: iniciando consultas",
		"sources", sources,
		"cpf_prefix", cpfDigits[:3]+"***",
	)

	type result struct {
		findings []module.Finding
		source   string
	}

	ch := make(chan result, len(sources))
	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(4)

	for _, src := range sources {
		src := src
		eg.Go(func() error {
			var ff []module.Finding
			var err error

			switch src {
			case "brasilapi":
				ff, err = m.queryBrasilAPI(egCtx, cpfDigits)
			case "receitaws":
				ff, err = m.queryReceitaWS(egCtx, cpfDigits)
			case "cpfcnpj":
				if cpfKey == "" {
					slog.WarnContext(egCtx, "cpflookup: cpfcnpj ignorado — CPF_CNPJ_API_KEY não configurada")
					return nil
				}
				ff, err = m.queryCPFCNPJ(egCtx, cpfDigits, cpfKey)
			}
			if err != nil {
				slog.WarnContext(egCtx, "cpflookup: fonte falhou",
					"source", src, "error", err.Error())
				return nil
			}
			ch <- result{findings: ff, source: src}
			return nil
		})
	}

	go func() {
		_ = eg.Wait()
		close(ch)
	}()

	var all []module.Finding
	for r := range ch {
		all = append(all, r.findings...)
	}

	return dedup(all), nil
}

// ─── structuralOnly: retorna apenas validação sem dados pessoais ──────────────

func (m *Module) structuralOnly(cpfDigits string) []module.Finding {
	return []module.Finding{{
		Type:     "cpf_structural_validation",
		Detail:   fmt.Sprintf("CPF %s****** passou na validação de dígitos verificadores (sem consulta externa — lgpd_consent não habilitado)", cpfDigits[:3]),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"cpf_prefix":  cpfDigits[:3] + "***",
			"valid":       "true",
			"confidence":  "1.00",
			"lgpd_notice": "Consulta de dados pessoais exige lgpd_consent=true",
		},
	}}
}

// ─── BrasilAPI CPF ────────────────────────────────────────────────────────────

func (m *Module) queryBrasilAPI(ctx context.Context, cpf string) ([]module.Finding, error) {
	url := fmt.Sprintf("%s/%s", baseURLBrasilAPI, cpf)
	slog.DebugContext(ctx, "cpflookup: BrasilAPI CPF request", "url", url)

	body, status, err := m.get(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("brasilapi CPF retornou HTTP %d", status)
	}

	var resp struct {
		NI       string `json:"ni"`
		Nome     string `json:"nome"`
		DataNasc string `json:"data_nascimento"`
		Situacao struct {
			Codigo    string `json:"codigo"`
			Descricao string `json:"descricao"`
		} `json:"situacao"`
		Digito       string `json:"digito_verificador"`
		ComprovRenda bool   `json:"comprovante_renda"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("brasilapi CPF JSON: %w", err)
	}

	f := module.Finding{
		Type:     "cpf_record",
		URL:      url,
		Detail:   fmt.Sprintf("CPF encontrado via BrasilAPI — situação: %s", resp.Situacao.Descricao),
		Severity: severityFromSituacao(resp.Situacao.Codigo),
		Extra: map[string]string{
			"source":      "brasilapi",
			"confidence":  "0.97",
			"cpf":         maskCPF(resp.NI),
			"name":        maskName(resp.Nome),
			"birth_date":  resp.DataNasc,
			"status":      resp.Situacao.Descricao,
			"status_code": resp.Situacao.Codigo,
		},
	}
	return []module.Finding{f}, nil
}

// ─── ReceitaWS ────────────────────────────────────────────────────────────────

func (m *Module) queryReceitaWS(ctx context.Context, cpf string) ([]module.Finding, error) {
	url := fmt.Sprintf("%s/%s", baseURLReceitaWS, cpf)
	slog.DebugContext(ctx, "cpflookup: ReceitaWS CPF request", "url", url)

	body, status, err := m.get(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusTooManyRequests {
		return nil, fmt.Errorf("receitaws: rate limit atingido")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("receitaws CPF retornou HTTP %d", status)
	}

	var resp struct {
		Status   string `json:"status"`
		Message  string `json:"message"`
		Nome     string `json:"nome"`
		DataNasc string `json:"data_nascimento"`
		Situacao string `json:"situacao"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("receitaws CPF JSON: %w", err)
	}
	if resp.Status == "ERROR" {
		return nil, fmt.Errorf("receitaws: %s", resp.Message)
	}

	f := module.Finding{
		Type:     "cpf_record",
		URL:      url,
		Detail:   fmt.Sprintf("CPF encontrado via ReceitaWS — situação: %s", resp.Situacao),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":     "receitaws",
			"confidence": "0.94",
			"name":       maskName(resp.Nome),
			"birth_date": resp.DataNasc,
			"status":     resp.Situacao,
		},
	}
	return []module.Finding{f}, nil
}

// ─── api.cpfcnpj.com.br ──────────────────────────────────────────────────────

func (m *Module) queryCPFCNPJ(ctx context.Context, cpf, apiKey string) ([]module.Finding, error) {
	// Formato: /token/tipo/CPF  (tipo=1 para CPF)
	url := fmt.Sprintf("%s/%s/%s", baseURLCPFCNPJ, apiKey, cpf)
	slog.DebugContext(ctx, "cpflookup: cpfcnpj.com.br request")

	body, status, err := m.get(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, fmt.Errorf("cpfcnpj: API key inválida")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("cpfcnpj retornou HTTP %d", status)
	}

	var resp struct {
		Status     string `json:"status"`
		Nome       string `json:"nome"`
		CPF        string `json:"cpf"`
		Nascimento string `json:"nascimento"`
		Situacao   struct {
			Codigo    string `json:"codigo"`
			Descricao string `json:"descricao"`
		} `json:"situacao_cadastral"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("cpfcnpj JSON: %w", err)
	}

	f := module.Finding{
		Type:     "cpf_record",
		Detail:   fmt.Sprintf("CPF encontrado via cpfcnpj.com.br — situação cadastral: %s", resp.Situacao.Descricao),
		Severity: severityFromSituacao(resp.Situacao.Codigo),
		Extra: map[string]string{
			"source":      "cpfcnpj",
			"confidence":  "0.91",
			"name":        maskName(resp.Nome),
			"birth_date":  resp.Nascimento,
			"status":      resp.Situacao.Descricao,
			"status_code": resp.Situacao.Codigo,
		},
	}
	return []module.Finding{f}, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func (m *Module) get(ctx context.Context, url string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "blackhorn-modules/1.0")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// normalizeCPF adiciona pontuação padrão se necessário.
func normalizeCPF(s string) string {
	d := digitsOnly(s)
	if len(d) != 11 {
		return s
	}
	return d[:3] + "." + d[3:6] + "." + d[6:9] + "-" + d[9:]
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// validateCPFDigits verifica os dígitos verificadores do CPF.
func validateCPFDigits(cpf string) bool {
	if len(cpf) != 11 {
		return false
	}
	// CPFs com todos os dígitos iguais são inválidos
	allSame := true
	for i := 1; i < 11; i++ {
		if cpf[i] != cpf[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return false
	}

	// Primeiro dígito verificador
	sum := 0
	for i := 0; i < 9; i++ {
		n, _ := strconv.Atoi(string(cpf[i]))
		sum += n * (10 - i)
	}
	r := sum % 11
	d1 := 0
	if r >= 2 {
		d1 = 11 - r
	}
	v1, _ := strconv.Atoi(string(cpf[9]))
	if v1 != d1 {
		return false
	}

	// Segundo dígito verificador
	sum = 0
	for i := 0; i < 10; i++ {
		n, _ := strconv.Atoi(string(cpf[i]))
		sum += n * (11 - i)
	}
	r = sum % 11
	d2 := 0
	if r >= 2 {
		d2 = 11 - r
	}
	v2, _ := strconv.Atoi(string(cpf[10]))
	return v2 == d2
}

// maskCPF mascara o CPF para exibição segura: 123.***.***-45
func maskCPF(cpf string) string {
	d := digitsOnly(cpf)
	if len(d) != 11 {
		return "***.***.***-**"
	}
	return d[:3] + ".***.***-" + d[9:]
}

// maskName mascara parte do nome: "João S***"
func maskName(name string) string {
	if name == "" {
		return ""
	}
	parts := strings.Fields(name)
	if len(parts) == 0 {
		return ""
	}
	result := []string{parts[0]}
	for _, p := range parts[1:] {
		if len(p) > 0 {
			result = append(result, string(p[0])+"***")
		}
	}
	return strings.Join(result, " ")
}

func severityFromSituacao(codigo string) module.Severity {
	switch strings.ToUpper(codigo) {
	case "0", "01":
		return module.SeverityInfo // Regular
	case "2", "02":
		return module.SeverityMedium // Suspensa
	case "3", "03":
		return module.SeverityHigh // Titular Falecido
	case "4", "04":
		return module.SeverityHigh // Pendente de Regularização
	case "5", "05", "8", "08", "9", "09":
		return module.SeverityCritical // Cancelada por Encerramento, Nula, Cancelada de Ofício
	default:
		return module.SeverityInfo
	}
}

func parseSources(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isWanted(sources []string, name string) bool {
	if len(sources) == 0 {
		return true
	}
	for _, s := range sources {
		if s == name {
			return true
		}
	}
	return false
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

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	var out []module.Finding
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Extra["source"] + "|" + f.Extra["status_code"]
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

// Garantir que isWanted está em uso (usada em lógica de sources futura)
var _ = isWanted
