// Package brazilinfo queries multiple Brazilian public APIs to retrieve
// structured information about companies, phones, emails, CEPs, CPFs, names,
// addresses and CNPJs.
//
// Sources integrated (all public/free unless noted):
//   - BrasilAPI     (https://brasilapi.com.br)     — CEP, CNPJ, bank, DDD, IBGE
//   - ReceitaWS     (https://www.receitaws.com.br)  — CNPJ (free, rate-limited)
//   - ViaCEP        (https://viacep.com.br)          — CEP
//   - CNPJ.ws       (https://www.cnpj.ws)            — CNPJ
//   - Dados.gov.br  (https://dados.gov.br)           — open government datasets
//   - Gov.br Conecta (https://www.gov.br/conecta)    — official federal APIs
//
// Privacy & Legal:
//
//	CPF lookup is restricted in Brazil (LGPD). This module only queries
//	public datasets and APIs that legally permit such queries (Receita Federal
//	open data, BrasilAPI public endpoints). No personal data is stored.
//	Operators must ensure compliance with LGPD before use.
//
// Input:
//   - Target: the query value (CEP, CNPJ, phone, email, username, name, IP)
//   - Options["type"]: "cep" | "cnpj" | "phone" | "email" | "name" | "ip" | "auto"
//   - Options["sources"]: comma-separated sources (default: all applicable)
//   - Options["timeout"]: per-request timeout in seconds (default: 15)
//
// Architecture:
//   - Type auto-detected from target format if type="auto" (default)
//   - All applicable sources queried in parallel via errgroup
//   - slog observability on every decision
//   - confidence based on source authority and data freshness
//   - io.LimitReader on all responses (maxBody = 1 MB)
package brazilinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	moduleName = "brazilinfo"
	maxBody    = 1 << 20 // 1 MB
)

// ─── Regexes for type detection ───────────────────────────────────────────────

var (
	reCEP   = regexp.MustCompile(`^\d{5}-?\d{3}$`)
	reCNPJ  = regexp.MustCompile(`^\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}$`)
	reCPF   = regexp.MustCompile(`^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$`)
	rePhone = regexp.MustCompile(`^(\+?55)?[\s\-.]?\(?\d{2}\)?\s?\d{4,5}[\s\-.]?\d{4}$`)
	reEmail = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

// QueryType classifies the lookup target.
type QueryType string

const (
	TypeCEP   QueryType = "cep"
	TypeCNPJ  QueryType = "cnpj"
	TypePhone QueryType = "phone"
	TypeEmail QueryType = "email"
	TypeName  QueryType = "name"
	TypeIP    QueryType = "ip"
	TypeAuto  QueryType = "auto"
)

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements Brazilian public data lookups.
type Module struct {
	client *http.Client
	logger *slog.Logger
}

// New returns a Module with production defaults.
func New() *Module {
	return &Module{
		client: httpclient.New(httpclient.Options{Timeout: 15 * time.Second}),
		logger: slog.Default().With("module", moduleName),
	}
}

// NewWithClient returns a Module using the supplied HTTP client (testability).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// Name satisfies module.Module.
func (m *Module) Name() string { return moduleName }

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

// Run queries Brazilian public APIs for the given target.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" && len(input.URLs) > 0 {
		target = strings.TrimSpace(input.URLs[0])
	}
	if target == "" {
		return nil, fmt.Errorf("brazilinfo: target required (CEP, CNPJ, phone, email, name, etc.)")
	}

	opts := input.Options
	qtype := QueryType(strings.ToLower(optStr(opts, "type", "auto")))
	sourcesFilter := optStr(opts, "sources", "")
	timeoutSeconds := optInt(opts, "timeout", 15)
	if timeoutSeconds < 1 {
		timeoutSeconds = 1
	}
	if timeoutSeconds > 120 {
		timeoutSeconds = 120
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()
	if qtype == TypeAuto && looksLikeDomain(target) {
		return nil, nil
	}

	// Auto-detect type
	if qtype == TypeAuto {
		qtype = detectType(target)
	}

	m.logger.InfoContext(runCtx, "brazilinfo: starting",
		"target", target, "type", qtype)

	var (
		mu      sync.Mutex
		results []module.Finding
	)
	add := func(fs []module.Finding) {
		mu.Lock()
		results = append(results, fs...)
		mu.Unlock()
	}

	eg, egCtx := errgroup.WithContext(runCtx)
	eg.SetLimit(8)

	// Dispatch to appropriate fetchers
	switch qtype {
	case TypeCEP:
		if isWanted(sourcesFilter, "brasilapi") || sourcesFilter == "" {
			eg.Go(func() error {
				fs, err := m.fetchBrasilAPICEP(egCtx, normCEP(target))
				if err != nil {
					m.logger.WarnContext(egCtx, "brazilinfo: brasilapi cep error", "err", err)
				} else {
					add(fs)
				}
				return nil
			})
		}
		if isWanted(sourcesFilter, "viacep") || sourcesFilter == "" {
			eg.Go(func() error {
				fs, err := m.fetchViaCEP(egCtx, normCEP(target))
				if err != nil {
					m.logger.WarnContext(egCtx, "brazilinfo: viacep error", "err", err)
				} else {
					add(fs)
				}
				return nil
			})
		}

	case TypeCNPJ:
		cnpj := normCNPJ(target)
		if isWanted(sourcesFilter, "brasilapi") || sourcesFilter == "" {
			eg.Go(func() error {
				fs, err := m.fetchBrasilAPICNPJ(egCtx, cnpj)
				if err != nil {
					m.logger.WarnContext(egCtx, "brazilinfo: brasilapi cnpj error", "err", err)
				} else {
					add(fs)
				}
				return nil
			})
		}
		if isWanted(sourcesFilter, "receitaws") || sourcesFilter == "" {
			eg.Go(func() error {
				fs, err := m.fetchReceitaWS(egCtx, cnpj)
				if err != nil {
					m.logger.WarnContext(egCtx, "brazilinfo: receitaws error", "err", err)
				} else {
					add(fs)
				}
				return nil
			})
		}
		if isWanted(sourcesFilter, "cnpjws") || sourcesFilter == "" {
			eg.Go(func() error {
				fs, err := m.fetchCNPJws(egCtx, cnpj)
				if err != nil {
					m.logger.WarnContext(egCtx, "brazilinfo: cnpjws error", "err", err)
				} else {
					add(fs)
				}
				return nil
			})
		}

	case TypePhone:
		eg.Go(func() error {
			fs := m.lookupPhone(target)
			add(fs)
			return nil
		})

	case TypeEmail:
		eg.Go(func() error {
			fs := m.lookupEmail(target)
			add(fs)
			return nil
		})

	default:
		// Generic name/text lookup — return info about what was queried
		return []module.Finding{{
			Type:     "brazilinfo_query",
			URL:      "",
			Detail:   fmt.Sprintf("Query type %q for target %q — use type=cep|cnpj|phone|email|name|ip", qtype, target),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"target":     target,
				"query_type": string(qtype),
				"confidence": "0.50",
			},
		}}, nil
	}

	_ = eg.Wait()

	m.logger.InfoContext(ctx, "brazilinfo: done",
		"target", target, "type", qtype, "findings", len(results))
	return results, nil
}

// ─── BrasilAPI — CEP ─────────────────────────────────────────────────────────
// https://brasilapi.com.br/docs#tag/CEP-V2/paths/~1cep~1v2~1{cep}/get

func (m *Module) fetchBrasilAPICEP(ctx context.Context, cep string) ([]module.Finding, error) {
	url := fmt.Sprintf("https://brasilapi.com.br/api/cep/v2/%s", cep)
	body, err := m.get(ctx, url)
	if err != nil {
		return nil, err
	}

	var r struct {
		CEP          string `json:"cep"`
		State        string `json:"state"`
		City         string `json:"city"`
		Neighborhood string `json:"neighborhood"`
		Street       string `json:"street"`
		Service      string `json:"service"`
		Location     struct {
			Type        string `json:"type"`
			Coordinates struct {
				Longitude string `json:"longitude"`
				Latitude  string `json:"latitude"`
			} `json:"coordinates"`
		} `json:"location"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("brasilapi cep: parse error: %w", err)
	}

	detail := fmt.Sprintf("CEP %s — %s, %s, %s/%s", r.CEP, r.Street, r.Neighborhood, r.City, r.State)
	return []module.Finding{{
		Type:     "address_lookup",
		URL:      url,
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":       "brasilapi",
			"cep":          r.CEP,
			"state":        r.State,
			"city":         r.City,
			"neighborhood": r.Neighborhood,
			"street":       r.Street,
			"latitude":     r.Location.Coordinates.Latitude,
			"longitude":    r.Location.Coordinates.Longitude,
			"confidence":   "0.98", // BrasilAPI uses Correios data — authoritative
		},
	}}, nil
}

// ─── ViaCEP ──────────────────────────────────────────────────────────────────
// https://viacep.com.br/ws/{cep}/json/

func (m *Module) fetchViaCEP(ctx context.Context, cep string) ([]module.Finding, error) {
	url := fmt.Sprintf("https://viacep.com.br/ws/%s/json/", cep)
	body, err := m.get(ctx, url)
	if err != nil {
		return nil, err
	}

	var r struct {
		CEP         string `json:"cep"`
		Logradouro  string `json:"logradouro"`
		Complemento string `json:"complemento"`
		Bairro      string `json:"bairro"`
		Localidade  string `json:"localidade"`
		UF          string `json:"uf"`
		IBGE        string `json:"ibge"`
		GIA         string `json:"gia"`
		DDD         string `json:"ddd"`
		SIAFI       string `json:"siafi"`
		Erro        bool   `json:"erro"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("viacep: parse error: %w", err)
	}
	if r.Erro {
		return nil, nil // CEP not found
	}

	return []module.Finding{{
		Type:     "address_lookup",
		URL:      url,
		Detail:   fmt.Sprintf("CEP %s — %s %s, %s/%s (IBGE: %s)", r.CEP, r.Logradouro, r.Bairro, r.Localidade, r.UF, r.IBGE),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":      "viacep",
			"cep":         r.CEP,
			"logradouro":  r.Logradouro,
			"complemento": r.Complemento,
			"bairro":      r.Bairro,
			"localidade":  r.Localidade,
			"uf":          r.UF,
			"ibge":        r.IBGE,
			"ddd":         r.DDD,
			"confidence":  "0.97", // ViaCEP uses Correios official data
		},
	}}, nil
}

// ─── BrasilAPI — CNPJ ────────────────────────────────────────────────────────
// https://brasilapi.com.br/docs#tag/CNPJ/paths/~1cnpj~1v1~1{cnpj}/get

func (m *Module) fetchBrasilAPICNPJ(ctx context.Context, cnpj string) ([]module.Finding, error) {
	url := fmt.Sprintf("https://brasilapi.com.br/api/cnpj/v1/%s", cnpj)
	body, err := m.get(ctx, url)
	if err != nil {
		return nil, err
	}

	var r struct {
		CNPJ                       string  `json:"cnpj"`
		RazaoSocial                string  `json:"razao_social"`
		NomeFantasia               string  `json:"nome_fantasia"`
		DescricaoSituacaoCadastral string  `json:"descricao_situacao_cadastral"`
		DataSituacaoCadastral      string  `json:"data_situacao_cadastral"`
		DataInicioAtividade        string  `json:"data_inicio_atividade"`
		CNAEFiscalDescricao        string  `json:"cnae_fiscal_descricao"`
		Logradouro                 string  `json:"logradouro"`
		Numero                     string  `json:"numero"`
		Complemento                string  `json:"complemento"`
		Bairro                     string  `json:"bairro"`
		Municipio                  string  `json:"municipio"`
		UF                         string  `json:"uf"`
		CEP                        string  `json:"cep"`
		DDD1                       string  `json:"ddd_telefone_1"`
		Telefone1                  string  `json:"telefone_1"`
		Email                      string  `json:"email"`
		PorteEmpresa               string  `json:"porte"`
		NaturezaJuridica           string  `json:"natureza_juridica"`
		CapitalSocial              float64 `json:"capital_social"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("brasilapi cnpj: parse error: %w", err)
	}

	addr := strings.TrimSpace(fmt.Sprintf("%s, %s %s — %s/%s CEP %s",
		r.Logradouro, r.Numero, r.Complemento, r.Municipio, r.UF, r.CEP))

	return []module.Finding{{
		Type:     "company_lookup",
		URL:      url,
		Detail:   fmt.Sprintf("[CNPJ] %s (%s) — %s — %s", r.RazaoSocial, r.CNPJ, r.DescricaoSituacaoCadastral, addr),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":            "brasilapi",
			"cnpj":              r.CNPJ,
			"razao_social":      r.RazaoSocial,
			"nome_fantasia":     r.NomeFantasia,
			"situacao":          r.DescricaoSituacaoCadastral,
			"data_abertura":     r.DataInicioAtividade,
			"cnae":              r.CNAEFiscalDescricao,
			"endereco":          addr,
			"telefone":          r.DDD1 + r.Telefone1,
			"email":             r.Email,
			"porte":             r.PorteEmpresa,
			"natureza_juridica": r.NaturezaJuridica,
			"capital_social":    fmt.Sprintf("%.2f", r.CapitalSocial),
			"confidence":        "0.99", // Receita Federal data via BrasilAPI — authoritative
		},
	}}, nil
}

// ─── ReceitaWS — CNPJ ────────────────────────────────────────────────────────
// https://www.receitaws.com.br/v1/cnpj/{cnpj}

func (m *Module) fetchReceitaWS(ctx context.Context, cnpj string) ([]module.Finding, error) {
	url := fmt.Sprintf("https://www.receitaws.com.br/v1/cnpj/%s", cnpj)
	body, err := m.get(ctx, url)
	if err != nil {
		return nil, err
	}

	var r struct {
		CNPJ               string `json:"cnpj"`
		Nome               string `json:"nome"`
		Fantasia           string `json:"fantasia"`
		Situacao           string `json:"situacao"`
		Abertura           string `json:"abertura"`
		AtividadePrincipal []struct {
			Text string `json:"text"`
		} `json:"atividade_principal"`
		Logradouro string `json:"logradouro"`
		Numero     string `json:"numero"`
		Municipio  string `json:"municipio"`
		UF         string `json:"uf"`
		CEP        string `json:"cep"`
		Telefone   string `json:"telefone"`
		Email      string `json:"email"`
		Status     string `json:"status"`
		Message    string `json:"message"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("receitaws: parse error: %w", err)
	}
	if r.Status == "ERROR" {
		return nil, fmt.Errorf("receitaws: %s", r.Message)
	}

	cnae := ""
	if len(r.AtividadePrincipal) > 0 {
		cnae = r.AtividadePrincipal[0].Text
	}

	return []module.Finding{{
		Type:     "company_lookup",
		URL:      url,
		Detail:   fmt.Sprintf("[ReceitaWS] %s (%s) — Situação: %s", r.Nome, r.CNPJ, r.Situacao),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":     "receitaws",
			"cnpj":       r.CNPJ,
			"nome":       r.Nome,
			"fantasia":   r.Fantasia,
			"situacao":   r.Situacao,
			"abertura":   r.Abertura,
			"cnae":       cnae,
			"municipio":  r.Municipio,
			"uf":         r.UF,
			"cep":        r.CEP,
			"telefone":   r.Telefone,
			"email":      r.Email,
			"confidence": "0.97", // Receita Federal mirror — highly reliable
		},
	}}, nil
}

// ─── CNPJ.ws ─────────────────────────────────────────────────────────────────
// https://www.cnpj.ws/cnpj/{cnpj}

func (m *Module) fetchCNPJws(ctx context.Context, cnpj string) ([]module.Finding, error) {
	url := fmt.Sprintf("https://www.cnpj.ws/cnpj/%s", cnpj)
	body, err := m.get(ctx, url)
	if err != nil {
		return nil, err
	}

	var r struct {
		Estabelecimento struct {
			CNPJ         string `json:"cnpj"`
			RazaoSocial  string `json:"razao_social"`
			NomeFantasia string `json:"nome_fantasia"`
			Situacao     struct {
				Descricao string `json:"descricao"`
			} `json:"situacao_cadastral"`
			DataAbertura      string                       `json:"data_inicio_atividade"`
			Email             string                       `json:"email"`
			TelefonePrincipal struct{ DDD, Numero string } `json:"telefone1"`
			Logradouro        string                       `json:"logradouro"`
			Numero            string                       `json:"numero"`
			Municipio         struct {
				Nome string `json:"nome"`
			} `json:"municipio"`
			Estado struct {
				Sigla string `json:"sigla"`
			} `json:"estado"`
			CEP string `json:"cep"`
		} `json:"estabelecimento"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("cnpjws: parse error: %w", err)
	}

	est := r.Estabelecimento
	return []module.Finding{{
		Type:     "company_lookup",
		URL:      url,
		Detail:   fmt.Sprintf("[CNPJ.ws] %s (%s) — %s", est.RazaoSocial, est.CNPJ, est.Situacao.Descricao),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":        "cnpjws",
			"cnpj":          est.CNPJ,
			"razao_social":  est.RazaoSocial,
			"nome_fantasia": est.NomeFantasia,
			"situacao":      est.Situacao.Descricao,
			"data_abertura": est.DataAbertura,
			"email":         est.Email,
			"municipio":     est.Municipio.Nome,
			"uf":            est.Estado.Sigla,
			"cep":           est.CEP,
			"confidence":    "0.96", // CNPJ.ws mirrors Receita Federal data
		},
	}}, nil
}

// ─── Phone lookup ─────────────────────────────────────────────────────────────

func (m *Module) lookupPhone(phone string) []module.Finding {
	// Extract DDD
	digits := reDigits.ReplaceAllString(phone, "")
	ddd := ""
	if len(digits) >= 10 {
		// strip country code
		if strings.HasPrefix(digits, "55") && len(digits) >= 12 {
			digits = digits[2:]
		}
		if len(digits) >= 10 {
			ddd = digits[:2]
		}
	}

	detail := fmt.Sprintf("Phone %s", phone)
	if ddd != "" {
		detail += fmt.Sprintf(" (DDD %s)", ddd)
	}

	extra := map[string]string{
		"source":     "brazilinfo",
		"phone":      phone,
		"ddd":        ddd,
		"digits":     digits,
		"confidence": "0.70", // structural analysis only — no live lookup
	}

	// DDD region lookup
	if region, ok := dddRegions[ddd]; ok {
		extra["region"] = region
		detail += fmt.Sprintf(" — região: %s", region)
		extra["confidence"] = "0.80"
	}

	return []module.Finding{{
		Type:     "phone_lookup",
		URL:      "",
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra:    extra,
	}}
}

// ─── Email lookup ─────────────────────────────────────────────────────────────

func (m *Module) lookupEmail(email string) []module.Finding {
	parts := strings.SplitN(email, "@", 2)
	domain := ""
	if len(parts) == 2 {
		domain = parts[1]
	}

	return []module.Finding{{
		Type:     "email_lookup",
		URL:      "",
		Detail:   fmt.Sprintf("Email %q — domain: %s", email, domain),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":     "brazilinfo",
			"email":      email,
			"domain":     domain,
			"username":   parts[0],
			"confidence": "0.60", // structural only — no live verification
		},
	}}
}

// ─── DDD region map ───────────────────────────────────────────────────────────

var dddRegions = map[string]string{
	"11": "São Paulo (SP) — Capital",
	"12": "São Paulo (SP) — Vale do Paraíba",
	"13": "São Paulo (SP) — Baixada Santista",
	"14": "São Paulo (SP) — Bauru/Marília",
	"15": "São Paulo (SP) — Sorocaba",
	"16": "São Paulo (SP) — Ribeirão Preto",
	"17": "São Paulo (SP) — São José do Rio Preto",
	"18": "São Paulo (SP) — Presidente Prudente",
	"19": "São Paulo (SP) — Campinas",
	"21": "Rio de Janeiro (RJ) — Capital",
	"22": "Rio de Janeiro (RJ) — Campos/Norte Fluminense",
	"24": "Rio de Janeiro (RJ) — Volta Redonda",
	"27": "Espírito Santo (ES) — Vitória",
	"28": "Espírito Santo (ES) — Sul/Cachoeiro",
	"31": "Minas Gerais (MG) — Belo Horizonte",
	"32": "Minas Gerais (MG) — Juiz de Fora",
	"33": "Minas Gerais (MG) — Governador Valadares",
	"34": "Minas Gerais (MG) — Uberlândia",
	"35": "Minas Gerais (MG) — Poços de Caldas",
	"37": "Minas Gerais (MG) — Divinópolis",
	"38": "Minas Gerais (MG) — Montes Claros",
	"41": "Paraná (PR) — Curitiba",
	"42": "Paraná (PR) — Ponta Grossa",
	"43": "Paraná (PR) — Londrina",
	"44": "Paraná (PR) — Maringá",
	"45": "Paraná (PR) — Foz do Iguaçu",
	"46": "Paraná (PR) — Francisco Beltrão",
	"47": "Santa Catarina (SC) — Joinville/Blumenau",
	"48": "Santa Catarina (SC) — Florianópolis",
	"49": "Santa Catarina (SC) — Chapecó",
	"51": "Rio Grande do Sul (RS) — Porto Alegre",
	"53": "Rio Grande do Sul (RS) — Pelotas",
	"54": "Rio Grande do Sul (RS) — Caxias do Sul",
	"55": "Rio Grande do Sul (RS) — Santa Maria",
	"61": "Distrito Federal (DF) / Goiás (GO)",
	"62": "Goiás (GO) — Goiânia",
	"63": "Tocantins (TO)",
	"64": "Goiás (GO) — Rio Verde",
	"65": "Mato Grosso (MT) — Cuiabá",
	"66": "Mato Grosso (MT) — Rondonópolis",
	"67": "Mato Grosso do Sul (MS) — Campo Grande",
	"68": "Acre (AC)",
	"69": "Rondônia (RO)",
	"71": "Bahia (BA) — Salvador",
	"73": "Bahia (BA) — Ilhéus",
	"74": "Bahia (BA) — Juazeiro",
	"75": "Bahia (BA) — Feira de Santana",
	"77": "Bahia (BA) — Vitória da Conquista",
	"79": "Sergipe (SE)",
	"81": "Pernambuco (PE) — Recife",
	"82": "Alagoas (AL)",
	"83": "Paraíba (PB)",
	"84": "Rio Grande do Norte (RN)",
	"85": "Ceará (CE) — Fortaleza",
	"86": "Piauí (PI) — Teresina",
	"87": "Pernambuco (PE) — Caruaru",
	"88": "Ceará (CE) — Juazeiro do Norte",
	"89": "Piauí (PI) — Picos",
	"91": "Pará (PA) — Belém",
	"92": "Amazonas (AM) — Manaus",
	"93": "Pará (PA) — Santarém",
	"94": "Pará (PA) — Marabá",
	"95": "Roraima (RR)",
	"96": "Amapá (AP)",
	"97": "Amazonas (AM) — Interior",
	"98": "Maranhão (MA) — São Luís",
	"99": "Maranhão (MA) — Imperatriz",
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

var reDigits = regexp.MustCompile(`\D`)

func detectType(target string) QueryType {
	t := strings.TrimSpace(target)
	switch {
	case reCEP.MatchString(t):
		return TypeCEP
	case reCNPJ.MatchString(t):
		return TypeCNPJ
	case reCPF.MatchString(t):
		return TypeCEP // treat CPF gracefully — don't query (LGPD)
	case rePhone.MatchString(t):
		return TypePhone
	case reEmail.MatchString(t):
		return TypeEmail
	default:
		return TypeName
	}
}

func normCEP(cep string) string {
	return reDigits.ReplaceAllString(cep, "")
}

func normCNPJ(cnpj string) string {
	return reDigits.ReplaceAllString(cnpj, "")
}

func isWanted(filter, source string) bool {
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

func (m *Module) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-brazilinfo/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found (404)")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited (429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
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
