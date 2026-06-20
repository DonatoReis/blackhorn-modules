// Package companyosint realiza OSINT empresarial profundo sobre empresas brasileiras.
//
// Fontes suportadas:
//   - brasilapi      : BrasilAPI CNPJ v1 — dados cadastrais básicos (RF)
//   - receitaws      : ReceitaWS CNPJ — dados expandidos da Receita Federal
//   - cnpjws         : CNPJ.ws — dados detalhados + atividades econômicas
//   - datajud        : DataJud (CNJ) — processos judiciais ativos
//   - cvm            : CVM Open Data — registros na Comissão de Valores Mobiliários
//   - licitacoes     : Portal da Transparência — licitações e contratos federais
//   - socios         : Sócios e quadro societário via Receita Federal open data
//
// Tipos de target detectados automaticamente:
//   - CNPJ           : 14 dígitos
//   - Razão Social   : string com nome da empresa
//
// Options:
//
//	sources      : lista separada por vírgula (padrão: brasilapi,receitaws,cnpjws,datajud,cvm,licitacoes)
//	datajud_key  : API key para DataJud (ou env DATAJUD_API_KEY)
//	max_results  : máximo de processos judiciais (padrão: 10)
package companyosint

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
	"strconv"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	maxBodyBytes   = 1024 * 1024 // 1 MB
	defaultTimeout = 30 * time.Second

	baseURLBrasilAPICNPJ = "https://brasilapi.com.br/api/cnpj/v1"
	baseURLReceitaWSCNPJ = "https://www.receitaws.com.br/v1/cnpj"
	baseURLCNPJws        = "https://publica.cnpj.ws/cnpj"
	baseURLDataJud       = "https://api-publica.datajud.cnj.jus.br/api_publica"
	baseURLCVM           = "https://dados.cvm.gov.br/dados/CIA_ABERTA/CAD/DADOS"
	baseURLTransparencia = "https://api.portaldatransparencia.gov.br/api-de-dados"
)

var (
	reCNPJ       = regexp.MustCompile(`^\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}$`)
	reCNPJDigits = regexp.MustCompile(`^\d{14}$`)
)

// Module implementa module.Module para OSINT empresarial.
type Module struct {
	client *http.Client
}

// New cria um Module com cliente HTTP padrão.
func New() *Module { return &Module{client: &http.Client{Timeout: defaultTimeout}} }

// NewWithClient cria um Module com cliente HTTP injetado (útil em testes).
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "companyosint" }

// Run executa as consultas de OSINT empresarial e retorna os findings.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	if strings.TrimSpace(input.Target) == "" {
		return nil, fmt.Errorf("companyosint: target não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	cnpjDigits := digitsOnly(input.Target)
	looksCNPJ := len(cnpjDigits) == 14 && (reCNPJDigits.MatchString(cnpjDigits) || reCNPJ.MatchString(input.Target))
	isCNPJ := looksCNPJ && validateCNPJDigits(cnpjDigits)

	if looksCNPJ && !isCNPJ {
		// Tem 14 dígitos mas os verificadores são inválidos
		return nil, fmt.Errorf("companyosint: CNPJ '%s' inválido (dígitos verificadores incorretos)", formatCNPJ(cnpjDigits))
	}
	if isCNPJ {
		// Normaliza para apenas dígitos
		input.Target = cnpjDigits
	}
	// Se não parece CNPJ (string de nome), segue como busca por nome

	sources := parseSources(optStr(opts, "sources", "brasilapi,receitaws,cnpjws,datajud,cvm,licitacoes"))
	datajudKey := firstNonEmpty(opts["datajud_key"], os.Getenv("DATAJUD_API_KEY"))
	maxResults := optInt(opts, "max_results", 10)

	slog.InfoContext(ctx, "companyosint: iniciando consultas",
		"target_preview", previewCNPJ(input.Target),
		"sources", sources,
		"is_cnpj", isCNPJ,
	)

	type result struct {
		findings []module.Finding
	}

	ch := make(chan result, len(sources))
	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(5)

	for _, src := range sources {
		src := src
		eg.Go(func() error {
			var ff []module.Finding
			var err error

			switch src {
			case "brasilapi":
				if isCNPJ {
					ff, err = m.queryBrasilAPICNPJ(egCtx, cnpjDigits)
				}
			case "receitaws":
				if isCNPJ {
					ff, err = m.queryReceitaWSCNPJ(egCtx, cnpjDigits)
				}
			case "cnpjws":
				if isCNPJ {
					ff, err = m.queryCNPJws(egCtx, cnpjDigits)
				}
			case "datajud":
				if datajudKey == "" {
					slog.WarnContext(egCtx, "companyosint: datajud ignorado — DATAJUD_API_KEY não configurada")
					return nil
				}
				ff, err = m.queryDataJud(egCtx, input.Target, datajudKey, maxResults)
			case "cvm":
				if isCNPJ {
					ff, err = m.queryCVM(egCtx, cnpjDigits)
				}
			case "licitacoes":
				if isCNPJ {
					ff, err = m.queryLicitacoes(egCtx, cnpjDigits)
				}
			}

			if err != nil {
				slog.WarnContext(egCtx, "companyosint: fonte falhou",
					"source", src, "error", err.Error())
				return nil
			}
			if len(ff) > 0 {
				ch <- result{findings: ff}
			}
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

// ─── BrasilAPI CNPJ v1 ────────────────────────────────────────────────────────

func (m *Module) queryBrasilAPICNPJ(ctx context.Context, cnpj string) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("%s/%s", baseURLBrasilAPICNPJ, cnpj)
	slog.DebugContext(ctx, "companyosint: BrasilAPI CNPJ", "url", apiURL)

	body, status, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("brasilapi cnpj HTTP %d", status)
	}

	var resp struct {
		CNPJ              string  `json:"cnpj"`
		RazaoSocial       string  `json:"razao_social"`
		NomeFantasia      string  `json:"nome_fantasia"`
		SituacaoCadastral string  `json:"descricao_situacao_cadastral"`
		DataSituacao      string  `json:"data_situacao_cadastral"`
		NaturezaJuridica  string  `json:"descricao_natureza_juridica"`
		Logradouro        string  `json:"logradouro"`
		Numero            string  `json:"numero"`
		Complemento       string  `json:"complemento"`
		CEP               string  `json:"cep"`
		Municipio         string  `json:"municipio"`
		UF                string  `json:"uf"`
		Email             string  `json:"email"`
		Telefone          string  `json:"telefone"`
		Capital           float64 `json:"capital_social"`
		Porte             string  `json:"descricao_porte"`
		// BrasilAPI retorna string, mas alguns parsers enviam array
		CnaeFiscal json.RawMessage `json:"cnae_fiscal_descricao"`
		QSA        []struct {
			NomeSocio    string `json:"nome_socio"`
			Qualificacao string `json:"qualificacao_socio"`
		} `json:"qsa"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("brasilapi cnpj JSON: %w", err)
	}
	// CnaeFiscal pode ser string ou array dependendo da versão da API
	var mainCNAE string
	if len(resp.CnaeFiscal) > 0 {
		var cnaes []struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(resp.CnaeFiscal, &cnaes) == nil && len(cnaes) > 0 {
			mainCNAE = cnaes[0].Text
		} else {
			// Tenta como string simples
			_ = json.Unmarshal(resp.CnaeFiscal, &mainCNAE)
		}
	}

	sev := severityFromSituacao(resp.SituacaoCadastral)
	f := module.Finding{
		Type:     "company_record",
		URL:      apiURL,
		Detail:   fmt.Sprintf("Empresa: %s (%s) — situação: %s — porte: %s via BrasilAPI", resp.RazaoSocial, resp.NomeFantasia, resp.SituacaoCadastral, resp.Porte),
		Severity: sev,
		Extra: map[string]string{
			"source":              "brasilapi",
			"confidence":          "0.99",
			"cnpj":                formatCNPJ(cnpj),
			"razao_social":        resp.RazaoSocial,
			"nome_fantasia":       resp.NomeFantasia,
			"situacao":            resp.SituacaoCadastral,
			"data_situacao":       resp.DataSituacao,
			"natureza":            resp.NaturezaJuridica,
			"porte":               resp.Porte,
			"capital_social":      strconv.FormatFloat(resp.Capital, 'f', 2, 64),
			"address":             fmt.Sprintf("%s, %s %s, %s/%s — CEP %s", resp.Logradouro, resp.Numero, resp.Complemento, resp.Municipio, resp.UF, resp.CEP),
			"email":               resp.Email,
			"telefone":            resp.Telefone,
			"qsa_count":           strconv.Itoa(len(resp.QSA)),
			"atividade_principal": mainCNAE,
		},
	}

	findings := []module.Finding{f}

	// Gera findings separados para cada sócio
	for _, s := range resp.QSA {
		sf := module.Finding{
			Type:     "company_partner",
			URL:      apiURL,
			Detail:   fmt.Sprintf("Sócio de %s: %s (%s)", resp.RazaoSocial, s.NomeSocio, s.Qualificacao),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":        "brasilapi",
				"confidence":    "0.99",
				"cnpj":          formatCNPJ(cnpj),
				"partner_name":  s.NomeSocio,
				"qualification": s.Qualificacao,
				"company":       resp.RazaoSocial,
			},
		}
		findings = append(findings, sf)
	}

	return findings, nil
}

// ─── ReceitaWS CNPJ ──────────────────────────────────────────────────────────

func (m *Module) queryReceitaWSCNPJ(ctx context.Context, cnpj string) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("%s/%s", baseURLReceitaWSCNPJ, cnpj)
	slog.DebugContext(ctx, "companyosint: ReceitaWS CNPJ", "url", apiURL)

	body, status, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusTooManyRequests {
		return nil, fmt.Errorf("receitaws: rate limit")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("receitaws cnpj HTTP %d", status)
	}

	var resp struct {
		Status        string `json:"status"`
		Message       string `json:"message"`
		CNPJ          string `json:"cnpj"`
		Nome          string `json:"nome"`
		Fantasia      string `json:"fantasia"`
		Situacao      string `json:"situacao"`
		DataSituacao  string `json:"data_situacao"`
		Tipo          string `json:"tipo"`
		Natureza      string `json:"natureza_juridica"`
		Logradouro    string `json:"logradouro"`
		Numero        string `json:"numero"`
		Municipio     string `json:"municipio"`
		UF            string `json:"uf"`
		CEP           string `json:"cep"`
		Email         string `json:"email"`
		Telefone      string `json:"telefone"`
		Capital       string `json:"capital_social"`
		Porte         string `json:"porte"`
		AtivPrincipal []struct {
			Code string `json:"code"`
			Text string `json:"text"`
		} `json:"atividade_principal"`
		QSA []struct {
			Nome string `json:"nome"`
			Qual string `json:"qual"`
		} `json:"qsa"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("receitaws cnpj JSON: %w", err)
	}
	if resp.Status == "ERROR" {
		return nil, fmt.Errorf("receitaws: %s", resp.Message)
	}

	var mainActivity string
	if len(resp.AtivPrincipal) > 0 {
		mainActivity = resp.AtivPrincipal[0].Text
	}

	f := module.Finding{
		Type:     "company_record",
		URL:      apiURL,
		Detail:   fmt.Sprintf("Empresa: %s (%s) — tipo: %s — situação: %s via ReceitaWS", resp.Nome, resp.Fantasia, resp.Tipo, resp.Situacao),
		Severity: severityFromSituacao(resp.Situacao),
		Extra: map[string]string{
			"source":              "receitaws",
			"confidence":          "0.97",
			"cnpj":                resp.CNPJ,
			"razao_social":        resp.Nome,
			"nome_fantasia":       resp.Fantasia,
			"situacao":            resp.Situacao,
			"data_situacao":       resp.DataSituacao,
			"tipo":                resp.Tipo,
			"natureza":            resp.Natureza,
			"porte":               resp.Porte,
			"capital_social":      resp.Capital,
			"address":             fmt.Sprintf("%s, %s, %s/%s", resp.Logradouro, resp.Numero, resp.Municipio, resp.UF),
			"email":               resp.Email,
			"telefone":            resp.Telefone,
			"atividade_principal": mainActivity,
			"qsa_count":           strconv.Itoa(len(resp.QSA)),
		},
	}
	return []module.Finding{f}, nil
}

// ─── CNPJ.ws ─────────────────────────────────────────────────────────────────

func (m *Module) queryCNPJws(ctx context.Context, cnpj string) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("%s/%s", baseURLCNPJws, cnpj)
	slog.DebugContext(ctx, "companyosint: CNPJ.ws", "url", apiURL)

	body, status, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status == http.StatusTooManyRequests {
		return nil, fmt.Errorf("cnpjws: rate limit")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("cnpjws HTTP %d", status)
	}

	var resp struct {
		RazaoSocial     string  `json:"razao_social"`
		NomeFantasia    string  `json:"nome_fantasia"`
		CNPJ            string  `json:"cnpj"`
		SituacaoCad     string  `json:"descricao_situacao_cadastral"`
		DataAbertura    string  `json:"data_inicio_atividade"`
		Capital         float64 `json:"capital_social"`
		Porte           string  `json:"descricao_porte"`
		NatJuridica     string  `json:"natureza_juridica"`
		Estabelecimento struct {
			Logradouro string `json:"logradouro"`
			Numero     string `json:"numero"`
			CEP        string `json:"cep"`
			Municipio  struct {
				Nome string `json:"nome"`
			} `json:"municipio"`
			Estado struct {
				Sigla string `json:"sigla"`
			} `json:"estado"`
			Email     string `json:"email"`
			Telefone1 string `json:"telefone1"`
		} `json:"estabelecimento"`
		Socios []struct {
			Nome string `json:"nome"`
			Pais struct {
				Nome string `json:"nome"`
			} `json:"pais"`
			Qualificacao struct {
				Descricao string `json:"descricao"`
			} `json:"qualificacao_socio"`
			DataEntrada string `json:"data_entrada_sociedade"`
		} `json:"socios"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("cnpjws JSON: %w", err)
	}

	estab := resp.Estabelecimento
	f := module.Finding{
		Type:     "company_record",
		URL:      apiURL,
		Detail:   fmt.Sprintf("Empresa: %s — abertura: %s — capital social: R$%.2f via CNPJ.ws", resp.RazaoSocial, resp.DataAbertura, resp.Capital),
		Severity: severityFromSituacao(resp.SituacaoCad),
		Extra: map[string]string{
			"source":         "cnpjws",
			"confidence":     "0.96",
			"cnpj":           formatCNPJ(cnpj),
			"razao_social":   resp.RazaoSocial,
			"nome_fantasia":  resp.NomeFantasia,
			"situacao":       resp.SituacaoCad,
			"data_abertura":  resp.DataAbertura,
			"capital_social": strconv.FormatFloat(resp.Capital, 'f', 2, 64),
			"porte":          resp.Porte,
			"natureza":       resp.NatJuridica,
			"email":          estab.Email,
			"telefone":       estab.Telefone1,
			"address":        fmt.Sprintf("%s, %s, %s/%s — CEP %s", estab.Logradouro, estab.Numero, estab.Municipio.Nome, estab.Estado.Sigla, estab.CEP),
			"socios_count":   strconv.Itoa(len(resp.Socios)),
		},
	}

	findings := []module.Finding{f}

	for _, s := range resp.Socios {
		sf := module.Finding{
			Type:     "company_partner",
			URL:      apiURL,
			Detail:   fmt.Sprintf("Sócio de %s: %s (%s) desde %s", resp.RazaoSocial, s.Nome, s.Qualificacao.Descricao, s.DataEntrada),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":        "cnpjws",
				"confidence":    "0.96",
				"cnpj":          formatCNPJ(cnpj),
				"partner_name":  s.Nome,
				"qualification": s.Qualificacao.Descricao,
				"entry_date":    s.DataEntrada,
				"country":       s.Pais.Nome,
				"company":       resp.RazaoSocial,
			},
		}
		findings = append(findings, sf)
	}

	return findings, nil
}

// ─── DataJud (CNJ) — processos judiciais ─────────────────────────────────────

func (m *Module) queryDataJud(ctx context.Context, target, apiKey string, maxResults int) ([]module.Finding, error) {
	// DataJud usa Elasticsearch Query DSL
	// Endpoint público: api_publica.datajud.cnj.jus.br/api_publica/{tribunal}/_search
	// Para busca geral, usa tribunal "tjsp" como exemplo mas aceita qualquer sigla
	// Aqui buscamos em todos os tribunais via endpoint genérico

	type datajudQuery struct {
		Size  int `json:"size"`
		Query struct {
			MultiMatch struct {
				Query  string   `json:"query"`
				Fields []string `json:"fields"`
			} `json:"multi_match"`
		} `json:"query"`
	}

	q := datajudQuery{Size: maxResults}
	q.Query.MultiMatch.Query = target
	q.Query.MultiMatch.Fields = []string{"orgaoJulgador.nome", "partes.nome"}

	bodyBytes, err := json.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("datajud: marshal query: %w", err)
	}

	apiURL := baseURLDataJud + "/tjsp/_search"
	slog.DebugContext(ctx, "companyosint: DataJud processos", "url", apiURL)

	respBody, status, err := m.post(ctx, apiURL, bodyBytes, map[string]string{
		"Authorization": "APIKey " + apiKey,
	})
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, fmt.Errorf("datajud: API key inválida")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("datajud HTTP %d", status)
	}

	var resp struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source struct {
					NumeroProcesso string `json:"numeroProcesso"`
					Classe         struct {
						Nome string `json:"nome"`
					} `json:"classe"`
					Assuntos []struct {
						Nome string `json:"nome"`
					} `json:"assuntos"`
					OrgaoJulgador struct {
						Nome string `json:"nome"`
					} `json:"orgaoJulgador"`
					DataAjuizamento string `json:"dataAjuizamento"`
					Partes          []struct {
						Nome string `json:"nome"`
						Polo string `json:"polo"`
					} `json:"partes"`
					MovimentoAtual string `json:"movimentoAtual"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("datajud JSON: %w", err)
	}

	var findings []module.Finding
	for _, h := range resp.Hits.Hits {
		s := h.Source
		var assuntos []string
		for _, a := range s.Assuntos {
			assuntos = append(assuntos, a.Nome)
		}
		var partes []string
		for _, p := range s.Partes {
			partes = append(partes, fmt.Sprintf("%s (%s)", p.Nome, p.Polo))
		}

		f := module.Finding{
			Type:     "judicial_process",
			URL:      fmt.Sprintf("https://datajud-wiki.cnj.jus.br/api-publica/acesso/processo/%s", s.NumeroProcesso),
			Detail:   fmt.Sprintf("Processo %s — %s — %s (%s) — ajuizado em %s", s.NumeroProcesso, s.Classe.Nome, s.OrgaoJulgador.Nome, s.MovimentoAtual, s.DataAjuizamento),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"source":           "datajud",
				"confidence":       "0.88",
				"process_number":   s.NumeroProcesso,
				"class":            s.Classe.Nome,
				"court":            s.OrgaoJulgador.Nome,
				"filing_date":      s.DataAjuizamento,
				"subjects":         strings.Join(assuntos, "; "),
				"parties":          strings.Join(partes, "; "),
				"current_movement": s.MovimentoAtual,
			},
		}
		findings = append(findings, f)
	}

	if len(findings) > 0 {
		slog.InfoContext(ctx, "companyosint: DataJud processos encontrados",
			"total", resp.Hits.Total.Value,
			"returned", len(findings),
		)
	}

	return findings, nil
}

// ─── CVM Open Data ────────────────────────────────────────────────────────────

func (m *Module) queryCVM(ctx context.Context, cnpj string) ([]module.Finding, error) {
	// CVM disponibiliza CSV, mas também tem endpoint JSON via dados abertos
	apiURL := fmt.Sprintf("%s/cad_cia_aberta.csv", baseURLCVM)
	slog.DebugContext(ctx, "companyosint: CVM consulta CNPJ")

	// Para evitar baixar o CSV inteiro, usamos a API de busca por CNPJ
	searchURL := "https://www.rad.cvm.gov.br/ENET/frmConsultaExternaCVM.aspx/ListarEmpresas"
	bodyBytes, _ := json.Marshal(map[string]string{"cnpj": cnpj})

	respBody, status, err := m.post(ctx, searchURL, bodyBytes, map[string]string{
		"Content-Type": "application/json; charset=utf-8",
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		// Fallback: tenta via API pública de dados abertos CVM
		return m.queryCVMOpenData(ctx, cnpj, apiURL)
	}

	var resp struct {
		D struct {
			Empresas []struct {
				CNPJ   string `json:"CNPJCIA"`
				Nome   string `json:"NOMECOMPANHIA"`
				Codigo string `json:"CODIGOCVM"`
				Tipo   string `json:"TIPO"`
			} `json:"Empresas"`
		} `json:"d"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return m.queryCVMOpenData(ctx, cnpj, apiURL)
	}

	var findings []module.Finding
	for _, emp := range resp.D.Empresas {
		if !strings.Contains(digitsOnly(emp.CNPJ), cnpj) {
			continue
		}
		f := module.Finding{
			Type:     "cvm_registration",
			URL:      fmt.Sprintf("https://www.rad.cvm.gov.br/ENET/frmConsultaExternaCVM.aspx?CodigoCVM=%s", emp.Codigo),
			Detail:   fmt.Sprintf("%s registrada na CVM — código CVM: %s — tipo: %s", emp.Nome, emp.Codigo, emp.Tipo),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":     "cvm",
				"confidence": "0.95",
				"cnpj":       formatCNPJ(cnpj),
				"company":    emp.Nome,
				"cvm_code":   emp.Codigo,
				"type":       emp.Tipo,
			},
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// queryCVMOpenData tenta buscar no conjunto de dados abertos da CVM.
func (m *Module) queryCVMOpenData(ctx context.Context, cnpj, _ string) ([]module.Finding, error) {
	// API de busca por CNPJ no portal dados.cvm.gov.br
	apiURL := fmt.Sprintf("https://dados.cvm.gov.br/api/action/datastore_search?resource_id=f42ee9e7-cd67-4d3a-a41a-a43e36a3c2aa&filters={\"CNPJ_CIA\":\"%s\"}", url.QueryEscape(cnpj))
	slog.DebugContext(ctx, "companyosint: CVM Open Data", "cnpj_prefix", cnpj[:4]+"***")

	body, status, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("cvm open data HTTP %d", status)
	}

	var resp struct {
		Result struct {
			Records []struct {
				CNPJ   string `json:"CNPJ_CIA"`
				Nome   string `json:"DENOM_CIA"`
				Codigo string `json:"CD_CVM"`
				Tipo   string `json:"TP_MERC"`
				Sits   string `json:"SIT"`
			} `json:"records"`
			Total int `json:"total"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("cvm open data JSON: %w", err)
	}

	var findings []module.Finding
	for _, r := range resp.Result.Records {
		f := module.Finding{
			Type:     "cvm_registration",
			Detail:   fmt.Sprintf("%s registrada na CVM — código: %s — situação: %s", r.Nome, r.Codigo, r.Sits),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":     "cvm",
				"confidence": "0.94",
				"cnpj":       formatCNPJ(cnpj),
				"company":    r.Nome,
				"cvm_code":   r.Codigo,
				"type":       r.Tipo,
				"situation":  r.Sits,
			},
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ─── Portal da Transparência — Licitações ─────────────────────────────────────

func (m *Module) queryLicitacoes(ctx context.Context, cnpj string) ([]module.Finding, error) {
	// API do Portal da Transparência para fornecedores/contratações
	apiURL := fmt.Sprintf("%s/contratos?cnpjFornecedor=%s&pagina=1&tamanhoPagina=10", baseURLTransparencia, cnpj)
	slog.DebugContext(ctx, "companyosint: Portal Transparência contratos")

	body, status, err := m.get(ctx, apiURL, map[string]string{
		"Accept": "application/json",
	})
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, fmt.Errorf("transparencia: chave de API necessária")
	}
	if status == http.StatusNotFound || status == http.StatusNoContent {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("transparencia contratos HTTP %d", status)
	}

	var contracts []struct {
		ID         int     `json:"id"`
		Numero     string  `json:"numero"`
		Modalidade string  `json:"modalidade"`
		Objeto     string  `json:"objeto"`
		Valor      float64 `json:"valor"`
		DataInicio string  `json:"dataInicioVigencia"`
		DataFim    string  `json:"dataFimVigencia"`
		Fornecedor struct {
			Nome string `json:"nome"`
			CNPJ string `json:"cnpj"`
		} `json:"unidadeGestora"`
		Orgao struct {
			Nome string `json:"nome"`
		} `json:"orgaoVinculado"`
	}
	if err := json.Unmarshal(body, &contracts); err != nil {
		return nil, fmt.Errorf("transparencia contratos JSON: %w", err)
	}

	var findings []module.Finding
	for _, c := range contracts {
		sev := module.SeverityInfo
		if c.Valor > 1_000_000 {
			sev = module.SeverityMedium // contrato de alto valor — interesse investigativo
		}

		f := module.Finding{
			Type:     "government_contract",
			URL:      fmt.Sprintf("https://www.portaltransparencia.gov.br/contratos/%d", c.ID),
			Detail:   fmt.Sprintf("Contrato federal #%s — %s — R$%.2f (%s a %s) — Órgão: %s", c.Numero, c.Objeto, c.Valor, c.DataInicio, c.DataFim, c.Orgao.Nome),
			Severity: sev,
			Extra: map[string]string{
				"source":       "licitacoes",
				"confidence":   "0.92",
				"cnpj":         formatCNPJ(cnpj),
				"contract_id":  strconv.Itoa(c.ID),
				"contract_num": c.Numero,
				"modality":     c.Modalidade,
				"object":       c.Objeto,
				"value":        strconv.FormatFloat(c.Valor, 'f', 2, 64),
				"start_date":   c.DataInicio,
				"end_date":     c.DataFim,
				"organ":        c.Orgao.Nome,
			},
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func (m *Module) get(ctx context.Context, apiURL string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
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
	return body, resp.StatusCode, err
}

func (m *Module) post(ctx context.Context, apiURL string, bodyData []byte, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyData))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "blackhorn-modules/1.0")
	req.Header.Set("Content-Type", "application/json")
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
	return body, resp.StatusCode, err
}

// validateCNPJDigits valida os dígitos verificadores do CNPJ.
func validateCNPJDigits(cnpj string) bool {
	if len(cnpj) != 14 {
		return false
	}
	// CNPJ com todos dígitos iguais é inválido
	allSame := true
	for i := 1; i < 14; i++ {
		if cnpj[i] != cnpj[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return false
	}

	calcDigit := func(cnpj string, length int) int {
		sum := 0
		pos := length - 7
		for i := length; i >= 1; i-- {
			n, _ := strconv.Atoi(string(cnpj[length-i]))
			sum += n * pos
			pos--
			if pos < 2 {
				pos = 9
			}
		}
		r := sum % 11
		if r < 2 {
			return 0
		}
		return 11 - r
	}

	d1 := calcDigit(cnpj, 12)
	v1, _ := strconv.Atoi(string(cnpj[12]))
	if v1 != d1 {
		return false
	}

	d2 := calcDigit(cnpj, 13)
	v2, _ := strconv.Atoi(string(cnpj[13]))
	return v2 == d2
}

// formatCNPJ formata 14 dígitos como XX.XXX.XXX/XXXX-XX.
func formatCNPJ(cnpj string) string {
	d := digitsOnly(cnpj)
	if len(d) != 14 {
		return cnpj
	}
	return d[:2] + "." + d[2:5] + "." + d[5:8] + "/" + d[8:12] + "-" + d[12:]
}

func previewCNPJ(target string) string {
	d := digitsOnly(target)
	if len(d) >= 8 {
		return d[:4] + "***"
	}
	if len(target) > 20 {
		return target[:20] + "..."
	}
	return target
}

func severityFromSituacao(situacao string) module.Severity {
	s := strings.ToUpper(situacao)
	switch {
	case strings.Contains(s, "ATIVA"), strings.Contains(s, "REGULAR"):
		return module.SeverityInfo
	case strings.Contains(s, "SUSPEN"):
		return module.SeverityMedium
	case strings.Contains(s, "INAPTA"), strings.Contains(s, "BAIXADA"), strings.Contains(s, "CANCEL"):
		return module.SeverityHigh
	case strings.Contains(s, "NULA"):
		return module.SeverityCritical
	default:
		return module.SeverityInfo
	}
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
	if v, ok := opts[key]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	var out []module.Finding
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Extra["source"] + "|" + f.Extra["process_number"] + "|" + f.Extra["partner_name"]
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}
