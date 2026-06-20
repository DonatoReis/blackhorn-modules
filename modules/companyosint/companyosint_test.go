package companyosint_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/companyosint"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers de teste ────────────────────────────────────────────────────────

type rewriteTransport struct{ base string }

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(r.base, "http://")
	return http.DefaultTransport.RoundTrip(clone)
}

func newTestClient(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: &rewriteTransport{srv.URL}}
}

// CNPJ válido para testes: 11.222.333/0001-81 (gerado com algoritmo)
const validCNPJ = "11222333000181"
const validCNPJFormatted = "11.222.333/0001-81"

// ─── estrutura ────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if companyosint.New().Name() != "companyosint" {
		t.Error("nome incorreto")
	}
}

func TestNew_NotNil(t *testing.T) {
	if companyosint.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := companyosint.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("target vazio deve retornar erro")
	}
}

func TestRun_InvalidCNPJ_AllSameDigits_ReturnsError(t *testing.T) {
	_, err := companyosint.New().Run(context.Background(), module.Input{
		Target: "00000000000000",
	})
	if err == nil {
		t.Fatal("CNPJ com dígitos repetidos deve retornar erro")
	}
}

func TestRun_InvalidCNPJDigits_ReturnsError(t *testing.T) {
	_, err := companyosint.New().Run(context.Background(), module.Input{
		Target: "12345678000100", // dígitos verificadores incorretos
	})
	if err == nil {
		t.Fatal("CNPJ com dígitos verificadores errados deve retornar erro")
	}
}

// ─── BrasilAPI CNPJ ───────────────────────────────────────────────────────────

func brasilAPICNPJHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"cnpj":                         "11222333000181",
		"razao_social":                 "EMPRESA TESTE LTDA",
		"nome_fantasia":                "Empresa Teste",
		"descricao_situacao_cadastral": "ATIVA",
		"data_situacao_cadastral":      "2010-01-15",
		"descricao_natureza_juridica":  "206-2 - Sociedade Empresária Limitada",
		"logradouro":                   "Rua das Flores",
		"numero":                       "100",
		"complemento":                  "Sala 1",
		"cep":                          "01310-100",
		"municipio":                    "São Paulo",
		"uf":                           "SP",
		"email":                        "contato@empresa.com.br",
		"telefone":                     "(11) 3333-4444",
		"capital_social":               500000.0,
		"descricao_porte":              "EMPRESA DE PEQUENO PORTE",
		"cnae_fiscal_descricao":        "Desenvolvimento de programas de computador sob encomenda",
		"qsa": []map[string]interface{}{
			{
				"nome_socio":         "JOÃO DA SILVA",
				"qualificacao_socio": "Sócio-Administrador",
			},
			{
				"nome_socio":         "MARIA OLIVEIRA",
				"qualificacao_socio": "Sócio",
			},
		},
	})
}

func TestRun_BrasilAPI_CNPJ_CompanyRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICNPJHandler))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  validCNPJ,
		Options: map[string]string{"sources": "brasilapi"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via BrasilAPI")
	}

	var companyFound, partnerFound bool
	for _, f := range findings {
		if f.Extra["source"] == "brasilapi" {
			switch f.Type {
			case "company_record":
				companyFound = true
				if f.Extra["razao_social"] != "EMPRESA TESTE LTDA" {
					t.Errorf("razao_social esperada, obteve '%s'", f.Extra["razao_social"])
				}
				if f.Extra["situacao"] != "ATIVA" {
					t.Errorf("situacao esperada 'ATIVA', obteve '%s'", f.Extra["situacao"])
				}
				if f.Severity != module.SeverityInfo {
					t.Errorf("empresa ATIVA deve ser SeverityInfo, obteve %s", f.Severity)
				}
				if f.Extra["confidence"] == "" {
					t.Error("confidence deve estar presente")
				}
				if f.Extra["qsa_count"] != "2" {
					t.Errorf("qsa_count esperado '2', obteve '%s'", f.Extra["qsa_count"])
				}
			case "company_partner":
				partnerFound = true
				if f.Extra["company"] != "EMPRESA TESTE LTDA" {
					t.Error("partner deve referenciar a empresa")
				}
			}
		}
	}
	if !companyFound {
		t.Error("esperava finding 'company_record'")
	}
	if !partnerFound {
		t.Error("esperava finding 'company_partner' para os sócios")
	}
}

func TestRun_BrasilAPI_CNPJ_FormattedInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICNPJHandler))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	// CNPJ com pontuação deve funcionar
	findings, err := m.Run(context.Background(), module.Input{
		Target:  validCNPJFormatted,
		Options: map[string]string{"sources": "brasilapi"},
	})
	if err != nil {
		t.Fatalf("CNPJ formatado não deve dar erro: %v", err)
	}
	_ = findings
}

func TestRun_BrasilAPI_CNPJ_404_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  validCNPJ,
		Options: map[string]string{"sources": "brasilapi"},
	})
	if err != nil {
		t.Fatalf("404 não deve retornar erro: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("404 deve retornar 0 findings, obteve %d", len(findings))
	}
}

// ─── ReceitaWS CNPJ ───────────────────────────────────────────────────────────

func receitaWSCNPJHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":            "OK",
		"cnpj":              "11.222.333/0001-81",
		"nome":              "EMPRESA TESTE LTDA",
		"fantasia":          "Empresa Teste",
		"situacao":          "ATIVA",
		"data_situacao":     "15/01/2010",
		"tipo":              "MATRIZ",
		"natureza_juridica": "206-2 - Sociedade Empresária Limitada",
		"logradouro":        "Rua das Flores",
		"numero":            "100",
		"municipio":         "São Paulo",
		"uf":                "SP",
		"cep":               "01310-100",
		"email":             "contato@empresa.com.br",
		"telefone":          "(11) 3333-4444",
		"capital_social":    "R$ 500.000,00",
		"porte":             "EPP",
		"atividade_principal": []map[string]string{
			{"code": "62.01-5-01", "text": "Desenvolvimento de programas de computador"},
		},
		"qsa": []map[string]string{
			{"nome": "JOÃO DA SILVA", "qual": "Sócio-Administrador"},
		},
	})
}

func TestRun_ReceitaWS_CNPJ_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(receitaWSCNPJHandler))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  validCNPJ,
		Options: map[string]string{"sources": "receitaws"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via ReceitaWS")
	}
	for _, f := range findings {
		if f.Extra["source"] == "receitaws" && f.Type == "company_record" {
			if f.Extra["atividade_principal"] != "Desenvolvimento de programas de computador" {
				t.Errorf("atividade incorreta: '%s'", f.Extra["atividade_principal"])
			}
		}
	}
}

func TestRun_ReceitaWS_CNPJ_ErrorStatus_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ERROR",
			"message": "CNPJ inválido",
		})
	}))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  validCNPJ,
		Options: map[string]string{"sources": "receitaws"},
	})
	if len(findings) != 0 {
		t.Errorf("ERROR status deve resultar em 0 findings, obteve %d", len(findings))
	}
}

// ─── CNPJ.ws ─────────────────────────────────────────────────────────────────

func cnpjWSHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"razao_social":                 "EMPRESA TESTE LTDA",
		"nome_fantasia":                "Empresa Teste",
		"cnpj":                         "11.222.333/0001-81",
		"descricao_situacao_cadastral": "ATIVA",
		"data_inicio_atividade":        "2010-01-15",
		"capital_social":               500000.0,
		"descricao_porte":              "EMPRESA DE PEQUENO PORTE",
		"natureza_juridica":            "206-2",
		"estabelecimento": map[string]interface{}{
			"logradouro": "Rua das Flores",
			"numero":     "100",
			"cep":        "01310100",
			"municipio":  map[string]string{"nome": "São Paulo"},
			"estado":     map[string]string{"sigla": "SP"},
			"email":      "contato@empresa.com.br",
			"telefone1":  "1133334444",
		},
		"socios": []map[string]interface{}{
			{
				"nome":                   "JOÃO DA SILVA",
				"pais":                   map[string]string{"nome": "BRASIL"},
				"qualificacao_socio":     map[string]string{"descricao": "Sócio-Administrador"},
				"data_entrada_sociedade": "2010-01-15",
			},
		},
	})
}

func TestRun_CNPJws_Found_WithSocios(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(cnpjWSHandler))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  validCNPJ,
		Options: map[string]string{"sources": "cnpjws"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via CNPJ.ws")
	}

	var companyFound, partnerFound bool
	for _, f := range findings {
		if f.Extra["source"] == "cnpjws" {
			switch f.Type {
			case "company_record":
				companyFound = true
				if f.Extra["capital_social"] != "500000.00" {
					t.Errorf("capital_social esperado '500000.00', obteve '%s'", f.Extra["capital_social"])
				}
				if f.Extra["socios_count"] != "1" {
					t.Errorf("socios_count esperado '1', obteve '%s'", f.Extra["socios_count"])
				}
			case "company_partner":
				partnerFound = true
				if f.Extra["entry_date"] != "2010-01-15" {
					t.Errorf("entry_date esperado '2010-01-15', obteve '%s'", f.Extra["entry_date"])
				}
			}
		}
	}
	if !companyFound {
		t.Error("esperava finding 'company_record' do cnpjws")
	}
	if !partnerFound {
		t.Error("esperava finding 'company_partner' do cnpjws")
	}
}

// ─── DataJud ─────────────────────────────────────────────────────────────────

func datajudHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"hits": map[string]interface{}{
			"total": map[string]interface{}{"value": 1},
			"hits": []map[string]interface{}{
				{
					"_source": map[string]interface{}{
						"numeroProcesso":  "0001234-56.2023.8.26.0001",
						"classe":          map[string]string{"nome": "Ação de Cobrança"},
						"assuntos":        []map[string]string{{"nome": "Cobrança de Dívida"}},
						"orgaoJulgador":   map[string]string{"nome": "1ª Vara Cível de São Paulo"},
						"dataAjuizamento": "2023-03-15",
						"partes": []map[string]string{
							{"nome": "EMPRESA TESTE LTDA", "polo": "passivo"},
							{"nome": "BANCO XYZ S.A.", "polo": "ativo"},
						},
						"movimentoAtual": "Concluso para sentença",
					},
				},
			},
		},
	})
}

func TestRun_DataJud_WithKey_JudicialProcess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(datajudHandler))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: validCNPJ,
		Options: map[string]string{
			"sources":     "datajud",
			"datajud_key": "test-key",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via DataJud")
	}

	for _, f := range findings {
		if f.Type == "judicial_process" {
			if f.Extra["process_number"] != "0001234-56.2023.8.26.0001" {
				t.Errorf("process_number incorreto: '%s'", f.Extra["process_number"])
			}
			if !strings.Contains(f.Extra["parties"], "EMPRESA TESTE LTDA") {
				t.Error("parties deve conter EMPRESA TESTE LTDA")
			}
			if f.Extra["confidence"] == "" {
				t.Error("confidence deve estar presente")
			}
			if f.Severity != module.SeverityMedium {
				t.Errorf("processo deve ser SeverityMedium, obteve %s", f.Severity)
			}
		}
	}
}

func TestRun_DataJud_NoKey_NoFindings(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: validCNPJ,
		Options: map[string]string{
			"sources": "datajud",
			// sem datajud_key
		},
	})
	if called {
		t.Error("DataJud não deve ser chamado sem API key")
	}
	if len(findings) != 0 {
		t.Errorf("sem key esperava 0 findings, obteve %d", len(findings))
	}
}

// ─── Portal da Transparência — Contratos ─────────────────────────────────────

func transparenciaContratosHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]map[string]interface{}{
		{
			"id":                 1234567,
			"numero":             "01/2023",
			"modalidade":         "Pregão Eletrônico",
			"objeto":             "Prestação de serviços de TI",
			"valor":              2500000.0,
			"dataInicioVigencia": "2023-01-01",
			"dataFimVigencia":    "2023-12-31",
			"unidadeGestora": map[string]string{
				"nome": "EMPRESA TESTE LTDA",
				"cnpj": "11222333000181",
			},
			"orgaoVinculado": map[string]string{
				"nome": "Ministério da Fazenda",
			},
		},
	})
}

func TestRun_Licitacoes_GovernmentContract(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(transparenciaContratosHandler))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  validCNPJ,
		Options: map[string]string{"sources": "licitacoes"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via Portal Transparência")
	}

	for _, f := range findings {
		if f.Type == "government_contract" {
			if !strings.Contains(f.Extra["object"], "TI") {
				t.Error("object deve mencionar TI")
			}
			if f.Extra["value"] != "2500000.00" {
				t.Errorf("value esperado '2500000.00', obteve '%s'", f.Extra["value"])
			}
			if f.Severity != module.SeverityMedium {
				t.Errorf("contrato > 1M deve ser SeverityMedium, obteve %s", f.Severity)
			}
		}
	}
}

func TestRun_Licitacoes_NotFound_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  validCNPJ,
		Options: map[string]string{"sources": "licitacoes"},
	})
	if err != nil {
		t.Fatalf("404 não deve retornar erro: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("404 deve retornar 0 findings, obteve %d", len(findings))
	}
}

// ─── Severity da situação ─────────────────────────────────────────────────────

func TestRun_InactiveCNPJ_HighSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"cnpj":                         "11222333000181",
			"razao_social":                 "EMPRESA INAPTA LTDA",
			"nome_fantasia":                "",
			"descricao_situacao_cadastral": "INAPTA",
			"data_situacao_cadastral":      "2020-01-01",
			"descricao_natureza_juridica":  "206-2",
			"capital_social":               0.0,
			"descricao_porte":              "ME",
			"logradouro":                   "", "numero": "", "municipio": "", "uf": "", "cep": "",
		})
	}))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  validCNPJ,
		Options: map[string]string{"sources": "brasilapi"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Type == "company_record" && f.Extra["situacao"] == "INAPTA" {
			if f.Severity != module.SeverityHigh {
				t.Errorf("empresa INAPTA deve ser SeverityHigh, obteve %s", f.Severity)
			}
		}
	}
}

// ─── confidence e detail ─────────────────────────────────────────────────────

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICNPJHandler))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  validCNPJ,
		Options: map[string]string{"sources": "brasilapi"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICNPJHandler))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  validCNPJ,
		Options: map[string]string{"sources": "brasilapi"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Errorf("finding sem Detail: %+v", f)
		}
	}
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestRun_Dedup_NoDuplicates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICNPJHandler))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  validCNPJ,
		Options: map[string]string{"sources": "brasilapi"},
	})
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.Type + "|" + f.Extra["source"] + "|" + f.Extra["partner_name"]
		if seen[key] {
			t.Errorf("finding duplicado: %s", key)
		}
		seen[key] = true
	}
}

// ─── context cancelado ────────────────────────────────────────────────────────

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv := httptest.NewServer(http.HandlerFunc(brasilAPICNPJHandler))
	defer srv.Close()

	m := companyosint.NewWithClient(newTestClient(srv))
	_, _ = m.Run(ctx, module.Input{
		Target:  validCNPJ,
		Options: map[string]string{"sources": "brasilapi"},
	})
}
