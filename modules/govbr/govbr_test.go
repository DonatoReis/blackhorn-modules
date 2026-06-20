package govbr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// rewriteTransport redireciona qualquer request ao servidor de teste.
type rewriteTransport struct{ base string }

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(r.base, "http://")
	return http.DefaultTransport.RoundTrip(clone)
}

func clientFor(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: &rewriteTransport{base: srv.URL}}
}

// ─── Testes de detectTargetType ───────────────────────────────────────────────

func TestDetectTargetType(t *testing.T) {
	cases := map[string]TargetType{
		"01310-100":          TargetCEP,
		"01310100":           TargetCEP,
		"11222333000181":     TargetCNPJ,
		"11.222.333/0001-81": TargetCNPJ,
		"USD":                TargetCurrency,
		"EUR":                TargetCurrency,
		"2026":               TargetYear,
		"2024":               TargetYear,
		"3550308":            TargetIBGECode,
		"Banco do Brasil":    TargetText,
	}
	for target, want := range cases {
		if got := detectTargetType(target); got != want {
			t.Errorf("detectTargetType(%q) = %q, want %q", target, got, want)
		}
	}
}

// ─── Testes de BrasilAPI CEP ──────────────────────────────────────────────────

func TestQueryBrasilAPICEP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(brasilAPICEP{
			CEP:          "01310-100",
			State:        "SP",
			City:         "São Paulo",
			Neighborhood: "Bela Vista",
			Street:       "Avenida Paulista",
			Service:      "viacep",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBrasilAPICEP(context.Background(), "01310100")
	if err != nil {
		t.Fatalf("queryBrasilAPICEP: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("esperado 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "cep_address" {
		t.Errorf("tipo esperado 'cep_address', got '%s'", f.Type)
	}
	if f.Extra["city"] != "São Paulo" {
		t.Errorf("city esperada 'São Paulo', got '%s'", f.Extra["city"])
	}
	if f.Extra["confidence"] == "" {
		t.Error("finding sem confidence")
	}
}

func TestQueryBrasilAPICEPNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.queryBrasilAPICEP(context.Background(), "99999999")
	if err == nil {
		t.Error("CEP inválido deve retornar erro")
	}
}

// ─── Testes de BrasilAPI CNPJ ────────────────────────────────────────────────

func TestQueryBrasilAPICNPJ(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(brasilAPICNPJ{
			CNPJ:              "11222333000181",
			RazaoSocial:       "EMPRESA TESTE LTDA",
			NomeFantasia:      "TESTE",
			SituacaoCadastral: "ATIVA",
			CnaeFiscalDesc:    "Desenvolvimento de software",
			Municipio:         "São Paulo",
			UF:                "SP",
			DataAbertura:      "2010-01-01",
			CapitalSocial:     100000.00,
			PorteEmpresa:      "PEQUENA EMPRESA",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBrasilAPICNPJ(context.Background(), "11222333000181")
	if err != nil {
		t.Fatalf("queryBrasilAPICNPJ: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("esperado 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "cnpj_record" {
		t.Errorf("tipo esperado 'cnpj_record', got '%s'", f.Type)
	}
	if f.Extra["situacao"] != "ATIVA" {
		t.Errorf("situação esperada 'ATIVA', got '%s'", f.Extra["situacao"])
	}
}

func TestQueryBrasilAPICNPJInapta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(brasilAPICNPJ{
			CNPJ:              "11222333000181",
			RazaoSocial:       "EMPRESA FECHADA",
			SituacaoCadastral: "INAPTA",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBrasilAPICNPJ(context.Background(), "11222333000181")
	if err != nil {
		t.Fatalf("queryBrasilAPICNPJ INAPTA: %v", err)
	}
	if findings[0].Severity != module.SeverityMedium {
		t.Errorf("INAPTA deve ter severidade Medium, got %s", findings[0].Severity)
	}
}

// ─── Testes de Feriados ───────────────────────────────────────────────────────

func TestQueryFeriados(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]feriadoItem{
			{Date: "2026-01-01", Name: "Confraternização Universal", Type: "national"},
			{Date: "2026-04-21", Name: "Tiradentes", Type: "national"},
			{Date: "2026-09-07", Name: "Independência do Brasil", Type: "national"},
			{Date: "2026-10-12", Name: "Nossa Senhora Aparecida", Type: "national"},
			{Date: "2026-11-02", Name: "Finados", Type: "national"},
			{Date: "2026-11-15", Name: "Proclamação da República", Type: "national"},
			{Date: "2026-12-25", Name: "Natal", Type: "national"},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryFeriados(context.Background(), "2026")
	if err != nil {
		t.Fatalf("queryFeriados: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("esperado 1 finding agregado, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "national_holidays" {
		t.Errorf("tipo esperado 'national_holidays', got '%s'", f.Type)
	}
	if f.Extra["count"] != "7" {
		t.Errorf("count esperado '7', got '%s'", f.Extra["count"])
	}
	if f.Extra["year"] != "2026" {
		t.Errorf("year esperado '2026', got '%s'", f.Extra["year"])
	}
	if f.Extra["confidence"] == "" {
		t.Error("finding sem confidence")
	}
}

func TestQueryFeriadosEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]feriadoItem{})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryFeriados(context.Background(), "1900")
	if err != nil {
		t.Fatalf("queryFeriados empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("lista vazia deve retornar 0 findings, got %d", len(findings))
	}
}

// ─── Testes de Câmbio BCB ─────────────────────────────────────────────────────

func TestQueryBCBCambio(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(bcbCambioResp{
			Value: []struct {
				CotacaoCompra float64 `json:"cotacaoCompra"`
				CotacaoVenda  float64 `json:"cotacaoVenda"`
				DataCotacao   string  `json:"dataHoraCotacao"`
			}{
				{CotacaoCompra: 5.1234, CotacaoVenda: 5.1240, DataCotacao: "2026-06-10 13:00:00"},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBCBCambio(context.Background(), "USD")
	if err != nil {
		t.Fatalf("queryBCBCambio: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("esperado 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "exchange_rate" {
		t.Errorf("tipo esperado 'exchange_rate', got '%s'", f.Type)
	}
	if f.Extra["buy_rate"] == "" {
		t.Error("buy_rate deve estar no extra")
	}
}

func TestQueryBCBCambioEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(bcbCambioResp{Value: nil})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBCBCambio(context.Background(), "XYZ")
	if err != nil {
		t.Fatalf("queryBCBCambio empty: %v", err)
	}
	if len(findings) != 1 || findings[0].Type != "exchange_rate_unavailable" {
		t.Errorf("cotação indisponível deve retornar 'exchange_rate_unavailable', got %v", findings)
	}
}

// ─── Testes de Bancos ─────────────────────────────────────────────────────────

func TestQueryBancos(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]brasilAPIBanco{
			{ISPB: "00000000", Name: "BCO DO BRASIL S.A.", Code: 1, FullName: "Banco do Brasil S.A."},
			{ISPB: "60701190", Name: "ITAÚ UNIBANCO S.A.", Code: 341, FullName: "ITAÚ UNIBANCO S.A."},
			{ISPB: "33172537", Name: "BRADESCO S.A.", Code: 237, FullName: "Banco Bradesco S.A."},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBancos(context.Background(), "brasil")
	if err != nil {
		t.Fatalf("queryBancos: %v", err)
	}
	// Deve encontrar "Banco do Brasil"
	found := false
	for _, f := range findings {
		if f.Type == "bank_record" && strings.Contains(f.Extra["full_name"], "Brasil") {
			found = true
		}
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
	}
	if !found {
		t.Error("deve encontrar Banco do Brasil na busca por 'brasil'")
	}
}

func TestQueryBancosNoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]brasilAPIBanco{
			{ISPB: "00000000", Name: "BCO DO BRASIL S.A.", Code: 1, FullName: "Banco do Brasil S.A."},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBancos(context.Background(), "naoexiste_xyz")
	if err != nil {
		t.Fatalf("queryBancos no match: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("sem match deve retornar 0 findings, got %d", len(findings))
	}
}

// ─── Testes de Portal Transparência ──────────────────────────────────────────

func TestQueryTransparencia(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("chave-api-dados") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode([]transparenciaContrato{
			{
				ID:     12345,
				Numero: "001/2026",
				Fornecedor: struct {
					Nome string `json:"nome"`
					CNPJ string `json:"cnpjFormatado"`
				}{Nome: "EMPRESA TESTE LTDA", CNPJ: "11.222.333/0001-81"},
				Orgao: struct {
					Nome string `json:"nome"`
				}{Nome: "MINISTERIO DA FAZENDA"},
				Valor:    500000.00,
				Vigencia: "2026-01-01",
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryTransparencia(context.Background(), "11222333000181", "test-key")
	if err != nil {
		t.Fatalf("queryTransparencia: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar pelo menos 1 contrato")
	}
	f := findings[0]
	if f.Type != "government_contract" {
		t.Errorf("tipo esperado 'government_contract', got '%s'", f.Type)
	}
	if f.Extra["valor"] == "" {
		t.Error("valor deve estar no extra")
	}
}

func TestQueryTransparenciaHighValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]transparenciaContrato{
			{
				ID:     99999,
				Numero: "BIG/2026",
				Fornecedor: struct {
					Nome string `json:"nome"`
					CNPJ string `json:"cnpjFormatado"`
				}{Nome: "MEGA CORP"},
				Orgao: struct {
					Nome string `json:"nome"`
				}{Nome: "MINISTERIO"},
				Valor:    5_000_000.00, // acima de 1 milhão
				Vigencia: "2026-01-01",
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryTransparencia(context.Background(), "11222333000181", "key")
	if err != nil {
		t.Fatalf("queryTransparencia high value: %v", err)
	}
	if findings[0].Severity != module.SeverityMedium {
		t.Errorf("contrato > 1M deve ter severidade Medium, got %s", findings[0].Severity)
	}
}

// ─── Testes de fluxo completo ─────────────────────────────────────────────────

func TestRunCEP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(brasilAPICEP{
			CEP:     "01310-100",
			State:   "SP",
			City:    "São Paulo",
			Street:  "Avenida Paulista",
			Service: "viacep",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "01310-100",
		Options: map[string]string{"sources": "brasilapi"},
	})
	if err != nil {
		t.Fatalf("Run CEP: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings para CEP")
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
	}
}

func TestRunCurrency(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(bcbCambioResp{
			Value: []struct {
				CotacaoCompra float64 `json:"cotacaoCompra"`
				CotacaoVenda  float64 `json:"cotacaoVenda"`
				DataCotacao   string  `json:"dataHoraCotacao"`
			}{{CotacaoCompra: 5.10, CotacaoVenda: 5.12, DataCotacao: "2026-06-10"}},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "USD",
		Options: map[string]string{"sources": "bcb"},
	})
	if err != nil {
		t.Fatalf("Run currency: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings para moeda")
	}
}

func TestRunEmpty(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Fatal("deve retornar erro para target vazio")
	}
}

func TestRunDomainIsNotApplicable(t *testing.T) {
	m := New()
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("domínio genérico deve ser ignorado: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("domínio não deve disparar consultas de feriados ou bancos: %+v", findings)
	}
}

func TestDedup(t *testing.T) {
	findings := []module.Finding{
		{Type: "cep_address", URL: "https://brasilapi.com.br", Detail: "CEP A"},
		{Type: "cep_address", URL: "https://brasilapi.com.br", Detail: "CEP A"},
		{Type: "cnpj_record", URL: "https://brasilapi.com.br", Detail: "CNPJ B"},
	}
	result := dedup(findings)
	if len(result) != 2 {
		t.Errorf("dedup: esperado 2 únicos, got %d", len(result))
	}
}
