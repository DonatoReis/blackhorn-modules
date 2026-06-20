package registroempresas

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

// ─── detectTargetType ─────────────────────────────────────────────────────────

func TestDetectTargetTypeCNPJ(t *testing.T) {
	cases := []struct {
		input string
		want  TargetType
	}{
		{"11.222.333/0001-81", TargetCNPJ},
		{"11222333000181", TargetCNPJ},
		{"60.746.948/0001-12", TargetCNPJ},
	}
	for _, tt := range cases {
		got, _ := detectTargetType(tt.input)
		if got != tt.want {
			t.Errorf("detectTargetType(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestDetectTargetTypeCPF(t *testing.T) {
	cases := []struct {
		input string
		want  TargetType
	}{
		{"123.456.789-09", TargetCPF},
		{"12345678909", TargetCPF},
	}
	for _, tt := range cases {
		got, _ := detectTargetType(tt.input)
		if got != tt.want {
			t.Errorf("detectTargetType(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestDetectTargetTypeName(t *testing.T) {
	cases := []string{
		"Empresa Teste LTDA",
		"Petrobras",
		"12345",     // número curto (não 11 nem 14 dígitos)
		"123456789", // 9 dígitos — não é CPF nem CNPJ
	}
	for _, input := range cases {
		got, _ := detectTargetType(input)
		if got != TargetName {
			t.Errorf("detectTargetType(%q) = %v, want TargetName", input, got)
		}
	}
}

// ─── maskCPF ─────────────────────────────────────────────────────────────────

func TestMaskCPF(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"12345678909", "123.***.***-09"},
		{"123.456.789-09", "123.***.***-09"},
	}
	for _, tt := range cases {
		got := maskCPF(tt.input)
		if got != tt.want {
			t.Errorf("maskCPF(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMaskCPFInvalid(t *testing.T) {
	got := maskCPF("abc")
	if got != "***.***.***-**" {
		t.Errorf("maskCPF inválido esperado placeholder, got %q", got)
	}
}

// ─── parseSources ─────────────────────────────────────────────────────────────

func TestParseSourcesAll(t *testing.T) {
	m := parseSources("all")
	if m != nil {
		t.Error("parseSources('all') deve retornar nil (todos habilitados)")
	}
}

func TestParseSourcesEmpty(t *testing.T) {
	m := parseSources("")
	if m != nil {
		t.Error("parseSources('') deve retornar nil")
	}
}

func TestParseSourcesSpecific(t *testing.T) {
	m := parseSources("cnpjws,simples")
	if !m["cnpjws"] || !m["simples"] {
		t.Error("fontes específicas não foram parseadas")
	}
	if m["brasilio"] {
		t.Error("brasilio não deve estar habilitado")
	}
}

// ─── clampMax ────────────────────────────────────────────────────────────────

func TestClampMax(t *testing.T) {
	if clampMax(100, 20) != 20 {
		t.Error("clampMax deve limitar a 20")
	}
	if clampMax(5, 20) != 5 {
		t.Error("clampMax deve retornar valor menor que o limite")
	}
	if clampMax(0, 20) != 20 {
		t.Error("clampMax(0) deve retornar default")
	}
	if clampMax(-1, 20) != 20 {
		t.Error("clampMax negativo deve retornar default")
	}
}

// ─── Validações de entrada ────────────────────────────────────────────────────

func TestEmptyTarget(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Fatal("deve retornar erro para target vazio")
	}
}

func TestCPFRequiresLGPDConsent(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{
		Target:  "12345678909",
		Options: map[string]string{},
	})
	if err == nil {
		t.Fatal("CPF sem lgpd_consent deve retornar erro")
	}
	if !strings.Contains(err.Error(), "lgpd_consent") {
		t.Errorf("erro deve mencionar lgpd_consent, got: %v", err)
	}
}

// ─── CNPJ.ws ─────────────────────────────────────────────────────────────────

func TestQueryCNPJwsActive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"razao_social": "EMPRESA TESTE LTDA",
			"cnpj":         "11222333000181",
			"estabelecimento": map[string]interface{}{
				"situacao_cadastral": map[string]interface{}{
					"descricao": "ATIVA",
				},
			},
			"socios": []map[string]interface{}{
				{
					"nome": "JOAO DA SILVA",
					"qualificacao_socio": map[string]interface{}{
						"descricao": "SÓCIO-ADMINISTRADOR",
					},
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryCNPJws(context.Background(), "11222333000181")
	if err != nil {
		t.Fatalf("queryCNPJws: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("deve retornar pelo menos 2 findings (empresa + sócio), got %d", len(findings))
	}

	// Finding da empresa
	var companyFinding *module.Finding
	var partnerFinding *module.Finding
	for i := range findings {
		if findings[i].Type == "company_record" {
			companyFinding = &findings[i]
		}
		if findings[i].Type == "company_partner" {
			partnerFinding = &findings[i]
		}
	}

	if companyFinding == nil {
		t.Fatal("deve ter finding 'company_record'")
	}
	if companyFinding.Extra["confidence"] == "" {
		t.Error("company_record sem confidence")
	}
	if companyFinding.Extra["razao_social"] == "" {
		t.Error("company_record sem razao_social")
	}
	if companyFinding.Severity != module.SeverityInfo {
		t.Errorf("empresa ATIVA deve ser SeverityInfo, got %s", companyFinding.Severity)
	}

	if partnerFinding == nil {
		t.Fatal("deve ter finding 'company_partner'")
	}
	if partnerFinding.Extra["nome_socio"] == "" {
		t.Error("company_partner sem nome_socio")
	}
}

func TestQueryCNPJwsInapta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"razao_social": "EMPRESA FECHADA SA",
			"cnpj":         "11222333000181",
			"estabelecimento": map[string]interface{}{
				"situacao_cadastral": map[string]interface{}{
					"descricao": "INAPTA",
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryCNPJws(context.Background(), "11222333000181")
	if err != nil {
		t.Fatalf("queryCNPJws inapta: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings")
	}
	if findings[0].Severity != module.SeverityMedium {
		t.Errorf("empresa INAPTA deve ser SeverityMedium, got %s", findings[0].Severity)
	}
}

func TestQueryCNPJwsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.queryCNPJws(context.Background(), "00000000000000")
	if err == nil {
		t.Error("404 deve retornar erro")
	}
}

// ─── Simples Nacional ─────────────────────────────────────────────────────────

func TestQuerySimplesOptante(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"cnpj":               "11222333000181",
			"simples":            true,
			"data_opcao_simples": "2020-01-01",
			"mei":                false,
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.querySimples(context.Background(), "11222333000181")
	if err != nil {
		t.Fatalf("querySimples: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar finding para optante Simples")
	}
	if findings[0].Type != "simples_nacional" {
		t.Errorf("tipo esperado 'simples_nacional', got '%s'", findings[0].Type)
	}
	if findings[0].Extra["optante"] != "true" {
		t.Error("extra.optante deve ser 'true'")
	}
	if findings[0].Extra["confidence"] == "" {
		t.Error("finding sem confidence")
	}
}

func TestQuerySimplesMEI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"cnpj":           "11222333000181",
			"simples":        false,
			"mei":            true,
			"data_opcao_mei": "2021-03-15",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.querySimples(context.Background(), "11222333000181")
	if err != nil {
		t.Fatalf("querySimples MEI: %v", err)
	}
	var meiFinding *module.Finding
	for i := range findings {
		if findings[i].Type == "mei_registration" {
			meiFinding = &findings[i]
		}
	}
	if meiFinding == nil {
		t.Fatal("deve retornar finding 'mei_registration'")
	}
	if meiFinding.Extra["is_mei"] != "true" {
		t.Error("extra.is_mei deve ser 'true'")
	}
}

func TestQuerySimplesNot404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.querySimples(context.Background(), "00000000000000")
	// 404 não é erro fatal para Simples
	if err != nil {
		t.Fatalf("404 em Simples não deve retornar erro, got: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("404 deve retornar 0 findings, got %d", len(findings))
	}
}

// ─── Brasil.io por nome ───────────────────────────────────────────────────────

func TestQueryBrasilIOByName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 2,
			"results": []map[string]interface{}{
				{
					"cnpj":               "11222333000181",
					"razao_social":       "PETROLEO BRASILEIRO SA",
					"nome_fantasia":      "PETROBRAS",
					"situacao_cadastral": "ATIVA",
					"municipio":          "RIO DE JANEIRO",
					"uf":                 "RJ",
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBrasilIO(context.Background(), "PETROBRAS", 10)
	if err != nil {
		t.Fatalf("queryBrasilIO: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings")
	}
	if findings[0].Type != "company_search_result" {
		t.Errorf("tipo esperado 'company_search_result', got '%s'", findings[0].Type)
	}
	if findings[0].Extra["cnpj"] == "" {
		t.Error("finding sem CNPJ")
	}
	if findings[0].Extra["confidence"] == "" {
		t.Error("finding sem confidence")
	}
}

func TestQueryBrasilIOEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   0,
			"results": []interface{}{},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBrasilIO(context.Background(), "EmpresaInexistente", 10)
	if err != nil {
		t.Fatalf("queryBrasilIO empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("sem resultados deve retornar 0 findings, got %d", len(findings))
	}
}

// ─── Brasil.io por CPF ────────────────────────────────────────────────────────

func TestQueryBrasilIOByCPF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 1,
			"results": []map[string]interface{}{
				{
					"cnpj_cpf_do_socio":      "123.***.***-09",
					"nome_socio":             "JOAO DA SILVA",
					"cnpj":                   "11222333000181",
					"qualificacao_socio":     "SÓCIO-ADMINISTRADOR",
					"data_entrada_sociedade": "2018-06-01",
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBrasilIOByCPF(context.Background(), "12345678909", 10)
	if err != nil {
		t.Fatalf("queryBrasilIOByCPF: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings para CPF com vínculos")
	}
	if findings[0].Type != "cpf_company_link" {
		t.Errorf("tipo esperado 'cpf_company_link', got '%s'", findings[0].Type)
	}
	// CPF nunca exposto em clear text
	if strings.Contains(findings[0].Detail, "12345678909") {
		t.Error("CPF em clear text não deve aparecer no Detail")
	}
	if findings[0].Extra["confidence"] == "" {
		t.Error("finding sem confidence")
	}
}

// ─── Fluxo completo ───────────────────────────────────────────────────────────

func TestRunCNPJ(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CNPJ.ws e BrasilAPI Simples compartilham o mesmo servidor de teste
		if strings.Contains(r.URL.Path, "simples") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"simples": false,
				"mei":     false,
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"razao_social": "EMPRESA TESTE",
			"cnpj":         "11222333000181",
			"estabelecimento": map[string]interface{}{
				"situacao_cadastral": map[string]interface{}{
					"descricao": "ATIVA",
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "11.222.333/0001-81",
	})
	if err != nil {
		t.Fatalf("Run CNPJ: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings para CNPJ")
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
	}
}

func TestRunCPFWithConsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   0,
			"results": []interface{}{},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "12345678909",
		Options: map[string]string{"lgpd_consent": "true"},
	})
	if err != nil {
		t.Fatalf("Run CPF com consent: %v", err)
	}
	// Pode retornar 0 findings se não houver vínculos
	_ = findings
}

func TestRunName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 1,
			"results": []map[string]interface{}{
				{
					"cnpj":               "11222333000181",
					"razao_social":       "PETROBRAS SA",
					"nome_fantasia":      "PETROBRAS",
					"situacao_cadastral": "ATIVA",
					"municipio":          "RIO DE JANEIRO",
					"uf":                 "RJ",
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "PETROBRAS",
	})
	if err != nil {
		t.Fatalf("Run por nome: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("busca por nome deve retornar findings")
	}
}

func TestRunContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := New()
	findings, err := m.Run(ctx, module.Input{Target: "EMPRESA TESTE"})
	if err != nil {
		t.Fatalf("context cancelado não deve retornar erro: %v", err)
	}
	_ = findings
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestDedup(t *testing.T) {
	findings := []module.Finding{
		{Type: "company_record", URL: "https://cnpj.ws/11222333000181", Detail: "CNPJ ativo"},
		{Type: "company_record", URL: "https://cnpj.ws/11222333000181", Detail: "CNPJ ativo"},
		{Type: "simples_nacional", URL: "https://brasilapi.com.br/simples", Detail: "Optante"},
	}
	result := dedup(findings)
	if len(result) != 2 {
		t.Errorf("dedup: esperado 2 únicos, got %d", len(result))
	}
}

// ─── sourceEnabled ────────────────────────────────────────────────────────────

func TestSourceEnabled(t *testing.T) {
	// nil = todos habilitados
	if !sourceEnabled(nil, "qualquer_fonte") {
		t.Error("nil map deve habilitar todas as fontes")
	}

	m := map[string]bool{"cnpjws": true}
	if !sourceEnabled(m, "cnpjws") {
		t.Error("cnpjws deve estar habilitado")
	}
	if sourceEnabled(m, "simples") {
		t.Error("simples não deve estar habilitado")
	}
}
