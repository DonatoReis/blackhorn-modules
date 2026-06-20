package namesearch

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

// ─── helpers de mock ─────────────────────────────────────────────────────────

func ibgeMockServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v2/censos/nomes/ranking") {
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"nome": "JOAO", "frequencia": 5000000},
			})
			return
		}
		if strings.Contains(r.URL.Path, "/api/v2/censos/nomes/") {
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"nome": "JOAO", "frequencia": 5000000, "sexo": "M"},
			})
			return
		}
		http.NotFound(w, r)
	}))
}

func transparenciaMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("chave-api-dados") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"nome":                   "JOAO SILVA",
				"cpf":                    "12345678900",
				"orgaoNome":              "MINISTERIO DA FAZENDA",
				"cargoEfetivo":           "ANALISTA",
				"remuneracaoBasicaBruta": 12000.00,
				"ufExercicio":            "DF",
			},
		})
	}))
}

func openSanctionsMockServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		resp := map[string]interface{}{
			"q": map[string]interface{}{
				"total": map[string]int{"value": 1},
				"results": []map[string]interface{}{
					{
						"id":       "Q12345",
						"caption":  "JOAO SILVA",
						"schema":   "Person",
						"datasets": []string{"sanctions", "ofac"},
						"score":    0.92,
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
}

func interpolMockServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"total": 1,
			"_embedded": map[string]interface{}{
				"notices": []map[string]interface{}{
					{
						"entity_id":     "2024-12345",
						"forenames":     "JOAO",
						"name":          "SILVA",
						"nationalities": []map[string]string{{"id": "BR"}},
						"date_of_birth": "1985/01/15",
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
}

func emptyInterpolServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"total":     0,
			"_embedded": map[string]interface{}{"notices": []interface{}{}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
}

// ─── Testes unitários ────────────────────────────────────────────────────────

func TestTokenizeName(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"João Silva", []string{"João", "Silva"}},
		{"Maria da Silva Santos", []string{"Maria", "Silva", "Santos"}},
		{"Ana", []string{"Ana"}},
		{"Carlos de Oliveira Junior", []string{"Carlos", "Oliveira", "Junior"}},
		{"", []string(nil)},
	}
	for _, tt := range tests {
		got := tokenizeName(tt.input)
		if len(got) != len(tt.expected) {
			t.Errorf("tokenizeName(%q): got %v, want %v", tt.input, got, tt.expected)
			continue
		}
		for i := range got {
			if got[i] != tt.expected[i] {
				t.Errorf("tokenizeName(%q)[%d]: got %q, want %q", tt.input, i, got[i], tt.expected[i])
			}
		}
	}
}

func TestNormalizeAccents(t *testing.T) {
	cases := map[string]string{
		"João":    "Joao",
		"Céu":     "Ceu",
		"ÂNGELA":  "ANGELA",
		"Façanha": "Facanha",
	}
	for input, want := range cases {
		if got := normalizeAccents(input); got != want {
			t.Errorf("normalizeAccents(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestMaskName(t *testing.T) {
	cases := map[string]string{
		"João Silva":         "João S****",
		"Ana":                "Ana",
		"Carlos de Oliveira": "Carlos d* O*******",
		"":                   "****",
	}
	for input, want := range cases {
		if got := maskName(input); got != want {
			t.Errorf("maskName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestMaskCPF(t *testing.T) {
	cases := map[string]string{
		"52998224725":    "529.***.***-25",
		"529.982.247-25": "529.***.***-25",
		"abc":            "***.***.***-**",
	}
	for input, want := range cases {
		if got := maskCPF(input); got != want {
			t.Errorf("maskCPF(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestEmptyTarget(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Fatal("deveria retornar erro para target vazio")
	}
}

func TestAnalyzeNameLocally(t *testing.T) {
	// Nome simples
	tokens := tokenizeName("Ana")
	findings := analyzeNameLocally("Ana", tokens, false)
	if len(findings) == 0 {
		t.Fatal("analyzeNameLocally: deveria retornar pelo menos 1 finding")
	}
	found := false
	for _, f := range findings {
		if f.Type == "name_analysis" {
			found = true
			break
		}
	}
	if !found {
		t.Error("deve conter finding do tipo 'name_analysis'")
	}

	// Nome composto — deve incluir name_structure
	tokensComp := tokenizeName("João Carlos Silva")
	findingsComp := analyzeNameLocally("João Carlos Silva", tokensComp, true)
	foundStruct := false
	for _, f := range findingsComp {
		if f.Type == "name_structure" {
			foundStruct = true
			break
		}
	}
	if !foundStruct {
		t.Error("nome composto deve gerar finding 'name_structure'")
	}
}

func TestLGPDConsentFlag(t *testing.T) {
	tokens := tokenizeName("João Silva")
	// Sem consentimento
	findings := analyzeNameLocally("João Silva", tokens, false)
	for _, f := range findings {
		if f.Extra["aviso"] == "" && f.Type == "name_analysis" {
			t.Error("sem lgpd_consent deve incluir aviso no extra")
		}
	}
	// Com consentimento
	findingsConsent := analyzeNameLocally("João Silva", tokens, true)
	for _, f := range findingsConsent {
		if f.Type == "name_analysis" && strings.Contains(f.Extra["aviso"], "lgpd_consent=false") {
			t.Error("com lgpd_consent=true não deve conter aviso de LGPD")
		}
	}
}

func TestIBGENomesFound(t *testing.T) {
	srv := ibgeMockServer()
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryIBGENomes(context.Background(), "João", []string{"João"}, 10, "pt")
	if err != nil {
		t.Fatalf("queryIBGENomes: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar pelo menos 1 finding para nome JOAO")
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding %s sem confidence", f.Type)
		}
		if f.Type != "name_frequency" && f.Type != "name_ranking" {
			t.Errorf("tipo inesperado: %s", f.Type)
		}
	}
}

func TestIBGENomesLang(t *testing.T) {
	srv := ibgeMockServer()
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryIBGENomes(context.Background(), "João", []string{"João"}, 10, "en")
	if err != nil {
		t.Fatalf("queryIBGENomes: %v", err)
	}
	for _, f := range findings {
		if f.Type == "name_frequency" && !strings.Contains(f.Detail, "found in IBGE") {
			t.Errorf("lang=en: detail deveria estar em inglês, got: %s", f.Detail)
		}
	}
}

func TestTransparenciaFound(t *testing.T) {
	srv := transparenciaMockServer(t)
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryTransparencia(context.Background(), "JOAO SILVA", "test-key", 10)
	if err != nil {
		t.Fatalf("queryTransparencia: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar ao menos 1 finding")
	}
	f := findings[0]
	if f.Type != "public_servant" {
		t.Errorf("tipo esperado 'public_servant', got '%s'", f.Type)
	}
	if f.Extra["cpf_mascarado"] == "" {
		t.Error("CPF mascarado deve estar no extra")
	}
	// CPF nunca exposto na íntegra
	if strings.Contains(f.Extra["cpf_mascarado"], "12345678900") {
		t.Error("CPF completo não deve aparecer no finding")
	}
	// Órgão e cargo presentes
	if f.Extra["orgao"] == "" || f.Extra["cargo"] == "" {
		t.Error("orgao e cargo devem estar no extra")
	}
}

func TestTransparenciaNoKey(t *testing.T) {
	// Sem API key: não deve chamar a fonte (enabledSources vai excluir)
	// Mas se chamar diretamente, deve tratar 401
	srv := transparenciaMockServer(t)
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.queryTransparencia(context.Background(), "JOAO", "", 10)
	// Com key vazia o header fica vazio → mock retorna 401 → get retorna erro
	if err == nil {
		t.Error("deve retornar erro quando key está vazia e servidor retorna 401")
	}
}

func TestOpenSanctionsFound(t *testing.T) {
	srv := openSanctionsMockServer()
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryOpenSanctions(context.Background(), "Joao Silva", "test-key", 10)
	if err != nil {
		t.Fatalf("queryOpenSanctions: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar pelo menos 1 finding")
	}
	f := findings[0]
	if f.Type != "sanctioned_entity" {
		t.Errorf("tipo esperado 'sanctioned_entity', got '%s'", f.Type)
	}
	if f.Severity != module.SeverityHigh {
		t.Errorf("severidade esperada High para sancionado, got '%s'", f.Severity)
	}
	if f.Extra["score"] == "" {
		t.Error("score deve estar no extra")
	}
}

func TestOpenSanctionsNoKey(t *testing.T) {
	srv := openSanctionsMockServer()
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.queryOpenSanctions(context.Background(), "Joao", "", 10)
	if err == nil {
		t.Error("deve retornar erro com key vazia (401)")
	}
}

func TestOpenSanctionsLowScore(t *testing.T) {
	// Servidor que retorna score baixo — deve ser filtrado
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"q": map[string]interface{}{
				"total": map[string]int{"value": 1},
				"results": []map[string]interface{}{
					{
						"id":       "Q99999",
						"caption":  "Someone",
						"schema":   "Person",
						"datasets": []string{"pep_list"},
						"score":    0.30, // abaixo do threshold 0.5
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryOpenSanctions(context.Background(), "Joao", "test-key", 10)
	if err != nil {
		t.Fatalf("queryOpenSanctions: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("score baixo (<0.5) deve ser filtrado, mas retornou %d findings", len(findings))
	}
}

func TestInterpolFound(t *testing.T) {
	srv := interpolMockServer()
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryInterpol(context.Background(), "Joao Silva", 10)
	if err != nil {
		t.Fatalf("queryInterpol: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar pelo menos 1 finding Interpol")
	}
	f := findings[0]
	if f.Type != "interpol_notice" {
		t.Errorf("tipo esperado 'interpol_notice', got '%s'", f.Type)
	}
	if f.Severity != module.SeverityCritical {
		t.Errorf("severidade esperada Critical para aviso Interpol, got '%s'", f.Severity)
	}
	if !strings.Contains(f.Detail, "AVISO VERMELHO") {
		t.Error("detail do aviso Interpol deve mencionar 'AVISO VERMELHO'")
	}
}

func TestInterpolEmpty(t *testing.T) {
	srv := emptyInterpolServer()
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryInterpol(context.Background(), "Nobody", 10)
	if err != nil {
		t.Fatalf("queryInterpol: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("não deve retornar findings para resposta vazia, got %d", len(findings))
	}
}

func TestRunBasic(t *testing.T) {
	srv := ibgeMockServer()
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "João Silva",
		Options: map[string]string{"sources": "ibge"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("Run deve retornar pelo menos 1 finding")
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem campo confidence", f.Type)
		}
	}
}

func TestRunAllSources(t *testing.T) {
	ibgeSrv := ibgeMockServer()
	defer ibgeSrv.Close()

	m := NewWithClient(clientFor(ibgeSrv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "Maria da Silva",
		Options: map[string]string{
			"sources":     "ibge",
			"max_results": "5",
		},
	})
	if err != nil {
		t.Fatalf("Run multi-source: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("Run deve retornar findings")
	}
}

func TestRunContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simula delay longo
		select {
		case <-r.Context().Done():
			http.Error(w, "cancelled", 499)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancela imediatamente

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(ctx, module.Input{
		Target:  "João",
		Options: map[string]string{"sources": "ibge"},
	})
	// Context cancelado: módulo tolera falhas, retorna análise local
	if err != nil {
		t.Fatalf("Run não deve propagar erro de contexto: %v", err)
	}
	// Deve ter pelo menos o finding de análise local
	if len(findings) == 0 {
		t.Fatal("deve retornar findings locais mesmo com contexto cancelado")
	}
}

func TestDedup(t *testing.T) {
	findings := []module.Finding{
		{Type: "name_analysis", URL: "", Detail: "Análise local."},
		{Type: "name_analysis", URL: "", Detail: "Análise local."},
		{Type: "name_frequency", URL: "http://ibge.gov.br", Detail: "Freq 1000."},
	}
	result := dedup(findings)
	if len(result) != 2 {
		t.Errorf("dedup: esperava 2 findings únicos, got %d", len(result))
	}
}

func TestParseSources(t *testing.T) {
	// "all" → nil (tudo habilitado)
	if m := parseSources("all"); m != nil {
		t.Error("parseSources('all') deve retornar nil")
	}
	// Lista específica
	m := parseSources("ibge,interpol")
	if !m["ibge"] || !m["interpol"] || m["opensanctions"] {
		t.Error("parseSources deve habilitar apenas as fontes listadas")
	}
}

func TestSourceEnabled(t *testing.T) {
	if !sourceEnabled(nil, "qualquer") {
		t.Error("nil enabled map deve habilitar tudo")
	}
	m := map[string]bool{"ibge": true}
	if !sourceEnabled(m, "ibge") {
		t.Error("ibge deve estar habilitado")
	}
	if sourceEnabled(m, "interpol") {
		t.Error("interpol não deve estar habilitado")
	}
}
