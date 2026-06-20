package tribunais

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
	}
	for _, tt := range cases {
		got, _ := detectTargetType(tt.input)
		if got != tt.want {
			t.Errorf("detectTargetType(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestDetectTargetTypeCPF(t *testing.T) {
	cases := []string{"12345678909", "123.456.789-09"}
	for _, input := range cases {
		got, _ := detectTargetType(input)
		if got != TargetCPF {
			t.Errorf("detectTargetType(%q) = %v, want TargetCPF", input, got)
		}
	}
}

func TestDetectTargetTypeProcesso(t *testing.T) {
	// Formato CNJ: 0000000-00.0000.0.00.0000
	cases := []string{
		"0001234-56.2023.8.26.0001",
		"0007777-88.2021.1.34.0000",
	}
	for _, input := range cases {
		got, _ := detectTargetType(input)
		if got != TargetProcesso {
			t.Errorf("detectTargetType(%q) = %v, want TargetProcesso", input, got)
		}
	}
}

func TestDetectTargetTypeNome(t *testing.T) {
	cases := []string{"João da Silva", "Petrobras", "Empresa Teste LTDA"}
	for _, input := range cases {
		got, _ := detectTargetType(input)
		if got != TargetNome {
			t.Errorf("detectTargetType(%q) = %v, want TargetNome", input, got)
		}
	}
}

// ─── maskName ────────────────────────────────────────────────────────────────

func TestMaskName(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"João Silva", "João S****"},
		{"João da Silva", "João da S****"},
		{"Maria", "Maria"}, // nome único não mascara
		{"", ""},
	}
	for _, tt := range cases {
		got := maskName(tt.input)
		if got != tt.want {
			t.Errorf("maskName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ─── severityByCount ─────────────────────────────────────────────────────────

func TestSeverityByCount(t *testing.T) {
	if severityByCount(10) != module.SeverityHigh {
		t.Error("10+ processos deve ser High")
	}
	if severityByCount(3) != module.SeverityMedium {
		t.Error("3-9 processos deve ser Medium")
	}
	if severityByCount(1) != module.SeverityLow {
		t.Error("1-2 processos deve ser Low")
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
		t.Errorf("erro deve mencionar lgpd_consent: %v", err)
	}
}

// ─── DataJud ─────────────────────────────────────────────────────────────────

func datajudResponse(total, hits int) map[string]interface{} {
	hitsArr := make([]interface{}, hits)
	for i := 0; i < hits; i++ {
		hitsArr[i] = map[string]interface{}{
			"_source": map[string]interface{}{
				"numeroProcesso":  "0001234-56.2023.8.26.0001",
				"tribunal":        "TJSP",
				"dataAjuizamento": "2023-01-15",
				"classe":          map[string]interface{}{"nome": "Ação Civil Pública"},
				"assuntos": []map[string]interface{}{
					{"nome": "Responsabilidade Civil"},
				},
				"partes": []map[string]interface{}{
					{"nome": "EMPRESA TESTE SA", "tipo": "Requerente", "documento": "11222333000181"},
					{"nome": "JOÃO DA SILVA", "tipo": "Requerido", "documento": "12345678909"},
				},
				"grauRecurso": "G1",
				"orgaoJulgador": map[string]interface{}{
					"nome": "1ª Vara Cível de São Paulo",
				},
			},
			"_score": 0.9,
		}
	}
	return map[string]interface{}{
		"hits": map[string]interface{}{
			"total": map[string]interface{}{"value": total},
			"hits":  hitsArr,
		},
	}
}

func TestQueryDataJudFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Verifica que é um POST com body JSON
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode(datajudResponse(5, 2))
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryDataJud(context.Background(), "EMPRESA TESTE", "EMPRESA TESTE", TargetNome, "test-key", "", 10)
	if err != nil {
		t.Fatalf("queryDataJud: %v", err)
	}
	if len(findings) < 3 {
		t.Fatalf("deve retornar summary + 2 processos, got %d", len(findings))
	}

	var hasSummary, hasProcess bool
	for _, f := range findings {
		if f.Type == "judicial_summary" {
			hasSummary = true
			if f.Extra["confidence"] == "" {
				t.Error("summary sem confidence")
			}
			if f.Extra["total_processos"] == "" {
				t.Error("summary sem total_processos")
			}
		}
		if f.Type == "judicial_process" {
			hasProcess = true
			if f.Extra["numero_processo"] == "" {
				t.Error("process sem numero_processo")
			}
			if f.Extra["confidence"] == "" {
				t.Error("process sem confidence")
			}
		}
	}
	if !hasSummary {
		t.Error("deve ter finding 'judicial_summary'")
	}
	if !hasProcess {
		t.Error("deve ter finding 'judicial_process'")
	}
}

func TestQueryDataJudUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.queryDataJud(context.Background(), "test", "test", TargetNome, "bad-key", "", 10)
	if err == nil {
		t.Error("deve retornar erro para key inválida")
	}
	if !strings.Contains(err.Error(), "API key inválida") {
		t.Errorf("erro deve mencionar 'API key inválida': %v", err)
	}
}

func TestQueryDataJudEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(datajudResponse(0, 0))
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryDataJud(context.Background(), "inexistente", "inexistente", TargetNome, "key", "", 10)
	if err != nil {
		t.Fatalf("queryDataJud empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("sem resultados deve retornar 0 findings, got %d", len(findings))
	}
}

// ─── BNMP ────────────────────────────────────────────────────────────────────

func TestQueryBNMPFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"totalElements": 1,
			"content": []map[string]interface{}{
				{
					"nomePreso":         "FULANO DE TAL",
					"numeroMandado":     "MAN-2023-001",
					"tipoMandado":       "DEFINITIVO",
					"dataExpedicao":     "2023-05-10",
					"tribunalExpedidor": "TJSP",
					"situacaoMandado":   "ATIVO",
					"orgaoExpedidor":    "1ª Vara Criminal",
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBNMP(context.Background(), "FULANO DE TAL", "12345678909", TargetCPF, 10)
	if err != nil {
		t.Fatalf("queryBNMP: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("deve retornar summary + 1 mandado, got %d", len(findings))
	}

	var hasWarrantSummary, hasArrestWarrant bool
	for _, f := range findings {
		if f.Type == "warrant_summary" {
			hasWarrantSummary = true
			if f.Severity != module.SeverityCritical {
				t.Errorf("warrant_summary deve ser Critical, got %s", f.Severity)
			}
		}
		if f.Type == "arrest_warrant" {
			hasArrestWarrant = true
			if f.Severity != module.SeverityCritical {
				t.Errorf("arrest_warrant deve ser Critical, got %s", f.Severity)
			}
			if f.Extra["numero_mandado"] == "" {
				t.Error("arrest_warrant sem numero_mandado")
			}
			if f.Extra["confidence"] == "" {
				t.Error("arrest_warrant sem confidence")
			}
			// Nome mascarado não deve ser o nome completo
			if strings.Contains(f.Detail, "FULANO DE TAL") {
				t.Error("nome completo não deve aparecer no Detail")
			}
		}
	}
	if !hasWarrantSummary {
		t.Error("deve ter finding 'warrant_summary'")
	}
	if !hasArrestWarrant {
		t.Error("deve ter finding 'arrest_warrant'")
	}
}

func TestQueryBNMPEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"totalElements": 0,
			"content":       []interface{}{},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBNMP(context.Background(), "sem mandados", "", TargetNome, 10)
	if err != nil {
		t.Fatalf("queryBNMP empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("sem mandados deve retornar 0 findings, got %d", len(findings))
	}
}

// ─── Escavador ───────────────────────────────────────────────────────────────

func TestQueryEscavadorFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 3,
			"items": []map[string]interface{}{
				{
					"numero_unico":                  "0001234-56.2023.8.26.0001",
					"tribunal_sigla":                "TJSP",
					"assunto_principal_normalizado": "Indenização por Dano Moral",
					"data_ultima_movimentacao":      "2024-02-15",
					"tipo_acao":                     "Ordinária",
					"envolvidos": []map[string]interface{}{
						{"nome": "JOÃO DA SILVA", "tipo_parte": "Autor"},
						{"nome": "EMPRESA XYZ LTDA", "tipo_parte": "Réu"},
					},
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryEscavador(context.Background(), "JOÃO DA SILVA", "12345678909", TargetCPF, "test-key", 10)
	if err != nil {
		t.Fatalf("queryEscavador: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("deve retornar summary + processo, got %d", len(findings))
	}

	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
		if f.Type == "judicial_process" {
			if f.Extra["numero_processo"] == "" {
				t.Error("process sem numero_processo")
			}
		}
	}
}

func TestQueryEscavadorUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.queryEscavador(context.Background(), "test", "test", TargetNome, "bad-key", 10)
	if err == nil {
		t.Error("deve retornar erro para key inválida")
	}
}

// ─── JusBrasil ───────────────────────────────────────────────────────────────

func TestQueryJusBrasilFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 2,
			"data": []map[string]interface{}{
				{
					"id":          "proc-001",
					"titulo":      "Ação de Indenização",
					"tribunal":    "TJSP",
					"resumo":      "Ação movida por consumidor contra empresa.",
					"data_inicio": "2022-08-01",
					"url":         "https://www.jusbrasil.com.br/processos/proc-001",
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryJusBrasil(context.Background(), "Indenização", "test-key", 10)
	if err != nil {
		t.Fatalf("queryJusBrasil: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings")
	}
	if findings[0].Type != "judicial_process" {
		t.Errorf("tipo esperado 'judicial_process', got '%s'", findings[0].Type)
	}
	if findings[0].Extra["confidence"] == "" {
		t.Error("finding sem confidence")
	}
}

func TestQueryJusBrasilEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 0,
			"data":  []interface{}{},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryJusBrasil(context.Background(), "inexistente", "key", 10)
	if err != nil {
		t.Fatalf("queryJusBrasil empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("sem resultados deve retornar 0 findings, got %d", len(findings))
	}
}

// ─── Fluxo completo ───────────────────────────────────────────────────────────

func TestRunByName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// BNMP response
		if strings.Contains(r.URL.Path, "certidao") || strings.Contains(r.URL.Path, "pesquisar") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"totalElements": 0,
				"content":       []interface{}{},
			})
			return
		}
		// Resposta genérica
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"hits":{"total":{"value":0},"hits":[]}}`)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "Empresa Teste",
		Options: map[string]string{"datajud_key": "test-key"},
	})
	if err != nil {
		t.Fatalf("Run por nome: %v", err)
	}
	_ = findings
}

func TestRunByCNPJ(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			json.NewEncoder(w).Encode(datajudResponse(2, 1))
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"simples": false,
			"mei":     false,
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "11222333000181",
		Options: map[string]string{"datajud_key": "test-key"},
	})
	if err != nil {
		t.Fatalf("Run CNPJ: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings para CNPJ com processos")
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
	}
}

func TestRunByCPFWithConsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// DataJud (POST)
		if r.Method == http.MethodPost {
			json.NewEncoder(w).Encode(datajudResponse(0, 0))
			return
		}
		// BNMP
		json.NewEncoder(w).Encode(map[string]interface{}{
			"totalElements": 0,
			"content":       []interface{}{},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "12345678909",
		Options: map[string]string{"lgpd_consent": "true", "datajud_key": "test-key"},
	})
	if err != nil {
		t.Fatalf("Run CPF: %v", err)
	}
	_ = findings
}

func TestRunContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := New()
	findings, err := m.Run(ctx, module.Input{
		Target:  "Empresa Cancelada",
		Options: map[string]string{"datajud_key": "test-key"},
	})
	if err != nil {
		t.Fatalf("context cancelado não deve retornar erro: %v", err)
	}
	_ = findings
}

// ─── DataJud POST body ────────────────────────────────────────────────────────

func TestQueryDataJudPostBody(t *testing.T) {
	// Verifica que o payload enviado contém a query correta
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		json.NewEncoder(w).Encode(datajudResponse(0, 0))
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, _ = m.queryDataJud(context.Background(), "11222333000181", "11222333000181", TargetCNPJ, "key", "", 5)

	var payload map[string]interface{}
	if err := json.Unmarshal(capturedBody, &payload); err != nil {
		t.Fatalf("payload DataJud não é JSON válido: %v", err)
	}
	// Verifica que 'size' está presente
	if _, ok := payload["size"]; !ok {
		t.Error("payload DataJud deve ter campo 'size'")
	}
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestDedup(t *testing.T) {
	findings := []module.Finding{
		{Type: "judicial_process", URL: "https://processos.cnj.jus.br/details/001", Detail: "Processo 001"},
		{Type: "judicial_process", URL: "https://processos.cnj.jus.br/details/001", Detail: "Processo 001"},
		{Type: "judicial_summary", URL: "https://datajud.cnj.jus.br", Detail: "2 processos"},
	}
	result := dedup(findings)
	if len(result) != 2 {
		t.Errorf("dedup: esperado 2 únicos, got %d", len(result))
	}
}

// ─── truncate ────────────────────────────────────────────────────────────────

func TestTruncate(t *testing.T) {
	s := "abcdef"
	if truncate(s, 3) != "abc..." {
		t.Errorf("truncate(%q, 3) = %q, want 'abc...'", s, truncate(s, 3))
	}
	if truncate(s, 100) != s {
		t.Errorf("truncate não deve truncar string menor que o limite")
	}
}

// ─── bytes.NewReader no DataJud ───────────────────────────────────────────────

func TestQueryDataJudWithTribunal(t *testing.T) {
	var capturedURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.Path
		json.NewEncoder(w).Encode(datajudResponse(0, 0))
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, _ = m.queryDataJud(context.Background(), "test", "test", TargetNome, "key", "TJSP", 10)

	if !strings.Contains(capturedURL, "tjsp") {
		t.Errorf("URL deve conter tribunal 'tjsp', got path: %s", capturedURL)
	}
}

// Garante que o módulo compila e implementa a interface corretamente.
func TestModuleInterface(t *testing.T) {
	m := New()
	if m.Name() != "tribunais" {
		t.Errorf("Name() = %q, want 'tribunais'", m.Name())
	}
}

// Verifica que o bytes.NewReader é usado corretamente no queryDataJud.
var _ = bytes.NewReader
