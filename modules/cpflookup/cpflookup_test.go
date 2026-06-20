package cpflookup_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/cpflookup"
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

// CPF válido para testes: 529.982.247-25 (gerado com algoritmo)
const validCPF = "52998224725"
const validCPFMasked = "529.***.***-25"

// ─── estrutura ────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if cpflookup.New().Name() != "cpflookup" {
		t.Error("nome incorreto")
	}
}

func TestNew_NotNil(t *testing.T) {
	if cpflookup.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

// ─── validação de CPF ────────────────────────────────────────────────────────

func TestRun_InvalidCPF_ReturnsError(t *testing.T) {
	_, err := cpflookup.New().Run(context.Background(), module.Input{
		Target: "00000000000",
	})
	if err == nil {
		t.Fatal("CPF com todos dígitos iguais deve retornar erro")
	}
}

func TestRun_InvalidCPFDigits_ReturnsError(t *testing.T) {
	_, err := cpflookup.New().Run(context.Background(), module.Input{
		Target: "12345678900",
	})
	if err == nil {
		t.Fatal("CPF com dígitos verificadores errados deve retornar erro")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := cpflookup.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("target vazio deve retornar erro")
	}
}

func TestRun_ShortCPF_ReturnsError(t *testing.T) {
	_, err := cpflookup.New().Run(context.Background(), module.Input{
		Target: "123456",
	})
	if err == nil {
		t.Fatal("CPF curto deve retornar erro")
	}
}

// ─── lgpd_consent gate ───────────────────────────────────────────────────────

func TestRun_NoConsent_ReturnsStructuralOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("não deve consultar API sem lgpd_consent=true")
	}))
	defer srv.Close()

	m := cpflookup.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: validCPF,
		// lgpd_consent ausente
	})
	if err != nil {
		t.Fatalf("sem consent não deve retornar erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava pelo menos 1 finding de validação estrutural")
	}
	if findings[0].Type != "cpf_structural_validation" {
		t.Errorf("tipo esperado 'cpf_structural_validation', obteve '%s'", findings[0].Type)
	}
}

func TestRun_ConsentFalse_NoExternalCall(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	m := cpflookup.NewWithClient(newTestClient(srv))
	_, _ = m.Run(context.Background(), module.Input{
		Target:  validCPF,
		Options: map[string]string{"lgpd_consent": "false"},
	})
	if called {
		t.Error("lgpd_consent=false não deve fazer chamadas externas")
	}
}

// ─── BrasilAPI CPF ────────────────────────────────────────────────────────────

func brasilAPICPFHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ni":              "52998224725",
		"nome":            "João Silva Santos",
		"data_nascimento": "1990-01-01",
		"situacao": map[string]string{
			"codigo":    "0",
			"descricao": "Regular",
		},
		"digito_verificador": "25",
	})
}

func TestRun_BrasilAPI_Found_CPFRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICPFHandler))
	defer srv.Close()

	m := cpflookup.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: validCPF,
		Options: map[string]string{
			"sources":      "brasilapi",
			"lgpd_consent": "true",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava pelo menos 1 finding via BrasilAPI")
	}

	var found bool
	for _, f := range findings {
		if f.Type == "cpf_record" && f.Extra["source"] == "brasilapi" {
			found = true
			if f.Extra["status"] != "Regular" {
				t.Errorf("status esperado 'Regular', obteve '%s'", f.Extra["status"])
			}
			if f.Extra["confidence"] == "" {
				t.Error("confidence não pode ser vazio")
			}
			// Verifica mascaramento do nome
			if strings.Contains(f.Extra["name"], "Silva") {
				t.Error("sobrenome completo não deve aparecer no finding")
			}
		}
	}
	if !found {
		t.Error("esperava finding 'cpf_record' do brasilapi")
	}
}

func TestRun_BrasilAPI_404_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := cpflookup.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: validCPF,
		Options: map[string]string{
			"sources":      "brasilapi",
			"lgpd_consent": "true",
		},
	})
	if err != nil {
		t.Fatalf("404 não deve retornar erro: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("404 deve retornar 0 findings, obteve %d", len(findings))
	}
}

// ─── ReceitaWS ────────────────────────────────────────────────────────────────

func receitaWSCPFHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "OK",
		"nome":            "Maria Oliveira Costa",
		"data_nascimento": "1985-05-15",
		"situacao":        "REGULAR",
	})
}

func TestRun_ReceitaWS_Found_CPFRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(receitaWSCPFHandler))
	defer srv.Close()

	m := cpflookup.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: validCPF,
		Options: map[string]string{
			"sources":      "receitaws",
			"lgpd_consent": "true",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding via ReceitaWS")
	}

	for _, f := range findings {
		if f.Extra["source"] == "receitaws" {
			if f.Extra["confidence"] == "" {
				t.Error("confidence não pode ser vazio")
			}
			// Nome não deve vazar completo
			if strings.Contains(f.Extra["name"], "Oliveira") {
				t.Error("sobrenome completo não deve aparecer")
			}
		}
	}
}

func TestRun_ReceitaWS_RateLimit_NoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	m := cpflookup.NewWithClient(newTestClient(srv))
	// Rate limit deve retornar 0 findings sem erro fatal
	findings, err := m.Run(context.Background(), module.Input{
		Target: validCPF,
		Options: map[string]string{
			"sources":      "receitaws",
			"lgpd_consent": "true",
		},
	})
	if err != nil {
		t.Fatalf("rate limit não deve retornar erro fatal: %v", err)
	}
	_ = findings // pode ser 0 ou mais
}

// ─── cpfcnpj.com.br ──────────────────────────────────────────────────────────

func cpfCNPJHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "OK",
		"nome":       "Pedro Alves Rocha",
		"cpf":        "529.982.247-25",
		"nascimento": "1992-07-20",
		"situacao_cadastral": map[string]string{
			"codigo":    "0",
			"descricao": "REGULAR",
		},
	})
}

func TestRun_CPFCNPJ_Found_WithKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(cpfCNPJHandler))
	defer srv.Close()

	m := cpflookup.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: validCPF,
		Options: map[string]string{
			"sources":      "cpfcnpj",
			"cpf_key":      "test-key-123",
			"lgpd_consent": "true",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding via cpfcnpj com key válida")
	}
	for _, f := range findings {
		if f.Extra["source"] == "cpfcnpj" {
			if f.Extra["status"] != "REGULAR" {
				t.Errorf("status esperado 'REGULAR', obteve '%s'", f.Extra["status"])
			}
		}
	}
}

func TestRun_CPFCNPJ_NoKey_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(cpfCNPJHandler))
	defer srv.Close()

	m := cpflookup.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: validCPF,
		Options: map[string]string{
			"sources":      "cpfcnpj",
			"lgpd_consent": "true",
			// sem cpf_key
		},
	})
	if len(findings) != 0 {
		t.Errorf("sem cpf_key esperava 0 findings, obteve %d", len(findings))
	}
}

// ─── confidence e detail ─────────────────────────────────────────────────────

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICPFHandler))
	defer srv.Close()

	m := cpflookup.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: validCPF,
		Options: map[string]string{
			"sources":      "brasilapi",
			"lgpd_consent": "true",
		},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICPFHandler))
	defer srv.Close()

	m := cpflookup.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: validCPF,
		Options: map[string]string{
			"sources":      "brasilapi",
			"lgpd_consent": "true",
		},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestRun_Dedup_NoDuplicates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICPFHandler))
	defer srv.Close()

	m := cpflookup.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: validCPF,
		Options: map[string]string{
			"sources":      "brasilapi",
			"lgpd_consent": "true",
		},
	})
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.Type + "|" + f.Extra["source"] + "|" + f.Extra["status_code"]
		if seen[key] {
			t.Errorf("finding duplicado: %s", key)
		}
		seen[key] = true
	}
}

// ─── LGPD / mascaramento ─────────────────────────────────────────────────────

func TestRun_NameMasking_NoFullName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICPFHandler))
	defer srv.Close()

	m := cpflookup.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: validCPF,
		Options: map[string]string{
			"sources":      "brasilapi",
			"lgpd_consent": "true",
		},
	})
	for _, f := range findings {
		// O nome mascarado deve ter "***" para sobrenomes
		if name := f.Extra["name"]; name != "" {
			if strings.Contains(name, "Silva Santos") {
				t.Error("nome completo vazou no finding — violação LGPD")
			}
		}
	}
}

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv := httptest.NewServer(http.HandlerFunc(brasilAPICPFHandler))
	defer srv.Close()

	m := cpflookup.NewWithClient(newTestClient(srv))
	_, _ = m.Run(ctx, module.Input{
		Target: validCPF,
		Options: map[string]string{
			"sources":      "brasilapi",
			"lgpd_consent": "true",
		},
	})
	// não deve entrar em panic
}
