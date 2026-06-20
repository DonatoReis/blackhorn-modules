package dehashed

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

// ─── Mocks ────────────────────────────────────────────────────────────────────

func successServer(entries []dehashedEntry, total int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verificar Basic Auth
		user, pass, ok := r.BasicAuth()
		if !ok || user == "" || pass == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(dehashedResponse{
			Balance: 100,
			Entries: entries,
			Success: true,
			Total:   total,
			Took:    0.05,
		})
	}))
}

func noResultsServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(dehashedResponse{
			Balance: 100,
			Entries: nil,
			Success: true,
			Total:   0,
			Took:    0.01,
		})
	}))
}

// ─── Testes de validação ──────────────────────────────────────────────────────

func TestEmptyTarget(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Fatal("deve retornar erro para target vazio")
	}
}

func TestMissingCredentials(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{},
	})
	if err == nil {
		t.Fatal("deve retornar erro quando credenciais estão ausentes")
	}
	if !strings.Contains(err.Error(), "credenciais") {
		t.Errorf("erro deve mencionar credenciais, got: %v", err)
	}
}

// ─── Testes de detectField ────────────────────────────────────────────────────

func TestDetectField(t *testing.T) {
	cases := map[string]string{
		"test@example.com": "email",
		"192.168.1.1":      "ip_address",
		"example.com":      "domain",
		"johndoe":          "username",
		"john.doe":         "username",
		"example.com.br":   "domain",
	}
	for target, want := range cases {
		if got := detectField(target); got != want {
			t.Errorf("detectField(%q) = %q, want %q", target, got, want)
		}
	}
}

// ─── Testes de mascaramento ───────────────────────────────────────────────────

func TestMaskEmail(t *testing.T) {
	cases := map[string]string{
		"test@example.com": "t**t@example.com",
		"ab@test.com":      "**@test.com",
		"not-an-email":     "***@***",
	}
	for input, want := range cases {
		if got := maskEmail(input); got != want {
			t.Errorf("maskEmail(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestMaskPhone(t *testing.T) {
	phone := "11999999999"
	masked := maskPhone(phone)
	if strings.Contains(masked, "9999999") {
		t.Errorf("maskPhone não deve expor número completo: %s", masked)
	}
	if !strings.Contains(masked, "119") {
		t.Errorf("maskPhone deve preservar prefixo: %s", masked)
	}
}

func TestMaskTargetPassword(t *testing.T) {
	got := maskTarget("minha_senha123", "password")
	if got != "***REDACTED***" {
		t.Errorf("senha deve ser redacted, got: %s", got)
	}
}

func TestHashPrefix(t *testing.T) {
	h := "5f4dcc3b5aa765d61d8327deb882cf99"
	prefix := hashPrefix(h)
	if !strings.HasSuffix(prefix, "...") {
		t.Error("hashPrefix de hash longo deve terminar com ...")
	}
	if len(prefix) > 12 {
		t.Errorf("hashPrefix muito longo: %s", prefix)
	}
	// Hash curto — retorna completo
	shortHash := "abc"
	if hashPrefix(shortHash) != "abc" {
		t.Error("hash curto deve ser retornado completo")
	}
}

// ─── Testes de severidade ─────────────────────────────────────────────────────

func TestTotalSeverity(t *testing.T) {
	cases := map[int]module.Severity{
		1:     module.SeverityLow,
		9:     module.SeverityLow,
		10:    module.SeverityMedium,
		99:    module.SeverityMedium,
		100:   module.SeverityHigh,
		9999:  module.SeverityHigh,
		10000: module.SeverityCritical,
		50000: module.SeverityCritical,
	}
	for total, want := range cases {
		if got := totalSeverity(total); got != want {
			t.Errorf("totalSeverity(%d) = %s, want %s", total, got, want)
		}
	}
}

// ─── Testes de busca ──────────────────────────────────────────────────────────

func TestSearchEmailFound(t *testing.T) {
	entries := []dehashedEntry{
		{
			ID:           "abc123",
			Email:        "test@example.com",
			Username:     "testuser",
			Password:     "hunter2",
			DatabaseName: "ExampleLeakDB",
		},
		{
			ID:           "def456",
			Email:        "test@example.com",
			Username:     "testuser2",
			DatabaseName: "AnotherBreach",
		},
	}
	srv := successServer(entries, 2)
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "test@example.com",
		Options: map[string]string{
			"dehashed_email": "account@test.com",
			"dehashed_key":   "test-api-key",
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings")
	}

	// Deve ter sumário + entries
	hasSummary := false
	hasRecord := false
	hasPasswordExposed := false
	for _, f := range findings {
		if f.Type == "dehashed_summary" {
			hasSummary = true
			if f.Extra["total"] != "2" {
				t.Errorf("total esperado '2', got '%s'", f.Extra["total"])
			}
		}
		if f.Type == "dehashed_record" {
			hasRecord = true
			// Senha nunca deve aparecer em texto claro
			if f.Extra["password"] != "" {
				t.Error("senha não deve aparecer em extra")
			}
			// Primeiro record tem senha
			if f.Extra["password_exposed"] == "true" {
				hasPasswordExposed = true
			}
			// Email mascarado
			if strings.Contains(f.Extra["email"], "test@example.com") {
				t.Error("email completo não deve aparecer no extra")
			}
		}
		// confidence obrigatório
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
	}
	if !hasPasswordExposed {
		t.Error("pelo menos 1 record deve indicar password_exposed=true")
	}
	if !hasSummary {
		t.Error("deve conter finding 'dehashed_summary'")
	}
	if !hasRecord {
		t.Error("deve conter finding 'dehashed_record'")
	}
}

func TestSearchWithPassword(t *testing.T) {
	entries := []dehashedEntry{
		{
			ID:             "zzz999",
			Email:          "victim@example.com",
			HashedPassword: "5f4dcc3b5aa765d61d8327deb882cf99",
			DatabaseName:   "SomeDB",
		},
	}
	srv := successServer(entries, 1)
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "victim@example.com",
		Options: map[string]string{
			"dehashed_email": "account@test.com",
			"dehashed_key":   "key",
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, f := range findings {
		if f.Type == "dehashed_record" {
			// Hash nunca exposto completo
			if hash, ok := f.Extra["hashed_password"]; ok {
				t.Errorf("hash completo não deve estar em extra, got: %s", hash)
			}
			if f.Extra["hashed_password_exposed"] != "true" {
				t.Error("deve indicar hashed_password_exposed=true")
			}
			// Prefix OK
			if prefix := f.Extra["hash_prefix"]; !strings.HasSuffix(prefix, "...") {
				t.Errorf("hash_prefix deve terminar com ..., got: %s", prefix)
			}
			// Severidade alta por ter hash
			if f.Severity != module.SeverityHigh {
				t.Errorf("entry com hash deve ter severidade High, got %s", f.Severity)
			}
		}
	}
}

func TestSearchNoResults(t *testing.T) {
	srv := noResultsServer()
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "nobody@example.com",
		Options: map[string]string{
			"dehashed_email": "account@test.com",
			"dehashed_key":   "key",
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 || findings[0].Type != "dehashed_no_results" {
		t.Errorf("sem resultados deve retornar 'dehashed_no_results', got %v", findings)
	}
}

func TestSearchByDomain(t *testing.T) {
	entries := []dehashedEntry{
		{ID: "1", Email: "admin@company.com", Username: "admin", DatabaseName: "CorpLeak"},
		{ID: "2", Email: "user@company.com", Username: "user", DatabaseName: "CorpLeak"},
	}
	srv := successServer(entries, 2)
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "company.com",
		Options: map[string]string{
			"dehashed_email": "account@test.com",
			"dehashed_key":   "key",
			"field":          "domain",
		},
	})
	if err != nil {
		t.Fatalf("Run domain: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("busca por domínio deve retornar findings")
	}
}

func TestSearchByUsername(t *testing.T) {
	entries := []dehashedEntry{
		{ID: "1", Username: "johndoe", Email: "john@example.com", DatabaseName: "ForumLeak"},
	}
	srv := successServer(entries, 1)
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "johndoe",
		Options: map[string]string{
			"dehashed_email": "account@test.com",
			"dehashed_key":   "key",
			"field":          "username",
		},
	})
	if err != nil {
		t.Fatalf("Run username: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("busca por username deve retornar findings")
	}
}

func TestSearchUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target: "test@example.com",
		Options: map[string]string{
			"dehashed_email": "bad@email.com",
			"dehashed_key":   "wrong-key",
		},
	})
	if err == nil {
		t.Fatal("deve retornar erro para 401")
	}
	if !strings.Contains(err.Error(), "credenciais inválidas") {
		t.Errorf("erro deve mencionar 'credenciais inválidas', got: %v", err)
	}
}

func TestSearchRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target: "test@example.com",
		Options: map[string]string{
			"dehashed_email": "account@test.com",
			"dehashed_key":   "key",
		},
	})
	if err == nil {
		t.Fatal("deve retornar erro para rate limit")
	}
}

func TestSearchPaymentRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "payment required", http.StatusPaymentRequired)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target: "test@example.com",
		Options: map[string]string{
			"dehashed_email": "account@test.com",
			"dehashed_key":   "key",
		},
	})
	if err == nil {
		t.Fatal("deve retornar erro para 402")
	}
	if !strings.Contains(err.Error(), "créditos") {
		t.Errorf("erro deve mencionar créditos, got: %v", err)
	}
}

func TestContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			http.Error(w, "cancelled", 499)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{
		Target: "test@example.com",
		Options: map[string]string{
			"dehashed_email": "account@test.com",
			"dehashed_key":   "key",
		},
	})
	if err == nil {
		t.Fatal("contexto cancelado deve retornar erro")
	}
}

func TestDedup(t *testing.T) {
	findings := []module.Finding{
		{Type: "dehashed_record", URL: "https://dehashed.com", Detail: "Test A"},
		{Type: "dehashed_record", URL: "https://dehashed.com", Detail: "Test A"},
		{Type: "dehashed_summary", URL: "https://dehashed.com", Detail: "Sum"},
	}
	result := dedup(findings)
	if len(result) != 2 {
		t.Errorf("dedup: esperado 2 únicos, got %d", len(result))
	}
}

func TestClampSize(t *testing.T) {
	if clampSize(0) != defaultMaxResults {
		t.Error("clampSize(0) deve retornar defaultMaxResults")
	}
	if clampSize(50000) != 10000 {
		t.Error("clampSize(50000) deve ser limitado a 10000")
	}
	if clampSize(100) != 100 {
		t.Error("clampSize(100) deve retornar 100")
	}
}
