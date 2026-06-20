package emailosint

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

// ─── Testes de validação ──────────────────────────────────────────────────────

func TestEmptyTarget(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Fatal("deve retornar erro para target vazio")
	}
}

func TestInvalidEmail(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{Target: "not-an-email"})
	if err == nil {
		t.Fatal("deve retornar erro para email inválido")
	}
}

func TestDomainInputIsNotApplicable(t *testing.T) {
	m := New()
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("domínio genérico deve ser ignorado, não falhar: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("domínio genérico não deve produzir findings de email: %+v", findings)
	}
}

func TestEmailWithoutDomain(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{Target: "user@"})
	if err == nil {
		t.Fatal("deve retornar erro para email sem domínio")
	}
}

// ─── Testes de análise local ──────────────────────────────────────────────────

func TestAnalyzeLocallyValidEmail(t *testing.T) {
	m := New()
	findings := m.analyzeLocally(context.Background(), "test@example.com", "test", "example.com", false)
	if len(findings) == 0 {
		t.Fatal("deve retornar pelo menos 1 finding para email válido")
	}
	found := false
	for _, f := range findings {
		if f.Type == "email_format_valid" {
			found = true
			if f.Extra["confidence"] == "" {
				t.Error("finding sem confidence")
			}
		}
	}
	if !found {
		t.Error("deve conter finding 'email_format_valid'")
	}
}

func TestAnalyzeLocallyDisposable(t *testing.T) {
	m := New()
	findings := m.analyzeLocally(context.Background(), "test@mailinator.com", "test", "mailinator.com", false)
	found := false
	for _, f := range findings {
		if f.Type == "disposable_email" {
			found = true
			if f.Severity != module.SeverityMedium {
				t.Errorf("severidade esperada Medium para email descartável, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("mailinator.com deve ser detectado como descartável")
	}
}

func TestAnalyzeLocallySuspiciousTLD(t *testing.T) {
	m := New()
	findings := m.analyzeLocally(context.Background(), "test@example.xyz", "test", "example.xyz", false)
	found := false
	for _, f := range findings {
		if f.Type == "suspicious_tld" {
			found = true
		}
	}
	if !found {
		t.Error(".xyz deve ser detectado como TLD suspeito")
	}
}

// ─── Testes de helpers ────────────────────────────────────────────────────────

func TestMaskEmail(t *testing.T) {
	cases := map[string]string{
		"test@example.com":       "t**t@example.com",
		"ab@test.com":            "**@test.com",
		"usuario@dominio.com.br": "u*****o@dominio.com.br",
		"not-an-email":           "***@***",
	}
	for input, want := range cases {
		if got := maskEmail(input); got != want {
			t.Errorf("maskEmail(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestDetectEmailProvider(t *testing.T) {
	cases := map[string]string{
		"aspmx.l.google.com":          "Google Workspace / Gmail",
		"mail.protection.outlook.com": "Microsoft 365 / Outlook",
		"mail.yahoo.com":              "Yahoo Mail",
		"mail.protonmail.ch":          "ProtonMail",
		"custom.mailserver.local":     "Custom / Unknown",
	}
	for mx, want := range cases {
		if got := detectEmailProvider([]string{mx}); got != want {
			t.Errorf("detectEmailProvider([%q]) = %q, want %q", mx, got, want)
		}
	}
}

func TestExtractSPFPolicy(t *testing.T) {
	cases := map[string]string{
		"v=spf1 include:_spf.google.com ~all": "softfail (~all)",
		"v=spf1 include:_spf.google.com -all": "hardfail (-all)",
		"v=spf1 include:_spf.google.com +all": "passall (+all) — INSEGURO",
		"v=spf1 include:something":            "sem política explícita",
	}
	for spf, want := range cases {
		if got := extractSPFPolicy(spf); got != want {
			t.Errorf("extractSPFPolicy(%q) = %q, want %q", spf, got, want)
		}
	}
}

func TestExtractDMARCPolicy(t *testing.T) {
	cases := map[string]string{
		"v=DMARC1; p=reject; rua=mailto:dmarc@example.com": "reject (mais seguro)",
		"v=DMARC1; p=quarantine; pct=100":                  "quarantine",
		"v=DMARC1; p=none; rua=mailto:test@example.com":    "none (monitoramento apenas)",
		"v=DMARC1; adkim=s":                                "desconhecida",
	}
	for dmarc, want := range cases {
		if got := extractDMARCPolicy(dmarc); got != want {
			t.Errorf("extractDMARCPolicy(%q) = %q, want %q", dmarc, got, want)
		}
	}
}

func TestIsDisposable(t *testing.T) {
	if !isDisposable("mailinator.com") {
		t.Error("mailinator.com deve ser descartável")
	}
	if !isDisposable("yopmail.com") {
		t.Error("yopmail.com deve ser descartável")
	}
	if isDisposable("gmail.com") {
		t.Error("gmail.com não deve ser descartável")
	}
	if isDisposable("example.com") {
		t.Error("example.com não deve ser descartável")
	}
}

// ─── Testes de Gravatar ───────────────────────────────────────────────────────

func TestGravatarFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"entry": []map[string]interface{}{
				{
					"id":          "12345",
					"hash":        "abc123",
					"displayName": "John Doe",
					"profileUrl":  "https://www.gravatar.com/12345",
					"accounts": []map[string]interface{}{
						{
							"domain":    "github.com",
							"username":  "johndoe",
							"verified":  true,
							"shortname": "github",
							"display":   "GitHub",
						},
					},
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryGravatar(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("queryGravatar: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings para perfil encontrado")
	}
	hasProfle := false
	hasLinked := false
	for _, f := range findings {
		if f.Type == "gravatar_profile" {
			hasProfle = true
		}
		if f.Type == "linked_account" {
			hasLinked = true
		}
	}
	if !hasProfle {
		t.Error("deve conter finding 'gravatar_profile'")
	}
	if !hasLinked {
		t.Error("deve conter finding 'linked_account' para contas vinculadas")
	}
}

func TestGravatarNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryGravatar(context.Background(), "nobody@example.com")
	if err != nil {
		t.Fatalf("404 não deve retornar erro: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("sem perfil deve retornar 0 findings, got %d", len(findings))
	}
}

// ─── Testes de Hunter.io ──────────────────────────────────────────────────────

func TestHunterDeliverable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"result":      "deliverable",
				"score":       95,
				"email":       "test@example.com",
				"mx_records":  true,
				"smtp_server": true,
				"smtp_check":  true,
				"disposable":  false,
				"webmail":     false,
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryHunter(context.Background(), "test@example.com", "key")
	if err != nil {
		t.Fatalf("queryHunter: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("esperado 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "email_deliverability" {
		t.Errorf("tipo esperado 'email_deliverability', got '%s'", findings[0].Type)
	}
	if findings[0].Severity != module.SeverityInfo {
		t.Errorf("severidade esperada Info para email entregável, got %s", findings[0].Severity)
	}
}

func TestHunterUndeliverable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"result":      "undeliverable",
				"score":       5,
				"mx_records":  false,
				"smtp_server": false,
				"smtp_check":  false,
				"disposable":  false,
				"webmail":     false,
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryHunter(context.Background(), "test@fake.invalid", "key")
	if err != nil {
		t.Fatalf("queryHunter: %v", err)
	}
	if findings[0].Severity != module.SeverityHigh {
		t.Errorf("severidade esperada High para undeliverable, got %s", findings[0].Severity)
	}
}

// ─── Testes de EmailRep ───────────────────────────────────────────────────────

func TestEmailRepHighReputaction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"email":      "test@example.com",
			"reputation": "high",
			"suspicious": false,
			"references": 25,
			"details": map[string]interface{}{
				"blacklisted":        false,
				"malicious_activity": false,
				"credentials_leaked": false,
				"data_breach":        false,
				"first_seen":         "01/01/2020",
				"last_seen":          "06/01/2026",
				"spam":               false,
				"free_provider":      false,
				"deliverable":        true,
				"valid_mx":           true,
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryEmailRep(context.Background(), "test@example.com", "")
	if err != nil {
		t.Fatalf("queryEmailRep: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("esperado 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "email_reputation" {
		t.Errorf("tipo esperado 'email_reputation', got '%s'", findings[0].Type)
	}
	if findings[0].Severity != module.SeverityInfo {
		t.Errorf("reputação high deve ter severidade Info, got %s", findings[0].Severity)
	}
}

func TestEmailRepBlacklisted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"email":      "spam@badactor.tk",
			"reputation": "none",
			"suspicious": true,
			"references": 3,
			"details": map[string]interface{}{
				"blacklisted":        true,
				"malicious_activity": true,
				"credentials_leaked": false,
				"data_breach":        false,
				"spam":               true,
				"free_provider":      false,
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryEmailRep(context.Background(), "spam@badactor.tk", "")
	if err != nil {
		t.Fatalf("queryEmailRep: %v", err)
	}
	if findings[0].Severity != module.SeverityCritical {
		t.Errorf("email blacklisted deve ter severidade Critical, got %s", findings[0].Severity)
	}
}

// ─── Testes de HIBP ───────────────────────────────────────────────────────────

func TestHIBPBreachFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"Name":        "Adobe",
				"Title":       "Adobe",
				"Domain":      "adobe.com",
				"BreachDate":  "2013-10-04",
				"PwnCount":    152445165,
				"DataClasses": []string{"Email addresses", "Password hints"},
				"IsVerified":  true,
				"IsSensitive": false,
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryHIBP(context.Background(), "test@example.com", "key", 20)
	if err != nil {
		t.Fatalf("queryHIBP: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar pelo menos 1 finding para breach encontrado")
	}
	if findings[0].Type != "email_in_breach" {
		t.Errorf("tipo esperado 'email_in_breach', got '%s'", findings[0].Type)
	}
	if findings[0].Severity != module.SeverityCritical {
		t.Errorf("152M contas → severidade esperada Critical, got %s", findings[0].Severity)
	}
	// Email mascarado no detail
	if strings.Contains(findings[0].Detail, "test@example.com") {
		t.Error("email completo não deve aparecer no detail")
	}
}

func TestHIBPNoBreachFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryHIBP(context.Background(), "clean@example.com", "key", 20)
	if err != nil {
		t.Fatalf("queryHIBP: %v", err)
	}
	if len(findings) != 1 || findings[0].Type != "hibp_no_breach" {
		t.Errorf("sem breach deve retornar 'hibp_no_breach', got %v", findings)
	}
}

// ─── Testes de LeakCheck ──────────────────────────────────────────────────────

func TestLeakCheckFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"found":   2,
			"fields":  []string{"email", "password", "hash"},
			"sources": []map[string]string{
				{"name": "SomeSite", "date": "2021-06-15"},
				{"name": "OtherBreach", "date": "2022-01-01"},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryLeakCheck(context.Background(), "test@example.com", "key", 10)
	if err != nil {
		t.Fatalf("queryLeakCheck: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("esperado 2 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Type != "email_in_leak" {
			t.Errorf("tipo esperado 'email_in_leak', got '%s'", f.Type)
		}
		if f.Severity != module.SeverityHigh {
			t.Errorf("severidade esperada High, got %s", f.Severity)
		}
	}
}

func TestLeakCheckNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"found":   0,
			"fields":  []string{},
			"sources": []interface{}{},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryLeakCheck(context.Background(), "clean@example.com", "key", 10)
	if err != nil {
		t.Fatalf("queryLeakCheck: %v", err)
	}
	if len(findings) != 1 || findings[0].Type != "leakcheck_no_breach" {
		t.Errorf("não encontrado deve retornar 'leakcheck_no_breach', got %v", findings)
	}
}

// ─── Testes de Clearbit ───────────────────────────────────────────────────────

func TestClearbitFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":       "abc123",
			"email":    "test@company.com",
			"name":     map[string]string{"fullName": "John Doe"},
			"location": "San Francisco, CA",
			"employment": map[string]string{
				"name":      "Acme Corp",
				"title":     "Senior Engineer",
				"seniority": "senior",
				"role":      "engineering",
				"domain":    "acmecorp.com",
			},
			"linkedin": map[string]string{"handle": "johndoe"},
			"github":   map[string]string{"handle": "johndoe-dev"},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryClearbit(context.Background(), "test@company.com", "test-key")
	if err != nil {
		t.Fatalf("queryClearbit: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("esperado 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "email_person_record" {
		t.Errorf("tipo esperado 'email_person_record', got '%s'", f.Type)
	}
	if f.Extra["linkedin"] == "" {
		t.Error("linkedin deve estar no extra")
	}
	if f.Extra["github"] == "" {
		t.Error("github deve estar no extra")
	}
}

// ─── Testes de fluxo completo ─────────────────────────────────────────────────

func TestRunLocalOnly(t *testing.T) {
	m := New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "user@example.com",
		Options: map[string]string{
			"sources":   "gravatar", // apenas gravatar (sem DNS pois não tem servidor de teste)
			"check_dns": "false",
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Análise local sempre roda, mesmo com sources específicas
	if len(findings) == 0 {
		t.Fatal("deve retornar ao menos 1 finding (análise local)")
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
	}
}

func TestRunContextCancelled(t *testing.T) {
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
	findings, err := m.Run(ctx, module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"check_dns": "false", "sources": "gravatar"},
	})
	if err != nil {
		t.Fatalf("Run não deve propagar erro de contexto: %v", err)
	}
	// Análise local sempre retorna
	if len(findings) == 0 {
		t.Fatal("deve retornar findings locais mesmo com contexto cancelado")
	}
}

func TestDedup(t *testing.T) {
	findings := []module.Finding{
		{Type: "email_format_valid", URL: "", Detail: "Válido."},
		{Type: "email_format_valid", URL: "", Detail: "Válido."},
		{Type: "disposable_email", URL: "", Detail: "Descartável."},
	}
	result := dedup(findings)
	if len(result) != 2 {
		t.Errorf("dedup: esperado 2 únicos, got %d", len(result))
	}
}

func TestRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.queryGravatar(context.Background(), "test@example.com")
	if err == nil {
		t.Error("rate limit deve retornar erro")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("erro deve mencionar 429, got: %v", err)
	}
}
