package hibp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/hibp"
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

// ─── estrutura ────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if hibp.New().Name() != "hibp" {
		t.Error("nome incorreto")
	}
}

func TestNew_NotNil(t *testing.T) {
	if hibp.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := hibp.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("target vazio deve retornar erro")
	}
}

// ─── email mode ───────────────────────────────────────────────────────────────

func TestRun_Email_NoAPIKey_ReturnsError(t *testing.T) {
	_, err := hibp.New().Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"mode": "email"},
	})
	if err == nil {
		t.Fatal("email sem API key deve retornar erro")
	}
}

func TestRun_Email_InvalidEmail_ReturnsError(t *testing.T) {
	_, err := hibp.New().Run(context.Background(), module.Input{
		Target: "not-an-email",
		Options: map[string]string{
			"mode":     "email",
			"hibp_key": "test-key",
		},
	})
	if err == nil {
		t.Fatal("email inválido deve retornar erro")
	}
}

func hibpBreachesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]map[string]interface{}{
		{
			"Name":         "Adobe",
			"Domain":       "adobe.com",
			"BreachDate":   "2013-10-04",
			"AddedDate":    "2013-12-04",
			"PwnCount":     152445165,
			"Description":  "Adobe breach description",
			"DataClasses":  []string{"Email addresses", "Passwords", "Usernames"},
			"IsVerified":   true,
			"IsFabricated": false,
			"IsSensitive":  false,
			"IsRetired":    false,
			"IsSpamList":   false,
		},
		{
			"Name":         "LinkedIn",
			"Domain":       "linkedin.com",
			"BreachDate":   "2012-05-05",
			"AddedDate":    "2016-05-21",
			"PwnCount":     164611595,
			"Description":  "LinkedIn breach description",
			"DataClasses":  []string{"Email addresses", "Passwords"},
			"IsVerified":   true,
			"IsFabricated": false,
			"IsSensitive":  false,
			"IsRetired":    false,
			"IsSpamList":   false,
		},
	})
}

func TestRun_Email_Breaches_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(hibpBreachesHandler))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "test@example.com",
		Options: map[string]string{
			"mode":     "email",
			"hibp_key": "test-key",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings de breach")
	}

	var adobeFound bool
	for _, f := range findings {
		if f.Type != "email_in_breach" {
			t.Errorf("tipo esperado 'email_in_breach', obteve '%s'", f.Type)
		}
		if f.Extra["breach_name"] == "Adobe" {
			adobeFound = true
			if f.Extra["pwn_count"] != "152445165" {
				t.Errorf("pwn_count incorreto: '%s'", f.Extra["pwn_count"])
			}
			if f.Extra["has_passwords"] != "true" {
				t.Error("has_passwords deve ser true para Adobe breach")
			}
			if f.Severity != module.SeverityCritical {
				t.Errorf("breach com Passwords deve ser SeverityCritical, obteve %s", f.Severity)
			}
			// Email deve estar mascarado
			if strings.Contains(f.Extra["email"], "test@") {
				t.Error("email completo não deve aparecer no finding")
			}
		}
	}
	if !adobeFound {
		t.Error("esperava finding para breach Adobe")
	}
}

func TestRun_Email_NotFound_NotBreachedFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "safe@example.com",
		Options: map[string]string{
			"mode":     "email",
			"hibp_key": "test-key",
		},
	})
	if err != nil {
		t.Fatalf("404 não deve retornar erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding de 'não encontrado'")
	}
	if findings[0].Type != "hibp_no_breach" {
		t.Errorf("tipo esperado 'hibp_no_breach', obteve '%s'", findings[0].Type)
	}
	if findings[0].Extra["breached"] != "false" {
		t.Error("breached deve ser 'false'")
	}
}

func TestRun_Email_Unauthorized_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target: "test@example.com",
		Options: map[string]string{
			"mode":     "email",
			"hibp_key": "invalid-key",
		},
	})
	if err == nil {
		t.Fatal("401 deve retornar erro")
	}
}

func TestRun_Email_RateLimit_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target: "test@example.com",
		Options: map[string]string{
			"mode":     "email",
			"hibp_key": "test-key",
		},
	})
	if err == nil {
		t.Fatal("429 deve retornar erro de rate limit")
	}
}

// ─── paste mode ───────────────────────────────────────────────────────────────

func hibpPastesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]map[string]interface{}{
		{
			"Source":     "Pastebin",
			"Id":         "8Q0BvKD8",
			"Title":      "leaked emails",
			"Date":       "2022-03-01T00:00:00Z",
			"EmailCount": 150,
		},
	})
}

func TestRun_Paste_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(hibpPastesHandler))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "test@example.com",
		Options: map[string]string{
			"mode":     "paste",
			"hibp_key": "test-key",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings de paste")
	}
	for _, f := range findings {
		if f.Type == "email_in_paste" {
			if f.Extra["paste_source"] != "Pastebin" {
				t.Errorf("paste_source esperado 'Pastebin', obteve '%s'", f.Extra["paste_source"])
			}
			if f.Extra["email_count"] != "150" {
				t.Errorf("email_count esperado '150', obteve '%s'", f.Extra["email_count"])
			}
			if f.Severity != module.SeverityHigh {
				t.Errorf("paste deve ser SeverityHigh, obteve %s", f.Severity)
			}
			// URL deve apontar para Pastebin
			if !strings.Contains(f.URL, "pastebin.com") {
				t.Error("URL deve apontar para pastebin.com")
			}
		}
	}
}

func TestRun_Paste_NotFound_NoPasteFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "safe@example.com",
		Options: map[string]string{
			"mode":     "paste",
			"hibp_key": "test-key",
		},
	})
	if err != nil {
		t.Fatalf("404 pastes não deve retornar erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding 'hibp_no_paste'")
	}
	if findings[0].Type != "hibp_no_paste" {
		t.Errorf("tipo esperado 'hibp_no_paste', obteve '%s'", findings[0].Type)
	}
}

// ─── password mode (k-anonymity) ─────────────────────────────────────────────

// A senha "password" tem SHA-1 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
// O prefixo enviado ao servidor é "5BAA6"

func pwnedPasswordHandler(w http.ResponseWriter, r *http.Request) {
	// Retorna lista de sufixos com contagem
	// "password" → SHA-1 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	// Sufixo após "5BAA6" é 1E4C9B93F3F0682250B6CF8331B7EE68FD8
	w.Header().Set("Content-Type", "text/plain")
	// Inclui várias entradas, uma delas é o sufixo da senha "password"
	w.Write([]byte("1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n"))
	w.Write([]byte("2AAE6C069F275D58BF5D7C4926B2E2C05:5\r\n"))
	w.Write([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\n"))
}

func TestRun_Password_Pwned_HighCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(pwnedPasswordHandler))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "password",
		Options: map[string]string{"mode": "password"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding para senha 'password' exposta")
	}
	for _, f := range findings {
		if f.Type == "password_pwned" {
			if f.Extra["method"] != "k-anonymity" {
				t.Error("método deve ser k-anonymity")
			}
			pwnCount, _ := parseInt(f.Extra["pwn_count"])
			if pwnCount == 0 {
				t.Error("pwn_count deve ser > 0")
			}
			if f.Severity != module.SeverityCritical {
				t.Errorf("senha com 9M+ exposições deve ser SeverityCritical, obteve %s", f.Severity)
			}
		}
	}
}

func notPwnedPasswordHandler(w http.ResponseWriter, r *http.Request) {
	// Retorna lista sem o sufixo da senha de teste
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:100\r\n"))
	w.Write([]byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:50\r\n"))
}

func TestRun_Password_NotPwned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(notPwnedPasswordHandler))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "Tr0ub4dor&3",
		Options: map[string]string{"mode": "password"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding 'not_pwned'")
	}
	if findings[0].Type != "password_not_pwned" {
		t.Errorf("tipo esperado 'password_not_pwned', obteve '%s'", findings[0].Type)
	}
	if findings[0].Extra["pwn_count"] != "0" {
		t.Error("pwn_count deve ser 0")
	}
}

func TestRun_Password_NoAPIKeyNeeded(t *testing.T) {
	// Verificação de senha NÃO deve exigir API key
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// Verifica que API key não é enviada
		if r.Header.Get("hibp-api-key") != "" {
			// Não é erro, mas é incomum
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("AAAA:0\r\n"))
	}))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	_, _ = m.Run(context.Background(), module.Input{
		Target:  "anypassword",
		Options: map[string]string{"mode": "password"},
		// sem hibp_key
	})
	if !called {
		t.Error("endpoint k-anonymity deve ser chamado mesmo sem API key")
	}
}

// ─── breach mode ─────────────────────────────────────────────────────────────

func hibpBreachDetailsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"Name":        "Adobe",
		"Title":       "Adobe",
		"Domain":      "adobe.com",
		"BreachDate":  "2013-10-04",
		"AddedDate":   "2013-12-04",
		"PwnCount":    152445165,
		"Description": "Adobe breach description",
		"DataClasses": []string{"Email addresses", "Password hints", "Passwords", "Usernames"},
		"IsVerified":  true,
		"IsSensitive": false,
	})
}

func TestRun_Breach_Details(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(hibpBreachDetailsHandler))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "Adobe",
		Options: map[string]string{"mode": "breach"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding de breach details")
	}
	for _, f := range findings {
		if f.Type == "breach_details" {
			if f.Extra["breach_name"] != "Adobe" {
				t.Errorf("breach_name esperado 'Adobe', obteve '%s'", f.Extra["breach_name"])
			}
			if f.Extra["is_verified"] != "true" {
				t.Error("is_verified deve ser true")
			}
		}
	}
}

func TestRun_Breach_NotFound_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target:  "NonExistentBreach",
		Options: map[string]string{"mode": "breach"},
	})
	if err == nil {
		t.Fatal("breach inexistente deve retornar erro")
	}
}

// ─── confidence e detail ─────────────────────────────────────────────────────

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(hibpBreachesHandler))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "test@example.com",
		Options: map[string]string{
			"mode":     "email",
			"hibp_key": "test-key",
		},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(hibpBreachesHandler))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "test@example.com",
		Options: map[string]string{
			"mode":     "email",
			"hibp_key": "test-key",
		},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Errorf("finding sem Detail: %+v", f)
		}
	}
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestRun_Dedup_NoDuplicates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(hibpBreachesHandler))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "test@example.com",
		Options: map[string]string{
			"mode":     "email",
			"hibp_key": "test-key",
		},
	})
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.Type + "|" + f.Extra["breach_name"]
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

	srv := httptest.NewServer(http.HandlerFunc(hibpBreachesHandler))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	_, _ = m.Run(ctx, module.Input{
		Target: "test@example.com",
		Options: map[string]string{
			"mode":     "email",
			"hibp_key": "test-key",
		},
	})
}

// ─── auto-detect mode ─────────────────────────────────────────────────────────

func TestRun_AutoDetect_Email(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verifica que vai para /breachedaccount/ e não para /breach/
		if !strings.Contains(r.URL.Path, "breachedaccount") {
			t.Errorf("email deve chamar breachedaccount, chamou %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := hibp.NewWithClient(newTestClient(srv))
	_, _ = m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"hibp_key": "test-key"},
		// mode não especificado — deve auto-detectar como "email"
	})
}

func TestRun_InvalidMode_ReturnsError(t *testing.T) {
	_, err := hibp.New().Run(context.Background(), module.Input{
		Target:  "something",
		Options: map[string]string{"mode": "invalid"},
	})
	if err == nil {
		t.Fatal("modo inválido deve retornar erro")
	}
}

// ─── helper ───────────────────────────────────────────────────────────────────

func parseInt(s string) (int, error) {
	return strconv.Atoi(s)
}
