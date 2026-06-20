package credleak_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/credleak"
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
	if credleak.New().Name() != "credleak" {
		t.Error("nome incorreto")
	}
}

func TestNew_NotNil(t *testing.T) {
	if credleak.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := credleak.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("target vazio deve retornar erro")
	}
}

func TestRun_InvalidEmail_ReturnsError(t *testing.T) {
	_, err := credleak.New().Run(context.Background(), module.Input{
		Target: "not-an-email@", // tem @ mas é malformado
		Options: map[string]string{
			"sources":  "hibp_breaches",
			"hibp_key": "test",
		},
	})
	if err == nil {
		t.Fatal("email inválido deve retornar erro")
	}
}

// ─── HIBP Breaches ────────────────────────────────────────────────────────────

func hibpBreachesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]map[string]interface{}{
		{
			"Name":        "Adobe",
			"Domain":      "adobe.com",
			"BreachDate":  "2013-10-04",
			"PwnCount":    152445165,
			"DataClasses": []string{"Email addresses", "Passwords", "Usernames"},
			"IsVerified":  true,
			"IsSensitive": false,
		},
		{
			"Name":        "LinkedIn",
			"Domain":      "linkedin.com",
			"BreachDate":  "2012-05-05",
			"PwnCount":    164611595,
			"DataClasses": []string{"Email addresses", "Passwords"},
			"IsVerified":  true,
			"IsSensitive": false,
		},
	})
}

func TestRun_HIBP_Email_BreachesFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(hibpBreachesHandler))
	defer srv.Close()

	m := credleak.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "user@example.com",
		Options: map[string]string{
			"sources":  "hibp_breaches",
			"hibp_key": "test-key",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings de breach")
	}

	var credFound, riskFound bool
	for _, f := range findings {
		if f.Type == "credential_in_breach" {
			credFound = true
			if strings.Contains(f.Extra["email"], "user@") {
				t.Error("email completo não deve aparecer no finding — LGPD/privacidade")
			}
			if f.Extra["breach_name"] == "Adobe" {
				if f.Extra["has_passwords"] != "true" {
					t.Error("Adobe breach deve ter has_passwords=true")
				}
				if f.Severity != module.SeverityCritical {
					t.Errorf("breach com senhas deve ser Critical, obteve %s", f.Severity)
				}
			}
		}
		if f.Type == "credential_risk_high" {
			riskFound = true
		}
	}
	if !credFound {
		t.Error("esperava finding 'credential_in_breach'")
	}
	if !riskFound {
		t.Error("esperava finding 'credential_risk_high' quando há breaches com senhas")
	}
}

func TestRun_HIBP_Email_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := credleak.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "safe@example.com",
		Options: map[string]string{
			"sources":  "hibp_breaches",
			"hibp_key": "test-key",
		},
	})
	if err != nil {
		t.Fatalf("404 não deve retornar erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding 'not in breach'")
	}
	if findings[0].Type != "email_not_in_breach" {
		t.Errorf("tipo esperado 'email_not_in_breach', obteve '%s'", findings[0].Type)
	}
}

func TestRun_HIBP_NoKey_NoBreachCheck(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	m := credleak.NewWithClient(newTestClient(srv))
	_, _ = m.Run(context.Background(), module.Input{
		Target: "user@example.com",
		Options: map[string]string{
			"sources": "hibp_breaches",
			// sem hibp_key
		},
	})
	if called {
		t.Error("sem hibp_key não deve chamar HIBP")
	}
}

// ─── HIBP Passwords (k-anonymity) ────────────────────────────────────────────

func hibpPasswordsHandler(w http.ResponseWriter, r *http.Request) {
	// Responde com o sufixo de "password" (SHA1 = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n"))
	w.Write([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:5\r\n"))
}

func TestRun_HIBP_Password_Exposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(hibpPasswordsHandler))
	defer srv.Close()

	m := credleak.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: ":password", // só senha, sem email
		Options: map[string]string{
			"sources": "hibp_passwords",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding de senha exposta")
	}
	for _, f := range findings {
		if f.Type == "password_exposed" {
			pwnCount, _ := strconv.Atoi(f.Extra["pwn_count"])
			if pwnCount == 0 {
				t.Error("pwn_count deve ser > 0")
			}
			if f.Extra["method"] != "k-anonymity" {
				t.Error("método deve ser k-anonymity")
			}
			if f.Severity != module.SeverityCritical {
				t.Errorf("senha com 9M+ exposições deve ser Critical, obteve %s", f.Severity)
			}
		}
	}
}

func notExposedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\n"))
	w.Write([]byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2\r\n"))
}

func TestRun_HIBP_Password_NotExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(notExposedHandler))
	defer srv.Close()

	m := credleak.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: ":Tr0ub4dor&3xK9!",
		Options: map[string]string{
			"sources": "hibp_passwords",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding 'not exposed'")
	}
	if findings[0].Type != "password_not_exposed" {
		t.Errorf("tipo esperado 'password_not_exposed', obteve '%s'", findings[0].Type)
	}
	if findings[0].Extra["pwn_count"] != "0" {
		t.Error("pwn_count deve ser 0")
	}
}

// ─── Pattern Analysis ─────────────────────────────────────────────────────────

func TestRun_PatternAnalysis_WeakPassword(t *testing.T) {
	m := credleak.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: ":123456",
		Options: map[string]string{
			"sources": "pattern_analysis",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings de análise de padrão")
	}

	var analysisFound, commonFound bool
	for _, f := range findings {
		if f.Type == "password_pattern_analysis" {
			analysisFound = true
			if f.Extra["score"] == "" {
				t.Error("score deve estar presente")
			}
			if f.Extra["entropy_bits"] == "" {
				t.Error("entropy_bits deve estar presente")
			}
			// Senha fraca deve ter severity alta
			if f.Severity != module.SeverityHigh && f.Severity != module.SeverityCritical {
				t.Errorf("senha fraca deve ser High ou Critical, obteve %s", f.Severity)
			}
		}
		if f.Type == "common_password_detected" {
			commonFound = true
			if f.Severity != module.SeverityCritical {
				t.Errorf("senha comum deve ser Critical, obteve %s", f.Severity)
			}
		}
	}
	if !analysisFound {
		t.Error("esperava finding 'password_pattern_analysis'")
	}
	if !commonFound {
		t.Error("esperava finding 'common_password_detected' para '123456'")
	}
}

func TestRun_PatternAnalysis_StrongPassword(t *testing.T) {
	m := credleak.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: ":Xk9#mP2@vLqR5&nT",
		Options: map[string]string{
			"sources": "pattern_analysis",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Type == "password_pattern_analysis" {
			score, _ := strconv.ParseFloat(f.Extra["score"], 64)
			if score < 0.5 {
				t.Errorf("senha forte deve ter score >= 0.5, obteve %.2f", score)
			}
		}
		if f.Type == "common_password_detected" {
			t.Error("senha forte não deve ser detectada como comum")
		}
	}
}

func TestRun_PatternAnalysis_Sequential(t *testing.T) {
	m := credleak.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: ":abc123def",
		Options: map[string]string{
			"sources": "pattern_analysis",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Type == "password_pattern_analysis" {
			if !strings.Contains(f.Extra["issues"], "sequência") {
				t.Error("issues deve mencionar sequência para 'abc123'")
			}
		}
	}
}

// ─── Credential Pair Analysis ─────────────────────────────────────────────────

func TestRun_CredentialPair_PasswordEqualsEmailLocal(t *testing.T) {
	m := credleak.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "joao@example.com:joao", // senha = parte local do email
		Options: map[string]string{
			"sources": "pattern_analysis",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}

	var credPatternFound bool
	for _, f := range findings {
		if f.Type == "credential_pattern_risk" && f.Extra["risk"] == "password_equals_email_local" {
			credPatternFound = true
			if f.Severity != module.SeverityCritical {
				t.Errorf("senha=email deve ser Critical, obteve %s", f.Severity)
			}
		}
	}
	if !credPatternFound {
		t.Error("esperava finding 'credential_pattern_risk' com risco password_equals_email_local")
	}
}

func TestRun_CredentialPair_PasswordContainsDomain(t *testing.T) {
	m := credleak.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "user@empresa.com.br:empresa2024!",
		Options: map[string]string{
			"sources": "pattern_analysis",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}

	var domainFound bool
	for _, f := range findings {
		if f.Type == "credential_pattern_risk" && f.Extra["risk"] == "password_contains_domain" {
			domainFound = true
		}
	}
	if !domainFound {
		t.Error("esperava finding 'credential_pattern_risk' com risco password_contains_domain")
	}
}

// ─── LeakCheck ───────────────────────────────────────────────────────────────

func leakCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"found":   2,
		"fields":  []string{"email", "password", "username"},
		"sources": []map[string]interface{}{
			{"name": "BreachSite1", "date": "2021-01-01", "unencrypted_hash": true},
			{"name": "BreachSite2", "date": "2022-06-15", "unencrypted_hash": false},
		},
	})
}

func TestRun_LeakCheck_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(leakCheckHandler))
	defer srv.Close()

	m := credleak.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "user@example.com",
		Options: map[string]string{
			"sources":       "leakcheck",
			"leakcheck_key": "test-key",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via LeakCheck")
	}

	for _, f := range findings {
		if f.Extra["source"] == "leakcheck" {
			if f.Extra["found_count"] != "2" {
				t.Errorf("found_count esperado '2', obteve '%s'", f.Extra["found_count"])
			}
			// Com hash não criptografado, deve ser Critical
			if f.Severity != module.SeverityCritical {
				t.Errorf("com hash não criptografado deve ser Critical, obteve %s", f.Severity)
			}
		}
	}
}

func TestRun_LeakCheck_NoKey_NoCall(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	m := credleak.NewWithClient(newTestClient(srv))
	_, _ = m.Run(context.Background(), module.Input{
		Target: "user@example.com",
		Options: map[string]string{
			"sources": "leakcheck",
			// sem leakcheck_key
		},
	})
	if called {
		t.Error("leakcheck sem key não deve fazer chamada")
	}
}

// ─── confidence e detail ─────────────────────────────────────────────────────

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(hibpBreachesHandler))
	defer srv.Close()

	m := credleak.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "user@example.com",
		Options: map[string]string{
			"sources":  "hibp_breaches",
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

	m := credleak.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "user@example.com",
		Options: map[string]string{
			"sources":  "hibp_breaches",
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

	m := credleak.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "user@example.com",
		Options: map[string]string{
			"sources":  "hibp_breaches",
			"hibp_key": "test-key",
		},
	})
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.Type + "|" + f.Extra["source"] + "|" + f.Extra["breach_name"]
		if seen[key] {
			t.Errorf("finding duplicado: %s", key)
		}
		seen[key] = true
	}
}

// ─── min_score filter ────────────────────────────────────────────────────────

func TestRun_MinScore_FiltersLowConfidence(t *testing.T) {
	m := credleak.New()
	// Análise de padrão de senha forte → confidence 0.85
	// com min_score=0.95 → deve filtrar
	findings, err := m.Run(context.Background(), module.Input{
		Target: ":Xk9#mP2@vLqR5&nT",
		Options: map[string]string{
			"sources":   "pattern_analysis",
			"min_score": "0.95",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	// Com min_score alto, findings de análise de padrão (0.85) devem ser filtrados
	for _, f := range findings {
		if f.Extra["source"] == "pattern_analysis" {
			conf, _ := strconv.ParseFloat(f.Extra["confidence"], 64)
			if conf < 0.95 {
				t.Errorf("finding com confidence %.2f não devia passar min_score 0.95", conf)
			}
		}
	}
}

// ─── context cancelado ────────────────────────────────────────────────────────

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv := httptest.NewServer(http.HandlerFunc(hibpBreachesHandler))
	defer srv.Close()

	m := credleak.NewWithClient(newTestClient(srv))
	_, _ = m.Run(ctx, module.Input{
		Target: "user@example.com",
		Options: map[string]string{
			"sources":  "hibp_breaches",
			"hibp_key": "test-key",
		},
	})
}
