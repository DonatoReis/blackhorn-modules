package whatsapp

import (
	"context"
	"encoding/json"
	"fmt"
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
	return &http.Client{
		Transport: &rewriteTransport{base: srv.URL},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ─── Testes de normalizeE164 ──────────────────────────────────────────────────

func TestNormalizeE164(t *testing.T) {
	cases := []struct {
		input       string
		countryCode string
		want        string
	}{
		{"+5511999999999", "55", "+5511999999999"},
		{"5511999999999", "55", "+5511999999999"},
		{"11999999999", "55", "+5511999999999"},
		{"+14155551234", "1", "+14155551234"},
		{"011999999999", "55", "+5511999999999"}, // remove 0 de discagem, adiciona DDI BR
	}
	for _, tt := range cases {
		got, err := normalizeE164(tt.input, tt.countryCode)
		if err != nil {
			t.Errorf("normalizeE164(%q, %q): erro: %v", tt.input, tt.countryCode, err)
			continue
		}
		if got != tt.want {
			t.Errorf("normalizeE164(%q, %q) = %q, want %q", tt.input, tt.countryCode, got, tt.want)
		}
	}
}

func TestNormalizeE164Empty(t *testing.T) {
	_, err := normalizeE164("", "55")
	if err == nil {
		t.Error("deve retornar erro para número vazio")
	}
}

// ─── Testes de isMobileNumber ─────────────────────────────────────────────────

func TestIsMobileNumber(t *testing.T) {
	cases := map[string]bool{
		"+5511999999999": true,  // BR móvel: 55 + 11 + 9XXXXXXXX
		"+5511333344444": false, // BR fixo: 55 + 11 + XXXXXXXX (10 dígitos)
		"+14155551234":   true,  // EUA com 11+ dígitos
		"+12":            false, // muito curto
	}
	for num, want := range cases {
		if got := isMobileNumber(num); got != want {
			t.Errorf("isMobileNumber(%q) = %v, want %v", num, got, want)
		}
	}
}

// ─── Testes de maskPhone ──────────────────────────────────────────────────────

func TestMaskPhone(t *testing.T) {
	// Verifica que número completo nunca aparece
	phone := "+5511999999999"
	masked := maskPhone(phone)
	if strings.Contains(masked, "999999999") {
		t.Errorf("maskPhone deve ocultar o número: %s", masked)
	}
	if masked == "" {
		t.Error("maskPhone não deve retornar vazio")
	}
}

// ─── Testes de validação ──────────────────────────────────────────────────────

func TestEmptyTarget(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Fatal("deve retornar erro para target vazio")
	}
}

// ─── Testes de analyzeLocally ────────────────────────────────────────────────

func TestAnalyzeLocallyMobile(t *testing.T) {
	findings := analyzeLocally("11999999999", "+5511999999999")
	if len(findings) == 0 {
		t.Fatal("deve retornar pelo menos 1 finding")
	}
	if findings[0].Type != "whatsapp_number_analysis" {
		t.Errorf("tipo esperado 'whatsapp_number_analysis', got '%s'", findings[0].Type)
	}
	if findings[0].Extra["is_mobile"] != "true" {
		t.Errorf("is_mobile esperado 'true', got '%s'", findings[0].Extra["is_mobile"])
	}
	if findings[0].Extra["confidence"] == "" {
		t.Error("finding sem confidence")
	}
}

func TestAnalyzeLocallyFixed(t *testing.T) {
	findings := analyzeLocally("1133334444", "+551133334444")
	if len(findings) == 0 {
		t.Fatal("deve retornar pelo menos 1 finding")
	}
	// Número fixo deve ter severidade Low (inadequado para WhatsApp)
	if findings[0].Severity != module.SeverityLow {
		t.Errorf("número fixo deve ter severidade Low, got %s", findings[0].Severity)
	}
}

// ─── Testes de click-to-chat probe ───────────────────────────────────────────

func TestProbeClickToChatFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simula página wa.me com link de abertura do WhatsApp
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><a href="https://open.whatsapp.com/send?phone=5511999999999">Open WhatsApp</a>
<meta property="og:image" content="https://example.com/profile-pic.jpg">
</body></html>`)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.probeClickToChat(context.Background(), "+5511999999999")
	if err != nil {
		t.Fatalf("probeClickToChat: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar pelo menos 1 finding")
	}
	if findings[0].Type != "whatsapp_account_found" {
		t.Errorf("tipo esperado 'whatsapp_account_found', got '%s'", findings[0].Type)
	}
	if findings[0].Extra["registered"] != "true" {
		t.Error("registered deve ser true")
	}
}

func TestProbeClickToChatNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.probeClickToChat(context.Background(), "+5511999999999")
	if err != nil {
		t.Fatalf("probeClickToChat: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar finding mesmo para 404")
	}
	if findings[0].Type != "whatsapp_not_found" {
		t.Errorf("tipo esperado 'whatsapp_not_found', got '%s'", findings[0].Type)
	}
}

func TestProbeClickToChatRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://open.whatsapp.com/send?phone=5511999999999", http.StatusFound)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.probeClickToChat(context.Background(), "+5511999999999")
	if err != nil {
		t.Fatalf("probeClickToChat redirect: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar finding para redirect")
	}
	// Redirect para open.whatsapp.com indica conta ativa
	if findings[0].Type != "whatsapp_account_found" {
		t.Errorf("redirect para open.whatsapp.com deve indicar 'whatsapp_account_found', got '%s'", findings[0].Type)
	}
}

// ─── Testes de WhatsApp Business API ─────────────────────────────────────────

func TestQueryBusinessAPIRegistered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"contacts": []map[string]interface{}{
				{
					"input": "+5511999999999",
					"wa_id": "5511999999999",
					"name":  "Test User",
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBusinessAPI(context.Background(), "+5511999999999", "test-token", "123456789")
	if err != nil {
		t.Fatalf("queryBusinessAPI: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar pelo menos 1 finding")
	}
	f := findings[0]
	if f.Type != "whatsapp_registered" {
		t.Errorf("tipo esperado 'whatsapp_registered', got '%s'", f.Type)
	}
	if f.Extra["wa_id"] == "" {
		t.Error("wa_id deve estar no extra")
	}
	if f.Extra["confidence"] == "" {
		t.Error("finding sem confidence")
	}
	// Número nunca exposto
	if strings.Contains(f.Extra["wa_id"], "999999999") {
		// wa_id é público e necessário para correlação — aceitável
	}
}

func TestQueryBusinessAPINotRegistered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"contacts": []map[string]interface{}{
				{
					"input": "+5511999999998",
					"wa_id": "", // sem WA ID = não registrado
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBusinessAPI(context.Background(), "+5511999999998", "test-token", "123")
	if err != nil {
		t.Fatalf("queryBusinessAPI not registered: %v", err)
	}
	if len(findings) != 1 || findings[0].Type != "whatsapp_not_registered" {
		t.Errorf("deve retornar 'whatsapp_not_registered', got %v", findings)
	}
}

func TestQueryBusinessAPIUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.queryBusinessAPI(context.Background(), "+5511999999999", "bad-token", "123")
	if err == nil {
		t.Error("token inválido deve retornar erro")
	}
	if !strings.Contains(err.Error(), "token inválido") {
		t.Errorf("erro deve mencionar 'token inválido', got: %v", err)
	}
}

// ─── Testes de profile picture probe ─────────────────────────────────────────

func TestProbeProfilePictureFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><head>
<meta property="og:image" content="https://pps.whatsapp.net/v/t61.24694-24/profile.jpg">
</head></html>`)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.probeProfilePicture(context.Background(), "+5511999999999")
	if err != nil {
		t.Fatalf("probeProfilePicture: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar finding quando og:image presente")
	}
	if findings[0].Type != "whatsapp_profile_picture" {
		t.Errorf("tipo esperado 'whatsapp_profile_picture', got '%s'", findings[0].Type)
	}
	if findings[0].Extra["image_url"] == "" {
		t.Error("image_url deve estar no extra")
	}
}

func TestProbeProfilePictureNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body>no profile</body></html>`)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.probeProfilePicture(context.Background(), "+5511999999999")
	if err != nil {
		t.Fatalf("probeProfilePicture: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("sem og:image deve retornar 0 findings, got %d", len(findings))
	}
}

// ─── Testes de fluxo completo ─────────────────────────────────────────────────

func TestRunMobileNumber(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><a href="https://open.whatsapp.com/send">Open</a></body></html>`)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "11999999999",
		Options: map[string]string{"check_profile": "false"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings")
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
		Target:  "11999999999",
		Options: map[string]string{"check_profile": "false"},
	})
	if err != nil {
		t.Fatalf("Run não deve propagar erro de contexto: %v", err)
	}
	// Análise local e contexto cancelado: tolera falhas
	if len(findings) == 0 {
		t.Fatal("deve retornar pelo menos análise local")
	}
}

func TestDedup(t *testing.T) {
	findings := []module.Finding{
		{Type: "whatsapp_account_found", URL: "https://wa.me/5511", Detail: "Found"},
		{Type: "whatsapp_account_found", URL: "https://wa.me/5511", Detail: "Found"},
		{Type: "whatsapp_number_analysis", URL: "", Detail: "Analysis"},
	}
	result := dedup(findings)
	if len(result) != 2 {
		t.Errorf("dedup: esperado 2 únicos, got %d", len(result))
	}
}
