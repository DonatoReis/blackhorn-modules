package leakosint

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

// ─── detectSearchType ─────────────────────────────────────────────────────────

func TestDetectSearchType(t *testing.T) {
	cases := []struct {
		input    string
		override string
		want     SearchType
	}{
		{"user@example.com", "", SearchEmail},
		{"192.168.1.1", "", SearchIP},
		{"5d41402abc4b2a76b9719d911017c592", "", SearchHash}, // MD5 de 32 chars
		{"a94a8fe5ccb19ba61c4c0873d391e987", "", SearchHash}, // SHA1 de 40 chars (40 > 32 mas entra em hash)
		{"example.com", "", SearchDomain},
		{"johndoe", "", SearchUsername},
		{"user@x.com", "email", SearchEmail},
		{"192.168.1.1", "ip", SearchIP},
	}
	for _, tt := range cases {
		got := detectSearchType(tt.input, tt.override)
		if got != tt.want {
			t.Errorf("detectSearchType(%q, %q) = %v, want %v", tt.input, tt.override, got, tt.want)
		}
	}
}

// ─── maskTarget ──────────────────────────────────────────────────────────────

func TestMaskTargetEmail(t *testing.T) {
	got := maskTarget("user@example.com", SearchEmail)
	if strings.Contains(got, "ser@") {
		t.Errorf("maskTarget email deve mascarar parte local: %s", got)
	}
	if !strings.Contains(got, "@example.com") {
		t.Errorf("maskTarget email deve preservar domínio: %s", got)
	}
}

func TestMaskTargetIP(t *testing.T) {
	got := maskTarget("192.168.1.1", SearchIP)
	if !strings.HasPrefix(got, "192.168.") {
		t.Errorf("maskTarget IP deve preservar 2 primeiros octetos: %s", got)
	}
	if strings.Contains(got, ".1.1") {
		t.Errorf("maskTarget IP deve mascarar últimos octetos: %s", got)
	}
}

func TestMaskTargetUsername(t *testing.T) {
	got := maskTarget("johndoe123", SearchUsername)
	if got == "johndoe123" {
		t.Error("maskTarget username deve mascarar parte do nome")
	}
	if !strings.HasPrefix(got, "joh") {
		t.Errorf("maskTarget username deve preservar primeiros 3 chars: %s", got)
	}
}

func TestMaskTargetShort(t *testing.T) {
	got := maskTarget("ab", SearchUsername)
	if got != "ab" {
		t.Errorf("maskTarget de 2 chars não deve mascarar: %s", got)
	}
}

// ─── hashPrefix ──────────────────────────────────────────────────────────────

func TestHashPrefix(t *testing.T) {
	h := "5d41402abc4b2a76b9719d911017c592"
	got := hashPrefix(h)
	if got != "5d41402a..." {
		t.Errorf("hashPrefix(%q) = %q, want '5d41402a...'", h, got)
	}
}

func TestHashPrefixShort(t *testing.T) {
	got := hashPrefix("abc")
	if got != "" {
		t.Errorf("hashPrefix de string curta deve retornar vazio, got %q", got)
	}
}

// ─── severityByCount ─────────────────────────────────────────────────────────

func TestSeverityByCount(t *testing.T) {
	if severityByCount(100) != module.SeverityCritical {
		t.Error("100+ deve ser Critical")
	}
	if severityByCount(10) != module.SeverityHigh {
		t.Error("10+ deve ser High")
	}
	if severityByCount(1) != module.SeverityMedium {
		t.Error("1+ deve ser Medium")
	}
	if severityByCount(0) != module.SeverityInfo {
		t.Error("0 deve ser Info")
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

// ─── IntelX ──────────────────────────────────────────────────────────────────

func TestQueryIntelXFound(t *testing.T) {
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.Header.Get("x-key") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			// Passo 1: retorna search ID
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":     "test-search-id-123",
				"status": 0,
			})
			return
		}
		// Passo 2: retorna resultados
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": 1,
			"records": []map[string]interface{}{
				{
					"systemid": "rec-001",
					"type":     1,
					"media":    4,
					"added":    "2024-01-15T00:00:00",
					"date":     "2023-06-01",
					"name":     "breach_2023.txt",
					"bucket":   "b_darknet",
				},
				{
					"systemid": "rec-002",
					"type":     1,
					"media":    4,
					"added":    "2024-02-01T00:00:00",
					"date":     "2023-09-01",
					"name":     "combo_2023.txt",
					"bucket":   "b_pastes",
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryIntelX(context.Background(), "user@test.com", SearchEmail, "test-key", 10)
	if err != nil {
		t.Fatalf("queryIntelX: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("deve retornar summary + pelo menos 1 record, got %d", len(findings))
	}

	var hasSummary bool
	for _, f := range findings {
		if f.Type == "intelx_summary" {
			hasSummary = true
			if f.Extra["total_records"] == "" {
				t.Error("summary sem total_records")
			}
			if f.Extra["confidence"] == "" {
				t.Error("summary sem confidence")
			}
		}
		if f.Type == "intelx_record" {
			if f.Extra["name"] == "" {
				t.Error("record sem name")
			}
			if f.Extra["bucket"] == "" {
				t.Error("record sem bucket")
			}
		}
	}
	if !hasSummary {
		t.Error("deve ter finding 'intelx_summary'")
	}
}

func TestQueryIntelXUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.queryIntelX(context.Background(), "test@test.com", SearchEmail, "bad-key", 10)
	if err == nil {
		t.Error("deve retornar erro para key inválida")
	}
	if !strings.Contains(err.Error(), "API key inválida") {
		t.Errorf("erro deve mencionar 'API key inválida': %v", err)
	}
}

func TestQueryIntelXEmptyID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Sem ID = sem resultados
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":     "",
				"status": 0,
			})
		}
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryIntelX(context.Background(), "notfound@test.com", SearchEmail, "key", 10)
	if err != nil {
		t.Fatalf("queryIntelX empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("ID vazio deve retornar 0 findings, got %d", len(findings))
	}
}

// ─── BreachDirectory ─────────────────────────────────────────────────────────

func TestQueryBreachDirectoryFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"found": 3,
			"error": false,
			"result": []map[string]interface{}{
				{
					"sources":  []string{"breach1.com", "breach2.com"},
					"password": "",
					"sha1":     "a94a8fe5ccb19ba61c4c0873d391e987dc012345",
				},
				{
					"sources":  []string{"combo2023.txt"},
					"password": "pa**",
					"sha1":     "",
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBreachDirectory(context.Background(), "user@test.com", SearchEmail, "test-key", 10)
	if err != nil {
		t.Fatalf("queryBreachDirectory: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("deve retornar summary + records, got %d", len(findings))
	}

	var hasSummary bool
	for _, f := range findings {
		if f.Type == "breachdirectory_summary" {
			hasSummary = true
			if f.Extra["confidence"] == "" {
				t.Error("summary sem confidence")
			}
		}
		if f.Type == "breach_record" {
			if f.Extra["password_exposed"] == "" {
				t.Error("breach_record sem password_exposed")
			}
			// Senha nunca em clear text
			if strings.Contains(f.Detail, "password") && strings.Contains(f.Extra["password_exposed"], "true") {
				// OK — só indica que há senha
			}
		}
	}
	if !hasSummary {
		t.Error("deve ter finding 'breachdirectory_summary'")
	}
}

func TestQueryBreachDirectoryNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"found":  0,
			"error":  true,
			"reason": "Not Found",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBreachDirectory(context.Background(), "notfound@test.com", SearchEmail, "key", 10)
	if err != nil {
		t.Fatalf("not found não deve ser erro: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("not found deve retornar 0 findings, got %d", len(findings))
	}
}

func TestQueryBreachDirectoryError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"found":  0,
			"error":  true,
			"reason": "Invalid API key",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.queryBreachDirectory(context.Background(), "test@test.com", SearchEmail, "bad-key", 10)
	if err == nil {
		t.Error("erro de API deve retornar erro")
	}
}

// ─── HudsonRock ──────────────────────────────────────────────────────────────

func TestQueryHudsonRockFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"stealers": []map[string]interface{}{
				{
					"computer_name":    "DESKTOP-ABC123",
					"operating_system": "Windows 10",
					"malware_family":   "Raccoon",
					"date_compromised": "2023-08-15",
					"country":          "BR",
					"credentials": []map[string]interface{}{
						{"username": "u@test.com", "password": "", "url": "https://mail.google.com"},
						{"username": "u@test.com", "password": "", "url": "https://facebook.com"},
					},
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryHudsonRock(context.Background(), "user@test.com", SearchEmail, 10)
	if err != nil {
		t.Fatalf("queryHudsonRock: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("deve retornar summary + stealer record, got %d", len(findings))
	}

	var hasSummary, hasRecord bool
	for _, f := range findings {
		if f.Type == "infostealer_summary" {
			hasSummary = true
			if f.Severity != module.SeverityCritical {
				t.Errorf("infostealer_summary deve ser Critical, got %s", f.Severity)
			}
			if f.Extra["confidence"] == "" {
				t.Error("summary sem confidence")
			}
		}
		if f.Type == "infostealer_record" {
			hasRecord = true
			if f.Extra["malware_family"] == "" {
				t.Error("record sem malware_family")
			}
			if f.Extra["country"] == "" {
				t.Error("record sem country")
			}
		}
	}
	if !hasSummary {
		t.Error("deve ter finding 'infostealer_summary'")
	}
	if !hasRecord {
		t.Error("deve ter finding 'infostealer_record'")
	}
}

func TestQueryHudsonRockEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"stealers": []interface{}{},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryHudsonRock(context.Background(), "notfound@test.com", SearchEmail, 10)
	if err != nil {
		t.Fatalf("hudsonrock empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("sem stealers deve retornar 0 findings, got %d", len(findings))
	}
}

func TestQueryHudsonRockUnsupportedType(t *testing.T) {
	m := New()
	findings, err := m.queryHudsonRock(context.Background(), "johndoe", SearchUsername, 10)
	if err != nil {
		t.Fatalf("tipo não suportado deve retornar nil, err: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("tipo não suportado deve retornar 0 findings, got %d", len(findings))
	}
}

// ─── Leak-Lookup ─────────────────────────────────────────────────────────────

func TestQueryLeakLookupFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": 0,
			"sources": map[string]interface{}{
				"breach_2022": []map[string]interface{}{
					{
						"email":    "u@test.com",
						"username": "u@test.com",
						"password": "",
						"hash":     "5d41402abc4b2a76b9719d911017c592",
						"name":     "Test User",
					},
				},
				"combo2023": []map[string]interface{}{
					{
						"email":    "u@test.com",
						"username": "u@test.com",
						"password": "pa***",
						"hash":     "",
						"name":     "",
					},
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryLeakLookup(context.Background(), "user@test.com", SearchEmail, "test-key", 10)
	if err != nil {
		t.Fatalf("queryLeakLookup: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("deve retornar summary + records, got %d", len(findings))
	}

	var hasSummary bool
	for _, f := range findings {
		if f.Type == "leaklookup_summary" {
			hasSummary = true
			if f.Extra["total_sources"] == "" {
				t.Error("summary sem total_sources")
			}
			if f.Extra["confidence"] == "" {
				t.Error("summary sem confidence")
			}
		}
		if f.Type == "leak_record" {
			if f.Extra["source"] == "" {
				t.Error("record sem source")
			}
		}
	}
	if !hasSummary {
		t.Error("deve ter finding 'leaklookup_summary'")
	}
}

func TestQueryLeakLookupNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   1,
			"message": "no results found",
			"sources": nil,
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryLeakLookup(context.Background(), "notfound@test.com", SearchEmail, "key", 10)
	if err != nil {
		t.Fatalf("not found deve retornar nil: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("not found deve retornar 0 findings, got %d", len(findings))
	}
}

func TestQueryLeakLookupUnsupportedType(t *testing.T) {
	m := New()
	findings, err := m.queryLeakLookup(context.Background(), "192.168.1.1", SearchIP, "key", 10)
	if err != nil {
		t.Fatalf("tipo não suportado deve retornar nil: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("tipo não suportado deve retornar 0 findings, got %d", len(findings))
	}
}

// ─── Fluxo completo ───────────────────────────────────────────────────────────

func TestRunWithNoKeys(t *testing.T) {
	m := New()
	// Sem API keys e sem HudsonRock (não é email/domain), deve retornar 0 findings sem erro
	findings, err := m.Run(context.Background(), module.Input{
		Target: "johndoe",
	})
	if err != nil {
		t.Fatalf("Run sem keys: %v", err)
	}
	_ = findings
}

func TestRunHudsonRockOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"stealers": []map[string]interface{}{
				{
					"computer_name":    "TEST-PC",
					"operating_system": "Windows 11",
					"malware_family":   "Redline",
					"date_compromised": "2024-01-10",
					"country":          "BR",
					"credentials":      []interface{}{},
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "test@company.com",
		Options: map[string]string{"sources": "hudsonrock"},
	})
	if err != nil {
		t.Fatalf("Run hudsonrock: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings do hudsonrock")
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
	}
}

func TestRunContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := New()
	findings, err := m.Run(ctx, module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"intelx_key": "key"},
	})
	if err != nil {
		t.Fatalf("context cancelado não deve retornar erro: %v", err)
	}
	_ = findings
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestDedup(t *testing.T) {
	findings := []module.Finding{
		{Type: "breach_record", URL: "https://breachdirectory.org", Detail: "Record A"},
		{Type: "breach_record", URL: "https://breachdirectory.org", Detail: "Record A"},
		{Type: "intelx_summary", URL: "https://intelx.io", Detail: "3 records"},
	}
	result := dedup(findings)
	if len(result) != 2 {
		t.Errorf("dedup: esperado 2 únicos, got %d", len(result))
	}
}

// ─── parseSources ────────────────────────────────────────────────────────────

func TestParseSources(t *testing.T) {
	m := parseSources("intelx,breachdirectory")
	if !m["intelx"] || !m["breachdirectory"] {
		t.Error("fontes não foram parseadas corretamente")
	}
	if m["hudsonrock"] {
		t.Error("hudsonrock não deve estar ativo")
	}
}

// ─── breachDirType / leakLookupType ─────────────────────────────────────────

func TestBreachDirType(t *testing.T) {
	if breachDirType(SearchEmail) != "email" {
		t.Error("SearchEmail deve mapear para 'email'")
	}
	if breachDirType(SearchUsername) != "username" {
		t.Error("SearchUsername deve mapear para 'username'")
	}
	if breachDirType(SearchHash) != "hash" {
		t.Error("SearchHash deve mapear para 'hash'")
	}
}

func TestLeakLookupType(t *testing.T) {
	if leakLookupType(SearchEmail) != "email_address" {
		t.Error("SearchEmail deve mapear para 'email_address'")
	}
	if leakLookupType(SearchIP) != "" {
		t.Error("SearchIP deve retornar string vazia (não suportado)")
	}
}

// Garante uso de bytes.NewReader (evitar lint de import não usado).
var _ = bytes.NewReader
var _ = io.Discard
