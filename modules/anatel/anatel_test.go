package anatel

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

// ─── Testes de parseNumber ────────────────────────────────────────────────────

func TestParseNumberMobile(t *testing.T) {
	cases := []struct {
		input    string
		ddd      string
		lineType LineType
		e164     string
		valid    bool
	}{
		{"11999999999", "11", LineTypeMobile, "+5511999999999", true},
		{"+5511999999999", "11", LineTypeMobile, "+5511999999999", true},
		{"(11) 99999-9999", "11", LineTypeMobile, "+5511999999999", true},
		{"21987654321", "21", LineTypeMobile, "+5521987654321", true},
	}
	for _, tt := range cases {
		p, err := parseNumber(tt.input)
		if err != nil {
			t.Errorf("parseNumber(%q): erro inesperado: %v", tt.input, err)
			continue
		}
		if p.DDD != tt.ddd {
			t.Errorf("parseNumber(%q).DDD = %q, want %q", tt.input, p.DDD, tt.ddd)
		}
		if p.LineType != tt.lineType {
			t.Errorf("parseNumber(%q).LineType = %q, want %q", tt.input, p.LineType, tt.lineType)
		}
		if p.E164 != tt.e164 {
			t.Errorf("parseNumber(%q).E164 = %q, want %q", tt.input, p.E164, tt.e164)
		}
		if p.IsValid != tt.valid {
			t.Errorf("parseNumber(%q).IsValid = %v, want %v", tt.input, p.IsValid, tt.valid)
		}
	}
}

func TestParseNumberFixed(t *testing.T) {
	p, err := parseNumber("1133334444")
	if err != nil {
		t.Fatalf("parseNumber fixed: %v", err)
	}
	if p.DDD != "11" {
		t.Errorf("DDD esperado '11', got '%s'", p.DDD)
	}
	if p.LineType != LineTypeFixed {
		t.Errorf("tipo esperado Fixed, got %s", p.LineType)
	}
}

func TestParseNumberService(t *testing.T) {
	cases := []string{"190", "192", "193", "197", "198", "199", "100", "111"}
	for _, num := range cases {
		p, err := parseNumber(num)
		if err != nil {
			t.Errorf("parseNumber(%q): %v", num, err)
			continue
		}
		if p.LineType != LineTypeService {
			t.Errorf("parseNumber(%q): esperado LineTypeService, got %s", num, p.LineType)
		}
	}
}

func TestParseNumber0800(t *testing.T) {
	p, err := parseNumber("08009999999")
	if err != nil {
		t.Fatalf("parseNumber 0800: %v", err)
	}
	if p.LineType != LineTypeFree {
		t.Errorf("tipo esperado LineTypeFree, got %s", p.LineType)
	}
}

func TestParseNumberOnlyDDD(t *testing.T) {
	p, err := parseNumber("11")
	if err != nil {
		t.Fatalf("parseNumber DDD only: %v", err)
	}
	if p.DDD != "11" {
		t.Errorf("DDD esperado '11', got '%s'", p.DDD)
	}
	if p.LineType != LineTypeUnknown {
		t.Errorf("tipo esperado Unknown para DDD só, got %s", p.LineType)
	}
}

func TestParseNumberInvalidDDD(t *testing.T) {
	_, err := parseNumber("00999999999")
	if err == nil {
		t.Error("DDD 00 deve retornar erro")
	}
}

func TestParseNumberInvalidFormat(t *testing.T) {
	_, err := parseNumber("abc")
	if err == nil {
		t.Error("número inválido deve retornar erro")
	}
}

func TestParseNumberInvalidDigitCount(t *testing.T) {
	// 7 dígitos — inválido
	_, err := parseNumber("1234567")
	if err == nil {
		t.Error("7 dígitos deve retornar erro")
	}
}

// ─── Testes de validDDDs ─────────────────────────────────────────────────────

func TestAllDDDsHaveInfo(t *testing.T) {
	for ddd, info := range validDDDs {
		if info.Estado == "" {
			t.Errorf("DDD %s sem estado", ddd)
		}
		if info.UF == "" {
			t.Errorf("DDD %s sem UF", ddd)
		}
		if info.Regiao == "" {
			t.Errorf("DDD %s sem região", ddd)
		}
		if len(ddd) != 2 {
			t.Errorf("DDD '%s' deve ter exatamente 2 dígitos", ddd)
		}
	}
}

func TestValidDDDCount(t *testing.T) {
	// ANATEL define 67 DDDs ativos no Brasil
	if len(validDDDs) < 60 {
		t.Errorf("mapa de DDDs parece incompleto: %d entradas", len(validDDDs))
	}
}

// ─── Testes de maskPhone ─────────────────────────────────────────────────────

func TestMaskPhone(t *testing.T) {
	cases := map[string]string{
		"11999999999":  "11*******99",
		"9999":         "****",
		"12":           "**",
		"(11) 9999-99": "11****99",
	}
	for input, want := range cases {
		if got := maskPhone(input); got != want {
			t.Errorf("maskPhone(%q) = %q, want %q", input, got, want)
		}
	}
}

// ─── Testes de classifyLineType ───────────────────────────────────────────────

func TestClassifyLineType(t *testing.T) {
	cases := map[string]LineType{
		"999999999": LineTypeMobile, // 9 dígitos começando com 9
		"987654321": LineTypeMobile, // 9 dígitos começando com 9
		"33334444":  LineTypeFixed,  // 8 dígitos começando com 3
		"23334444":  LineTypeFixed,  // 8 dígitos começando com 2
	}
	for num, want := range cases {
		if got := classifyLineType(num); got != want {
			t.Errorf("classifyLineType(%q) = %q, want %q", num, got, want)
		}
	}
}

// ─── Testes de BrasilAPI DDD ──────────────────────────────────────────────────

func TestQueryBrasilAPIDDD(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(brasilAPIDDDResp{
			State:  "SP",
			Cities: []string{"São Paulo", "Campinas", "Santos", "São José dos Campos", "Guarulhos", "Osasco"},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBrasilAPIDDD(context.Background(), "11")
	if err != nil {
		t.Fatalf("queryBrasilAPIDDD: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("esperado 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "ddd_info" {
		t.Errorf("tipo esperado 'ddd_info', got '%s'", f.Type)
	}
	if f.Extra["confidence"] == "" {
		t.Error("finding sem confidence")
	}
	// Verifica que lista de cidades tem no máximo 5 samples
	sample := f.Extra["city_sample"]
	if strings.Count(sample, ",") > 4 {
		t.Error("city_sample deve ter no máximo 5 cidades")
	}
}

func TestQueryBrasilAPIDDDNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.queryBrasilAPIDDD(context.Background(), "99")
	if err == nil {
		t.Error("404 deve retornar erro")
	}
}

// ─── Testes de IBGE municípios ────────────────────────────────────────────────

func TestQueryIBGEMunicipios(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]ibgeMunicipio{
			{ID: 3550308, Nome: "São Paulo"},
			{ID: 3509502, Nome: "Campinas"},
			{ID: 3548500, Nome: "Santos"},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryIBGEMunicipios(context.Background(), "SP", "11")
	if err != nil {
		t.Fatalf("queryIBGEMunicipios: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("esperado 1 finding, got %d", len(findings))
	}
	if findings[0].Extra["total_municipios"] != "3" {
		t.Errorf("total_municipios esperado '3', got '%s'", findings[0].Extra["total_municipios"])
	}
}

// ─── Testes de análise local ──────────────────────────────────────────────────

func TestAnalyzeNumberLocallyMobile(t *testing.T) {
	p, _ := parseNumber("11999999999")
	findings := analyzeNumberLocally(p)
	if len(findings) == 0 {
		t.Fatal("deve retornar pelo menos 1 finding")
	}
	hasPrimary := false
	for _, f := range findings {
		if f.Type == "phone_analysis" {
			hasPrimary = true
			if f.Extra["ddd"] != "11" {
				t.Errorf("DDD esperado '11', got '%s'", f.Extra["ddd"])
			}
			if f.Extra["estado"] != "São Paulo" {
				t.Errorf("estado esperado 'São Paulo', got '%s'", f.Extra["estado"])
			}
		}
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
	}
	if !hasPrimary {
		t.Error("deve conter finding 'phone_analysis'")
	}
}

func TestAnalyzeNumberLocally0800(t *testing.T) {
	p, _ := parseNumber("08009999999")
	findings := analyzeNumberLocally(p)
	hasService := false
	for _, f := range findings {
		if f.Type == "phone_service_number" {
			hasService = true
			if f.Extra["service"] != "0800_free" {
				t.Errorf("service esperado '0800_free', got '%s'", f.Extra["service"])
			}
		}
	}
	if !hasService {
		t.Error("0800 deve gerar finding 'phone_service_number'")
	}
}

func TestAnalyzeNumberLocallyService(t *testing.T) {
	p, _ := parseNumber("190")
	findings := analyzeNumberLocally(p)
	hasService := false
	for _, f := range findings {
		if f.Type == "phone_service_number" {
			hasService = true
		}
	}
	if !hasService {
		t.Error("190 deve gerar finding 'phone_service_number'")
	}
}

// ─── Testes de fluxo completo ─────────────────────────────────────────────────

func TestRunEmpty(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Fatal("deve retornar erro para target vazio")
	}
}

func TestRunMobileNumber(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/ddd") {
			json.NewEncoder(w).Encode(brasilAPIDDDResp{
				State:  "SP",
				Cities: []string{"São Paulo", "Campinas"},
			})
			return
		}
		if strings.Contains(r.URL.Path, "/api/v1/localidades") {
			json.NewEncoder(w).Encode([]ibgeMunicipio{
				{ID: 1, Nome: "São Paulo"},
			})
			return
		}
		// ANATEL portabilidade — retorna operadora
		json.NewEncoder(w).Encode(map[string]interface{}{
			"operadoraAtual": "TIM",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "11999999999",
		Options: map[string]string{"sources": "brasilapi,ibge,anatel"},
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

func TestRunDDDOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(brasilAPIDDDResp{
			State:  "RJ",
			Cities: []string{"Rio de Janeiro"},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "21",
		Options: map[string]string{"sources": "brasilapi"},
	})
	if err != nil {
		t.Fatalf("Run DDD: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings para DDD")
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
		Options: map[string]string{"sources": "brasilapi"},
	})
	if err != nil {
		t.Fatalf("Run não deve propagar erro de contexto: %v", err)
	}
	// Análise local deve ser retornada mesmo com contexto cancelado
	if len(findings) == 0 {
		t.Fatal("deve retornar findings locais mesmo com contexto cancelado")
	}
}

func TestDedup(t *testing.T) {
	findings := []module.Finding{
		{Type: "phone_analysis", URL: "", Detail: "Info A"},
		{Type: "phone_analysis", URL: "", Detail: "Info A"},
		{Type: "ddd_info", URL: "https://brasilapi.com.br", Detail: "DDD"},
	}
	result := dedup(findings)
	if len(result) != 2 {
		t.Errorf("dedup: esperado 2 únicos, got %d", len(result))
	}
}
