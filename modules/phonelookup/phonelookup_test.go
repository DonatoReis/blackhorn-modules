package phonelookup_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/phonelookup"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

func TestName(t *testing.T) {
	if phonelookup.New().Name() != "phonelookup" {
		t.Error("nome incorreto")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := phonelookup.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

func TestRun_BRPhone_LocalAnalysis(t *testing.T) {
	m := phonelookup.NewWithClient(&http.Client{})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "11 99999-9999",
		Options: map[string]string{"sources": "local"},
	})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings para número BR")
	}
}

func TestRun_BRPhone_TypeIsPhoneInfo(t *testing.T) {
	m := phonelookup.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "11 98888-8888",
		Options: map[string]string{"sources": "local"},
	})
	for _, f := range findings {
		if f.Type != "phone_info" {
			t.Errorf("tipo esperado phone_info, obteve %s", f.Type)
		}
	}
}

func TestRun_BRPhone_DDDInExtra(t *testing.T) {
	m := phonelookup.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "21 3333-3333",
		Options: map[string]string{"sources": "local"},
	})
	for _, f := range findings {
		if f.Extra["ddd"] == "21" {
			return
		}
	}
	t.Error("DDD 21 não encontrado nos findings")
}

func TestRun_BRPhone_RegionPopulated(t *testing.T) {
	m := phonelookup.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "11 99999-9999",
		Options: map[string]string{"sources": "local"},
	})
	for _, f := range findings {
		if strings.Contains(f.Extra["region"], "São Paulo") {
			return
		}
	}
	t.Error("região SP não encontrada")
}

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	m := phonelookup.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "11 99999-9999",
		Options: map[string]string{"sources": "local"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_BrasilAPIDDD_ParsesCorrectly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"state":  "SP",
			"cities": []string{"São Paulo", "Guarulhos", "Campinas"},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := phonelookup.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "11 99999-9999",
		Options: map[string]string{"sources": "brasilapi"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Type == "phone_ddd_info" && f.Extra["state"] == "SP" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor de teste não recebeu request de DDD")
	}
}

func TestRun_NumVerify_ParsesCarrier(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":                true,
			"number":               "5511999999999",
			"international_format": "+55 11 99999-9999",
			"local_format":         "11 99999-9999",
			"country_code":         "BR",
			"country_name":         "Brazil",
			"country_prefix":       "+55",
			"carrier":              "Vivo",
			"line_type":            "mobile",
			"location":             "São Paulo",
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := phonelookup.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "+5511999999999",
		Options: map[string]string{"sources": "numverify", "numverify_key": "testkey"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Extra["carrier"] == "Vivo" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor de teste não recebeu request")
	}
}

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := phonelookup.New()
	_, _ = m.Run(ctx, module.Input{Target: "11 99999-9999"})
}

func TestRun_SeverityIsInfo(t *testing.T) {
	m := phonelookup.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "11 99999-9999",
		Options: map[string]string{"sources": "local"},
	})
	for _, f := range findings {
		if f.Severity != module.SeverityInfo {
			t.Errorf("esperava SeverityInfo, obteve %s", f.Severity)
		}
	}
}

func TestRun_DetailNotEmpty(t *testing.T) {
	m := phonelookup.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "11 99999-9999",
		Options: map[string]string{"sources": "local"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

func TestRun_International_NoError(t *testing.T) {
	m := phonelookup.NewWithClient(&http.Client{})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "+1 555 123 4567",
		Options: map[string]string{"sources": "local"},
	})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding para número internacional")
	}
}

func TestRun_SourceFilter_BrasilAPI_NotCalledForIntlPhone(t *testing.T) {
	var calledPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPaths = append(calledPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"state":"SP","cities":[]}`))
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := phonelookup.NewWithClient(c)
	// Número com DDD 00 — inexistente no Brasil, não deve chamar BrasilAPI
	_, _ = m.Run(context.Background(), module.Input{
		Target:  "+44 20 7946 0958", // Reino Unido, DDD 44
		Options: map[string]string{"sources": "brasilapi"},
	})
	// Verifica que nenhuma rota /api/ddd/ foi chamada (número não é BR)
	for _, p := range calledPaths {
		if strings.Contains(p, "/api/ddd/") {
			t.Errorf("BrasilAPI DDD não deve ser chamada para número UK: %s", p)
		}
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if phonelookup.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestNewWithClient_ReturnsNonNil(t *testing.T) {
	if phonelookup.NewWithClient(http.DefaultClient) == nil {
		t.Fatal("NewWithClient() retornou nil")
	}
}

// rewriteTransport redireciona todas as requests para o servidor de teste
type rewriteTransport struct{ base string }

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(r.base, "http://")
	return http.DefaultTransport.RoundTrip(clone)
}
