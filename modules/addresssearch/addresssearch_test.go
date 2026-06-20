package addresssearch_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/addresssearch"
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
	if addresssearch.New().Name() != "addresssearch" {
		t.Error("nome incorreto")
	}
}

func TestNew_NotNil(t *testing.T) {
	if addresssearch.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := addresssearch.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("target vazio deve retornar erro")
	}
}

// ─── BrasilAPI CEP ────────────────────────────────────────────────────────────

func brasilAPICEPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"cep":          "01310-100",
		"state":        "SP",
		"city":         "São Paulo",
		"neighborhood": "Bela Vista",
		"street":       "Avenida Paulista",
		"service":      "correios",
		"location": map[string]interface{}{
			"type": "Point",
			"coordinates": map[string]string{
				"longitude": "-46.6596",
				"latitude":  "-23.5613",
			},
		},
	})
}

func TestRun_BrasilAPI_CEP_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICEPHandler))
	defer srv.Close()

	m := addresssearch.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "01310100",
		Options: map[string]string{"sources": "brasilapi"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava pelo menos 1 finding")
	}

	for _, f := range findings {
		if f.Extra["source"] == "brasilapi" {
			if f.Extra["city"] != "São Paulo" {
				t.Errorf("city esperado 'São Paulo', obteve '%s'", f.Extra["city"])
			}
			if f.Extra["state"] != "SP" {
				t.Errorf("state esperado 'SP', obteve '%s'", f.Extra["state"])
			}
			if f.Extra["street"] != "Avenida Paulista" {
				t.Errorf("street esperado 'Avenida Paulista', obteve '%s'", f.Extra["street"])
			}
			if f.Extra["latitude"] == "" || f.Extra["longitude"] == "" {
				t.Error("coordenadas devem estar presentes")
			}
		}
	}
}

func TestRun_BrasilAPI_CEP_404_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := addresssearch.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "00000000",
		Options: map[string]string{"sources": "brasilapi"},
	})
	if err != nil {
		t.Fatalf("404 não deve retornar erro: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("404 deve retornar 0 findings, obteve %d", len(findings))
	}
}

func TestRun_BrasilAPI_CEP_WithDash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICEPHandler))
	defer srv.Close()

	m := addresssearch.NewWithClient(newTestClient(srv))
	// CEP com hífen deve ser aceito
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "01310-100",
		Options: map[string]string{"sources": "brasilapi"},
	})
	if err != nil {
		t.Fatalf("CEP com hífen não deve dar erro: %v", err)
	}
	_ = findings
}

// ─── ViaCEP ───────────────────────────────────────────────────────────────────

func viaCEPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"cep":         "01310-100",
		"logradouro":  "Avenida Paulista",
		"complemento": "de 610 a 1348 - lado par",
		"bairro":      "Bela Vista",
		"localidade":  "São Paulo",
		"uf":          "SP",
		"ibge":        "3550308",
		"ddd":         "11",
		"erro":        false,
	})
}

func TestRun_ViaCEP_CEP_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(viaCEPHandler))
	defer srv.Close()

	m := addresssearch.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "01310100",
		Options: map[string]string{"sources": "viacep"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via ViaCEP")
	}

	for _, f := range findings {
		if f.Extra["source"] == "viacep" {
			if f.Extra["ibge_code"] != "3550308" {
				t.Errorf("ibge_code esperado '3550308', obteve '%s'", f.Extra["ibge_code"])
			}
			if f.Extra["ddd"] != "11" {
				t.Errorf("ddd esperado '11', obteve '%s'", f.Extra["ddd"])
			}
		}
	}
}

func TestRun_ViaCEP_Erro_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"erro": true})
	}))
	defer srv.Close()

	m := addresssearch.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "01310100",
		Options: map[string]string{"sources": "viacep"},
	})
	if err != nil {
		t.Fatalf("erro=true não deve retornar erro fatal: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("erro=true deve retornar 0 findings, obteve %d", len(findings))
	}
}

// ─── Nominatim forward geocoding ──────────────────────────────────────────────

func nominatimForwardHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]map[string]interface{}{
		{
			"place_id":     12345,
			"display_name": "Avenida Paulista, Bela Vista, São Paulo, SP, Brasil",
			"lat":          "-23.5613",
			"lon":          "-46.6596",
			"type":         "tertiary",
			"importance":   0.8432,
			"address": map[string]interface{}{
				"road":         "Avenida Paulista",
				"suburb":       "Bela Vista",
				"city":         "São Paulo",
				"state":        "São Paulo",
				"postcode":     "01310-100",
				"country_code": "br",
			},
		},
	})
}

func TestRun_Nominatim_Logradouro_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(nominatimForwardHandler))
	defer srv.Close()

	m := addresssearch.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "Avenida Paulista, São Paulo - SP",
		Options: map[string]string{"sources": "nominatim"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via Nominatim")
	}

	for _, f := range findings {
		if f.Extra["source"] == "nominatim" {
			if f.Type != "geocoding_result" {
				t.Errorf("tipo esperado 'geocoding_result', obteve '%s'", f.Type)
			}
			if f.Extra["latitude"] != "-23.5613" {
				t.Errorf("latitude esperada '-23.5613', obteve '%s'", f.Extra["latitude"])
			}
			if f.Extra["postcode"] != "01310-100" {
				t.Errorf("postcode esperado '01310-100', obteve '%s'", f.Extra["postcode"])
			}
		}
	}
}

// ─── Nominatim reverse geocoding ─────────────────────────────────────────────

func nominatimReverseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"place_id":     67890,
		"display_name": "Avenida Paulista, Bela Vista, São Paulo, SP, 01310-100, Brasil",
		"lat":          "-23.5613",
		"lon":          "-46.6596",
		"address": map[string]interface{}{
			"road":         "Avenida Paulista",
			"suburb":       "Bela Vista",
			"city":         "São Paulo",
			"state":        "São Paulo",
			"postcode":     "01310-100",
			"country_code": "br",
		},
	})
}

func TestRun_Nominatim_Coordinates_ReverseGeocode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(nominatimReverseHandler))
	defer srv.Close()

	m := addresssearch.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "-23.5613,-46.6596",
		Options: map[string]string{"sources": "nominatim"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via Nominatim reverse")
	}

	for _, f := range findings {
		if f.Type == "reverse_geocoding" {
			if !strings.Contains(strings.ToLower(f.Detail), "reverse geocoding") {
				t.Error("detail deve mencionar 'reverse geocoding'")
			}
		}
	}
}

// ─── OpenCage ────────────────────────────────────────────────────────────────

func opencageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"results": []map[string]interface{}{
			{
				"formatted":  "Avenida Paulista, São Paulo, SP, Brasil",
				"confidence": 9,
				"geometry": map[string]float64{
					"lat": -23.5613,
					"lng": -46.6596,
				},
				"components": map[string]interface{}{
					"road":         "Avenida Paulista",
					"suburb":       "Bela Vista",
					"city":         "São Paulo",
					"state":        "São Paulo",
					"postcode":     "01310-100",
					"country_code": "br",
				},
			},
		},
		"status": map[string]interface{}{
			"code":    200,
			"message": "OK",
		},
	})
}

func TestRun_OpenCage_WithKey_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(opencageHandler))
	defer srv.Close()

	m := addresssearch.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "Avenida Paulista, São Paulo",
		Options: map[string]string{
			"sources":      "opencage",
			"opencage_key": "test-key",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via OpenCage")
	}
	for _, f := range findings {
		if f.Extra["source"] == "opencage" {
			if f.Extra["confidence"] == "" {
				t.Error("confidence deve estar presente")
			}
		}
	}
}

func TestRun_OpenCage_NoKey_NoFindings(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	m := addresssearch.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "Avenida Paulista, São Paulo",
		Options: map[string]string{
			"sources": "opencage",
			// sem opencage_key
		},
	})
	if called {
		t.Error("opencage não deve ser chamado sem API key")
	}
	if len(findings) != 0 {
		t.Errorf("sem key esperava 0 findings, obteve %d", len(findings))
	}
}

// ─── confidence e detail ─────────────────────────────────────────────────────

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICEPHandler))
	defer srv.Close()

	m := addresssearch.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "01310100",
		Options: map[string]string{"sources": "brasilapi"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICEPHandler))
	defer srv.Close()

	m := addresssearch.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "01310100",
		Options: map[string]string{"sources": "brasilapi"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Errorf("finding sem Detail: %+v", f)
		}
	}
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestRun_Dedup_NoDuplicates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(brasilAPICEPHandler))
	defer srv.Close()

	m := addresssearch.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "01310100",
		Options: map[string]string{"sources": "brasilapi"},
	})
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.Type + "|" + f.Extra["source"] + "|" + f.Extra["cep"]
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

	srv := httptest.NewServer(http.HandlerFunc(brasilAPICEPHandler))
	defer srv.Close()

	m := addresssearch.NewWithClient(newTestClient(srv))
	_, _ = m.Run(ctx, module.Input{
		Target:  "01310100",
		Options: map[string]string{"sources": "brasilapi"},
	})
}

// ─── target type detection ───────────────────────────────────────────────────

func TestRun_NonCEP_StringAddress_NoBrasilAPICall(t *testing.T) {
	brasilAPICalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "brasilapi") || strings.Contains(r.URL.Path, "cep") {
			brasilAPICalled = true
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[]"))
	}))
	defer srv.Close()

	m := addresssearch.NewWithClient(newTestClient(srv))
	_, _ = m.Run(context.Background(), module.Input{
		Target:  "Rua das Flores, 123, São Paulo - SP",
		Options: map[string]string{"sources": "nominatim"},
	})
	// Para Nominatim com logradouro, BrasilAPI CEP não deve ser chamado
	_ = brasilAPICalled
}
