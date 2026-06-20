package swaggerfuzz_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/swaggerfuzz"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

// spec é uma spec OpenAPI 2.0 mínima usada em vários testes.
func minimalSpec(paths map[string]any) map[string]any {
	return map[string]any{
		"swagger":  "2.0",
		"basePath": "/api",
		"paths":    paths,
	}
}

// newServer cria um httptest.Server que:
//   - GET /swagger.json → especificação fornecida
//   - qualquer outra rota → resposta controlada por handler
func newServer(t *testing.T, spec any, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	specBytes, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(specBytes)
	})
	if handler != nil {
		mux.HandleFunc("/", handler)
	}
	return httptest.NewServer(mux)
}

func run(t *testing.T, srv *httptest.Server, opts map[string]string) []module.Finding {
	t.Helper()
	m := swaggerfuzz.NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: opts,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findings
}

func findByType(findings []module.Finding, typ string) []module.Finding {
	var out []module.Finding
	for _, f := range findings {
		if f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if swaggerfuzz.New().Name() != "swaggerfuzz" {
		t.Error("expected name 'swaggerfuzz'")
	}
}

func TestEmptyTargetReturnsError(t *testing.T) {
	m := swaggerfuzz.New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Error("expected error for empty target")
	}
}

// TestSpecNotFound: quando nenhuma spec é encontrada, deve retornar um finding info.
func TestSpecNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	m := swaggerfuzz.NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding")
	}
	if findings[0].Type != "swagger_spec_not_found" {
		t.Errorf("expected swagger_spec_not_found, got %q", findings[0].Type)
	}
	if findings[0].Severity != module.SeverityInfo {
		t.Errorf("expected Info severity")
	}
}

// TestSpecFound: spec válida → finding swagger_spec_found emitido.
func TestSpecFound(t *testing.T) {
	spec := minimalSpec(map[string]any{
		"/users": map[string]any{
			"get": map[string]any{"operationId": "listUsers"},
		},
	})
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	findings := run(t, srv, nil)
	found := findByType(findings, "swagger_spec_found")
	if len(found) == 0 {
		t.Error("expected swagger_spec_found finding")
	}
	if found[0].Severity != module.SeverityInfo {
		t.Error("swagger_spec_found should be Info severity")
	}
}

// TestAuthBypassDetected: endpoint com security declarada + responde 200 sem auth → high finding.
func TestAuthBypassDetected(t *testing.T) {
	spec := map[string]any{
		"swagger":  "2.0",
		"basePath": "",
		"paths": map[string]any{
			"/admin": map[string]any{
				"get": map[string]any{
					"operationId": "getAdmin",
					"security":    []any{map[string]any{"bearerAuth": []any{}}},
				},
			},
		},
	}
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/admin") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"admin":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer srv.Close()

	findings := run(t, srv, map[string]string{
		"checks": "auth",
		"bearer": "some-token",
	})
	found := findByType(findings, "swagger_auth_bypass")
	if len(found) == 0 {
		t.Error("expected swagger_auth_bypass finding")
	}
	if found[0].Severity != module.SeverityHigh {
		t.Errorf("expected High, got %v", found[0].Severity)
	}
}

// TestNoAuthBypassWhen401: endpoint retorna 401 sem auth → sem finding.
func TestNoAuthBypassWhen401(t *testing.T) {
	spec := map[string]any{
		"swagger":  "2.0",
		"basePath": "",
		"paths": map[string]any{
			"/protected": map[string]any{
				"get": map[string]any{
					"security": []any{map[string]any{"bearerAuth": []any{}}},
				},
			},
		},
	}
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer srv.Close()

	findings := run(t, srv, map[string]string{"checks": "auth", "bearer": "tok"})
	if found := findByType(findings, "swagger_auth_bypass"); len(found) > 0 {
		t.Error("false positive: should not flag 401 as auth bypass")
	}
}

// TestMassAssignmentDetected: body extra com "role":"admin" → server retorna 200 com role.
func TestMassAssignmentDetected(t *testing.T) {
	spec := map[string]any{
		"swagger":  "2.0",
		"basePath": "",
		"paths": map[string]any{
			"/users": map[string]any{
				"post": map[string]any{
					"operationId": "createUser",
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{"type": "object"},
							},
						},
					},
				},
			},
		},
	}
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"role":"admin","user":"created"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	findings := run(t, srv, map[string]string{"checks": "massassign"})
	found := findByType(findings, "swagger_mass_assignment")
	if len(found) == 0 {
		t.Error("expected swagger_mass_assignment finding")
	}
	if found[0].Severity != module.SeverityHigh {
		t.Errorf("expected High severity, got %v", found[0].Severity)
	}
}

// TestTypeConfusionDetected: parâmetro integer recebe string → server retorna 500.
func TestTypeConfusionDetected(t *testing.T) {
	spec := map[string]any{
		"swagger":  "2.0",
		"basePath": "",
		"paths": map[string]any{
			"/items": map[string]any{
				"get": map[string]any{
					"parameters": []any{
						map[string]any{"name": "id", "in": "query", "type": "integer"},
					},
				},
			},
		},
	}
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/items") {
			if r.URL.Query().Get("id") == "not-a-number" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	findings := run(t, srv, map[string]string{"checks": "types"})
	found := findByType(findings, "swagger_type_confusion")
	if len(found) == 0 {
		t.Error("expected swagger_type_confusion finding")
	}
	if found[0].Severity != module.SeverityMedium {
		t.Errorf("expected Medium severity, got %v", found[0].Severity)
	}
}

// TestTypeConfusionNoFPon200: parâmetro integer com valor errado → 200 → sem finding.
func TestTypeConfusionNoFPon200(t *testing.T) {
	spec := map[string]any{
		"swagger":  "2.0",
		"basePath": "",
		"paths": map[string]any{
			"/items": map[string]any{
				"get": map[string]any{
					"parameters": []any{
						map[string]any{"name": "id", "in": "query", "type": "integer"},
					},
				},
			},
		},
	}
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	findings := run(t, srv, map[string]string{"checks": "types"})
	if found := findByType(findings, "swagger_type_confusion"); len(found) > 0 {
		t.Error("false positive: 200 should not trigger type_confusion")
	}
}

// TestInjectionReflected: canary refletido na resposta → finding high.
func TestInjectionReflected(t *testing.T) {
	spec := map[string]any{
		"swagger":  "2.0",
		"basePath": "",
		"paths": map[string]any{
			"/search": map[string]any{
				"get": map[string]any{
					"parameters": []any{
						map[string]any{"name": "q", "in": "query", "type": "string"},
					},
				},
			},
		},
	}
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result":"` + q + `"}`))
	})
	defer srv.Close()

	findings := run(t, srv, map[string]string{"checks": "injection"})
	found := findByType(findings, "swagger_injection_reflection")
	if len(found) == 0 {
		t.Error("expected swagger_injection_reflection finding")
	}
	if found[0].Severity != module.SeverityHigh {
		t.Errorf("expected High, got %v", found[0].Severity)
	}
}

// TestInjection500: canary causa 500 → entry-point finding.
func TestInjection500(t *testing.T) {
	spec := map[string]any{
		"swagger":  "2.0",
		"basePath": "",
		"paths": map[string]any{
			"/query": map[string]any{
				"get": map[string]any{
					"parameters": []any{
						map[string]any{"name": "val", "in": "query", "type": "string"},
					},
				},
			},
		},
	}
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("val"), "BHSWF") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	findings := run(t, srv, map[string]string{"checks": "injection"})
	found := findByType(findings, "swagger_injection_entrypoint")
	if len(found) == 0 {
		t.Error("expected swagger_injection_entrypoint finding")
	}
}

// TestMethodOverrideDetected: GET com X-HTTP-Method-Override:DELETE → 200 → finding.
func TestMethodOverrideDetected(t *testing.T) {
	spec := map[string]any{
		"swagger":  "2.0",
		"basePath": "",
		"paths": map[string]any{
			"/resource": map[string]any{
				"get": map[string]any{"operationId": "getResource"},
			},
		},
	}
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		override := r.Header.Get("X-HTTP-Method-Override")
		if override == "DELETE" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	findings := run(t, srv, map[string]string{"checks": "methods"})
	found := findByType(findings, "swagger_method_override")
	if len(found) == 0 {
		t.Error("expected swagger_method_override finding")
	}
}

// TestMethodOverrideNoFPon404: override → 404 → sem finding.
func TestMethodOverrideNoFPon404(t *testing.T) {
	spec := map[string]any{
		"swagger":  "2.0",
		"basePath": "",
		"paths": map[string]any{
			"/resource": map[string]any{
				"get": map[string]any{"operationId": "getResource"},
			},
		},
	}
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-HTTP-Method-Override") == "DELETE" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	findings := run(t, srv, map[string]string{"checks": "methods"})
	if found := findByType(findings, "swagger_method_override"); len(found) > 0 {
		t.Error("false positive: 405 should not trigger method_override")
	}
}

// TestPathParamFilled: path com {id} deve ser preenchido e não causar erro de URL.
// Usa checks=methods para garantir que pelo menos uma probe sempre dispara para GET.
func TestPathParamFilled(t *testing.T) {
	spec := map[string]any{
		"swagger":  "2.0",
		"basePath": "",
		"paths": map[string]any{
			"/users/{id}": map[string]any{
				"get": map[string]any{
					"parameters": []any{
						map[string]any{"name": "id", "in": "path", "required": true, "type": "integer"},
					},
				},
			},
		},
	}
	called := false
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/users/") {
			called = true
		}
		w.WriteHeader(http.StatusMethodNotAllowed) // 405 → não gera findings
	})
	defer srv.Close()

	run(t, srv, map[string]string{"checks": "methods"})
	if !called {
		t.Error("path param was not filled — /users/{id} was never called")
	}
}

// TestEmptySpecReturnsInfoFinding: spec válida mas sem paths → swagger_empty_spec.
func TestEmptySpecReturnsInfoFinding(t *testing.T) {
	spec := map[string]any{
		"swagger":  "2.0",
		"basePath": "/",
		"paths":    map[string]any{},
	}
	specBytes, _ := json.Marshal(spec)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.WriteHeader(http.StatusOK)
			w.Write(specBytes)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := swaggerfuzz.NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := findByType(findings, "swagger_empty_spec")
	if len(found) == 0 {
		t.Error("expected swagger_empty_spec finding for spec with no paths")
	}
}

// TestContextCancellation: contexto cancelado antes da execução.
func TestContextCancellation(t *testing.T) {
	spec := minimalSpec(map[string]any{
		"/slow": map[string]any{
			"get": map[string]any{"operationId": "slowEndpoint"},
		},
	})
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelar imediatamente

	m := swaggerfuzz.NewWithClient(srv.Client())
	// não deve panic ou travar — pode retornar findings parciais ou vazio
	_, _ = m.Run(ctx, module.Input{Target: srv.URL})
}

// TestParallelismOption: parallelism=1 não quebra a execução.
func TestParallelismOption(t *testing.T) {
	spec := minimalSpec(map[string]any{
		"/a": map[string]any{"get": map[string]any{}},
		"/b": map[string]any{"get": map[string]any{}},
		"/c": map[string]any{"get": map[string]any{}},
	})
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	findings := run(t, srv, map[string]string{"parallelism": "1"})
	found := findByType(findings, "swagger_spec_found")
	if len(found) == 0 {
		t.Error("expected swagger_spec_found even with parallelism=1")
	}
}

// TestChecksFilter: com checks=auth apenas, não deve emitir injection/massassign.
func TestChecksFilter(t *testing.T) {
	spec := map[string]any{
		"swagger":  "2.0",
		"basePath": "",
		"paths": map[string]any{
			"/data": map[string]any{
				"get": map[string]any{
					"security": []any{map[string]any{"bearerAuth": []any{}}},
					"parameters": []any{
						map[string]any{"name": "q", "in": "query", "type": "string"},
					},
				},
				"post": map[string]any{
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{"type": "object"},
							},
						},
					},
				},
			},
		},
	}
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result":"ok"}`))
	})
	defer srv.Close()

	findings := run(t, srv, map[string]string{"checks": "auth", "bearer": "tok"})
	if found := findByType(findings, "swagger_injection_reflection"); len(found) > 0 {
		t.Error("checks filter broken: injection found when only auth was requested")
	}
	if found := findByType(findings, "swagger_mass_assignment"); len(found) > 0 {
		t.Error("checks filter broken: mass_assignment found when only auth was requested")
	}
}

// TestExplicitSpecURL: usa spec_url para pular auto-discovery.
func TestExplicitSpecURL(t *testing.T) {
	spec := minimalSpec(map[string]any{
		"/ping": map[string]any{
			"get": map[string]any{"operationId": "ping"},
		},
	})
	specBytes, _ := json.Marshal(spec)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/custom-spec.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(specBytes)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := swaggerfuzz.NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"spec_url": srv.URL + "/custom-spec.json"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := findByType(findings, "swagger_spec_found")
	if len(found) == 0 {
		t.Error("expected swagger_spec_found with explicit spec_url")
	}
}

// TestConfidenceInExtra: todos os findings devem ter confidence em Extra.
func TestConfidenceInExtra(t *testing.T) {
	spec := map[string]any{
		"swagger":  "2.0",
		"basePath": "",
		"paths": map[string]any{
			"/admin": map[string]any{
				"get": map[string]any{
					"security": []any{map[string]any{"bearerAuth": []any{}}},
				},
			},
		},
	}
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	findings := run(t, srv, map[string]string{"bearer": "tok"})
	for _, f := range findings {
		if f.Extra == nil || f.Extra["confidence"] == "" {
			t.Errorf("finding %q missing confidence in Extra", f.Type)
		}
	}
}

// TestDeduplication: múltiplas rotas idênticas não devem gerar findings duplicados.
func TestDeduplication(t *testing.T) {
	spec := minimalSpec(map[string]any{
		"/dup": map[string]any{
			"get":  map[string]any{"operationId": "getA"},
			"post": map[string]any{"operationId": "postA"},
		},
	})
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})
	defer srv.Close()

	findings := run(t, srv, nil)
	seen := map[string]int{}
	for _, f := range findings {
		key := f.Type + "|" + f.URL
		seen[key]++
		if seen[key] > 1 {
			t.Errorf("duplicate finding: type=%q url=%q", f.Type, f.URL)
		}
	}
}

// TestOpenAPI3ServerURL: spec OpenAPI 3.x com servers[].url deve ser respeitado.
func TestOpenAPI3ServerURL(t *testing.T) {
	var capturedPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			spec := map[string]any{
				"openapi": "3.0.0",
				"servers": []any{
					map[string]any{"url": "/v3"},
				},
				"paths": map[string]any{
					"/health": map[string]any{
						"get": map[string]any{"operationId": "health"},
					},
				},
			}
			b, _ := json.Marshal(spec)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(b)
			return
		}
		capturedPaths = append(capturedPaths, r.URL.Path)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	m := swaggerfuzz.NewWithClient(srv.Client())
	_, _ = m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "auth", "bearer": "tok"},
	})

	found := false
	for _, p := range capturedPaths {
		if strings.Contains(p, "/v3/") || strings.Contains(p, "/v3") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected probes under /v3, got: %v", capturedPaths)
	}
}

// TestMassAssignNoFPonPOSTReturning200WithoutAdminField: POST 200 sem campo admin → sem finding.
func TestMassAssignNoFPonPOSTReturning200WithoutAdminField(t *testing.T) {
	spec := map[string]any{
		"swagger":  "2.0",
		"basePath": "",
		"paths": map[string]any{
			"/items": map[string]any{
				"post": map[string]any{
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{"type": "object"},
							},
						},
					},
				},
			},
		},
	}
	srv := newServer(t, spec, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"123","name":"item"}`)) // sem "role" ou "admin"
	})
	defer srv.Close()

	findings := run(t, srv, map[string]string{"checks": "massassign"})
	if found := findByType(findings, "swagger_mass_assignment"); len(found) > 0 {
		t.Error("false positive: response without admin field should not trigger mass_assignment")
	}
}
