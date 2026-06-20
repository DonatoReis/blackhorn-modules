package apiaudit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/apiaudit"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// debugServer exposes Swagger and debug endpoints.
func debugServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasPrefix(path, "/swagger"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(`{"swagger":"2.0","paths":{"/users":{"get":{}}}}`))
		case strings.HasPrefix(path, "/actuator"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(`{"_links":{"health":{"href":"/actuator/health"}}}`))
		case strings.HasPrefix(path, "/debug"):
			w.WriteHeader(200)
			w.Write([]byte(`goroutine pprof heap`))
		case strings.HasPrefix(path, "/metrics"):
			w.WriteHeader(200)
			w.Write([]byte(`# HELP go_gc_duration_seconds\n# TYPE go_gc_duration_seconds summary`))
		default:
			w.WriteHeader(404)
		}
	}))
}

// apiServer exposes a simple API without authentication.
func apiServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasPrefix(path, "/api/users"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			data := map[string]interface{}{"users": []map[string]string{
				{"name": "Alice", "email": "alice@example.com"},
			}}
			json.NewEncoder(w).Encode(data)
		case strings.HasPrefix(path, "/api/v1") || strings.HasPrefix(path, "/v1"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(`{"version":"1.0","deprecated":true}`))
		case strings.HasPrefix(path, "/api/admin"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(`{"admin":"accessible","users":100}`))
		case strings.HasSuffix(path, "/api/export"):
			w.WriteHeader(200)
			w.Write([]byte("export data"))
		default:
			w.WriteHeader(404)
		}
	}))
}

// methodBypassServer accepts GET normally but also accepts DELETE/PUT.
func methodBypassServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "DELETE":
			w.WriteHeader(200)
			w.Write([]byte(`{"deleted":true}`))
		case "PUT", "PATCH":
			w.WriteHeader(200)
			w.Write([]byte(`{"updated":true}`))
		default:
			w.WriteHeader(200)
			w.Write([]byte(`{"resource":"data"}`))
		}
	}))
}

// sensitiveDataServer returns a JSON response with a "password" field.
func sensitiveDataServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"user":"alice","email":"alice@example.com","password":"s3cr3t"}`))
	}))
}

// safeServer: minimal, secure API.
func safeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(403)
		w.Write([]byte(`{"error":"forbidden"}`))
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := apiaudit.New()
	if m.Name() != "apiaudit" {
		t.Fatalf("expected 'apiaudit', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = apiaudit.New()
}

// TestDebugEndpointsDetected: swagger and actuator exposed.
func TestDebugEndpointsDetected(t *testing.T) {
	srv := debugServer(t)
	defer srv.Close()

	m := apiaudit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"categories": "API8"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected debug endpoint findings")
	}
}

// TestOldVersionDetected: /v1 accessible.
func TestOldVersionDetected(t *testing.T) {
	srv := apiServer(t)
	defer srv.Close()

	m := apiaudit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"categories": "API9"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "api9_old_version" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected api9_old_version finding")
	}
}

// TestMethodBypassDetected: DELETE returns 200.
func TestMethodBypassDetected(t *testing.T) {
	srv := methodBypassServer(t)
	defer srv.Close()

	m := apiaudit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/users/1"},
		Options: map[string]string{"categories": "API5"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected API5 method bypass finding")
	}
}

// TestSensitiveDataExposure: password field in JSON response.
func TestSensitiveDataExposure(t *testing.T) {
	srv := sensitiveDataServer(t)
	defer srv.Close()

	m := apiaudit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"categories": "API8"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "api8_sensitive_data_exposure" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected api8_sensitive_data_exposure finding")
	}
}

// TestAuthBypassDetected: /api/users returns JSON without auth.
func TestAuthBypassDetected(t *testing.T) {
	srv := apiServer(t)
	defer srv.Close()

	m := apiaudit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/users"},
		Options: map[string]string{"categories": "API2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "api2_auth_bypass" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected api2_auth_bypass finding for unauthenticated /api/users")
	}
}

// TestSensitiveFlowDetected: /api/admin accessible.
func TestSensitiveFlowDetected(t *testing.T) {
	srv := apiServer(t)
	defer srv.Close()

	m := apiaudit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"categories": "API6"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "api6_sensitive_flow" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected api6_sensitive_flow finding")
	}
}

// TestNoVulnerability: strict safe server returns no findings.
func TestNoVulnerability(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := apiaudit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/users"},
		Options: map[string]string{"categories": "API2,API8"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type == "api2_auth_bypass" || f.Type == "api8_sensitive_data_exposure" {
			t.Errorf("should not flag secure server: %v", f)
		}
	}
}

// TestEmptyInput: no targets returns nil.
func TestEmptyInput(t *testing.T) {
	m := apiaudit.New()
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(findings))
	}
}

// TestContextCancellation: cancelled context does not panic.
func TestContextCancellation(t *testing.T) {
	srv := debugServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := apiaudit.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{URLs: []string{srv.URL + "/"}})
	_ = err
}

// TestDeduplication: same check on same URL not duplicated.
func TestDeduplication(t *testing.T) {
	srv := debugServer(t)
	defer srv.Close()

	u := srv.URL + "/"
	m := apiaudit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{u, u, u},
		Options: map[string]string{"categories": "API8"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Type + "|" + f.Extra["check_id"]
		seen[key]++
	}
	for k, count := range seen {
		if count > 1 {
			t.Errorf("duplicate finding %q count=%d", k, count)
		}
	}
}

// TestFindingFields: all required fields populated.
func TestFindingFields(t *testing.T) {
	srv := debugServer(t)
	defer srv.Close()

	m := apiaudit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"categories": "API8"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.URL == "" {
		t.Error("URL empty")
	}
	if f.Detail == "" {
		t.Error("Detail empty")
	}
	if f.Severity == "" {
		t.Error("Severity empty")
	}
	if f.Extra["check_id"] == "" {
		t.Error("Extra.check_id empty")
	}
	if f.Extra["category"] == "" {
		t.Error("Extra.category empty")
	}
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	srv := debugServer(t)
	defer srv.Close()

	m := apiaudit.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"parallelism": "3"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := debugServer(t)
	defer srv.Close()

	m := apiaudit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/",
		Options: map[string]string{"categories": "API8"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from Target")
	}
}

// TestNewWithClientReplaces: NewWithClient does not panic.
func TestNewWithClientReplaces(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := apiaudit.NewWithClient(c)
	if m == nil || m.Name() != "apiaudit" {
		t.Fatal("NewWithClient failed")
	}
}

// TestCategoriesFilter: only API8 checks run when categories=API8.
func TestCategoriesFilter(t *testing.T) {
	srv := debugServer(t)
	defer srv.Close()

	m := apiaudit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"categories": "API8"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.HasPrefix(f.Type, "api8_") {
			// API5 check shouldn't run.
			if f.Extra["category"] != "API8" {
				t.Errorf("non-API8 finding returned with categories=API8: %v", f)
			}
		}
	}
}

// TestMultipleURLs: multiple targets checked.
func TestMultipleURLs(t *testing.T) {
	srv := debugServer(t)
	defer srv.Close()

	m := apiaudit.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/", srv.URL + "/api"},
		Options: map[string]string{"categories": "API8"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}
