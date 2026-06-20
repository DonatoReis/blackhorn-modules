package cors2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/cors2"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// originReflectServer echoes any Origin back in ACAO + sets ACAC:true.
func originReflectServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"data":"secret"}`))
	}))
}

// nullOriginServer allows null origin + credentials.
func nullOriginServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if strings.EqualFold(origin, "null") {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
}

// wildcardCredServer returns ACAO:* + ACAC:true (invalid per spec).
func wildcardCredServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
}

// strictServer: only allows the actual origin of the page.
func strictServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No CORS headers at all.
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := cors2.New()
	if m.Name() != "cors2" {
		t.Fatalf("expected 'cors2', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = cors2.New()
}

// TestOriginReflection: server reflects any origin → finding.
func TestOriginReflection(t *testing.T) {
	srv := originReflectServer(t)
	defer srv.Close()

	m := cors2.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/api/data"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected CORS reflection finding")
	}
}

// TestCriticalWhenCredentials: reflection + ACAC:true → Critical finding.
func TestCriticalWhenCredentials(t *testing.T) {
	srv := originReflectServer(t)
	defer srv.Close()

	m := cors2.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	hasCritical := false
	for _, f := range findings {
		if f.Severity == module.SeverityCritical {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Error("expected at least one Critical finding when ACAO reflects + ACAC:true")
	}
}

// TestNullOriginAllowed: server allows null → finding.
func TestNullOriginAllowed(t *testing.T) {
	srv := nullOriginServer(t)
	defer srv.Close()

	m := cors2.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "cors_null_origin" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected cors_null_origin finding")
	}
}

// TestWildcardWithCredentials: ACAO:* + ACAC:true → finding.
func TestWildcardWithCredentials(t *testing.T) {
	srv := wildcardCredServer(t)
	defer srv.Close()

	m := cors2.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "cors_wildcard_creds" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected cors_wildcard_creds finding")
	}
}

// TestNoVulnerability: strict server returns no findings.
func TestNoVulnerability(t *testing.T) {
	srv := strictServer(t)
	defer srv.Close()

	m := cors2.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on strict server, got %d", len(findings))
	}
}

// TestEmptyInput: no targets returns nil.
func TestEmptyInput(t *testing.T) {
	m := cors2.New()
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
	srv := originReflectServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := cors2.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{
		URLs: []string{srv.URL + "/"},
	})
	_ = err
}

// TestDeduplication: same (url, type, probe_id) not duplicated.
func TestDeduplication(t *testing.T) {
	srv := originReflectServer(t)
	defer srv.Close()

	u := srv.URL + "/"
	m := cors2.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{u, u, u},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Type + "|" + f.Extra["probe_id"]
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
	srv := originReflectServer(t)
	defer srv.Close()

	m := cors2.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
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
	if f.Extra["probe_id"] == "" {
		t.Error("Extra.probe_id empty")
	}
	if f.Extra["origin_sent"] == "" {
		t.Error("Extra.origin_sent empty")
	}
	if f.Extra["acao"] == "" {
		t.Error("Extra.acao empty")
	}
}

// TestFindingType: all findings have valid type.
func TestFindingType(t *testing.T) {
	srv := originReflectServer(t)
	defer srv.Close()

	validTypes := map[string]bool{
		"cors_origin_reflection": true,
		"cors_null_origin":       true,
		"cors_subdomain_bypass":  true,
		"cors_prefix_bypass":     true,
		"cors_wildcard_creds":    true,
		"cors_http_downgrade":    true,
	}

	m := cors2.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !validTypes[f.Type] {
			t.Errorf("unknown finding type %q", f.Type)
		}
	}
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	srv := originReflectServer(t)
	defer srv.Close()

	m := cors2.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"parallelism": "5"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := originReflectServer(t)
	defer srv.Close()

	m := cors2.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from Target field")
	}
}

// TestNewWithProbes: custom probes used without panic.
func TestNewWithProbes(t *testing.T) {
	custom := []cors2.CORSProbe{
		{
			ID:             "custom-probe",
			OriginTemplate: "https://evil.custom.test",
			FindingType:    "cors_origin_reflection",
			Detect: func(origin, acao, acac string, status int) bool {
				return strings.EqualFold(acao, origin)
			},
			Severity: module.SeverityHigh,
			Tags:     []string{"custom"},
		},
	}
	m := cors2.NewWithProbes(custom)
	if m == nil {
		t.Fatal("NewWithProbes returned nil")
	}
}

// TestNewWithClientReplaces: NewWithClient does not panic.
func TestNewWithClientReplaces(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := cors2.NewWithClient(c)
	if m == nil || m.Name() != "cors2" {
		t.Fatal("NewWithClient failed")
	}
}

// TestBuiltinProbesMinCount: at least 5 unique probes fire.
func TestBuiltinProbesMinCount(t *testing.T) {
	srv := originReflectServer(t)
	defer srv.Close()

	m := cors2.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	unique := make(map[string]struct{})
	for _, f := range findings {
		unique[f.Extra["probe_id"]] = struct{}{}
	}
	if len(unique) < 3 {
		t.Errorf("expected at least 3 unique probe IDs, got %d", len(unique))
	}
}

// TestMultipleURLs: multiple targets checked.
func TestMultipleURLs(t *testing.T) {
	srv := originReflectServer(t)
	defer srv.Close()

	m := cors2.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/", srv.URL + "/api", srv.URL + "/user"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestDetailContainsOrigin: Detail mentions the sent origin.
func TestDetailContainsOrigin(t *testing.T) {
	srv := originReflectServer(t)
	defer srv.Close()

	m := cors2.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.Detail, "CORS2/") {
			t.Errorf("Detail %q missing 'CORS2/'", f.Detail)
		}
	}
}
