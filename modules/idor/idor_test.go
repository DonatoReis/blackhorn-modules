package idor_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/idor"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// userDataServer returns user data for IDs 100 and 101, 403 for anything else.
func userDataServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/100"):
			w.WriteHeader(200)
			fmt.Fprint(w, `{"id":100,"name":"Alice","email":"alice@example.com"}`)
		case strings.HasSuffix(path, "/101"):
			w.WriteHeader(200)
			fmt.Fprint(w, `{"id":101,"name":"Bob","email":"bob@example.com","password":"secret123"}`)
		default:
			w.WriteHeader(403)
			fmt.Fprint(w, `{"error":"forbidden"}`)
		}
	}))
}

// idorQueryServer: returns 200 with data for uid=5, 403 for others.
func idorQueryServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid := r.URL.Query().Get("uid")
		if uid == "5" {
			w.WriteHeader(200)
			fmt.Fprint(w, `{"uid":5,"name":"Admin","email":"admin@example.com"}`)
			return
		}
		if uid == "6" {
			w.WriteHeader(200)
			fmt.Fprint(w, `{"uid":6,"name":"User","email":"user@example.com"}`)
			return
		}
		w.WriteHeader(403)
		fmt.Fprint(w, `{"error":"forbidden"}`)
	}))
}

// safeServer: always 403 for any ID variant.
func safeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"error":"forbidden"}`)
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := idor.New()
	if m.Name() != "idor" {
		t.Fatalf("expected 'idor', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = idor.New()
}

// TestIDORPathDetected: incrementing path ID reveals another user's data.
func TestIDORPathDetected(t *testing.T) {
	srv := userDataServer(t)
	defer srv.Close()

	m := idor.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/users/100"},
		Options: map[string]string{"max_offset": "3"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected IDOR finding for path ID increment")
	}
}

// TestIDORQueryParamDetected: changing query param uid reveals other user.
func TestIDORQueryParamDetected(t *testing.T) {
	srv := idorQueryServer(t)
	defer srv.Close()

	m := idor.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/profile?uid=5"},
		Options: map[string]string{"max_offset": "3"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected IDOR finding for query param uid")
	}
}

// TestNoIDOR: safe server always returns 403 → no findings.
func TestNoIDOR(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := idor.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/orders/42"},
		Options: map[string]string{"max_offset": "3"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on safe server, got %d", len(findings))
	}
}

// TestEmptyInput: no targets returns nil.
func TestEmptyInput(t *testing.T) {
	m := idor.New()
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(findings))
	}
}

// TestNoNumericID: URL without numeric IDs returns no findings.
func TestNoNumericID(t *testing.T) {
	srv := userDataServer(t)
	defer srv.Close()

	m := idor.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/api/users/me"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for non-numeric ID, got %d", len(findings))
	}
}

// TestContextCancellation: cancelled context does not panic.
func TestContextCancellation(t *testing.T) {
	srv := userDataServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := idor.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{
		URLs: []string{srv.URL + "/api/users/100"},
	})
	_ = err
}

// TestDeduplication: same (url, id_type, tested_id) not duplicated.
func TestDeduplication(t *testing.T) {
	srv := userDataServer(t)
	defer srv.Close()

	u := srv.URL + "/api/users/100"
	m := idor.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{u, u, u},
		Options: map[string]string{"max_offset": "1"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Extra["id_type"] + "|" + f.Extra["tested_id"]
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
	srv := userDataServer(t)
	defer srv.Close()

	m := idor.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/users/100"},
		Options: map[string]string{"max_offset": "2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type != "idor" {
		t.Errorf("Type = %q, want 'idor'", f.Type)
	}
	if f.URL == "" {
		t.Error("URL empty")
	}
	if f.Detail == "" {
		t.Error("Detail empty")
	}
	if f.Severity == "" {
		t.Error("Severity empty")
	}
	if f.Extra["id_type"] == "" {
		t.Error("Extra.id_type empty")
	}
	if f.Extra["tested_id"] == "" {
		t.Error("Extra.tested_id empty")
	}
}

// TestFindingType: all findings have Type == "idor".
func TestFindingType(t *testing.T) {
	srv := userDataServer(t)
	defer srv.Close()

	m := idor.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/users/100"},
		Options: map[string]string{"max_offset": "2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type != "idor" {
			t.Errorf("finding.Type = %q, want 'idor'", f.Type)
		}
	}
}

// TestCriticalWithPII: response with password field → Critical.
func TestCriticalWithPII(t *testing.T) {
	srv := userDataServer(t)
	defer srv.Close()

	m := idor.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/users/100"},
		Options: map[string]string{"max_offset": "2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	// ID 101 returns password field → should be Critical.
	for _, f := range findings {
		if f.Extra["tested_id"] == "101" {
			if f.Severity != module.SeverityCritical {
				t.Errorf("expected Critical for PII-containing response, got %q", f.Severity)
			}
		}
	}
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	srv := userDataServer(t)
	defer srv.Close()

	m := idor.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/users/100"},
		Options: map[string]string{"parallelism": "3", "max_offset": "2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := userDataServer(t)
	defer srv.Close()

	m := idor.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/api/users/100",
		Options: map[string]string{"max_offset": "2"},
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
	m := idor.NewWithClient(c)
	if m == nil || m.Name() != "idor" {
		t.Fatal("NewWithClient failed")
	}
}

// TestDetailContainsIDType: Detail mentions path or query type.
func TestDetailContainsIDType(t *testing.T) {
	srv := userDataServer(t)
	defer srv.Close()

	m := idor.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/users/100"},
		Options: map[string]string{"max_offset": "2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.Detail, "IDOR:") {
			t.Errorf("Detail %q missing 'IDOR:'", f.Detail)
		}
	}
}

// TestMultipleIDs: URL with multiple numeric path segments.
func TestMultipleIDs(t *testing.T) {
	srv := userDataServer(t)
	defer srv.Close()

	m := idor.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/users/100/orders/200"},
		Options: map[string]string{"max_offset": "2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestRun_FindingsHaveConfidence verifies all findings have a non-empty confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	srv := userDataServer(t)
	defer srv.Close()

	m := idor.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/users/100"},
		Options: map[string]string{"max_offset": "2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding missing Extra[confidence]: %+v", f)
		}
	}
}

// TestRun_FindingTypeValid verifies all findings have Type == "idor".
func TestRun_FindingTypeValid(t *testing.T) {
	srv := userDataServer(t)
	defer srv.Close()

	m := idor.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/users/100"},
		Options: map[string]string{"max_offset": "2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type == "" {
			t.Errorf("finding has empty Type: %+v", f)
		}
	}
}

// TestRun_FindingURLOrDetailSet verifies each finding has at least URL or Detail set.
func TestRun_FindingURLOrDetailSet(t *testing.T) {
	srv := userDataServer(t)
	defer srv.Close()

	m := idor.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/users/100"},
		Options: map[string]string{"max_offset": "2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.URL == "" && f.Detail == "" {
			t.Errorf("finding has neither URL nor Detail: %+v", f)
		}
	}
}
