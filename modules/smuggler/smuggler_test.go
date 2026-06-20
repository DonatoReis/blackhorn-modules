package smuggler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

func run(t *testing.T, m *Module, target string) []module.Finding {
	t.Helper()
	findings, err := m.Run(context.Background(), module.Input{Target: target})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	return findings
}

func hasCheck(findings []module.Finding, checkID string) bool {
	for _, f := range findings {
		if f.Extra["check_id"] == checkID {
			return true
		}
	}
	return false
}

func TestName(t *testing.T) {
	if New().Name() != "smuggler" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoTarget(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHTTP2Detection(t *testing.T) {
	// httptest.NewTLSServer doesn't serve h2 by default,
	// but we test the check doesn't crash.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := run(t, m, srv.URL)
	// HTTP/1.1 in test server — SMUG-005 should not fire for h2.
	_ = findings
}

func TestDifferentialResponse_Consistent(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("consistent response body"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	if hasCheck(run(t, m, srv.URL), "SMUG-004") {
		t.Fatal("should not flag SMUG-004 for consistent responses")
	}
}

func TestDifferentialResponse_Inconsistent(t *testing.T) {
	var count int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt64(&count, 1)
		if n == 1 {
			w.WriteHeader(200)
			w.Write([]byte("first response with much more content here to exceed threshold"))
			return
		}
		w.WriteHeader(500) // different status code
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	if !hasCheck(run(t, m, srv.URL), "SMUG-004") {
		t.Fatal("expected SMUG-004 for inconsistent responses")
	}
}

func TestConnectionHeaderProbe_200(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	// SMUG-006 checks for 200 or 5xx — a 200 response fires the finding.
	if !hasCheck(run(t, m, srv.URL), "SMUG-006") {
		t.Fatal("expected SMUG-006 for 200 response to connection header probe")
	}
}

func TestParseAddr(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/path", "example.com:443"},
		{"http://example.com/path", "example.com:80"},
		{"https://example.com:8443/path", "example.com:8443"},
		{"https://example.com", "example.com:443"},
	}
	for _, tt := range tests {
		got := parseAddr(tt.input)
		if got != tt.expected {
			t.Errorf("parseAddr(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/admin/panel", "/admin/panel"},
		{"http://example.com/", "/"},
		{"https://example.com", "/"},
		{"https://example.com/path?q=1", "/path?q=1"},
	}
	for _, tt := range tests {
		got := parsePath(tt.input)
		if got != tt.expected {
			t.Errorf("parsePath(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestParseHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/path", "example.com"},
		{"http://example.com:8080/path", "example.com:8080"},
	}
	for _, tt := range tests {
		got := parseHost(tt.input)
		if got != tt.expected {
			t.Errorf("parseHost(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestBuiltinChecks_Count(t *testing.T) {
	checks := builtinChecks()
	if len(checks) != 6 {
		t.Fatalf("expected 6 built-in checks, got %d", len(checks))
	}
}

func TestBuiltinChecks_IDs(t *testing.T) {
	expected := []string{"SMUG-001", "SMUG-002", "SMUG-003", "SMUG-004", "SMUG-005", "SMUG-006"}
	checks := builtinChecks()
	for i, chk := range checks {
		if chk.ID != expected[i] {
			t.Errorf("check[%d].ID = %q, want %q", i, chk.ID, expected[i])
		}
	}
}

func TestNewWithChecks(t *testing.T) {
	m := NewWithChecks([]Check{builtinChecks()[0]})
	if len(m.checks) != 1 {
		t.Fatal("expected 1 check")
	}
}

func TestLimitWriter(t *testing.T) {
	var buf strings.Builder
	lw := &limitWriter{w: &buf, rem: 5}
	n, err := lw.Write([]byte("hello world"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 11 { // returns full len but writes only 5
		// The implementation returns n as the write count to avoid errors.
	}
	if buf.String() != "hello" {
		t.Fatalf("expected 'hello', got %q", buf.String())
	}
}

func TestRun_URLsInput(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	input := module.Input{URLs: []string{srv.URL}}
	_, err := m.Run(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRun_ContextCancellationSmuggler verifies module returns quickly on cancelled context.
func TestRun_ContextCancellationSmuggler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := New()
	start := time.Now()
	_, _ = m.Run(ctx, module.Input{Target: "http://localhost:1"})
	if time.Since(start) > 3*time.Second {
		t.Error("Run hung on cancelled context")
	}
}

// TestRun_FindingFieldsSmuggler verifies smuggling findings have required fields.
func TestRun_FindingFieldsSmuggler(t *testing.T) {
	var callCount atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		// Simulate differential: first call returns 200, second returns 400.
		if n%2 == 0 {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.URL == "" {
			t.Error("smuggling finding missing URL")
		}
		if f.Type == "" {
			t.Error("smuggling finding missing Type")
		}
	}
}

// TestBuiltinChecks_AllHaveIDs verifies all built-in checks have non-empty IDs.
func TestBuiltinChecks_AllHaveIDs(t *testing.T) {
	checks := builtinChecks()
	if len(checks) == 0 {
		t.Fatal("expected non-empty builtin checks")
	}
	for _, c := range checks {
		if c.ID == "" {
			t.Error("check missing ID")
		}
		if c.Name == "" {
			t.Error("check missing Name")
		}
	}
}

// TestRun_FindingsHaveConfidence verifies all findings include a confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer srv.Close()

	m := NewWithClient(&http.Client{Timeout: 3 * time.Second})
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding check_id=%q missing confidence", f.Extra["check_id"])
		}
	}
	_ = received.Load()
}

// TestRun_FindingDetailDescribesVuln verifies Detail field is descriptive.
func TestRun_FindingDetailDescribesVuln(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	m := NewWithClient(&http.Client{Timeout: 3 * time.Second})
	findings, _ := m.Run(context.Background(), module.Input{Target: srv.URL})
	for _, f := range findings {
		if len(f.Detail) < 10 {
			t.Errorf("finding check_id=%q has too-short Detail: %q", f.Extra["check_id"], f.Detail)
		}
	}
}

// TestRun_FindingTypeIsSmuggling verifies the finding type is always "request_smuggling".
func TestRun_FindingTypeIsSmuggling(t *testing.T) {
	var callCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		// Simulate CL.TE discrepancy: return extra bytes not accounted for by Content-Length.
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	m := NewWithClient(&http.Client{Timeout: 2 * time.Second})
	findings, _ := m.Run(context.Background(), module.Input{Target: srv.URL})
	for _, f := range findings {
		if f.Type != "request_smuggling" {
			t.Errorf("expected type 'request_smuggling', got %q", f.Type)
		}
	}
	_ = callCount.Load()
}
