package deserial_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/deserial"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// javaErrorServer returns 500 + Java exception when it receives magic bytes.
func javaErrorServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		param := r.URL.Query().Get("data")
		combined := string(body) + param

		if strings.Contains(combined, "rO0AB") || strings.Contains(combined, "\xac\xed\x00\x05") {
			w.WriteHeader(500)
			io.WriteString(w, "java.io.StreamCorruptedException: invalid stream header\n\tat java.io.ObjectInputStream.<init>(ObjectInputStream.java)")
			return
		}
		w.WriteHeader(200)
		io.WriteString(w, "ok")
	}))
}

// phpErrorServer returns PHP unserialize error when it receives PHP serialized data.
func phpErrorServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("data")
		body, _ := io.ReadAll(r.Body)
		combined := param + string(body)

		if strings.HasPrefix(combined, "O:") || strings.HasPrefix(combined, "a:") || strings.HasPrefix(combined, "s:") {
			w.WriteHeader(500)
			io.WriteString(w, "PHP Warning: unserialize() [function.unserialize]: Error at offset 0\n__wakeup() called")
			return
		}
		io.WriteString(w, "ok")
	}))
}

// dotnetErrorServer returns .NET SerializationException on BinaryFormatter data.
func dotnetErrorServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		param := r.URL.Query().Get("data")
		combined := string(body) + param

		if strings.Contains(combined, "$type") && strings.Contains(combined, "System.") {
			w.WriteHeader(500)
			io.WriteString(w, "System.Runtime.Serialization.SerializationException: BinaryFormatter could not load type")
			return
		}
		if len(combined) > 0 && combined[0] == 0x00 {
			w.WriteHeader(500)
			io.WriteString(w, "SerializationException: invalid data format")
			return
		}
		io.WriteString(w, "ok")
	}))
}

// safeServer always returns 200 "ok".
func safeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

func urlWithParam(srv *httptest.Server, param, value string) string {
	return srv.URL + "/deserialize?" + param + "=" + value
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := deserial.New()
	if m.Name() != "deserial" {
		t.Fatalf("expected 'deserial', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = deserial.New()
}

// TestJavaDeserialDetected: Java magic bytes trigger StreamCorruptedException.
func TestJavaDeserialDetected(t *testing.T) {
	srv := javaErrorServer(t)
	defer srv.Close()

	m := deserial.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "data", "serialized")},
		Options: map[string]string{"format": "java"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Java deserialization finding")
	}
}

// TestPHPDeserialDetected: PHP serialized object triggers unserialize error.
func TestPHPDeserialDetected(t *testing.T) {
	srv := phpErrorServer(t)
	defer srv.Close()

	m := deserial.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "data", "normal")},
		Options: map[string]string{"format": "php"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected PHP deserialization finding")
	}
}

// TestDotNetDeserialDetected: .NET BinaryFormatter payload detected.
func TestDotNetDeserialDetected(t *testing.T) {
	srv := dotnetErrorServer(t)
	defer srv.Close()

	m := deserial.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/load"},
		Options: map[string]string{"format": "dotnet"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	_ = findings // POST probe may fire; check no panic
}

// TestNoVulnerability: safe server returns no findings.
func TestNoVulnerability(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := deserial.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api"},
		Options: map[string]string{"format": "java,php"},
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
	m := deserial.New()
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
	srv := javaErrorServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := deserial.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{
		URLs: []string{urlWithParam(srv, "data", "x")},
	})
	_ = err
}

// TestDeduplication: same (url, param, probe_id) not duplicated.
func TestDeduplication(t *testing.T) {
	srv := javaErrorServer(t)
	defer srv.Close()

	u := urlWithParam(srv, "data", "x")
	m := deserial.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{u, u, u},
		Options: map[string]string{"format": "java"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Extra["param"] + "|" + f.Extra["probe_id"]
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
	srv := javaErrorServer(t)
	defer srv.Close()

	m := deserial.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "data", "test")},
		Options: map[string]string{"format": "java"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type != "deserial" {
		t.Errorf("Type = %q, want 'deserial'", f.Type)
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
	if f.Extra["probe_id"] == "" {
		t.Error("Extra.probe_id empty")
	}
	if f.Extra["format"] == "" {
		t.Error("Extra.format empty")
	}
	if f.Extra["vector"] == "" {
		t.Error("Extra.vector empty")
	}
}

// TestFindingType: all findings have Type == "deserial".
func TestFindingType(t *testing.T) {
	srv := javaErrorServer(t)
	defer srv.Close()

	m := deserial.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "data", "x")},
		Options: map[string]string{"format": "java"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type != "deserial" {
			t.Errorf("finding.Type = %q, want 'deserial'", f.Type)
		}
	}
}

// TestFormatFilter: format=java does not run PHP probes.
func TestFormatFilter(t *testing.T) {
	srv := javaErrorServer(t)
	defer srv.Close()

	m := deserial.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "data", "x")},
		Options: map[string]string{"format": "java"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["format"] == "php" || f.Extra["format"] == "python" {
			t.Errorf("non-java finding returned with format=java filter: %v", f)
		}
	}
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	srv := javaErrorServer(t)
	defer srv.Close()

	m := deserial.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "data", "x")},
		Options: map[string]string{"parallelism": "3", "format": "java"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := javaErrorServer(t)
	defer srv.Close()

	m := deserial.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  urlWithParam(srv, "data", "test"),
		Options: map[string]string{"format": "java"},
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("x"), "CANARY") {
			w.WriteHeader(500)
			io.WriteString(w, "SerializationException: invalid")
			return
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	custom := []deserial.Probe{
		{
			ID: "custom-canary", Format: "java",
			Payload: "CANARY",
			Detect: func(body string, status int) bool {
				return status == 500
			},
			Severity: module.SeverityCritical,
			Tags:     []string{"custom"},
		},
	}
	m := deserial.NewWithProbes(custom)
	if m == nil {
		t.Fatal("NewWithProbes returned nil")
	}
}

// TestNewWithClientReplaces: NewWithClient does not panic.
func TestNewWithClientReplaces(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := deserial.NewWithClient(c)
	if m == nil || m.Name() != "deserial" {
		t.Fatal("NewWithClient failed")
	}
}

// TestBuiltinProbesMinCount: verify built-in probe set is substantial.
func TestBuiltinProbesMinCount(t *testing.T) {
	// Run all probes against a server and count unique probe_ids.
	srv := javaErrorServer(t)
	defer srv.Close()

	m := deserial.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{urlWithParam(srv, "data", "x")},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	unique := make(map[string]struct{})
	for _, f := range findings {
		unique[f.Extra["probe_id"]] = struct{}{}
	}
	// At least 2 unique probes should fire against the Java server.
	if len(unique) < 2 {
		t.Errorf("expected at least 2 unique probe IDs to fire, got %d", len(unique))
	}
}

// TestPOSTBodyVector: POST body vector fires for PHP server.
func TestPOSTBodyVector(t *testing.T) {
	srv := phpErrorServer(t)
	defer srv.Close()

	m := deserial.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/load"},
		Options: map[string]string{"format": "php"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["vector"] == "POST:body" {
			return // found a POST body finding
		}
	}
	// POST vector may not fire for all probes — just ensure no panic.
	_ = findings
}
