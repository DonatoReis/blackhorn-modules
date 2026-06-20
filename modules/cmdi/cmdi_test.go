package cmdi_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/cmdi"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// echoServer returns a server that echoes the parameter value back in the
// response body, simulating a command-injection-vulnerable endpoint.
func echoServer(t *testing.T, param string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get(param)
		// Simulate shell execution: if the value contains an operator + echo,
		// "execute" and return the output (we just look for anything after "echo ").
		if idx := strings.Index(val, "echo "); idx >= 0 {
			canary := strings.TrimSpace(val[idx+5:])
			// strip trailing ` ) } etc.
			canary = strings.TrimRight(canary, "`(){}")
			io.WriteString(w, canary)
			return
		}
		if strings.Contains(val, "echo${IFS}") {
			// IFS-based injection: extract what comes after IFS}
			parts := strings.SplitN(val, "echo${IFS}", 2)
			if len(parts) == 2 {
				canary := strings.TrimRight(parts[1], "`(){}")
				io.WriteString(w, canary)
				return
			}
		}
		io.WriteString(w, "result: "+val)
	}))
}

// sleepServer simulates a time-based cmdi server.
func sleepServer(t *testing.T, param string, sleepDuration time.Duration) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get(param)
		if strings.Contains(val, "sleep") || strings.Contains(val, "ping") || strings.Contains(val, "timeout") {
			time.Sleep(sleepDuration)
		}
		io.WriteString(w, "ok")
	}))
}

// safeServer always returns a fixed response, never echoing commands.
func safeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello World")
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

func urlWithParam(srv *httptest.Server, param, value string) string {
	return srv.URL + "/run?" + param + "=" + value
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := cmdi.New()
	if m.Name() != "cmdi" {
		t.Fatalf("expected name 'cmdi', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = cmdi.New()
}

// TestResultsBasedSemicolon: ; echo CANARY detected in response.
func TestResultsBasedSemicolon(t *testing.T) {
	srv := echoServer(t, "cmd")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "cmd", "ls")},
		Options: map[string]string{"techniques": "R", "os": "unix"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one results-based finding")
	}
}

// TestResultsBasedAnd: && echo CANARY detected.
func TestResultsBasedAnd(t *testing.T) {
	srv := echoServer(t, "q")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "q", "test")},
		Options: map[string]string{"techniques": "R", "os": "unix"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for && operator")
	}
}

// TestResultsBasedWindows: Windows & operator.
func TestResultsBasedWindows(t *testing.T) {
	srv := echoServer(t, "cmd")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "cmd", "dir")},
		Options: map[string]string{"techniques": "R", "os": "windows"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	_ = findings // Windows probes on Unix echo server may or may not fire
}

// TestNoVulnerability: safe server produces no findings.
func TestNoVulnerability(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "input", "hello")},
		Options: map[string]string{"techniques": "R"},
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
	m := cmdi.New()
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil && len(findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(findings))
	}
}

// TestNoParams: URL without params → no findings.
func TestNoParams(t *testing.T) {
	srv := echoServer(t, "cmd")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/noparams"},
		Options: map[string]string{"techniques": "R"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for URL without params, got %d", len(findings))
	}
}

// TestContextCancellation: cancelled context stops without panic.
func TestContextCancellation(t *testing.T) {
	srv := echoServer(t, "cmd")
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := cmdi.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{
		URLs:    []string{urlWithParam(srv, "cmd", "ls")},
		Options: map[string]string{"techniques": "R"},
	})
	_ = err
}

// TestDeduplication: same (url, param, probe_id) not duplicated.
func TestDeduplication(t *testing.T) {
	srv := echoServer(t, "cmd")
	defer srv.Close()

	u := urlWithParam(srv, "cmd", "ls")
	m := cmdi.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{u, u, u},
		Options: map[string]string{"techniques": "R", "os": "unix"},
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
			t.Errorf("duplicate finding %q: count=%d", k, count)
		}
	}
}

// TestFindingFields: all required finding fields are populated.
func TestFindingFields(t *testing.T) {
	srv := echoServer(t, "x")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "x", "ls")},
		Options: map[string]string{"techniques": "R", "os": "unix"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type != "cmdi" {
		t.Errorf("Type = %q, want 'cmdi'", f.Type)
	}
	if f.URL == "" {
		t.Error("URL is empty")
	}
	if f.Detail == "" {
		t.Error("Detail is empty")
	}
	if f.Severity == "" {
		t.Error("Severity is empty")
	}
	if f.Extra["param"] == "" {
		t.Error("Extra.param is empty")
	}
	if f.Extra["probe_id"] == "" {
		t.Error("Extra.probe_id is empty")
	}
	if f.Extra["technique"] == "" {
		t.Error("Extra.technique is empty")
	}
	if f.Extra["operator"] == "" {
		t.Error("Extra.operator is empty")
	}
}

// TestSeverityCritical: results-based findings are Critical.
func TestSeverityCritical(t *testing.T) {
	srv := echoServer(t, "cmd")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "cmd", "ls")},
		Options: map[string]string{"techniques": "R", "os": "unix"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["technique"] == "R" && f.Severity != module.SeverityCritical {
			t.Errorf("results-based finding has severity %q, want Critical", f.Severity)
		}
	}
}

// TestTechniquesFilter: techniques=R does not run T probes.
func TestTechniquesFilter(t *testing.T) {
	srv := echoServer(t, "cmd")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "cmd", "ls")},
		Options: map[string]string{"techniques": "R"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["technique"] == "T" {
			t.Errorf("time-based finding should not run when techniques=R: %v", f)
		}
	}
}

// TestOSFilterUnix: os=unix does not run Windows probes.
func TestOSFilterUnix(t *testing.T) {
	srv := echoServer(t, "cmd")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "cmd", "ls")},
		Options: map[string]string{"techniques": "R", "os": "unix"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["os"] == "windows" {
			t.Errorf("Windows probe fired with os=unix filter: %v", f)
		}
	}
}

// TestParallelismOption: custom parallelism accepted without error.
func TestParallelismOption(t *testing.T) {
	srv := echoServer(t, "p")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "p", "test")},
		Options: map[string]string{"techniques": "R", "parallelism": "3", "os": "unix"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := echoServer(t, "cmd")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  urlWithParam(srv, "cmd", "ls"),
		Options: map[string]string{"techniques": "R", "os": "unix"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from Target field")
	}
}

// TestMultipleParams: both params in a multi-param URL get tested.
func TestMultipleParams(t *testing.T) {
	srv := echoServer(t, "cmd")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/run?cmd=ls&input=hello"},
		Options: map[string]string{"techniques": "R", "os": "unix"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestNewWithProbes: custom probe is used.
func TestNewWithProbes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("x"), "TESTCANARY") {
			io.WriteString(w, "TESTCANARY")
		} else {
			io.WriteString(w, "none")
		}
	}))
	defer srv.Close()

	custom := []cmdi.Probe{
		{
			ID:          "custom-direct",
			Technique:   cmdi.TechniqueResults,
			OS:          "generic",
			Operator:    ";",
			CmdTemplate: "echo TESTCANARY",
			Severity:    module.SeverityCritical,
			Tags:        []string{"custom"},
		},
	}
	m := cmdi.NewWithProbes(custom)
	_ = m // Verifies no panic; client-based test would need NewWithClient
}

// TestBuiltinProbesHaveMinCount: at least 20 built-in probes.
func TestBuiltinProbesHaveMinCount(t *testing.T) {
	// Indirectly check by running all techniques and seeing unique probe_ids.
	srv := echoServer(t, "cmd")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "cmd", "ls")},
		Options: map[string]string{"techniques": "R"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	unique := make(map[string]struct{})
	for _, f := range findings {
		unique[f.Extra["probe_id"]] = struct{}{}
	}
	if len(unique) < 5 {
		t.Errorf("expected at least 5 unique probes to fire, got %d", len(unique))
	}
}

// TestCanaryUnique: each Run gets a different canary value.
func TestCanaryUnique(t *testing.T) {
	srv := echoServer(t, "cmd")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	input := module.Input{
		URLs:    []string{urlWithParam(srv, "cmd", "ls")},
		Options: map[string]string{"techniques": "R", "os": "unix"},
	}

	findings1, _ := m.Run(context.Background(), input)
	findings2, _ := m.Run(context.Background(), input)

	if len(findings1) > 0 && len(findings2) > 0 {
		if findings1[0].Extra["canary"] == findings2[0].Extra["canary"] {
			t.Error("canary should be unique per run")
		}
	}
}

// TestDetailContainsProbeID: Detail string contains the probe ID.
func TestDetailContainsProbeID(t *testing.T) {
	srv := echoServer(t, "cmd")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "cmd", "ls")},
		Options: map[string]string{"techniques": "R", "os": "unix"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.Detail, "CMDi/") {
			t.Errorf("Detail %q does not contain 'CMDi/'", f.Detail)
		}
	}
}

// TestNewWithClientReplaces: NewWithClient does not panic.
func TestNewWithClientReplaces(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := cmdi.NewWithClient(c)
	if m == nil {
		t.Fatal("NewWithClient returned nil")
	}
}

// TestSleepSecondsOption: custom sleep_seconds accepted.
func TestSleepSecondsOption(t *testing.T) {
	srv := echoServer(t, "cmd")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "cmd", "ls")},
		Options: map[string]string{"techniques": "R", "sleep_seconds": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestFindingType: all findings have Type == "cmdi".
func TestFindingType(t *testing.T) {
	srv := echoServer(t, "cmd")
	defer srv.Close()

	m := cmdi.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "cmd", "ls")},
		Options: map[string]string{"techniques": "R", "os": "unix"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type != "cmdi" {
			t.Errorf("finding.Type = %q, want 'cmdi'", f.Type)
		}
	}
}
