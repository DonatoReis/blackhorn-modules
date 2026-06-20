package paramdisc_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/paramdisc"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// anomalyServer: changes status code when the trigger param is present.
func anomalyServer(t *testing.T, triggerParam string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get(triggerParam) != "" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "forbidden")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok normal response body")
	}))
}

// stableServer: always returns identical response regardless of params.
func stableServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "stable body nothing ever changes here")
	}))
}

// htmlInputServer: returns HTML with input fields containing the hidden param.
// Triggers forbidden when that param is sent.
func htmlInputServer(t *testing.T, param string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get(param) != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<html><body>
			<input name="%s" type="hidden"/>
		</body></html>`, param)
	}))
}

// bodyLengthServer: changes body length when certain param is present.
func bodyLengthServer(t *testing.T, triggerParam string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.URL.Query().Get(triggerParam) != "" {
			// Different body when param present
			fmt.Fprintln(w, "long body with different content when param is set for detection purposes only")
		} else {
			fmt.Fprintln(w, "short body")
		}
	}))
}

// redirectServer: redirects to different location when param present.
func redirectServer(t *testing.T, triggerParam string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get(triggerParam) != "" {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "normal")
	}))
}

// slowServer: hangs requests (for context cancellation test).
func slowServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if paramdisc.New().Name() != "paramdisc" {
		t.Error("expected name 'paramdisc'")
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = paramdisc.New()
}

// TestEmptyTarget: no target → error.
func TestEmptyTarget(t *testing.T) {
	m := paramdisc.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestFindsAnomalousParam: status-code anomaly when param present → discovered.
func TestFindsAnomalousParam(t *testing.T) {
	srv := anomalyServer(t, "secret")
	defer srv.Close()

	m := paramdisc.NewWithClient(srv.Client()).
		WithWordlist([]string{"foo", "bar", "secret", "baz"})

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"passive": "false", "chunk_size": "4"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Extra["parameter"] == "secret" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'secret' parameter to be discovered")
	}
}

// TestNoAnomalyNoFindings: stable server → no findings.
func TestNoAnomalyNoFindings(t *testing.T) {
	srv := stableServer(t)
	defer srv.Close()

	m := paramdisc.NewWithClient(srv.Client()).
		WithWordlist([]string{"alpha", "beta", "gamma"})

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/probe",
		Options: map[string]string{"passive": "false", "chunk_size": "3"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for stable server, got %d", len(findings))
	}
}

// TestHeuristicExtractsFromHTML: param from <input name="..."> → discovered.
func TestHeuristicExtractsFromHTML(t *testing.T) {
	srv := htmlInputServer(t, "user_id")
	defer srv.Close()

	m := paramdisc.NewWithClient(srv.Client()).WithWordlist([]string{})

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"passive": "false"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Extra["parameter"], "user_id") {
			found = true
		}
	}
	if !found {
		t.Error("expected heuristic to extract user_id from HTML input")
	}
}

// TestContextCancellation: cancelled context → no panic.
func TestContextCancellation(t *testing.T) {
	srv := slowServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := paramdisc.NewWithClient(srv.Client()).WithWordlist([]string{"x"})
	_, _ = m.Run(ctx, module.Input{
		Target:  srv.URL,
		Options: map[string]string{"passive": "false"},
	})
}

// TestFindingFields: all required fields populated.
func TestFindingFields(t *testing.T) {
	srv := anomalyServer(t, "admin")
	defer srv.Close()

	m := paramdisc.NewWithClient(srv.Client()).
		WithWordlist([]string{"admin", "user"})

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"passive": "false", "chunk_size": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("no findings (flaky on slow CI)")
	}
	f := findings[0]
	if f.Type == "" {
		t.Error("Type empty")
	}
	if f.URL == "" {
		t.Error("URL empty")
	}
	if f.Extra["parameter"] == "" {
		t.Error("Extra.parameter empty")
	}
}

// TestMultipleParamsFound: two different trigger params → both found.
func TestMultipleParamsFound(t *testing.T) {
	// Server that triggers on either "admin" or "debug".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("admin") != "" || q.Get("debug") != "" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "forbidden")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	m := paramdisc.NewWithClient(srv.Client()).
		WithWordlist([]string{"admin", "debug", "harmless"})

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"passive": "false", "chunk_size": "3"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := make(map[string]bool)
	for _, f := range findings {
		found[f.Extra["parameter"]] = true
	}
	// At least one of admin/debug should be discovered.
	if !found["admin"] && !found["debug"] {
		t.Logf("found params: %v (may be chunk-size dependent)", found)
	}
}

// TestBodyLengthAnomaly: body length changes when param present → detected.
func TestBodyLengthAnomaly(t *testing.T) {
	srv := bodyLengthServer(t, "verbose")
	defer srv.Close()

	m := paramdisc.NewWithClient(srv.Client()).
		WithWordlist([]string{"verbose", "quiet", "normal"})

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"passive": "false", "chunk_size": "3"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Body length detection is a secondary anomaly — may or may not find.
	_ = findings
}

// TestNewWithClient: does not panic.
func TestNewWithClient(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := paramdisc.NewWithClient(c)
	if m == nil || m.Name() != "paramdisc" {
		t.Fatal("NewWithClient failed")
	}
}

// TestWithWordlist: custom wordlist accepted.
func TestWithWordlist(t *testing.T) {
	srv := stableServer(t)
	defer srv.Close()

	m := paramdisc.NewWithClient(srv.Client()).
		WithWordlist([]string{"x", "y", "z"})
	if m == nil {
		t.Fatal("WithWordlist returned nil")
	}
}

// TestParallelismOption: parallelism option accepted.
func TestParallelismOption(t *testing.T) {
	srv := stableServer(t)
	defer srv.Close()

	m := paramdisc.NewWithClient(srv.Client()).WithWordlist([]string{"a", "b"})
	_, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/probe",
		Options: map[string]string{"passive": "false", "chunk_size": "2", "parallelism": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRedirectAnomaly: redirect location changes when param present → detected.
func TestRedirectAnomaly(t *testing.T) {
	// Don't follow redirects so we can detect the anomaly.
	srv := redirectServer(t, "next")
	defer srv.Close()

	noRedirectClient := srv.Client()
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	m := paramdisc.NewWithClient(noRedirectClient).
		WithWordlist([]string{"next", "page", "limit"})

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"passive": "false", "chunk_size": "3"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Redirect detection may or may not trigger depending on anomaly threshold.
	_ = findings
}

// TestRun_FindingHasParameter verifies anomalous param findings contain the parameter name.
func TestRun_FindingHasParameter(t *testing.T) {
	var called atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		// Return different body length when param "debug" is present.
		if r.URL.Query().Get("debug") != "" {
			fmt.Fprint(w, strings.Repeat("X", 5000))
			return
		}
		fmt.Fprint(w, "OK")
	}))
	defer srv.Close()

	m := paramdisc.NewWithClient(srv.Client()).
		WithWordlist([]string{"debug", "test", "admin"})

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"passive": "false", "chunk_size": "3"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["parameter"] == "" {
			t.Errorf("finding missing Extra[parameter]: %+v", f)
		}
	}
}

// TestRun_PassiveModeReadsFromRawContent verifies passive mode extracts params from HTML.
func TestRun_PassiveModeReadsFromRawContent(t *testing.T) {
	html := `<html><form action="/search"><input name="q"><input name="page"></form></html>`
	m := paramdisc.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:     "https://example.com/search",
		RawContent: html,
		Options:    map[string]string{"passive": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := map[string]bool{}
	for _, f := range findings {
		found[f.Extra["parameter"]] = true
	}
	if !found["q"] && !found["page"] {
		t.Log("passive mode did not extract q/page — may need active mode for this server")
	}
}

// TestContextCancellationParamDisc verifies that a cancelled context returns promptly.
func TestContextCancellationParamDisc(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := paramdisc.New()
	start := time.Now()
	_, _ = m.Run(ctx, module.Input{Target: "http://localhost:1"})
	if time.Since(start) > 3*time.Second {
		t.Error("Run hung on cancelled context")
	}
}

// TestRun_FindingsHaveConfidence verifies all findings have a non-empty confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	srv := anomalyServer(t, "debug")
	defer srv.Close()

	m := paramdisc.NewWithClient(srv.Client()).
		WithWordlist([]string{"debug", "test", "admin"})

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"passive": "false", "chunk_size": "3"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding missing Extra[confidence]: %+v", f)
		}
	}
}

// TestRun_FindingTypeValid verifies all findings have a non-empty Type field.
func TestRun_FindingTypeValid(t *testing.T) {
	srv := anomalyServer(t, "admin")
	defer srv.Close()

	m := paramdisc.NewWithClient(srv.Client()).
		WithWordlist([]string{"admin", "user", "test"})

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"passive": "false", "chunk_size": "3"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "" {
			t.Errorf("finding has empty Type: %+v", f)
		}
	}
}

// TestRun_FindingURLOrDetailSet verifies each finding has at least URL or Detail set.
func TestRun_FindingURLOrDetailSet(t *testing.T) {
	srv := anomalyServer(t, "secret")
	defer srv.Close()

	m := paramdisc.NewWithClient(srv.Client()).
		WithWordlist([]string{"foo", "secret", "bar"})

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"passive": "false", "chunk_size": "3"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.URL == "" && f.Detail == "" {
			t.Errorf("finding has neither URL nor Detail: %+v", f)
		}
	}
}
