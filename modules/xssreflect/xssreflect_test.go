package xssreflect_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/xssreflect"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// reflectServer: echoes query parameter value raw (no encoding) — vulnerable.
func reflectServer(t *testing.T, param string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>%s</body></html>", val)
	}))
}

// safeServer: HTML-encodes all parameter values — not vulnerable.
func safeServer(t *testing.T) *httptest.Server {
	t.Helper()
	replacer := strings.NewReplacer(
		"<", "&lt;", ">", "&gt;",
		`"`, "&quot;", "'", "&#39;",
		"`", "&#96;", "(", "&#40;", ")", "&#41;",
	)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var vals []string
		for _, v := range r.URL.Query() {
			for _, val := range v {
				vals = append(vals, replacer.Replace(val))
			}
		}
		fmt.Fprintf(w, "<html><body>%s</body></html>", strings.Join(vals, " "))
	}))
}

// attrReflectServer: reflects query value inside an HTML attribute.
func attrReflectServer(t *testing.T, param string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><div data-val="%s"></div></body></html>`, val)
	}))
}

// scriptReflectServer: reflects query value inside a <script> block.
func scriptReflectServer(t *testing.T, param string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><head><script>var x='%s';</script></head></html>", val)
	}))
}

// slowServer: hangs requests indefinitely (for context cancellation test).
func slowServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
}

func makeProbe(id, template string) xssreflect.Probe {
	return xssreflect.Probe{ID: id, Template: template, Tags: []string{"test"}}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if xssreflect.New().Name() != "xssreflect" {
		t.Error("expected name 'xssreflect'")
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = xssreflect.New()
}

// TestEmptyInput: no targets → no findings, no error.
func TestEmptyInput(t *testing.T) {
	m := xssreflect.New()
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// TestNoParamsNoFindings: URL without query params → no findings.
func TestNoParamsNoFindings(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := xssreflect.NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/no-params",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for URL without params, got %d", len(findings))
	}
}

// TestBasicReflectionDetected: server echoes param raw → finding emitted.
func TestBasicReflectionDetected(t *testing.T) {
	srv := reflectServer(t, "q")
	defer srv.Close()

	probe := makeProbe("basic", `{CANARY}<"'`)
	m := xssreflect.NewWithProbesAndClient([]xssreflect.Probe{probe}, srv.Client())

	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "?q=hello",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type != "reflected_xss_candidate" {
		t.Errorf("expected type 'reflected_xss_candidate', got %q", f.Type)
	}
	if f.Extra["parameter"] != "q" {
		t.Errorf("expected parameter 'q', got %q", f.Extra["parameter"])
	}
}

// TestSafeServerNoFindings: HTML-encoded server → no findings.
func TestSafeServerNoFindings(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := xssreflect.NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "?q=hello&name=world",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings on safe server, got %d: %v", len(findings), findings)
	}
}

// TestHighSeverityBracketsAndQuotes: < > " ' reflected → High severity.
func TestHighSeverityBracketsAndQuotes(t *testing.T) {
	srv := reflectServer(t, "q")
	defer srv.Close()

	probe := makeProbe("full", `{CANARY}<"'>`)
	m := xssreflect.NewWithProbesAndClient([]xssreflect.Probe{probe}, srv.Client())

	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "?q=test",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Severity != module.SeverityHigh {
			t.Errorf("expected High severity, got %q", f.Severity)
		}
	}
}

// TestDetailHasPrefix: findings have [XSSReflect] in detail.
func TestDetailHasPrefix(t *testing.T) {
	srv := reflectServer(t, "q")
	defer srv.Close()

	probe := makeProbe("basic", `{CANARY}<`)
	m := xssreflect.NewWithProbesAndClient([]xssreflect.Probe{probe}, srv.Client())

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "?q=x"})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.Detail, "[XSSReflect]") {
			t.Errorf("Detail %q missing '[XSSReflect]'", f.Detail)
		}
	}
}

// TestFindingFields: all required fields populated.
func TestFindingFields(t *testing.T) {
	srv := reflectServer(t, "search")
	defer srv.Close()

	probe := makeProbe("basic", `{CANARY}<"`)
	m := xssreflect.NewWithProbesAndClient([]xssreflect.Probe{probe}, srv.Client())

	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "?search=test",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type == "" {
		t.Error("Type empty")
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
	if f.Extra["parameter"] == "" {
		t.Error("Extra.parameter empty")
	}
	if f.Extra["probe_id"] == "" {
		t.Error("Extra.probe_id empty")
	}
	if f.Extra["reflected_chars"] == "" {
		t.Error("Extra.reflected_chars empty")
	}
	if f.Extra["canary"] == "" {
		t.Error("Extra.canary empty")
	}
	if f.Extra["injected_url"] == "" {
		t.Error("Extra.injected_url empty")
	}
}

// TestDeduplication: same param + probe combination not reported twice.
func TestDeduplication(t *testing.T) {
	srv := reflectServer(t, "q")
	defer srv.Close()

	probe := makeProbe("basic", `{CANARY}<`)
	u := srv.URL + "?q=test"
	m := xssreflect.NewWithProbesAndClient([]xssreflect.Probe{probe}, srv.Client())

	findings, err := m.Run(context.Background(), module.Input{URLs: []string{u, u, u}})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Extra["parameter"] + "|" + f.Extra["probe_id"]
		seen[key]++
	}
	for k, count := range seen {
		if count > 1 {
			t.Errorf("duplicate finding %q count=%d", k, count)
		}
	}
}

// TestMultipleParams: each parameter tested independently.
func TestMultipleParams(t *testing.T) {
	// Server that echoes "q" raw and "safe" encoded.
	replacer := strings.NewReplacer("<", "&lt;")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		safe := replacer.Replace(r.URL.Query().Get("safe"))
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>q=%s safe=%s</body></html>", q, safe)
	}))
	defer srv.Close()

	probe := makeProbe("basic", `{CANARY}<`)
	m := xssreflect.NewWithProbesAndClient([]xssreflect.Probe{probe}, srv.Client())

	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "?q=test&safe=test",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	// Only "q" should produce a finding.
	for _, f := range findings {
		if f.Extra["parameter"] != "q" {
			t.Errorf("unexpected finding for parameter %q", f.Extra["parameter"])
		}
	}
	found := false
	for _, f := range findings {
		if f.Extra["parameter"] == "q" {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for parameter 'q'")
	}
}

// TestMultipleURLs: multiple targets all processed.
func TestMultipleURLs(t *testing.T) {
	srv := reflectServer(t, "q")
	defer srv.Close()

	probe := makeProbe("basic", `{CANARY}<`)
	m := xssreflect.NewWithProbesAndClient([]xssreflect.Probe{probe}, srv.Client())

	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			srv.URL + "?q=test1",
			srv.URL + "/page2?q=test2",
		},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) < 2 {
		t.Errorf("expected findings from both URLs, got %d", len(findings))
	}
}

// TestContextCancellation: cancelled context → no panic.
func TestContextCancellation(t *testing.T) {
	srv := slowServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := xssreflect.NewWithClient(srv.Client())
	_, err := m.Run(ctx, module.Input{Target: srv.URL + "?q=test"})
	_ = err
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := xssreflect.NewWithClient(srv.Client())
	_, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "?q=test",
		Options: map[string]string{"parallelism": "3"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestNewWithClient: does not panic.
func TestNewWithClient(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := xssreflect.NewWithClient(c)
	if m == nil || m.Name() != "xssreflect" {
		t.Fatal("NewWithClient failed")
	}
}

// TestNewWithProbes: custom probes accepted.
func TestNewWithProbes(t *testing.T) {
	probes := []xssreflect.Probe{{ID: "test", Template: `{CANARY}<`, Tags: []string{"t"}}}
	m := xssreflect.NewWithProbes(probes)
	if m == nil || m.Name() != "xssreflect" {
		t.Fatal("NewWithProbes failed")
	}
}

// TestCanaryUnique: different invocations produce different canaries.
func TestCanaryUnique(t *testing.T) {
	srv := reflectServer(t, "q")
	defer srv.Close()

	probe := makeProbe("basic", `{CANARY}<`)
	m := xssreflect.NewWithProbesAndClient([]xssreflect.Probe{probe}, srv.Client())

	f1, _ := m.Run(context.Background(), module.Input{Target: srv.URL + "?q=x"})
	f2, _ := m.Run(context.Background(), module.Input{Target: srv.URL + "?q=x"})
	if len(f1) == 0 || len(f2) == 0 {
		t.Skip("no findings")
	}
	if f1[0].Extra["canary"] == f2[0].Extra["canary"] {
		t.Error("canary should differ per invocation")
	}
}

// TestBuiltinProbesOnSafe: all built-in probes run without panic on safe server.
func TestBuiltinProbesOnSafe(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := xssreflect.NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "?q=test&name=x"})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings on safe server, got %d: %v", len(findings), findings)
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := reflectServer(t, "q")
	defer srv.Close()

	probe := makeProbe("basic", `{CANARY}<`)
	m := xssreflect.NewWithProbesAndClient([]xssreflect.Probe{probe}, srv.Client())

	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "?q=test",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding via Target fallback")
	}
}

// TestURLInInjectedExtra: Extra.injected_url is a valid URL.
func TestURLInInjectedExtra(t *testing.T) {
	srv := reflectServer(t, "q")
	defer srv.Close()

	probe := makeProbe("basic", `{CANARY}<`)
	m := xssreflect.NewWithProbesAndClient([]xssreflect.Probe{probe}, srv.Client())

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "?q=test"})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("no findings")
	}
	injURL := findings[0].Extra["injected_url"]
	if !strings.HasPrefix(injURL, "http") {
		t.Errorf("expected injected_url to be a full URL, got %q", injURL)
	}
}
