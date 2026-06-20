package ssti_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/ssti"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// evalServer: evaluates simple arithmetic injections and echoes the result.
// Simulates a vulnerable template engine that evaluates {{7*7}} → 49.
func evalServer(t *testing.T, param string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get(param)
		// Simulate template evaluation for basic patterns.
		result := evalTemplate(val)
		w.WriteHeader(200)
		fmt.Fprint(w, result)
	}))
}

// evalTemplate: minimal expression evaluator for test purposes.
func evalTemplate(input string) string {
	replacements := map[string]string{
		"{{7*7}}":               "49",
		"${7*7}":                "49",
		"#{7*7}":                "49",
		"<%=7*7%>":              "49",
		"{{49*49}}":             "2401",
		"${1337+1}":             "1338",
		"{{7*'7'}}":             "7777777",
		"#set($x=7*7)$x":        "49",
		"<%= 7*7 %>":            "49",
		"<%=7777+1%>":           "7778",
		"{{7|times:7}}":         "49",
		"<#assign x=7*7>${x}":   "49",
		"{math equation='7*7'}": "49",
		"{php}echo 49;{/php}":   "49",
		"<% x = 7*7 %>${x}":     "49",
	}
	for pattern, result := range replacements {
		if input == pattern {
			return "result: " + result
		}
	}
	// Return input as-is (not vulnerable).
	return "hello " + input
}

// safeServer: escapes template syntax — never evaluates.
func safeServer(t *testing.T, param string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get(param)
		// Escape HTML entities to simulate proper escaping.
		escaped := strings.ReplaceAll(val, "{", "&#123;")
		escaped = strings.ReplaceAll(escaped, "}", "&#125;")
		escaped = strings.ReplaceAll(escaped, "$", "&#36;")
		w.WriteHeader(200)
		fmt.Fprintf(w, "hello %s", escaped)
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := ssti.New()
	if m.Name() != "ssti" {
		t.Fatalf("expected 'ssti', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = ssti.New()
}

// TestGenericMathDetection: {{7*7}} → 49 in response.
func TestGenericMathDetection(t *testing.T) {
	srv := evalServer(t, "q")
	defer srv.Close()

	probe := ssti.Probe{
		ID:       "generic-7x7",
		Engine:   "generic",
		Inject:   "{{7*7}}",
		Expected: "49",
		Severity: module.SeverityCritical,
		Tags:     []string{"math"},
	}

	m := ssti.NewWithProbesAndClient([]ssti.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=hello",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected SSTI finding for {{7*7}}")
	}
}

// TestDollarSignExpression: ${7*7} → 49.
func TestDollarSignExpression(t *testing.T) {
	srv := evalServer(t, "q")
	defer srv.Close()

	probe := ssti.Probe{
		ID:       "generic-dollar",
		Engine:   "generic",
		Inject:   "${7*7}",
		Expected: "49",
		Severity: module.SeverityCritical,
		Tags:     []string{"dollar"},
	}

	m := ssti.NewWithProbesAndClient([]ssti.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=hello",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected SSTI finding for ${7*7}")
	}
}

// TestJinja2StringMultiply: Jinja2-specific {{7*'7'}} → 7777777.
func TestJinja2StringMultiply(t *testing.T) {
	srv := evalServer(t, "name")
	defer srv.Close()

	probe := ssti.Probe{
		ID:       "jinja2-7x7",
		Engine:   "jinja2",
		Inject:   "{{7*'7'}}",
		Expected: "7777777",
		Severity: module.SeverityCritical,
		Tags:     []string{"jinja2"},
	}

	m := ssti.NewWithProbesAndClient([]ssti.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?name=test",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Jinja2 SSTI finding")
	}
	if findings[0].Extra["engine"] != "jinja2" {
		t.Errorf("engine = %q, want 'jinja2'", findings[0].Extra["engine"])
	}
}

// TestERBExpression: <%= 7*7 %> → 49.
func TestERBExpression(t *testing.T) {
	srv := evalServer(t, "input")
	defer srv.Close()

	probe := ssti.Probe{
		ID:       "erb-math",
		Engine:   "erb",
		Inject:   "<%= 7*7 %>",
		Expected: "49",
		Severity: module.SeverityCritical,
		Tags:     []string{"erb", "ruby"},
	}

	m := ssti.NewWithProbesAndClient([]ssti.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?input=test",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected ERB SSTI finding")
	}
}

// TestNoVulnerability: safe server escapes → no findings.
func TestNoVulnerability(t *testing.T) {
	srv := safeServer(t, "q")
	defer srv.Close()

	m := ssti.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=hello",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on safe server, got %d", len(findings))
	}
}

// TestEmptyInput: no targets → nil.
func TestEmptyInput(t *testing.T) {
	m := ssti.New()
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(findings))
	}
}

// TestNoParams: URL without query params → no probes run.
func TestNoParams(t *testing.T) {
	srv := evalServer(t, "q")
	defer srv.Close()

	m := ssti.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/page",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for URL without params, got %d", len(findings))
	}
}

// TestContextCancellation: cancelled context does not panic.
func TestContextCancellation(t *testing.T) {
	srv := evalServer(t, "q")
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := ssti.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{Target: srv.URL + "/?q=test"})
	_ = err
}

// TestDeduplication: same probe + same URL + same param not duplicated.
func TestDeduplication(t *testing.T) {
	srv := evalServer(t, "q")
	defer srv.Close()

	probe := ssti.Probe{
		ID:       "dedup-probe",
		Engine:   "generic",
		Inject:   "{{7*7}}",
		Expected: "49",
		Severity: module.SeverityCritical,
		Tags:     []string{"test"},
	}

	u := srv.URL + "/?q=hello"
	m := ssti.NewWithProbesAndClient([]ssti.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{u, u, u},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Extra["probe_id"] + "|" + f.Extra["param"]
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
	srv := evalServer(t, "q")
	defer srv.Close()

	probe := ssti.Probe{
		ID:       "fields-probe",
		Engine:   "generic",
		Inject:   "{{7*7}}",
		Expected: "49",
		Severity: module.SeverityCritical,
		Tags:     []string{"test"},
	}

	m := ssti.NewWithProbesAndClient([]ssti.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=hello",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type != "ssti" {
		t.Errorf("Type = %q, want 'ssti'", f.Type)
	}
	if f.URL == "" {
		t.Error("URL empty")
	}
	if f.Detail == "" {
		t.Error("Detail empty")
	}
	if f.Severity != module.SeverityCritical {
		t.Errorf("Severity = %q, want Critical", f.Severity)
	}
	if f.Extra["probe_id"] == "" {
		t.Error("Extra.probe_id empty")
	}
	if f.Extra["engine"] == "" {
		t.Error("Extra.engine empty")
	}
	if f.Extra["param"] == "" {
		t.Error("Extra.param empty")
	}
	if f.Extra["inject"] == "" {
		t.Error("Extra.inject empty")
	}
	if f.Extra["expected"] == "" {
		t.Error("Extra.expected empty")
	}
}

// TestEngineFilter: only specified engine probes run.
func TestEngineFilter(t *testing.T) {
	srv := evalServer(t, "q")
	defer srv.Close()

	probes := []ssti.Probe{
		{ID: "jinja2-probe", Engine: "jinja2", Inject: "{{7*7}}", Expected: "49", Severity: module.SeverityCritical, Tags: []string{"jinja2"}},
		{ID: "erb-probe", Engine: "erb", Inject: "{{7*7}}", Expected: "49", Severity: module.SeverityCritical, Tags: []string{"erb"}},
	}

	m := ssti.NewWithProbesAndClient(probes, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?q=hello",
		Options: map[string]string{"engine": "jinja2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["engine"] != "jinja2" {
			t.Errorf("got engine=%q, expected only 'jinja2'", f.Extra["engine"])
		}
	}
}

// TestMultipleParams: all params are probed.
func TestMultipleParams(t *testing.T) {
	srv := evalServer(t, "q")
	defer srv.Close()

	probe := ssti.Probe{
		ID:       "multi-param",
		Engine:   "generic",
		Inject:   "{{7*7}}",
		Expected: "49",
		Severity: module.SeverityCritical,
		Tags:     []string{"test"},
	}

	m := ssti.NewWithProbesAndClient([]ssti.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		// q and name — both should be probed.
		Target: srv.URL + "/?q=hello&name=test",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	// At least one param should trigger.
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from multi-param URL")
	}
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	srv := safeServer(t, "q")
	defer srv.Close()

	m := ssti.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?q=test",
		Options: map[string]string{"parallelism": "3"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := evalServer(t, "q")
	defer srv.Close()

	probe := ssti.Probe{
		ID:       "fallback",
		Engine:   "generic",
		Inject:   "{{7*7}}",
		Expected: "49",
		Severity: module.SeverityCritical,
		Tags:     []string{"test"},
	}

	m := ssti.NewWithProbesAndClient([]ssti.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=hello",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from Target")
	}
}

// TestNewWithClient: does not panic.
func TestNewWithClient(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := ssti.NewWithClient(c)
	if m == nil || m.Name() != "ssti" {
		t.Fatal("NewWithClient failed")
	}
}

// TestDetailContainsSSTI: Detail has [SSTI] prefix.
func TestDetailContainsSSTI(t *testing.T) {
	srv := evalServer(t, "q")
	defer srv.Close()

	probe := ssti.Probe{
		ID:       "detail-probe",
		Engine:   "generic",
		Inject:   "{{7*7}}",
		Expected: "49",
		Severity: module.SeverityCritical,
		Tags:     []string{"test"},
	}

	m := ssti.NewWithProbesAndClient([]ssti.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=hello",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.Detail, "[SSTI]") {
			t.Errorf("Detail %q missing '[SSTI]'", f.Detail)
		}
	}
}

// TestTagsPopulated: Extra.tags contains "ssti".
func TestTagsPopulated(t *testing.T) {
	srv := evalServer(t, "q")
	defer srv.Close()

	probe := ssti.Probe{
		ID:       "tags-probe",
		Engine:   "generic",
		Inject:   "{{7*7}}",
		Expected: "49",
		Severity: module.SeverityCritical,
		Tags:     []string{"math", "generic"},
	}

	m := ssti.NewWithProbesAndClient([]ssti.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=hello",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.HasPrefix(f.Extra["tags"], "ssti,") {
			t.Errorf("Extra.tags = %q, expected to start with 'ssti,'", f.Extra["tags"])
		}
	}
}

// TestVelocityExpression: Velocity-style expression.
func TestVelocityExpression(t *testing.T) {
	srv := evalServer(t, "q")
	defer srv.Close()

	probe := ssti.Probe{
		ID:       "velocity-math",
		Engine:   "velocity",
		Inject:   "#set($x=7*7)$x",
		Expected: "49",
		Severity: module.SeverityCritical,
		Tags:     []string{"velocity", "java"},
	}

	m := ssti.NewWithProbesAndClient([]ssti.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=hello",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Velocity SSTI finding")
	}
}

// TestFreemarkerExpression: Freemarker ${7*7} expression.
func TestFreemarkerExpression(t *testing.T) {
	srv := evalServer(t, "q")
	defer srv.Close()

	probe := ssti.Probe{
		ID:       "freemarker-math",
		Engine:   "freemarker",
		Inject:   "${7*7}",
		Expected: "49",
		Severity: module.SeverityCritical,
		Tags:     []string{"freemarker", "java"},
	}

	m := ssti.NewWithProbesAndClient([]ssti.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=hello",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Freemarker SSTI finding")
	}
}
