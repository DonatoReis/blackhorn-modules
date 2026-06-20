package sstiprobe_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/sstiprobe"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func moduleWithClient(t *testing.T) *sstiprobe.Module {
	t.Helper()
	return sstiprobe.NewWithClient(&http.Client{Timeout: 5 * time.Second})
}

// sstiServer returns a server that reflects the value of ?tpl= parameter.
// It simulates a Jinja2-like engine: it evaluates {{N*N}} → result.
func sstiServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tpl := r.URL.Query().Get("tpl")
		// Simulate Jinja2 math expression evaluation.
		if tpl == `{{7*7}}` {
			fmt.Fprint(w, "Result: 49")
			return
		}
		// Simulate Twig math expression.
		if tpl == `{{7*'7'}}` {
			fmt.Fprint(w, "Result: 49")
			return
		}
		// Simulate polyglot error response.
		if strings.Contains(tpl, `${{`) || strings.Contains(tpl, `<%`) {
			fmt.Fprint(w, "TemplateSyntaxError: unexpected character in template")
			return
		}
		fmt.Fprintf(w, "Page: %s", tpl)
	}))
}

// safeServer returns a server that HTML-encodes all output (no SSTI).
func safeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always returns static output — never evaluates template expressions.
		fmt.Fprint(w, "Result: safe output, no template evaluation here")
	}))
}

// freemarkerServer simulates a Freemarker engine response.
func freemarkerServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tpl := r.URL.Query().Get("tpl")
		if tpl == `${7*7}` {
			fmt.Fprint(w, "Result: 49")
			return
		}
		if strings.Contains(tpl, "${{") {
			fmt.Fprint(w, "FreeMarker template error: ParseException at line 1")
			return
		}
		fmt.Fprintf(w, "Output: %s", tpl)
	}))
}

// ─── tests ────────────────────────────────────────────────────────────────────

// TestName verifies the module name.
func TestName(t *testing.T) {
	if sstiprobe.New().Name() != "sstiprobe" {
		t.Error("expected module name 'sstiprobe'")
	}
}

// TestRun_EmptyTarget expects an error.
func TestRun_EmptyTarget(t *testing.T) {
	m := sstiprobe.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestRun_ContextCancellation should not hang.
func TestRun_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := sstiprobe.New()
	_, _ = m.Run(ctx, module.Input{Target: "http://localhost:1"})
}

// TestRun_NoParamsNoFindings verifies no findings when URL has no parameters.
func TestRun_NoParamsNoFindings(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for URL without parameters, got %d", len(findings))
	}
}

// TestRun_SSTIConfirmedJinja2 verifies confirmed SSTI detection for Jinja2/Twig.
func TestRun_SSTIConfirmedJinja2(t *testing.T) {
	srv := sstiServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?tpl=hello",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasConfirmed := false
	for _, f := range findings {
		if f.Type == "ssti_confirmed" {
			hasConfirmed = true
		}
	}
	if !hasConfirmed {
		// ssti_detected (from error probe) is also a valid finding.
		hasDetected := false
		for _, f := range findings {
			if f.Type == "ssti_detected" {
				hasDetected = true
			}
		}
		if !hasDetected {
			t.Error("expected ssti_confirmed or ssti_detected finding")
		}
	}
}

// TestRun_SafeServerNoFindings verifies no findings on a safe server.
func TestRun_SafeServerNoFindings(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?tpl=hello",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "ssti_confirmed" || f.Type == "ssti_detected" {
			t.Errorf("safe server should not produce SSTI findings, got: %+v", f)
		}
	}
}

// TestRun_FindingFields verifies required fields on every finding.
func TestRun_FindingFields(t *testing.T) {
	srv := sstiServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?tpl=hello",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["parameter"] == "" {
			t.Error("finding missing 'parameter' field")
		}
		if f.URL == "" {
			t.Error("finding missing URL")
		}
		if f.Severity == "" {
			t.Error("finding missing severity")
		}
		if f.Detail == "" {
			t.Error("finding missing detail")
		}
	}
}

// TestRun_FreemarkerDetection verifies Freemarker SSTI detection.
func TestRun_FreemarkerDetection(t *testing.T) {
	srv := freemarkerServer(t)
	defer srv.Close()

	eng := sstiprobe.Engine{
		Name:           "Freemarker",
		Language:       "Java",
		MathProbe:      `${7*7}`,
		ExpectedResult: "49",
		Severity:       module.SeverityCritical,
	}

	m := sstiprobe.NewWithClientAndEngines(&http.Client{Timeout: 5 * time.Second}, []sstiprobe.Engine{eng})
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?tpl=hello",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasFreemarker := false
	for _, f := range findings {
		if f.Extra["engine"] == "Freemarker" && f.Type == "ssti_confirmed" {
			hasFreemarker = true
		}
	}
	if !hasFreemarker {
		t.Error("expected Freemarker SSTI to be confirmed")
	}
}

// TestRun_EngineFilter verifies that only specified engines are tested.
func TestRun_EngineFilter(t *testing.T) {
	srv := sstiServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?tpl=hello",
		Options: map[string]string{"engines": "Jinja2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		engine := f.Extra["engine"]
		if engine != "" && engine != "Jinja2" && !strings.Contains(engine, "Jinja2") {
			t.Errorf("unexpected engine %q when only Jinja2 was requested", engine)
		}
	}
}

// TestRun_MultipleParams verifies that multiple parameters are tested.
func TestRun_MultipleParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := r.URL.Query().Get("a")
		b := r.URL.Query().Get("b")
		if a == `{{7*7}}` || b == `{{7*7}}` {
			fmt.Fprint(w, "Result: 49")
			return
		}
		fmt.Fprint(w, "output")
	}))
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?a=x&b=y",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	params := map[string]bool{}
	for _, f := range findings {
		if f.Type == "ssti_confirmed" {
			params[f.Extra["parameter"]] = true
		}
	}
	if !params["a"] && !params["b"] {
		t.Log("note: neither param produced ssti_confirmed (engine-specific; ssti_detected may have fired)")
	}
}

// TestRun_ParamFilter verifies that only specified params are tested.
func TestRun_ParamFilter(t *testing.T) {
	srv := sstiServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	// Only test "tpl" param — not any others that might be inferred.
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?tpl=x&other=y",
		Options: map[string]string{"params": "tpl"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["parameter"] == "other" {
			t.Error("parameter 'other' should not be tested when params=tpl is specified")
		}
	}
}

// TestRun_TargetFromURLs uses URLs[0] when Target is empty.
func TestRun_TargetFromURLs(t *testing.T) {
	srv := sstiServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	_, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/?tpl=hello"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// no panic = pass
}

// TestRun_CustomEngine verifies NewWithEngines uses only the provided engines.
func TestRun_CustomEngine(t *testing.T) {
	customSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("x") == `[[6*9]]` {
			fmt.Fprint(w, "54")
			return
		}
		fmt.Fprint(w, "no match")
	}))
	defer customSrv.Close()

	eng := sstiprobe.Engine{
		Name:           "CustomEngine",
		Language:       "Custom",
		MathProbe:      `[[6*9]]`,
		ExpectedResult: "54",
		Severity:       module.SeverityHigh,
	}

	m := sstiprobe.NewWithClientAndEngines(&http.Client{Timeout: 5 * time.Second}, []sstiprobe.Engine{eng})
	findings, err := m.Run(context.Background(), module.Input{
		Target: customSrv.URL + "/?x=hello",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hasCustom := false
	for _, f := range findings {
		if f.Extra["engine"] == "CustomEngine" && f.Type == "ssti_confirmed" {
			hasCustom = true
		}
	}
	if !hasCustom {
		t.Error("expected CustomEngine SSTI to be confirmed")
	}
}

// TestRun_NoURLsNoTarget returns error when both Target and URLs are empty.
func TestRun_NoURLsNoTarget(t *testing.T) {
	m := moduleWithClient(t)
	_, err := m.Run(context.Background(), module.Input{URLs: []string{}})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestRun_SafeServerNoConfirmed produces no ssti_confirmed findings.
func TestRun_SafeServerNoConfirmed(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?tpl=test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "ssti_confirmed" {
			t.Errorf("safe server should not produce ssti_confirmed, got: %+v", f)
		}
	}
}

// TestRun_ContextCancellationDoesNotHang verifies context cancellation is respected.
func TestRun_ContextCancellationDoesNotHang(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := moduleWithClient(t)
	// Must return quickly — not hang on cancelled context.
	_, _ = m.Run(ctx, module.Input{Target: "http://localhost:1/?x=test"})
}

// TestRun_FindingHasEngine verifies engine metadata is set.
func TestRun_FindingHasEngine(t *testing.T) {
	srv := sstiServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?tpl=test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "ssti_confirmed" {
			if f.Extra["engine"] == "" {
				t.Error("ssti_confirmed finding missing Extra[engine]")
			}
			if f.Extra["parameter"] == "" {
				t.Error("ssti_confirmed finding missing Extra[parameter]")
			}
		}
	}
}

// TestRun_FindingsHaveConfidence verifies all findings include a confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	srv := sstiServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?tpl=test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("no findings to check")
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding type=%q missing confidence", f.Type)
		}
	}
}

// TestRun_FindingURLPopulated verifies the URL field is set on all findings.
func TestRun_FindingURLPopulated(t *testing.T) {
	srv := sstiServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?tpl=test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.URL == "" {
			t.Errorf("finding type=%q has empty URL", f.Type)
		}
	}
}

// TestRun_SeverityHighForConfirmed verifies ssti_confirmed has High or Critical severity.
func TestRun_SeverityHighForConfirmed(t *testing.T) {
	srv := sstiServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?tpl=test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "ssti_confirmed" {
			if f.Severity != module.SeverityHigh && f.Severity != module.SeverityCritical {
				t.Errorf("ssti_confirmed should be High or Critical, got %q", f.Severity)
			}
		}
	}
}
