package vulnscan_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/vulnscan"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── test templates ───────────────────────────────────────────────────────

// wordTemplate returns a simple template that matches a word in the response body.
func wordTemplate(id, path, word string, sev module.Severity) vulnscan.Template {
	return vulnscan.Template{
		ID:                id,
		Name:              id,
		Severity:          sev,
		Description:       "test template",
		Tags:              []string{"test"},
		Path:              path,
		Method:            "GET",
		MatchersCondition: "and",
		Matchers: []vulnscan.Matcher{
			{Type: vulnscan.StatusMatcher, Status: []int{200}},
			{Type: vulnscan.WordMatcher, Part: "body", Words: []string{word}},
		},
	}
}

// regexTemplate returns a template that matches a regex in the response body.
func regexTemplate(id, path, pattern string, sev module.Severity) vulnscan.Template {
	return vulnscan.Template{
		ID:                id,
		Name:              id,
		Severity:          sev,
		Description:       "test regex template",
		Tags:              []string{"test"},
		Path:              path,
		MatchersCondition: "and",
		Matchers: []vulnscan.Matcher{
			{Type: vulnscan.StatusMatcher, Status: []int{200}},
			{Type: vulnscan.RegexMatcher, Part: "body", Regex: []string{pattern}},
		},
	}
}

// statusTemplate returns a template that matches a specific status code.
func statusTemplate(id, path string, statusCode int, sev module.Severity) vulnscan.Template {
	return vulnscan.Template{
		ID:                id,
		Name:              id,
		Severity:          sev,
		Description:       "test status template",
		Tags:              []string{"test"},
		Path:              path,
		MatchersCondition: "and",
		Matchers: []vulnscan.Matcher{
			{Type: vulnscan.StatusMatcher, Status: []int{statusCode}},
		},
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────

// newMockServer creates a test server and a Module with custom templates.
func newMockServer(t *testing.T, handler http.HandlerFunc, templates []vulnscan.Template) (*httptest.Server, *vulnscan.Module) {
	t.Helper()
	srv := httptest.NewServer(handler)
	return srv, vulnscan.NewWithTemplates(templates)
}

// ─── tests ────────────────────────────────────────────────────────────────

// TestName verifies the module name.
func TestName(t *testing.T) {
	if vulnscan.New().Name() != "vulnscan" {
		t.Error("expected module name 'vulnscan'")
	}
}

// TestRun_EmptyTarget expects an error.
func TestRun_EmptyTarget(t *testing.T) {
	m := vulnscan.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestRun_ContextCancellation should not hang.
func TestRun_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := vulnscan.New()
	_, _ = m.Run(ctx, module.Input{Target: "http://localhost:1"})
}

// TestRun_WordMatcherHit verifies a word matcher fires when the word is present.
func TestRun_WordMatcherHit(t *testing.T) {
	tmpl := wordTemplate("test-word", "/secret", "[core]", module.SeverityHigh)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "[core]")
	}))
	defer srv.Close()

	m := vulnscan.NewWithTemplates([]vulnscan.Template{tmpl})
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Extra["template_id"] == "test-word" {
			found = true
		}
	}
	if !found {
		t.Error("expected word matcher to fire")
	}
}

// TestRun_WordMatcherMiss verifies no finding when word is absent.
func TestRun_WordMatcherMiss(t *testing.T) {
	tmpl := wordTemplate("test-word-miss", "/", "[core]", module.SeverityHigh)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "nothing here")
	}))
	defer srv.Close()

	m := vulnscan.NewWithTemplates([]vulnscan.Template{tmpl})
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["template_id"] == "test-word-miss" {
			t.Error("word matcher should not fire when word is absent")
		}
	}
}

// TestRun_RegexMatcherHit verifies a regex matcher fires.
func TestRun_RegexMatcherHit(t *testing.T) {
	tmpl := regexTemplate("test-regex", "/", `APP_KEY\s*=`, module.SeverityCritical)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "APP_KEY=supersecret123")
	}))
	defer srv.Close()

	m := vulnscan.NewWithTemplates([]vulnscan.Template{tmpl})
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Extra["template_id"] == "test-regex" {
			found = true
			if f.Severity != module.SeverityCritical {
				t.Errorf("expected critical severity, got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected regex matcher to fire")
	}
}

// TestRun_StatusMatcherHit verifies a status matcher fires on the right code.
func TestRun_StatusMatcherHit(t *testing.T) {
	tmpl := statusTemplate("test-404", "/missing", 404, module.SeverityLow)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	m := vulnscan.NewWithTemplates([]vulnscan.Template{tmpl})
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Extra["template_id"] == "test-404" {
			found = true
		}
	}
	if !found {
		t.Error("expected status matcher to fire on 404")
	}
}

// TestRun_NegativeMatcher verifies negative matcher inverts the result.
func TestRun_NegativeMatcher(t *testing.T) {
	// Negative word matcher: fires when word is NOT present.
	tmpl := vulnscan.Template{
		ID:                "test-negative",
		Name:              "test-negative",
		Severity:          module.SeverityMedium,
		Tags:              []string{"test"},
		Path:              "/",
		MatchersCondition: "and",
		Matchers: []vulnscan.Matcher{
			{Type: vulnscan.StatusMatcher, Status: []int{200}},
			{Type: vulnscan.WordMatcher, Part: "header", Negative: true,
				Words: []string{"x-absent-header"}},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "body")
	}))
	defer srv.Close()

	m := vulnscan.NewWithTemplates([]vulnscan.Template{tmpl})
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Extra["template_id"] == "test-negative" {
			found = true
		}
	}
	if !found {
		t.Error("negative matcher should fire when header is absent")
	}
}

// TestRun_FindingFields verifies required fields on every finding.
func TestRun_FindingFields(t *testing.T) {
	tmpl := wordTemplate("test-fields", "/", "hello", module.SeverityInfo)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello world")
	}))
	defer srv.Close()

	m := vulnscan.NewWithTemplates([]vulnscan.Template{tmpl})
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type != "vuln_match" {
			t.Errorf("expected type 'vuln_match', got %q", f.Type)
		}
		if f.Extra["template_id"] == "" {
			t.Error("finding missing template_id")
		}
		if f.Extra["template_name"] == "" {
			t.Error("finding missing template_name")
		}
		if f.Extra["status_code"] == "" {
			t.Error("finding missing status_code")
		}
		if f.URL == "" {
			t.Error("finding missing URL")
		}
	}
}

// TestRun_TagFilter verifies that only matching tags run.
func TestRun_TagFilter(t *testing.T) {
	templates := []vulnscan.Template{
		wordTemplate("tagged-a", "/", "hit", module.SeverityInfo),
		wordTemplate("tagged-b", "/", "hit", module.SeverityInfo),
	}
	templates[0].Tags = []string{"group-a"}
	templates[1].Tags = []string{"group-b"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hit")
	}))
	defer srv.Close()

	m := vulnscan.NewWithTemplates(templates)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"tags": "group-a"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Extra["template_id"] == "tagged-b" {
			t.Error("template with non-matching tag should not run")
		}
	}
}

// TestRun_IDFilter verifies that only matching IDs run.
func TestRun_IDFilter(t *testing.T) {
	templates := []vulnscan.Template{
		wordTemplate("id-alpha", "/", "match", module.SeverityInfo),
		wordTemplate("id-beta", "/", "match", module.SeverityInfo),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "match")
	}))
	defer srv.Close()

	m := vulnscan.NewWithTemplates(templates)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"ids": "id-alpha"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Extra["template_id"] == "id-beta" {
			t.Error("template id-beta should not run when only id-alpha is requested")
		}
	}
}

// TestRun_HeaderMatcher verifies matchers against response headers.
func TestRun_HeaderMatcher(t *testing.T) {
	tmpl := vulnscan.Template{
		ID:                "test-header",
		Name:              "test-header",
		Severity:          module.SeverityMedium,
		Tags:              []string{"test"},
		Path:              "/",
		MatchersCondition: "and",
		Matchers: []vulnscan.Matcher{
			{Type: vulnscan.StatusMatcher, Status: []int{200}},
			// Go's http.Header normalises keys to canonical form: X-Custom-Header.
			// Use regex for case-insensitive header matching.
			{Type: vulnscan.RegexMatcher, Part: "header",
				Regex: []string{`(?i)X-Custom-Header:\s*present`}},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "present")
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	m := vulnscan.NewWithTemplates([]vulnscan.Template{tmpl})
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Extra["template_id"] == "test-header" {
			found = true
		}
	}
	if !found {
		t.Error("expected header matcher to fire")
	}
}

// TestRun_MultipleTargets verifies that multiple URLs in input are all scanned.
func TestRun_MultipleTargets(t *testing.T) {
	tmpl := wordTemplate("multi-target", "/", "ok", module.SeverityInfo)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	m := vulnscan.NewWithTemplates([]vulnscan.Template{tmpl})
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL, srv.URL + "/path"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both URLs should produce a finding.
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings for 2 URLs, got %d", len(findings))
	}
}

// TestRun_BuiltinTemplatesLoad verifies that the default template set loads without panic.
func TestRun_BuiltinTemplatesLoad(t *testing.T) {
	m := vulnscan.New()
	if m == nil {
		t.Fatal("expected non-nil module")
	}

	// Run against a mock that returns 200 with empty body — should not panic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 2 * time.Second}
	mc := vulnscan.NewWithClient(client)

	_, err := mc.Run(ctx, module.Input{
		Target: srv.URL,
		Options: map[string]string{
			"threads": "5",
			"timeout": "5",
		},
	})
	if err != nil {
		// context timeout is acceptable
		if !strings.Contains(err.Error(), "context") {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

// TestRun_FindingsHaveSeverity verifies all findings have a populated severity.
func TestRun_FindingsHaveSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/5.4.0")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "vulnerable-string")
	}))
	defer srv.Close()

	m := vulnscan.NewWithClient(&http.Client{Timeout: 3 * time.Second})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"threads": "3", "timeout": "3"},
	})
	if err != nil && !strings.Contains(err.Error(), "context") {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == "" {
			t.Errorf("finding %q missing Severity", f.Type)
		}
	}
}

// TestRun_ContextCancellationVulnscan verifies module returns quickly on cancelled context.
func TestRun_ContextCancellationVulnscan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := vulnscan.New()
	start := time.Now()
	_, _ = m.Run(ctx, module.Input{Target: "http://localhost:1"})
	if time.Since(start) > 3*time.Second {
		t.Error("Run hung on cancelled context")
	}
}

// TestRun_SeverityInfoNotCritical verifies info-level findings don't get critical severity.
func TestRun_SeverityInfoNotCritical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	m := vulnscan.NewWithClient(&http.Client{Timeout: 3 * time.Second})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"threads": "3", "timeout": "3", "severity": "info"},
	})
	if err != nil && !strings.Contains(err.Error(), "context") {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == module.SeverityCritical {
			t.Errorf("info-severity filter should not return critical finding: %+v", f)
		}
	}
}

// TestRun_FindingsHaveConfidence verifies all findings include a confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "VULN-TOKEN-XYZ")
	}))
	defer srv.Close()

	tmpl := wordTemplate("conf-test", "/", "VULN-TOKEN-XYZ", module.SeverityHigh)
	m := vulnscan.NewWithTemplates([]vulnscan.Template{tmpl})
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding id=%q missing confidence", f.Extra["template_id"])
		}
	}
}

// TestRun_DetailNotEmpty verifies all findings have a non-empty Detail field.
func TestRun_DetailNotEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "DETAIL-MARKER")
	}))
	defer srv.Close()

	tmpl := wordTemplate("detail-test", "/", "DETAIL-MARKER", module.SeverityMedium)
	m := vulnscan.NewWithTemplates([]vulnscan.Template{tmpl})
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Detail == "" {
			t.Errorf("finding id=%q has empty Detail", f.Extra["template_id"])
		}
	}
}

// TestRun_URLFieldSet verifies all findings have their URL field populated.
func TestRun_URLFieldSet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "URL-MARKER-CHECK")
	}))
	defer srv.Close()

	tmpl := wordTemplate("url-test", "/", "URL-MARKER-CHECK", module.SeverityLow)
	m := vulnscan.NewWithTemplates([]vulnscan.Template{tmpl})
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.URL == "" {
			t.Errorf("finding id=%q has empty URL", f.Extra["template_id"])
		}
	}
}
