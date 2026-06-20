package verbtamper

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func run(t *testing.T, m *Module, urls []string) []module.Finding {
	t.Helper()
	findings, err := m.Run(context.Background(), module.Input{URLs: urls})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	return findings
}

func hasCheck(findings []module.Finding, check string) bool {
	for _, f := range findings {
		if f.Extra["check"] == check {
			return true
		}
	}
	return false
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "verbtamper" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoInput(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestRun_TargetInput(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	_, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_AuthzBypass_Critical(t *testing.T) {
	// GET returns 403; DELETE returns 200 → CRITICAL authz bypass.
	var requestVerb atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestVerb.Store(r.Method)
		if r.Method == http.MethodGet {
			w.WriteHeader(403)
			w.Write([]byte("forbidden"))
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(200)
			w.Write([]byte("deleted successfully with a response that has at least 128 more bytes than the baseline forbidden page"))
			return
		}
		w.WriteHeader(405)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.testVerbs = []string{"DELETE"}
	m.testTrace = false
	m.testOverride = false
	findings := run(t, m, []string{srv.URL + "/api/resource"})
	if !hasCheck(findings, "authz-bypass") {
		t.Fatal("expected authz-bypass finding for DELETE on 403-protected resource")
	}
	for _, f := range findings {
		if f.Extra["check"] == "authz-bypass" {
			if f.Severity != module.SeverityCritical {
				t.Errorf("expected critical severity, got %q", f.Severity)
			}
		}
	}
}

func TestRun_TraceEnabled_Low(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodTrace {
			w.WriteHeader(200)
			w.Write([]byte("TRACE response"))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("normal page with plenty of real content here to avoid soft-404 detection"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.testVerbs = []string{"TRACE"}
	m.testDestructive = false
	m.testOverride = false
	findings := run(t, m, []string{srv.URL + "/api/resource"})
	if !hasCheck(findings, "trace-enabled") {
		t.Fatal("expected trace-enabled finding")
	}
	for _, f := range findings {
		if f.Extra["check"] == "trace-enabled" {
			if f.Severity != module.SeverityLow {
				t.Errorf("expected low severity for TRACE, got %q", f.Severity)
			}
		}
	}
}

func TestRun_OptionsExposing_Medium(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST, PUT, DELETE, OPTIONS")
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("regular response with enough content to not be a soft-404 page here"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.testVerbs = []string{"OPTIONS"}
	m.testDestructive = false
	m.testTrace = false
	m.testOverride = false
	findings := run(t, m, []string{srv.URL + "/api/resource"})
	if !hasCheck(findings, "options-allow") {
		t.Fatal("expected options-allow finding when Allow header exposes DELETE/PUT/PATCH")
	}
	for _, f := range findings {
		if f.Extra["check"] == "options-allow" {
			if f.Severity != module.SeverityMedium {
				t.Errorf("expected medium severity for OPTIONS, got %q", f.Severity)
			}
		}
	}
}

func TestRun_SoftResponseDiscarded(t *testing.T) {
	// DELETE returns 200 but with a WAF block page containing 2+ soft-404 markers — discarded.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(200)
			// Two unambiguous markers: "page not found" + "this page is gone"
			w.Write([]byte("<html><body>Page not found. This page is gone and no longer available.</body></html>"))
			return
		}
		w.WriteHeader(403)
		w.Write([]byte("forbidden"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.testVerbs = []string{"DELETE"}
	m.testTrace = false
	m.testOverride = false
	findings := run(t, m, []string{srv.URL + "/api/resource"})
	if hasCheck(findings, "authz-bypass") {
		t.Fatal("soft-404/WAF block page should be discarded, not reported as authz-bypass")
	}
}

func TestRun_DifferentResponse_High(t *testing.T) {
	// GET returns 200 with normal content; PUT returns 200 with very different content.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(200)
			// Content must be >= minBodyDiff different from baseline.
			w.Write([]byte(strings.Repeat("resource updated successfully with new data - ", 10)))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("original content here"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.testVerbs = []string{"PUT"}
	m.testTrace = false
	m.testOverride = false
	findings := run(t, m, []string{srv.URL + "/api/item"})
	if !hasCheck(findings, "different-response") {
		t.Fatal("expected different-response finding for PUT with different body")
	}
	for _, f := range findings {
		if f.Extra["check"] == "different-response" {
			if f.Severity != module.SeverityHigh {
				t.Errorf("expected high severity for different response, got %q", f.Severity)
			}
		}
	}
}

func TestSelectTargets_PrioritisesAPI(t *testing.T) {
	urls := []string{
		"https://example.com/about",
		"https://example.com/api/users",
		"https://example.com/v1/items",
		"https://example.com/contact",
	}
	targets := selectTargets(urls, 2)
	apiFirst := false
	for _, t := range targets {
		if strings.Contains(t, "/api/") || strings.Contains(t, "/v1/") {
			apiFirst = true
		}
	}
	if !apiFirst {
		t.Fatal("selectTargets should prioritise API paths")
	}
}

func TestSelectTargets_Deduplication(t *testing.T) {
	urls := []string{
		"https://example.com/api?page=1",
		"https://example.com/api?page=2",
		"https://example.com/api?page=3",
	}
	targets := selectTargets(urls, 10)
	// All have same host+path, so only 1 should be selected.
	if len(targets) != 1 {
		t.Fatalf("expected 1 unique target (same path), got %d", len(targets))
	}
}

func TestActiveVerbs_Default(t *testing.T) {
	verbs := activeVerbs(true, true)
	required := []string{"OPTIONS", "PUT", "DELETE", "PATCH", "TRACE"}
	verbSet := make(map[string]bool)
	for _, v := range verbs {
		verbSet[v] = true
	}
	for _, r := range required {
		if !verbSet[r] {
			t.Errorf("expected verb %q in active verbs", r)
		}
	}
}

func TestActiveVerbs_NoDestructive(t *testing.T) {
	verbs := activeVerbs(false, true)
	for _, v := range verbs {
		if v == "PUT" || v == "DELETE" || v == "PATCH" {
			t.Errorf("destructive verb %q should not be active when testDestructive=false", v)
		}
	}
}

func TestActiveVerbs_NoTrace(t *testing.T) {
	verbs := activeVerbs(true, false)
	for _, v := range verbs {
		if v == "TRACE" {
			t.Fatal("TRACE should not be active when testTrace=false")
		}
	}
}

func TestBodyHash_Stable(t *testing.T) {
	h1 := bodyHash("same content")
	h2 := bodyHash("same content")
	if h1 != h2 {
		t.Fatal("bodyHash should be deterministic")
	}
}

func TestBodyHash_Different(t *testing.T) {
	h1 := bodyHash("content A")
	h2 := bodyHash("content B")
	if h1 == h2 {
		t.Fatal("bodyHash should differ for different inputs")
	}
}

func TestIsSoft404_WAFBlock(t *testing.T) {
	// Body with 2+ unambiguous soft-404 markers.
	body := "<html><body>Page not found. This page is gone and no longer available here.</body></html>"
	if !isSoft404(body) {
		t.Fatal("body with 2+ error markers should be classified as soft-404")
	}
}

func TestIsSoft404_JSON(t *testing.T) {
	if isSoft404(`{"error":"not found"}`) {
		t.Fatal("JSON error should not be classified as soft-404")
	}
}

func TestRun_BaselineSoft404_Skipped(t *testing.T) {
	// All requests return a soft-404 body — baseline is unreliable, no verb test should fire.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html><body>404 Not Found - sorry page not found</body></html>"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := run(t, m, []string{srv.URL + "/api/test"})
	// Findings may or may not be empty — the key thing is no panic/error and
	// soft-404 baseline causes endpoints to be skipped (0 meaningful findings).
	for _, f := range findings {
		if f.Extra["check"] == "authz-bypass" || f.Extra["check"] == "different-response" {
			t.Fatal("should not produce authz or diff findings from soft-404 baseline")
		}
	}
}

func TestRun_OptionsNoAllowHeader(t *testing.T) {
	// OPTIONS returns 200 but without Allow header.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("content here with enough words for a valid baseline response check"))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.testVerbs = []string{"OPTIONS"}
	m.testDestructive = false
	m.testTrace = false
	m.testOverride = false
	findings := run(t, m, []string{srv.URL + "/api/resource"})
	if hasCheck(findings, "options-allow") {
		t.Fatal("should not report options-allow without dangerous verbs in Allow header")
	}
}

func TestCollectURLs_Dedup(t *testing.T) {
	input := module.Input{
		Target: "https://example.com/api",
		URLs:   []string{"https://example.com/api", "https://other.com/api"},
	}
	urls := collectURLs(input)
	if len(urls) != 2 {
		t.Fatalf("expected 2 unique URLs, got %d: %v", len(urls), urls)
	}
}
