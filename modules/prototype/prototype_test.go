package prototype_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/prototype"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// echoQueryServer: echoes all query parameter values back in the response body.
// This simulates a server that is vulnerable to server-side prototype pollution
// via query parameters — the parameter value appears in the output.
func echoQueryServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		// Echo all query parameter values.
		for _, vals := range r.URL.Query() {
			for _, v := range vals {
				fmt.Fprintf(w, `{"value":"%s"}`, v)
			}
		}
	}))
}

// echoJSONServer: echoes JSON body values back in the response.
// Simulates a server vulnerable to JSON prototype pollution — any
// nested key in "__proto__" or "constructor.prototype" is reflected.
func echoJSONServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var buf strings.Builder
		_, _ = fmt.Fscan(r.Body, &buf) // best-effort read
		body := buf.String()
		if body == "" {
			// Also accept via ReadAll pattern
			b := make([]byte, 4096)
			n, _ := r.Body.Read(b)
			body = string(b[:n])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		// Echo body back verbatim so canary is reflected.
		fmt.Fprint(w, body)
	}))
}

// safeServer: a server that never reflects user-controlled input.
// Simulates a properly sanitized server — should produce no findings.
func safeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

// makeQueryProbe: returns a single query-location probe for testing.
func makeQueryProbe(id, injectTemplate string) prototype.Probe {
	return prototype.Probe{
		ID:             id,
		Location:       prototype.LocationQuery,
		InjectTemplate: injectTemplate,
		Severity:       module.SeverityCritical,
		Tags:           []string{"test"},
	}
}

// makeJSONProbe: returns a single JSON-location probe for testing.
func makeJSONProbe(id, injectTemplate string) prototype.Probe {
	return prototype.Probe{
		ID:             id,
		Location:       prototype.LocationJSON,
		InjectTemplate: injectTemplate,
		Severity:       module.SeverityCritical,
		Tags:           []string{"test"},
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := prototype.New()
	if m.Name() != "prototype" {
		t.Fatalf("expected 'prototype', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = prototype.New()
}

// TestEmptyInput: no targets → nil findings, no error.
func TestEmptyInput(t *testing.T) {
	m := prototype.New()
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(findings))
	}
}

// TestQueryPollutionDetected: server echoes query values → canary reflected → found.
func TestQueryPollutionDetected(t *testing.T) {
	srv := echoQueryServer(t)
	defer srv.Close()

	probe := makeQueryProbe("query-proto-bracket", "__proto__[canary]={CANARY}")
	m := prototype.NewWithProbesAndClient([]prototype.Probe{probe}, clientFor(srv))

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type != "prototype_pollution" {
		t.Errorf("expected type 'prototype_pollution', got %q", f.Type)
	}
}

// TestJSONPollutionDetected: echo JSON server reflects the body → canary found.
func TestJSONPollutionDetected(t *testing.T) {
	srv := echoJSONServer(t)
	defer srv.Close()

	probe := makeJSONProbe("json-proto-direct", `{"__proto__":{"canary":"{CANARY}"}}`)
	m := prototype.NewWithProbesAndClient([]prototype.Probe{probe}, clientFor(srv))

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
}

// TestSafeServerNoFindings: safe server (no reflection) → no findings.
func TestSafeServerNoFindings(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := prototype.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings on safe server, got %d: %v", len(findings), findings)
	}
}

// TestConstructorPrototypeQuery: constructor[prototype] bypass probe detected.
func TestConstructorPrototypeQuery(t *testing.T) {
	srv := echoQueryServer(t)
	defer srv.Close()

	probe := makeQueryProbe("query-constructor-prototype", "constructor[prototype][canary]={CANARY}")
	m := prototype.NewWithProbesAndClient([]prototype.Probe{probe}, clientFor(srv))

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for constructor[prototype] probe")
	}
}

// TestConstructorPrototypeJSON: JSON constructor.prototype probe detected.
func TestConstructorPrototypeJSON(t *testing.T) {
	srv := echoJSONServer(t)
	defer srv.Close()

	probe := makeJSONProbe("json-constructor-prototype", `{"constructor":{"prototype":{"canary":"{CANARY}"}}}`)
	m := prototype.NewWithProbesAndClient([]prototype.Probe{probe}, clientFor(srv))

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for json constructor.prototype probe")
	}
}

// TestFindingFields: all required fields are populated.
func TestFindingFields(t *testing.T) {
	srv := echoQueryServer(t)
	defer srv.Close()

	probe := makeQueryProbe("query-proto-bracket", "__proto__[canary]={CANARY}")
	m := prototype.NewWithProbesAndClient([]prototype.Probe{probe}, clientFor(srv))

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
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
	if f.Extra["probe_id"] == "" {
		t.Error("Extra.probe_id empty")
	}
	if f.Extra["location"] == "" {
		t.Error("Extra.location empty")
	}
	if f.Extra["canary"] == "" {
		t.Error("Extra.canary empty")
	}
	if f.Extra["inject"] == "" {
		t.Error("Extra.inject empty")
	}
}

// TestDetailHasPrefix: findings have [ProtoPollution] in detail.
func TestDetailHasPrefix(t *testing.T) {
	srv := echoQueryServer(t)
	defer srv.Close()

	probe := makeQueryProbe("query-proto-bracket", "__proto__[canary]={CANARY}")
	m := prototype.NewWithProbesAndClient([]prototype.Probe{probe}, clientFor(srv))

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.Detail, "[ProtoPollution]") {
			t.Errorf("Detail %q missing '[ProtoPollution]'", f.Detail)
		}
	}
}

// TestDeduplication: same probe + URL not reported twice.
func TestDeduplication(t *testing.T) {
	srv := echoQueryServer(t)
	defer srv.Close()

	probe := makeQueryProbe("query-proto-bracket", "__proto__[canary]={CANARY}")
	u := srv.URL + "/"
	m := prototype.NewWithProbesAndClient([]prototype.Probe{probe}, clientFor(srv))

	findings, err := m.Run(context.Background(), module.Input{URLs: []string{u, u, u}})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Extra["probe_id"]
		seen[key]++
	}
	for k, count := range seen {
		if count > 1 {
			t.Errorf("duplicate finding %q count=%d", k, count)
		}
	}
}

// TestLocationFilter: location filter only runs specified probe types.
func TestLocationFilterQuery(t *testing.T) {
	srv := echoJSONServer(t)
	defer srv.Close()

	// Include both query and JSON probes, but filter to JSON only.
	probes := []prototype.Probe{
		makeQueryProbe("query-test", "__proto__[canary]={CANARY}"),
		makeJSONProbe("json-test", `{"__proto__":{"canary":"{CANARY}"}}`),
	}
	m := prototype.NewWithProbesAndClient(probes, clientFor(srv))

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/",
		Options: map[string]string{"location": "json"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["location"] != "json" {
			t.Errorf("expected only json findings, got location=%q", f.Extra["location"])
		}
	}
}

// TestLocationFilterJSON: json filter excludes query probes.
func TestLocationFilterJSON(t *testing.T) {
	srv := echoQueryServer(t)
	defer srv.Close()

	probes := []prototype.Probe{
		makeQueryProbe("query-test", "__proto__[canary]={CANARY}"),
		makeJSONProbe("json-test", `{"__proto__":{"canary":"{CANARY}"}}`),
	}
	m := prototype.NewWithProbesAndClient(probes, clientFor(srv))

	// Filter to query only.
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/",
		Options: map[string]string{"location": "query"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["location"] != "query" {
			t.Errorf("expected only query findings, got location=%q", f.Extra["location"])
		}
	}
}

// TestMultipleURLs: multiple targets all processed.
func TestMultipleURLs(t *testing.T) {
	srv := echoQueryServer(t)
	defer srv.Close()

	probe := makeQueryProbe("query-proto-bracket", "__proto__[canary]={CANARY}")
	m := prototype.NewWithProbesAndClient([]prototype.Probe{probe}, clientFor(srv))

	u := srv.URL
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{u + "/api", u + "/search"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings (one per URL), got %d", len(findings))
	}
}

// TestContextCancellation: cancelled context does not panic.
func TestContextCancellation(t *testing.T) {
	srv := echoQueryServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := prototype.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{Target: srv.URL + "/"})
	_ = err
}

// TestParallelismOption: custom parallelism accepted without error.
func TestParallelismOption(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := prototype.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/",
		Options: map[string]string{"parallelism": "3"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestNewWithClient: does not panic.
func TestNewWithClient(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := prototype.NewWithClient(c)
	if m == nil || m.Name() != "prototype" {
		t.Fatal("NewWithClient returned nil or wrong name")
	}
}

// TestNewWithProbes: custom probes set correctly.
func TestNewWithProbes(t *testing.T) {
	probes := []prototype.Probe{makeQueryProbe("test-probe", "__proto__[x]={CANARY}")}
	m := prototype.NewWithProbes(probes)
	if m == nil || m.Name() != "prototype" {
		t.Fatal("NewWithProbes returned nil or wrong name")
	}
}

// TestBuiltinProbesAllRun: built-in probes run without panic on safe server.
func TestBuiltinProbesAllRun(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := prototype.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings on safe server, got %d: %v", len(findings), findings)
	}
}

// TestSeverityCritical: prototype pollution findings have Critical severity.
func TestSeverityCritical(t *testing.T) {
	srv := echoQueryServer(t)
	defer srv.Close()

	probe := prototype.Probe{
		ID:             "critical-probe",
		Location:       prototype.LocationQuery,
		InjectTemplate: "__proto__[canary]={CANARY}",
		Severity:       module.SeverityCritical,
		Tags:           []string{"test"},
	}
	m := prototype.NewWithProbesAndClient([]prototype.Probe{probe}, clientFor(srv))

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Severity != module.SeverityCritical {
		t.Errorf("expected Critical, got %q", findings[0].Severity)
	}
}

// TestCanaryUnique: each probe invocation uses a unique canary.
func TestCanaryUnique(t *testing.T) {
	srv := echoQueryServer(t)
	defer srv.Close()

	probe := makeQueryProbe("query-proto-bracket", "__proto__[canary]={CANARY}")
	m := prototype.NewWithProbesAndClient([]prototype.Probe{probe}, clientFor(srv))

	// Run twice on same target; canaries should differ across runs.
	f1, _ := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	f2, _ := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	if len(f1) == 0 || len(f2) == 0 {
		t.Fatal("expected findings in both runs")
	}
	if f1[0].Extra["canary"] == f2[0].Extra["canary"] {
		t.Error("canary should be unique per invocation")
	}
}

// TestURLWithExistingQuery: target URL with existing query params — probes appended correctly.
func TestURLWithExistingQuery(t *testing.T) {
	srv := echoQueryServer(t)
	defer srv.Close()

	probe := makeQueryProbe("query-proto-bracket", "__proto__[canary]={CANARY}")
	m := prototype.NewWithProbesAndClient([]prototype.Probe{probe}, clientFor(srv))

	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?page=1&limit=10",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding when URL already has query params")
	}
}
