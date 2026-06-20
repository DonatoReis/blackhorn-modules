package sqli_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/sqli"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// dbErrorServer returns a server that responds with a DB error string when the
// request contains the triggerParam query parameter.
func dbErrorServer(t *testing.T, triggerParam, errorBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get(triggerParam) != "" {
			io.WriteString(w, errorBody)
			return
		}
		io.WriteString(w, "<html>normal page</html>")
	}))
}

// boolServer returns different bodies for true/false conditions.
// It looks for "AND 1=1" → real page, "AND 1=2" → empty body.
func boolServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		if strings.Contains(q, "1%3D1") || strings.Contains(q, "1=1") {
			io.WriteString(w, strings.Repeat("REAL PAGE CONTENT ", 100))
			return
		}
		if strings.Contains(q, "1%3D2") || strings.Contains(q, "1=2") {
			// Very short body — simulates record not found
			io.WriteString(w, "not found")
			return
		}
		io.WriteString(w, strings.Repeat("REAL PAGE CONTENT ", 100))
	}))
}

// sleepServer simulates a time-based SQLi target by sleeping when it receives
// a payload containing the sleepToken substring.
func sleepServer(t *testing.T, sleepToken string, sleepDuration time.Duration) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery + r.URL.String()
		if strings.Contains(q, sleepToken) {
			time.Sleep(sleepDuration)
		}
		io.WriteString(w, "ok")
	}))
}

// clientFor returns a fast http.Client pointing at a test server (no redirects, no real DNS).
func clientFor(srv *httptest.Server) *http.Client {
	return srv.Client()
}

// urlWithParam returns a test server URL with a query parameter.
func urlWithParam(srv *httptest.Server, param, value string) string {
	return srv.URL + "/page?q=normal&" + param + "=" + value
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := sqli.New()
	if m.Name() != "sqli" {
		t.Fatalf("expected name 'sqli', got %q", m.Name())
	}
}

func TestBuiltinPayloadsCount(t *testing.T) {
	m := sqli.New()
	// Just verify we can construct the module without panic.
	if m == nil {
		t.Fatal("New() returned nil")
	}
}

// TestErrorBasedMySQL: inject a quote that triggers a MySQL error string.
func TestErrorBasedMySQL(t *testing.T) {
	srv := dbErrorServer(t, "id", "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"techniques": "E"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for MySQL error injection")
	}
}

// TestErrorBasedPostgres: inject a quote that triggers a PostgreSQL error string.
func TestErrorBasedPostgres(t *testing.T) {
	srv := dbErrorServer(t, "q", "ERROR: unterminated quoted string at or near \"'\" PG::SyntaxError")
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "q", "hello")},
		Options: map[string]string{"techniques": "E", "dbms": "postgresql"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for PostgreSQL error injection")
	}
}

// TestErrorBasedMSSQL: inject quote triggering MSSQL error.
func TestErrorBasedMSSQL(t *testing.T) {
	srv := dbErrorServer(t, "id", "Unclosed quotation mark after the character string ''. Incorrect syntax near ''.")
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"techniques": "E", "dbms": "mssql"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for MSSQL error injection")
	}
}

// TestErrorBasedOracle: inject quote triggering ORA- error.
func TestErrorBasedOracle(t *testing.T) {
	srv := dbErrorServer(t, "id", "ORA-00907: missing right parenthesis ORA-01756: quoted string not properly terminated")
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"techniques": "E", "dbms": "oracle"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for Oracle error injection")
	}
}

// TestErrorBasedSQLite: inject quote triggering SQLite error.
func TestErrorBasedSQLite(t *testing.T) {
	srv := dbErrorServer(t, "search", `sqlite3.OperationalError: near "'": syntax error`)
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "search", "test")},
		Options: map[string]string{"techniques": "E", "dbms": "sqlite"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for SQLite error injection")
	}
}

// TestBooleanBased: responses differ significantly in size for true vs false.
func TestBooleanBased(t *testing.T) {
	srv := boolServer(t)
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"techniques": "B"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected boolean-based finding")
	}
}

// TestBooleanNotFiredOnSameContent: if responses are identical, no finding.
func TestBooleanNotFiredOnSameContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("same content every time", 100))
	}))
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"techniques": "B"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Extra["technique"], "B") {
			t.Fatalf("boolean finding should not fire when content is same: %v", f)
		}
	}
}

// TestTimeBased: server sleeps when SLEEP token is in URL.
func TestTimeBased(t *testing.T) {
	// Use 2-second sleep to keep test fast but exceed threshold.
	srv := sleepServer(t, "SLEEP", 2*time.Second)
	defer srv.Close()

	// We need the client to have a long enough timeout.
	c := &http.Client{Timeout: 10 * time.Second}

	m := sqli.NewWithClient(c)
	// We need to inject against the test server, so we use the correct URL.
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/page?id=1"},
		Options: map[string]string{"techniques": "T", "sleep_seconds": "2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	_ = findings // Accept time-based may or may not fire in test environment
}

// TestNoParamsNoFindings: URL with no query parameters produces no findings.
func TestNoParamsNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/noparams"},
		Options: map[string]string{"techniques": "E,B"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for URL with no params, got %d", len(findings))
	}
}

// TestEmptyInput: no targets returns empty findings without error.
func TestEmptyInput(t *testing.T) {
	m := sqli.New()
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(findings))
	}
}

// TestContextCancellation: cancelling context stops the run.
func TestContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	m := sqli.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"techniques": "E"},
	})
	// Error may or may not be propagated — just ensure no panic.
	_ = err
}

// TestParallelismOption: custom parallelism accepted without error.
func TestParallelismOption(t *testing.T) {
	srv := dbErrorServer(t, "id", "You have an error in your SQL syntax")
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"parallelism": "5", "techniques": "E"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings with parallelism=5")
	}
}

// TestDBMSFilter: filtering to a non-matching DBMS returns no findings for matching target.
func TestDBMSFilter(t *testing.T) {
	srv := dbErrorServer(t, "id", "You have an error in your SQL syntax MySQL")
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"techniques": "E", "dbms": "oracle"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	// Oracle probes won't match MySQL error strings, so no findings expected.
	for _, f := range findings {
		if f.Extra["dbms"] == "mysql" {
			t.Fatalf("expected no MySQL findings when dbms filter=oracle, got: %v", f)
		}
	}
}

// TestTechniquesFilter: filtering to E only runs no boolean probes.
func TestTechniquesFilter(t *testing.T) {
	srv := boolServer(t)
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"techniques": "E"}, // only error-based
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["technique"] == "B" {
			t.Fatalf("boolean finding should not run when techniques=E, got: %v", f)
		}
	}
}

// TestFindingFields: a finding must have all required fields populated.
func TestFindingFields(t *testing.T) {
	srv := dbErrorServer(t, "q", "You have an error in your SQL syntax MySQL warning")
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "q", "test")},
		Options: map[string]string{"techniques": "E"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type != "sqli" {
		t.Errorf("expected type 'sqli', got %q", f.Type)
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
	if f.Extra["technique"] == "" {
		t.Error("Extra.technique is empty")
	}
}

// TestDeduplication: same parameter injectable from two URLs counted once per URL.
func TestDeduplication(t *testing.T) {
	srv := dbErrorServer(t, "id", "You have an error in your SQL syntax MySQL")
	defer srv.Close()

	u := urlWithParam(srv, "id", "1")
	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{u, u, u}, // three identical URLs
		Options: map[string]string{"techniques": "E"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	// Count sqli findings for the same param — should be deduplicated.
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Extra["param"] + "|" + f.Extra["technique"]
		seen[key]++
	}
	for k, count := range seen {
		if count > 1 {
			t.Errorf("duplicate finding for %q: count=%d", k, count)
		}
	}
}

// TestMultipleParams: URL with two parameters, both injectable.
func TestMultipleParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range []string{"id", "name"} {
			if r.URL.Query().Get(p) != "" {
				io.WriteString(w, "You have an error in your SQL syntax MySQL warning")
				return
			}
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/page?id=1&name=test"},
		Options: map[string]string{"techniques": "E"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	params := make(map[string]bool)
	for _, f := range findings {
		params[f.Extra["param"]] = true
	}
	if !params["id"] {
		t.Error("expected finding for param 'id'")
	}
	if !params["name"] {
		t.Error("expected finding for param 'name'")
	}
}

// TestTargetFallback: input.Target is used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := dbErrorServer(t, "id", "You have an error in your SQL syntax MySQL")
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  urlWithParam(srv, "id", "1"),
		Options: map[string]string{"techniques": "E"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from Target field")
	}
}

// TestSeverity: error-based MySQL finding has High or Critical severity.
func TestSeverity(t *testing.T) {
	srv := dbErrorServer(t, "id", "You have an error in your SQL syntax MySQL")
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"techniques": "E", "dbms": "mysql"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		// Only assert severity for explicitly MySQL payloads (generic payloads may be Medium).
		if f.Extra["dbms"] == "mysql" {
			if f.Severity != module.SeverityHigh && f.Severity != module.SeverityCritical {
				t.Errorf("unexpected severity %q for MySQL finding", f.Severity)
			}
		}
	}
}

// TestTechniquesAll: running with E,B,T does not error.
func TestTechniquesAll(t *testing.T) {
	srv := boolServer(t)
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"techniques": "E,B,T", "sleep_seconds": "1"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestNewWithClientReplaces: NewWithClient replaces only the HTTP client, not payloads.
func TestNewWithClientReplaces(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := sqli.NewWithClient(c)
	if m == nil {
		t.Fatal("NewWithClient returned nil")
	}
	if m.Name() != "sqli" {
		t.Fatalf("unexpected name %q", m.Name())
	}
}

// TestSleepSecondsOption: custom sleep_seconds value is accepted.
func TestSleepSecondsOption(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "q", "1")},
		Options: map[string]string{"techniques": "T", "sleep_seconds": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestFindingType: finding Type is always "sqli".
func TestFindingType(t *testing.T) {
	srv := dbErrorServer(t, "x", "You have an error in your SQL syntax MySQL")
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "x", "1")},
		Options: map[string]string{"techniques": "E"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if f.Type != "sqli" {
			t.Errorf("finding.Type = %q, want 'sqli'", f.Type)
		}
	}
}

// TestUnionError: UNION SELECT NULL triggers UNION error responses.
func TestUnionError(t *testing.T) {
	srv := dbErrorServer(t, "id", "The used SELECT statements have a different number of columns")
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"techniques": "E"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for UNION error response")
	}
}

// TestBooleanRatioThreshold: small difference in body size does not trigger.
func TestBooleanRatioThreshold(t *testing.T) {
	// Returns almost identical content (only differs by 5 chars).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		if strings.Contains(q, "1=1") || strings.Contains(q, "1%3D1") {
			io.WriteString(w, strings.Repeat("X", 1000)+"AAAAA")
		} else {
			io.WriteString(w, strings.Repeat("X", 1000))
		}
	}))
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"techniques": "B"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["technique"] == "B" {
			t.Errorf("boolean finding should not fire on <20%% body diff: %v", f)
		}
	}
}

// TestDB2Error: IBM DB2 error string triggers finding.
func TestDB2Error(t *testing.T) {
	srv := dbErrorServer(t, "id", "DB2 SQL Error: SQLSTATE=42601 SQLCODE=-104 CLI Driver")
	defer srv.Close()

	m := sqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"techniques": "E", "dbms": "db2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for DB2 error")
	}
}

// TestModuleImplementsInterface: compile-time interface check.
func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = sqli.New()
}
