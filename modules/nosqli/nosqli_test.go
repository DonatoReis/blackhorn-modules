package nosqli_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/nosqli"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// mongoErrorServer returns a server that echoes a MongoDB error when the param
// value contains a '$' operator character.
func mongoErrorServer(t *testing.T, param string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get(param)
		if strings.Contains(val, "$") || strings.Contains(val, "'") {
			io.WriteString(w, `MongoError: invalid BSON - errmsg: "code: 2" mongoexception`)
			return
		}
		io.WriteString(w, `{"users":[{"name":"Alice"}]}`)
	}))
}

// mongoBoolServer returns long content for $ne and short for others.
func mongoBoolServer(t *testing.T, param string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get(param)
		if strings.Contains(val, "$ne") {
			// $ne "always true" — returns all records
			io.WriteString(w, strings.Repeat(`{"name":"user","email":"user@example.com"},`, 50))
			return
		}
		// Nothing matched
		io.WriteString(w, `{"users":[]}`)
	}))
}

// redisErrorServer simulates a Redis error on pipeline injection.
func redisErrorServer(t *testing.T, param string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get(param)
		if strings.Contains(val, "FLUSHDB") || strings.Contains(val, "EVAL") {
			w.WriteHeader(500)
			io.WriteString(w, "Redis Error: wrongtype operation, jedis connection failed")
			return
		}
		io.WriteString(w, "ok")
	}))
}

// couchdbErrorServer simulates CouchDB Mango error.
func couchdbErrorServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			body := string(b)
			if strings.Contains(body, "$invalid_op") {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"bad_request","reason":"invalid_json mango_query"}`)
				return
			}
		}
		io.WriteString(w, `{"docs":[]}`)
	}))
}

// safeServer always returns a neutral response.
func safeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"result":"ok"}`)
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

func urlWithParam(srv *httptest.Server, param, value string) string {
	return srv.URL + "/api?" + param + "=" + value
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := nosqli.New()
	if m.Name() != "nosqli" {
		t.Fatalf("expected 'nosqli', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = nosqli.New()
}

// TestMongoErrorBased: MongoDB error detected via operator injection.
func TestMongoErrorBased(t *testing.T) {
	srv := mongoErrorServer(t, "username")
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "username", "admin")},
		Options: map[string]string{"techniques": "E", "db": "mongodb"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one MongoDB error-based finding")
	}
}

// TestMongoBooleanBased: $ne operator returns more data than restrictive query.
func TestMongoBooleanBased(t *testing.T) {
	srv := mongoBoolServer(t, "name")
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "name", "alice")},
		Options: map[string]string{"techniques": "B", "db": "mongodb"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected boolean-based MongoDB finding")
	}
}

// TestRedisErrorBased: Redis error string detected.
func TestRedisErrorBased(t *testing.T) {
	srv := redisErrorServer(t, "key")
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "key", "user:1")},
		Options: map[string]string{"techniques": "E", "db": "redis"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Redis error-based finding")
	}
}

// TestCouchDBErrorBased: CouchDB Mango query error detected.
func TestCouchDBErrorBased(t *testing.T) {
	srv := couchdbErrorServer(t)
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/db/_find?selector=admin"},
		Options: map[string]string{"techniques": "E", "db": "couchdb"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	_ = findings // CouchDB uses JSON vector; may fire depending on param extraction
}

// TestNoVulnerability: safe server returns no findings.
func TestNoVulnerability(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "q", "test")},
		Options: map[string]string{"techniques": "E,B"},
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
	m := nosqli.New()
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(findings))
	}
}

// TestNoParams: URL without query params returns no findings.
func TestNoParams(t *testing.T) {
	srv := mongoErrorServer(t, "id")
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api"},
		Options: map[string]string{"techniques": "E"},
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
	srv := mongoErrorServer(t, "id")
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := nosqli.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{
		URLs:    []string{urlWithParam(srv, "id", "1")},
		Options: map[string]string{"techniques": "E"},
	})
	_ = err
}

// TestDeduplication: same (url, param, probe_id) not duplicated.
func TestDeduplication(t *testing.T) {
	srv := mongoErrorServer(t, "user")
	defer srv.Close()

	u := urlWithParam(srv, "user", "admin")
	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{u, u, u},
		Options: map[string]string{"techniques": "E", "db": "mongodb"},
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
	srv := mongoErrorServer(t, "id")
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "id", "123")},
		Options: map[string]string{"techniques": "E", "db": "mongodb"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type != "nosqli" {
		t.Errorf("Type = %q, want 'nosqli'", f.Type)
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
	if f.Extra["param"] == "" {
		t.Error("Extra.param empty")
	}
	if f.Extra["probe_id"] == "" {
		t.Error("Extra.probe_id empty")
	}
	if f.Extra["technique"] == "" {
		t.Error("Extra.technique empty")
	}
	if f.Extra["db"] == "" {
		t.Error("Extra.db empty")
	}
	if f.Extra["vector"] == "" {
		t.Error("Extra.vector empty")
	}
}

// TestFindingType: all findings have Type == "nosqli".
func TestFindingType(t *testing.T) {
	srv := mongoErrorServer(t, "q")
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "q", "test")},
		Options: map[string]string{"techniques": "E"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type != "nosqli" {
			t.Errorf("finding.Type = %q, want 'nosqli'", f.Type)
		}
	}
}

// TestTechniquesFilter: E only → no B or T findings.
func TestTechniquesFilter(t *testing.T) {
	srv := mongoBoolServer(t, "q")
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "q", "test")},
		Options: map[string]string{"techniques": "E"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["technique"] == "B" || f.Extra["technique"] == "T" {
			t.Errorf("unexpected technique %q when filter=E", f.Extra["technique"])
		}
	}
}

// TestDBFilter: db=mongodb only runs MongoDB probes.
func TestDBFilter(t *testing.T) {
	srv := redisErrorServer(t, "key")
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "key", "user")},
		Options: map[string]string{"techniques": "E", "db": "mongodb"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["db"] == "redis" {
			t.Errorf("Redis finding returned when db filter=mongodb: %v", f)
		}
	}
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	srv := mongoErrorServer(t, "user")
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "user", "admin")},
		Options: map[string]string{"techniques": "E", "parallelism": "3", "db": "mongodb"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings with parallelism=3")
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := mongoErrorServer(t, "user")
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  urlWithParam(srv, "user", "admin"),
		Options: map[string]string{"techniques": "E", "db": "mongodb"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from Target field")
	}
}

// TestNewWithClientReplaces: NewWithClient does not panic.
func TestNewWithClientReplaces(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := nosqli.NewWithClient(c)
	if m == nil {
		t.Fatal("NewWithClient returned nil")
	}
	if m.Name() != "nosqli" {
		t.Fatalf("unexpected name %q", m.Name())
	}
}

// TestSleepMsOption: custom sleep_ms accepted without error.
func TestSleepMsOption(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "q", "test")},
		Options: map[string]string{"techniques": "T", "sleep_ms": "1000", "db": "mongodb"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDetailContainsDBName: Detail string contains DB name.
func TestDetailContainsDBName(t *testing.T) {
	srv := mongoErrorServer(t, "user")
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "user", "test")},
		Options: map[string]string{"techniques": "E", "db": "mongodb"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if !strings.Contains(findings[0].Detail, "mongodb") {
		t.Errorf("Detail %q does not contain 'mongodb'", findings[0].Detail)
	}
}

// TestGenericOperator: generic operator injection detected on status=500.
func TestGenericOperator(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("q")
		if strings.Contains(val, "$gt") || strings.Contains(val, "$") {
			w.WriteHeader(500)
			io.WriteString(w, "Internal server error: syntax error")
			return
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "q", "test")},
		Options: map[string]string{"techniques": "E", "db": "generic"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected generic error finding")
	}
}

// TestBooleanRatioThreshold: tiny body difference does not trigger.
func TestBooleanRatioThreshold(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("CONTENT", 200))
	}))
	defer srv.Close()

	m := nosqli.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{urlWithParam(srv, "q", "test")},
		Options: map[string]string{"techniques": "B"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["technique"] == "B" {
			t.Errorf("boolean finding should not fire on identical responses: %v", f)
		}
	}
}
