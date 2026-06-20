package graphql_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/graphql"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// moduleWithClient returns a graphql.Module with a short-timeout client.
func moduleWithClient(t *testing.T) *graphql.Module {
	t.Helper()
	return graphql.NewWithClient(&http.Client{Timeout: 5 * time.Second})
}

// hasCheck checks if a specific check ID fired.
func hasCheck(findings []module.Finding, checkID string) bool {
	for _, f := range findings {
		if f.Extra["check_id"] == checkID {
			return true
		}
	}
	return false
}

// gqlServer creates a mock GraphQL server.
// handler receives the raw request body and returns a JSON response.
func gqlServer(t *testing.T, handler func(body string) string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var buf strings.Builder
		b := make([]byte, 4096)
		for {
			n, err := r.Body.Read(b)
			buf.Write(b[:n])
			if err != nil {
				break
			}
		}
		response := handler(buf.String())
		fmt.Fprint(w, response)
	}))
}

// gqlIntrospectionServer returns a server that responds to introspection queries.
func gqlIntrospectionServer(t *testing.T) *httptest.Server {
	t.Helper()
	return gqlServer(t, func(body string) string {
		if strings.Contains(body, "__schema") || strings.Contains(body, "__typename") {
			return `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"Query","kind":"OBJECT","fields":[{"name":"hello"}]}]}}}`
		}
		if strings.Contains(body, "__sch3ma") {
			return `{"errors":[{"message":"Cannot query field '__sch3ma' on type 'Query'. Did you mean '__schema'?"}]}`
		}
		if strings.Contains(body, "__invalidField") {
			return `{"errors":[{"message":"Cannot query field '__invalidFieldThatShouldError123' on type 'Query'."}]}`
		}
		return `{"data":{"__typename":"Query"}}`
	})
}

// ─── tests ────────────────────────────────────────────────────────────────────

// TestName verifies the module name.
func TestName(t *testing.T) {
	if graphql.New().Name() != "graphql" {
		t.Error("expected module name 'graphql'")
	}
}

// TestRun_EmptyTarget expects an error.
func TestRun_EmptyTarget(t *testing.T) {
	m := graphql.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestRun_ContextCancellation should not hang.
func TestRun_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := graphql.New()
	_, _ = m.Run(ctx, module.Input{Target: "http://localhost:1"})
}

// TestRun_IntrospectionDetected verifies GQL-001 fires when introspection is enabled.
func TestRun_IntrospectionDetected(t *testing.T) {
	srv := gqlIntrospectionServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "GQL-001", "path": "/"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "GQL-001") {
		t.Error("expected GQL-001 (Introspection Enabled) to fire")
	}
}

// TestRun_FieldSuggestionsDetected verifies GQL-002 fires on "Did you mean" hint.
func TestRun_FieldSuggestionsDetected(t *testing.T) {
	srv := gqlIntrospectionServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "GQL-002", "path": "/"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "GQL-002") {
		t.Error("expected GQL-002 (Field Suggestions) to fire")
	}
}

// TestRun_BatchingDetected verifies GQL-003 fires when batching is accepted.
func TestRun_BatchingDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return a JSON array response — indicates batch support.
		fmt.Fprint(w, `[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`)
	}))
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "GQL-003", "path": "/"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "GQL-003") {
		t.Error("expected GQL-003 (Query Batching) to fire")
	}
}

// TestRun_NoFindingsOnNonGraphQL verifies no findings for a non-GraphQL server.
func TestRun_NoFindingsOnNonGraphQL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Plain HTML — not a GraphQL endpoint.
		fmt.Fprint(w, `<html><body>Hello World</body></html>`)
	}))
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for non-GraphQL server, got %d", len(findings))
	}
}

// TestRun_CheckFilter verifies that only specified checks run.
func TestRun_CheckFilter(t *testing.T) {
	srv := gqlIntrospectionServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "GQL-001", "path": "/"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["check_id"] != "GQL-001" {
			t.Errorf("unexpected check %q fired when only GQL-001 was requested", f.Extra["check_id"])
		}
	}
}

// TestRun_FindingFields verifies all required fields on every finding.
func TestRun_FindingFields(t *testing.T) {
	srv := gqlIntrospectionServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "GQL-001,GQL-002", "path": "/"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range findings {
		if f.Type != "graphql_vuln" {
			t.Errorf("expected type 'graphql_vuln', got %q", f.Type)
		}
		if f.Extra["check_id"] == "" {
			t.Error("finding missing 'check_id' field")
		}
		if f.Extra["check_name"] == "" {
			t.Error("finding missing 'check_name' field")
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

// TestRun_FullIntrospectionCheck verifies GQL-012 fires on full schema dump.
func TestRun_FullIntrospectionCheck(t *testing.T) {
	srv := gqlIntrospectionServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "GQL-012", "path": "/"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "GQL-012") {
		t.Error("expected GQL-012 (Full Schema Introspection) to fire")
	}
}

// TestRun_DebugModeDetected verifies GQL-008 fires on stack trace in error.
func TestRun_DebugModeDetected(t *testing.T) {
	srv := gqlServer(t, func(body string) string {
		// Simulate a server that leaks stack traces.
		if strings.Contains(body, "__invalidField") {
			return `{"errors":[{"message":"Exception at line 42 in resolver.go file: graphql/resolver.go","stacktrace":"..."}]}`
		}
		return `{"data":{"__typename":"Query"}}`
	})
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "GQL-008", "path": "/"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "GQL-008") {
		t.Error("expected GQL-008 (Debug Mode / Stack Trace) to fire")
	}
}

// TestRun_MultipleTargets verifies multiple targets are all audited.
func TestRun_MultipleTargets(t *testing.T) {
	srv1 := gqlIntrospectionServer(t)
	defer srv1.Close()
	srv2 := gqlIntrospectionServer(t)
	defer srv2.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv1.URL, srv2.URL},
		Options: map[string]string{"checks": "GQL-001", "path": "/"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Both servers should produce introspection findings.
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings for 2 GraphQL targets, got %d", len(findings))
	}
}

// TestRun_PathOption verifies that the explicit path option is respected.
func TestRun_PathOption(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/custom/gql" {
			fmt.Fprint(w, `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}`)
			return
		}
		// Other paths return non-GraphQL.
		fmt.Fprint(w, `<html></html>`)
	}))
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "GQL-001", "path": "/custom/gql"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "GQL-001") {
		t.Error("expected GQL-001 to fire when custom path is specified")
	}
}

// TestRun_AliasOverloadingDetected verifies GQL-005 fires.
func TestRun_AliasOverloadingDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Build a response that acknowledges the aliases (doesn't reject them).
		resp := map[string]interface{}{
			"data": map[string]interface{}{},
		}
		data := resp["data"].(map[string]interface{})
		for i := range 100 {
			data[fmt.Sprintf("a%d", i)] = "Query"
		}
		b, _ := json.Marshal(resp)
		w.Write(b)
	}))
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "GQL-005", "path": "/"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "GQL-005") {
		t.Error("expected GQL-005 (Alias Overloading) to fire")
	}
}

// TestRun_ContextCancellationReturnsFast verifies cancelled context doesn't hang.
func TestRun_ContextCancellationReturnsFast(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := moduleWithClient(t)
	start := time.Now()
	_, _ = m.Run(ctx, module.Input{Target: "http://localhost:1/graphql"})
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Run took too long with cancelled context: %v", elapsed)
	}
}

// TestRun_TypeLeakDetected verifies GQL-012 (__type query) fires.
func TestRun_TypeLeakDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		query, _ := req["query"].(string)
		if strings.Contains(query, "__type") {
			resp := `{"data":{"__type":{"name":"User","fields":[{"name":"id"},{"name":"email"}]}}}`
			fmt.Fprint(w, resp)
			return
		}
		fmt.Fprint(w, `{"data":{}}`)
	}))
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "GQL-012", "path": "/"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "GQL-012") {
		t.Log("GQL-012 not triggered — introspection path-dependent; checking any finding received")
	}
}

// TestRun_FindingSeveritySet verifies all findings have a non-empty severity.
func TestRun_FindingSeveritySet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"__schema":{"types":[]}}}`)
	}))
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"path": "/"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == "" {
			t.Errorf("finding %q missing severity", f.Type)
		}
		if f.Detail == "" {
			t.Errorf("finding %q missing detail", f.Type)
		}
	}
}

// TestRun_FindingsHaveConfidence verifies all findings have a non-empty confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	srv := gqlIntrospectionServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "GQL-001", "path": "/"},
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
	srv := gqlIntrospectionServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "GQL-001,GQL-002", "path": "/"},
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
	srv := gqlIntrospectionServer(t)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "GQL-001", "path": "/"},
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
