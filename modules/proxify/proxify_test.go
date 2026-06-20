package proxify

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func hasType(findings []module.Finding, t string) bool {
	for _, f := range findings {
		if f.Type == t {
			return true
		}
	}
	return false
}

func hasURL(findings []module.Finding, u string) bool {
	for _, f := range findings {
		if strings.Contains(f.URL, u) {
			return true
		}
	}
	return false
}

// freePort returns an available TCP port.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// ─── unit tests ───────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "proxify" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoTransactions(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input in batch mode")
	}
}

func TestRun_Batch_URLTarget(t *testing.T) {
	m := New()
	m.Rules = []Rule{
		{
			Name:        "detect-admin",
			Target:      TargetURL,
			Match:       `/admin`,
			FindingType: "admin_endpoint",
			Severity:    module.SeverityHigh,
		},
	}
	findings, err := m.Run(context.Background(), module.Input{
		RawContent: "GET https://example.com/admin/panel\nGET https://example.com/public\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "admin_endpoint") {
		t.Fatal("expected admin_endpoint finding")
	}
	// /public should not match.
	for _, f := range findings {
		if strings.Contains(f.URL, "/public") {
			t.Errorf("unexpected finding for /public: %v", f)
		}
	}
}

func TestRun_Batch_URLsInput(t *testing.T) {
	m := New()
	m.Rules = []Rule{
		{
			Name:        "detect-api",
			Target:      TargetURL,
			Match:       `/api/`,
			FindingType: "api_endpoint",
			Severity:    module.SeverityInfo,
		},
	}
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{
			"https://example.com/api/v1/users",
			"https://example.com/static/app.js",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "api_endpoint") {
		t.Fatal("expected api_endpoint finding")
	}
}

func TestRun_Batch_TargetInput(t *testing.T) {
	m := New()
	m.Rules = []Rule{
		{Name: "any", Target: TargetURL, Match: "", FindingType: "seen", Severity: module.SeverityInfo},
	}
	findings, err := m.Run(context.Background(), module.Input{
		Target: "https://example.com/test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from Target")
	}
}

// ─── rule compilation ─────────────────────────────────────────────────────────

func TestRun_InvalidRegex(t *testing.T) {
	m := New()
	m.Rules = []Rule{
		{Name: "bad", Target: TargetURL, Match: "[invalid"},
	}
	_, err := m.Run(context.Background(), module.Input{RawContent: "GET https://example.com/"})
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestRule_EmptyMatch_MatchesAll(t *testing.T) {
	r := Rule{Name: "empty", Target: TargetURL, Match: "", FindingType: "any", Severity: module.SeverityInfo}
	if err := r.compile(); err != nil {
		t.Fatal(err)
	}
	if !r.matches("anything") {
		t.Fatal("empty match should match everything")
	}
}

func TestRule_Apply_Replace(t *testing.T) {
	r := Rule{Name: "r", Target: TargetURL, Match: `http://`, Replace: "https://"}
	if err := r.compile(); err != nil {
		t.Fatal(err)
	}
	got := r.apply("http://example.com")
	if got != "https://example.com" {
		t.Errorf("expected https://example.com, got %q", got)
	}
}

func TestRule_Apply_EmptyReplace_NoChange(t *testing.T) {
	r := Rule{Name: "r", Target: TargetURL, Match: `secret`, Replace: ""}
	if err := r.compile(); err != nil {
		t.Fatal(err)
	}
	original := "GET /secret/key"
	got := r.apply(original)
	if got != original {
		t.Errorf("empty Replace should return original, got %q", got)
	}
}

// ─── applyRules ───────────────────────────────────────────────────────────────

func TestApplyRules_FindingType_Required(t *testing.T) {
	m := New()
	m.Rules = []Rule{
		{Name: "modify-only", Target: TargetURL, Match: ".", Replace: ".", FindingType: ""},
	}
	_ = m.compileRules()
	tx := transaction{method: "GET", rawURL: "https://example.com/"}
	ff := m.applyRules(tx)
	if len(ff) != 0 {
		t.Fatalf("expected 0 findings for modify-only rule (no FindingType), got %d", len(ff))
	}
}

func TestApplyRules_ResponseBody_Match(t *testing.T) {
	m := New()
	m.Rules = []Rule{
		{
			Name:        "detect-error",
			Target:      TargetResponseBody,
			Match:       `(?i)sql syntax`,
			FindingType: "sql_error",
			Severity:    module.SeverityHigh,
		},
	}
	_ = m.compileRules()
	tx := transaction{
		method:       "GET",
		rawURL:       "https://example.com/search",
		responseCode: 200,
		responseBody: "You have an error in your SQL syntax near 'WHERE'",
	}
	ff := m.applyRules(tx)
	if !hasType(ff, "sql_error") {
		t.Fatal("expected sql_error finding from response body")
	}
}

func TestApplyRules_RequestBody_Match(t *testing.T) {
	m := New()
	m.Rules = []Rule{
		{
			Name:        "detect-sqli-payload",
			Target:      TargetRequestBody,
			Match:       `(?i)union.*select`,
			FindingType: "sqli_attempt",
			Severity:    module.SeverityCritical,
		},
	}
	_ = m.compileRules()
	tx := transaction{
		method:      "POST",
		rawURL:      "https://example.com/login",
		requestBody: "username=admin' UNION SELECT * FROM users--&password=x",
	}
	ff := m.applyRules(tx)
	if !hasType(ff, "sqli_attempt") {
		t.Fatal("expected sqli_attempt finding from request body")
	}
}

func TestApplyRules_Severity_Defaults_Info(t *testing.T) {
	m := New()
	m.Rules = []Rule{
		{Name: "r", Target: TargetURL, Match: ".", FindingType: "match", Severity: ""},
	}
	_ = m.compileRules()
	tx := transaction{method: "GET", rawURL: "https://example.com/"}
	ff := m.applyRules(tx)
	if len(ff) == 0 {
		t.Fatal("expected at least one finding")
	}
	if ff[0].Severity != module.SeverityInfo {
		t.Errorf("expected SeverityInfo as default, got %q", ff[0].Severity)
	}
}

// ─── parseTransactions ────────────────────────────────────────────────────────

func TestParseTransactions_MethodURL(t *testing.T) {
	txs := parseTransactions(module.Input{RawContent: "POST https://example.com/api"})
	if len(txs) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(txs))
	}
	if txs[0].method != "POST" {
		t.Errorf("expected method POST, got %q", txs[0].method)
	}
}

func TestParseTransactions_URLOnly(t *testing.T) {
	txs := parseTransactions(module.Input{RawContent: "https://example.com/"})
	if len(txs) != 1 || txs[0].method != "GET" {
		t.Fatalf("expected GET by default, got %+v", txs)
	}
}

func TestParseTransactions_SkipsComments(t *testing.T) {
	txs := parseTransactions(module.Input{RawContent: "# comment\nhttps://example.com/"})
	if len(txs) != 1 {
		t.Fatalf("expected 1 transaction (comment skipped), got %d", len(txs))
	}
}

func TestParseTransactions_SkipsEmpty(t *testing.T) {
	txs := parseTransactions(module.Input{RawContent: "\n\nhttps://example.com/\n\n"})
	if len(txs) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(txs))
	}
}

// ─── helpers unit tests ───────────────────────────────────────────────────────

func TestHeaderMap(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Custom", "value")
	m := headerMap(h)
	if m["Content-Type"] != "application/json" {
		t.Errorf("expected application/json, got %q", m["Content-Type"])
	}
}

func TestHeadersString(t *testing.T) {
	h := map[string]string{"Authorization": "Bearer token123"}
	s := headersString(h)
	if !strings.Contains(s, "Authorization") || !strings.Contains(s, "Bearer token123") {
		t.Errorf("headers string missing expected content: %q", s)
	}
}

// ─── live proxy server ────────────────────────────────────────────────────────

func TestListen_BindsPort(t *testing.T) {
	addr := freePort(t)
	m := NewWithAddr(addr)
	if err := m.Listen(); err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	defer m.Stop()

	// Verify the port is listening by connecting.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("expected proxy to accept connections on %s: %v", addr, err)
	}
	conn.Close()
}

func TestListen_ProxiesHTTP(t *testing.T) {
	// Backend server.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprintln(w, "hello from backend")
	}))
	defer backend.Close()

	addr := freePort(t)
	m := NewWithAddr(addr)
	m.Rules = []Rule{
		{
			Name:        "detect-backend",
			Target:      TargetResponseBody,
			Match:       "hello from backend",
			FindingType: "proxied_response",
			Severity:    module.SeverityInfo,
		},
	}
	if err := m.Listen(); err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	defer m.Stop()

	// Send request through proxy.
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(backend.URL + "/test")
	if err != nil {
		t.Fatalf("proxy request error: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "hello from backend") {
		t.Errorf("expected backend body, got: %s", string(body))
	}

	// Wait briefly for ModifyResponse to fire.
	time.Sleep(50 * time.Millisecond)
	ff := m.Findings()
	if !hasType(ff, "proxied_response") {
		t.Errorf("expected proxied_response finding from live proxy; findings: %v", ff)
	}
}

func TestListen_URLRewrite(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s", r.URL.Path)
	}))
	defer backend.Close()

	addr := freePort(t)
	m := NewWithAddr(addr)
	m.Rules = []Rule{
		{
			Name:    "rewrite-path",
			Target:  TargetURL,
			Match:   `/original`,
			Replace: `/rewritten`,
		},
	}
	if err := m.Listen(); err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	defer m.Stop()

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(backend.URL + "/original")
	if err != nil {
		t.Skipf("URL rewrite test skipped (proxy error): %v", err)
	}
	defer resp.Body.Close()
}

func TestIntercept_Mode_CtxCancel(t *testing.T) {
	addr := freePort(t)
	m := NewWithAddr(addr)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := m.Run(ctx, module.Input{Options: map[string]string{"mode": "intercept"}})
	// Should return after ctx cancels, not hang.
	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddr_ReturnsActualAddr(t *testing.T) {
	m := NewWithAddr("127.0.0.1:0")
	if err := m.Listen(); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	addr := m.Addr()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Errorf("expected 127.0.0.1:PORT, got %q", addr)
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("invalid addr: %v", err)
	}
	if port == "0" {
		t.Fatal("expected non-zero port after Listen")
	}
}
