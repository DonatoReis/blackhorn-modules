package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// captureServer returns a TLS test server that captures the last received body.
func captureServer(t *testing.T) (*httptest.Server, func() string) {
	t.Helper()
	var (
		mu       sync.RWMutex
		lastBody string
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		lastBody = string(b)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	return srv, func() string {
		mu.RLock()
		defer mu.RUnlock()
		return lastBody
	}
}

// failServer returns a TLS test server that always responds with HTTP 500.
func failServer() *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
}

func singleProvider(kind, webhookURL string, client *http.Client) *Module {
	return NewWithClient(client, []Provider{{Kind: kind, WebhookURL: webhookURL}})
}

// ─── basic ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New(nil).Name() != "notify" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoProviders(t *testing.T) {
	m := New(nil)
	findings, err := m.Run(context.Background(), module.Input{RawContent: "hello"})
	if err != nil {
		t.Fatalf("optional notifier without providers should skip: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestRun_NoMessages(t *testing.T) {
	srv, _ := captureServer(t)
	defer srv.Close()
	m := singleProvider("slack", srv.URL, srv.Client())
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("notifier without messages should skip: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

// ─── Slack ───────────────────────────────────────────────────────────────────

func TestDispatchSlack_RawContent(t *testing.T) {
	srv, getBody := captureServer(t)
	defer srv.Close()
	m := singleProvider("slack", srv.URL, srv.Client())

	findings, err := m.Run(context.Background(), module.Input{RawContent: "alert: XSS found"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	body := getBody()
	if !strings.Contains(body, "alert: XSS found") {
		t.Errorf("expected message in Slack payload, got: %s", body)
	}
}

func TestDispatchSlack_JSONPayload(t *testing.T) {
	srv, getBody := captureServer(t)
	defer srv.Close()
	m := singleProvider("slack", srv.URL, srv.Client())

	_, err := m.Run(context.Background(), module.Input{RawContent: "test-message"})
	if err != nil {
		t.Fatal(err)
	}
	var p slackPayload
	if err := json.Unmarshal([]byte(getBody()), &p); err != nil {
		t.Fatalf("invalid Slack JSON payload: %v — body: %s", err, getBody())
	}
	if p.Text != "test-message" {
		t.Errorf("expected text=test-message, got %q", p.Text)
	}
}

func TestDispatchSlack_FindingType(t *testing.T) {
	srv, _ := captureServer(t)
	defer srv.Close()
	m := singleProvider("slack", srv.URL, srv.Client())
	findings, err := m.Run(context.Background(), module.Input{RawContent: "msg"})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Type != "notification_sent" {
		t.Errorf("expected type notification_sent, got %q", findings[0].Type)
	}
}

// ─── Discord ──────────────────────────────────────────────────────────────────

func TestDispatchDiscord_JSONPayload(t *testing.T) {
	srv, getBody := captureServer(t)
	defer srv.Close()
	m := singleProvider("discord", srv.URL, srv.Client())

	_, err := m.Run(context.Background(), module.Input{RawContent: "discord-alert"})
	if err != nil {
		t.Fatal(err)
	}
	var p discordPayload
	if err := json.Unmarshal([]byte(getBody()), &p); err != nil {
		t.Fatalf("invalid Discord JSON: %v", err)
	}
	if p.Content != "discord-alert" {
		t.Errorf("expected content=discord-alert, got %q", p.Content)
	}
}

// ─── Teams ────────────────────────────────────────────────────────────────────

func TestDispatchTeams_JSONPayload(t *testing.T) {
	srv, getBody := captureServer(t)
	defer srv.Close()
	m := singleProvider("teams", srv.URL, srv.Client())

	_, err := m.Run(context.Background(), module.Input{RawContent: "teams-message"})
	if err != nil {
		t.Fatal(err)
	}
	var p teamsPayload
	if err := json.Unmarshal([]byte(getBody()), &p); err != nil {
		t.Fatalf("invalid Teams JSON: %v", err)
	}
	if p.Text != "teams-message" {
		t.Errorf("expected text=teams-message, got %q", p.Text)
	}
	if p.Type != "MessageCard" {
		t.Errorf("expected @type=MessageCard, got %q", p.Type)
	}
}

// ─── Generic Webhook ─────────────────────────────────────────────────────────

func TestDispatchWebhook_JSONPayload(t *testing.T) {
	srv, getBody := captureServer(t)
	defer srv.Close()
	m := singleProvider("webhook", srv.URL, srv.Client())

	_, err := m.Run(context.Background(), module.Input{RawContent: "webhook-payload"})
	if err != nil {
		t.Fatal(err)
	}
	var p webhookPayload
	if err := json.Unmarshal([]byte(getBody()), &p); err != nil {
		t.Fatalf("invalid webhook JSON: %v", err)
	}
	if p.Message != "webhook-payload" {
		t.Errorf("expected message=webhook-payload, got %q", p.Message)
	}
}

// ─── Custom template ──────────────────────────────────────────────────────────

func TestDispatchCustom_Template(t *testing.T) {
	srv, getBody := captureServer(t)
	defer srv.Close()

	m := NewWithClient(srv.Client(), []Provider{{
		Kind:       "custom",
		WebhookURL: srv.URL,
		Template:   `{"alert":"{{.Message}}"}`,
	}})

	_, err := m.Run(context.Background(), module.Input{RawContent: "critical-alert"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(getBody(), "critical-alert") {
		t.Errorf("expected critical-alert in custom template body, got: %s", getBody())
	}
}

func TestDispatchCustom_FindingVars(t *testing.T) {
	srv, getBody := captureServer(t)
	defer srv.Close()

	m := NewWithClient(srv.Client(), []Provider{{
		Kind:       "custom",
		WebhookURL: srv.URL,
		Template:   `type={{.Type}} url={{.URL}} sev={{.Severity}}`,
	}})

	f := module.Finding{Type: "sqli", URL: "https://example.com/login", Severity: module.SeverityHigh}
	ff, _ := json.Marshal([]module.Finding{f})
	_, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"findings_json": string(ff)},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := getBody()
	if !strings.Contains(body, "type=sqli") {
		t.Errorf("expected type=sqli in template body, got: %s", body)
	}
	if !strings.Contains(body, "url=https://example.com/login") {
		t.Errorf("expected url in template body, got: %s", body)
	}
}

func TestDispatchCustom_NoTemplate_Error(t *testing.T) {
	srv, _ := captureServer(t)
	defer srv.Close()
	m := NewWithClient(srv.Client(), []Provider{{
		Kind:       "custom",
		WebhookURL: srv.URL,
		Template:   "", // missing
	}})
	// Soft failure — no error returned, but also no successful findings.
	findings, err := m.Run(context.Background(), module.Input{RawContent: "msg"})
	if err != nil {
		t.Fatal("expected soft failure, got hard error:", err)
	}
	// No successful dispatches.
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on custom without template, got %d", len(findings))
	}
}

func TestDispatchCustom_BadTemplate_Error(t *testing.T) {
	srv, _ := captureServer(t)
	defer srv.Close()
	m := NewWithClient(srv.Client(), []Provider{{
		Kind:       "custom",
		WebhookURL: srv.URL,
		Template:   "{{.Unclosed", // invalid template
	}})
	findings, err := m.Run(context.Background(), module.Input{RawContent: "msg"})
	if err != nil {
		t.Fatal("expected soft failure:", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on bad template, got %d", len(findings))
	}
}

// ─── Telegram ────────────────────────────────────────────────────────────────

func TestDispatchTelegram_NoToken_SoftFail(t *testing.T) {
	srv, _ := captureServer(t)
	defer srv.Close()
	m := NewWithClient(srv.Client(), []Provider{{
		Kind:   "telegram",
		ChatID: "123",
		// Token missing
	}})
	findings, err := m.Run(context.Background(), module.Input{RawContent: "msg"})
	if err != nil {
		t.Fatal("expected soft failure")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without token, got %d", len(findings))
	}
}

// ─── error handling ───────────────────────────────────────────────────────────

func TestDispatch_HTTP500_SoftFail(t *testing.T) {
	srv := failServer()
	defer srv.Close()
	m := singleProvider("slack", srv.URL, srv.Client())
	// HTTP 500 is a soft failure — returns no findings but no error.
	findings, err := m.Run(context.Background(), module.Input{RawContent: "msg"})
	if err != nil {
		t.Fatal("expected soft failure, got hard error:", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on HTTP 500, got %d", len(findings))
	}
}

func TestDispatch_UnknownProvider_SoftFail(t *testing.T) {
	srv, _ := captureServer(t)
	defer srv.Close()
	m := singleProvider("sms", srv.URL, srv.Client())
	findings, err := m.Run(context.Background(), module.Input{RawContent: "msg"})
	if err != nil {
		t.Fatal("expected soft failure for unknown provider")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for unknown provider, got %d", len(findings))
	}
}

// ─── multi-provider ───────────────────────────────────────────────────────────

func TestMultiProvider_AllDispatched(t *testing.T) {
	srv1, _ := captureServer(t)
	defer srv1.Close()
	srv2, _ := captureServer(t)
	defer srv2.Close()

	m := NewWithClient(srv1.Client(), []Provider{
		{Kind: "slack", WebhookURL: srv1.URL},
		{Kind: "discord", WebhookURL: srv2.URL},
	})
	// Override second provider's client via custom setup.
	m.client = srv1.Client() // both test servers share the same TLS root — use srv1 client

	findings, err := m.Run(context.Background(), module.Input{RawContent: "multi-dispatch"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (one per provider), got %d", len(findings))
	}
}

func TestMultiMessage_AllDispatched(t *testing.T) {
	srv, _ := captureServer(t)
	defer srv.Close()
	m := singleProvider("slack", srv.URL, srv.Client())
	findings, err := m.Run(context.Background(), module.Input{
		RawContent: "msg1\nmsg2\nmsg3",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings for 3 messages, got %d", len(findings))
	}
}

// ─── findings_json ────────────────────────────────────────────────────────────

func TestFindingsJSON_Dispatched(t *testing.T) {
	srv, getBody := captureServer(t)
	defer srv.Close()
	m := singleProvider("slack", srv.URL, srv.Client())

	ff := []module.Finding{
		{Type: "xss", URL: "https://example.com/search", Severity: module.SeverityHigh, Detail: "Reflected XSS"},
	}
	raw, _ := json.Marshal(ff)
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"findings_json": string(raw)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	// Body should contain the rendered finding text.
	body := getBody()
	if !strings.Contains(body, "xss") {
		t.Errorf("expected xss in dispatched payload, got: %s", body)
	}
}

func TestFindingsJSON_Invalid(t *testing.T) {
	srv, _ := captureServer(t)
	defer srv.Close()
	m := singleProvider("slack", srv.URL, srv.Client())
	_, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"findings_json": "{not-json}"},
	})
	if err == nil {
		t.Fatal("expected error for invalid findings_json")
	}
}

// ─── helpers unit tests ───────────────────────────────────────────────────────

func TestBuildMessages_RawContent(t *testing.T) {
	msgs, err := buildMessages(module.Input{RawContent: "line1\nline2\n\nline3"})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}
}

func TestBuildMessages_Target(t *testing.T) {
	msgs, err := buildMessages(module.Input{Target: "hello world"})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].text != "hello world" {
		t.Fatalf("expected [hello world], got %v", msgs)
	}
}

func TestTruncate(t *testing.T) {
	long := strings.Repeat("a", 200)
	got := truncate(long, 120)
	if len(got) > 125 { // 120 + ellipsis
		t.Errorf("truncate result too long: %d chars", len(got))
	}
}

func TestFindingText(t *testing.T) {
	f := module.Finding{
		Type:     "sqli",
		URL:      "https://example.com/q",
		Severity: module.SeverityHigh,
		Detail:   "SQL injection",
	}
	text := findingText(f)
	if !strings.Contains(text, "sqli") || !strings.Contains(text, "SQL injection") {
		t.Errorf("findingText missing expected fields: %q", text)
	}
}

func TestHeaders_Forwarded(t *testing.T) {
	var capturedHeader string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get("X-Custom-Header")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client(), []Provider{{
		Kind:       "webhook",
		WebhookURL: srv.URL,
		Headers:    map[string]string{"X-Custom-Header": "blackhorn"},
	}})
	_, err := m.Run(context.Background(), module.Input{RawContent: "msg"})
	if err != nil {
		t.Fatal(err)
	}
	if capturedHeader != "blackhorn" {
		t.Errorf("expected X-Custom-Header=blackhorn, got %q", capturedHeader)
	}
}
