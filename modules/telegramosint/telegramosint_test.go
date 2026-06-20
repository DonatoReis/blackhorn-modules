package telegramosint_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/telegramosint"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// rewriteTransport redireciona qualquer requisição ao servidor de teste.
type rewriteTransport struct{ base string }

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(r.base, "http://")
	return http.DefaultTransport.RoundTrip(clone)
}

func newTestClient(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: &rewriteTransport{srv.URL}}
}

// ─── estrutura ────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if telegramosint.New().Name() != "telegramosint" {
		t.Error("nome incorreto")
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if telegramosint.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

// ─── target vazio / inválido ──────────────────────────────────────────────────

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := telegramosint.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

func TestRun_ShortUsername_ReturnsError(t *testing.T) {
	// usernames Telegram precisam de pelo menos 5 chars
	_, err := telegramosint.New().Run(context.Background(), module.Input{Target: "ab"})
	if err == nil {
		t.Fatal("esperava erro para username muito curto")
	}
}

// ─── normalização de target ───────────────────────────────────────────────────

func TestRun_AtPrefix_Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(previewHandler))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target:  "@testchannel",
		Options: map[string]string{"sources": "preview"},
	})
	// Pode retornar findings ou não — não deve dar erro
	if err != nil {
		t.Fatalf("@prefix gerou erro: %v", err)
	}
}

func TestRun_TmeDotMeURL_Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(previewHandler))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target:  "https://t.me/testchannel",
		Options: map[string]string{"sources": "preview"},
	})
	if err != nil {
		t.Fatalf("t.me URL gerou erro: %v", err)
	}
}

// ─── t.me preview scraping ────────────────────────────────────────────────────

func previewHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
<meta property="og:title" content="Test Channel" />
<meta property="og:description" content="Canal de testes. Contato: test@example.com Tel: +55 11 99999-1234 Veja também @otheruser" />
</head>
<body>
<div class="tgme_page_context_action">
<a>View Channel</a>
</div>
<div class="tgme_channel_info">
<span class="tgme_channel_info_counter_value">1 234 members</span>
</div>
</body>
</html>`))
}

func TestRun_Preview_EntityFindingReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(previewHandler))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "testchannel",
		Options: map[string]string{"sources": "preview"},
	})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.Type == "telegram_entity" {
			found = true
		}
	}
	if !found {
		t.Error("esperava finding 'telegram_entity'")
	}
}

func TestRun_Preview_EmailExtracted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(previewHandler))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testchannel",
		Options: map[string]string{"sources": "preview"},
	})

	var found bool
	for _, f := range findings {
		if f.Type == "email_exposed" {
			found = true
			if f.Extra["email_domain"] == "" {
				t.Error("email_exposed deve ter email_domain")
			}
		}
	}
	if !found {
		t.Error("esperava finding 'email_exposed' com test@example.com na descrição")
	}
}

func TestRun_Preview_PhoneExtracted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(previewHandler))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testchannel",
		Options: map[string]string{"sources": "preview"},
	})

	var found bool
	for _, f := range findings {
		if f.Type == "phone_number_exposed" {
			found = true
			if f.Extra["phone"] == "" {
				t.Error("phone_number_exposed deve ter phone")
			}
		}
	}
	if !found {
		t.Error("esperava finding 'phone_number_exposed' com +55 11 99999-1234")
	}
}

func TestRun_Preview_MentionExtracted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(previewHandler))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testchannel",
		Options: map[string]string{"sources": "preview"},
	})

	var found bool
	for _, f := range findings {
		if f.Type == "telegram_mention" {
			found = true
			if f.Extra["mentioned"] == "" {
				t.Error("telegram_mention deve ter mentioned")
			}
		}
	}
	if !found {
		t.Error("esperava finding 'telegram_mention' para @otheruser")
	}
}

func TestRun_Preview_404_ReturnsNoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	// Source com erro não deve propagar — só loga warning
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "notexistuser",
		Options: map[string]string{"sources": "preview"},
	})
	if err != nil {
		t.Fatalf("404 não deve retornar erro para o caller: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("404 deve retornar 0 findings, obteve %d", len(findings))
	}
}

// ─── scam flag ───────────────────────────────────────────────────────────────

func TestRun_Preview_ScamTitle_SeverityHigh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head>
<meta property="og:title" content="SCAM WARNING — Fraud Channel" />
<meta property="og:description" content="Beware of fraud" />
</head><body></body></html>`))
	}))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "scamchannel",
		Options: map[string]string{"sources": "preview"},
	})

	for _, f := range findings {
		if f.Type == "telegram_entity" {
			if f.Severity != module.SeverityHigh {
				t.Errorf("scam channel deve ser SeverityHigh, obteve %s", f.Severity)
			}
			return
		}
	}
	t.Error("esperava finding 'telegram_entity'")
}

// ─── Bot API mock ─────────────────────────────────────────────────────────────

func botAPIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if strings.Contains(r.URL.Path, "getChatMemberCount") {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":     true,
			"result": map[string]int{"count": 5000},
		})
		return
	}

	// getChat
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok": true,
		"result": map[string]interface{}{
			"id":                    -1001234567890,
			"type":                  "channel",
			"title":                 "Test Bot Channel",
			"username":              "testchannel",
			"description":           "Canal de testes via bot API",
			"has_protected_content": false,
		},
	})
}

func TestRun_BotAPI_EntityFindingReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(botAPIHandler))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "testchannel",
		Options: map[string]string{
			"sources":   "botapi",
			"bot_token": "test-token",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.Type == "telegram_entity" && f.Extra["source"] == "telegram_botapi" {
			found = true
			if f.Extra["chat_type"] != "channel" {
				t.Errorf("chat_type esperado 'channel', obteve '%s'", f.Extra["chat_type"])
			}
		}
	}
	if !found {
		t.Error("esperava finding 'telegram_entity' via botapi")
	}
}

func TestRun_BotAPI_NoToken_ReturnsNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(botAPIHandler))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "testchannel",
		Options: map[string]string{
			"sources": "botapi",
			// sem bot_token
		},
	})
	if len(findings) != 0 {
		t.Errorf("sem bot_token esperava 0 findings, obteve %d", len(findings))
	}
}

func TestRun_BotAPI_ProtectedContent_FindingReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "getChatMemberCount") {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "result": map[string]int{"count": 100}})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true,
			"result": map[string]interface{}{
				"id": -1001234567890, "type": "channel",
				"title":                 "Protected Channel",
				"has_protected_content": true,
			},
		})
	}))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "protectedchan",
		Options: map[string]string{
			"sources":   "botapi",
			"bot_token": "test-token",
		},
	})

	var found bool
	for _, f := range findings {
		if f.Type == "telegram_protected_content" {
			found = true
		}
	}
	if !found {
		t.Error("esperava finding 'telegram_protected_content'")
	}
}

// ─── Fragment mock ────────────────────────────────────────────────────────────

func TestRun_Fragment_Available_FindingReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>Available for Auction</body></html>`))
	}))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testusername",
		Options: map[string]string{"sources": "fragment"},
	})

	var found bool
	for _, f := range findings {
		if f.Type == "telegram_username_available_fragment" {
			found = true
		}
	}
	if !found {
		t.Error("esperava finding 'telegram_username_available_fragment'")
	}
}

func TestRun_Fragment_Sold_FindingReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>Sold to highest bidder</body></html>`))
	}))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testusername",
		Options: map[string]string{"sources": "fragment"},
	})

	var found bool
	for _, f := range findings {
		if f.Type == "telegram_username_sold_fragment" {
			found = true
			if f.Severity != module.SeverityMedium {
				t.Errorf("sold deve ser SeverityMedium, obteve %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("esperava finding 'telegram_username_sold_fragment'")
	}
}

func TestRun_Fragment_404_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "testusername",
		Options: map[string]string{"sources": "fragment"},
	})
	if err != nil {
		t.Fatalf("404 fragment não deve dar erro: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("404 fragment esperava 0 findings, obteve %d", len(findings))
	}
}

// ─── confidence ──────────────────────────────────────────────────────────────

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(previewHandler))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testchannel",
		Options: map[string]string{"sources": "preview"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(previewHandler))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testchannel",
		Options: map[string]string{"sources": "preview"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestRun_Dedup_NoduplicateFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(previewHandler))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testchannel",
		Options: map[string]string{"sources": "preview"},
	})
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Extra["source"]
		if seen[key] {
			t.Errorf("finding duplicado: %s", key)
		}
		seen[key] = true
	}
}

// ─── context cancelado ───────────────────────────────────────────────────────

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv := httptest.NewServer(http.HandlerFunc(previewHandler))
	defer srv.Close()

	m := telegramosint.NewWithClient(newTestClient(srv))
	_, _ = m.Run(ctx, module.Input{
		Target:  "testchannel",
		Options: map[string]string{"sources": "preview"},
	})
}
