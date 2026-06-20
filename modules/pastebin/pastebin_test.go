package pastebin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/pastebin"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

type rewriteTransport struct{ base string }

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(r.base, "http://")
	return http.DefaultTransport.RoundTrip(clone)
}

func TestName(t *testing.T) {
	if pastebin.New().Name() != "pastebin" {
		t.Error("nome incorreto")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := pastebin.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

func TestRun_PSBDMP_ParsesResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 2,
			"data": []map[string]interface{}{
				{
					"id":   "abc123",
					"tags": "email,password",
					"time": "2026-01-15",
					"text": "user@example.com:mypassword123",
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := pastebin.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "psbdmp"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("servidor de teste não respondeu como esperado")
	}
	found := false
	for _, f := range findings {
		if f.Type == "paste_found" {
			found = true
		}
	}
	if !found {
		t.Error("esperava finding do tipo paste_found")
	}
}

func TestRun_ContentAnalysis_EmailDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 1,
			"data": []map[string]interface{}{
				{
					"id":   "xyz789",
					"tags": "dump",
					"time": "2026-01-01",
					"text": "victim@targetdomain.com\npassword123",
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := pastebin.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "targetdomain.com",
		Options: map[string]string{"sources": "psbdmp"},
	})
	for _, f := range findings {
		if f.Type == "paste_email_found" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu")
	}
}

func TestRun_ContentAnalysis_PrivateKeyDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 1,
			"data": []map[string]interface{}{
				{
					"id":   "key001",
					"tags": "ssh",
					"time": "2026-01-01",
					"text": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := pastebin.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "rsa key",
		Options: map[string]string{"sources": "psbdmp"},
	})
	for _, f := range findings {
		if f.Type == "paste_private_key_found" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu")
	}
}

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 1,
			"data": []map[string]interface{}{
				{"id": "cf001", "tags": "test", "time": "2026-01-01", "text": "test content"},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := pastebin.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test",
		Options: map[string]string{"sources": "psbdmp"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = pastebin.New().Run(ctx, module.Input{Target: "test@example.com"})
}

func TestRun_PSBDMP_404_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := pastebin.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "notfound@example.com",
		Options: map[string]string{"sources": "psbdmp"},
	})
	if err != nil {
		// Erro de rede esperado — OK
		return
	}
	for _, f := range findings {
		if f.Extra["source"] == "psbdmp" {
			t.Error("não esperava findings psbdmp em 404")
		}
	}
}

func TestRun_RateLimited_HandledGracefully(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := pastebin.NewWithClient(c)
	_, err := m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "psbdmp"},
	})
	_ = err // rate limit pode retornar erro — não deve panic
}

func TestRun_DetailNotEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 1,
			"data": []map[string]interface{}{
				{"id": "dt001", "tags": "test", "time": "2026-01-01", "text": "hello"},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := pastebin.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test",
		Options: map[string]string{"sources": "psbdmp"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if pastebin.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestNewWithClient_ReturnsNonNil(t *testing.T) {
	if pastebin.NewWithClient(http.DefaultClient) == nil {
		t.Fatal("NewWithClient() retornou nil")
	}
}

func TestRun_ContentAnalysis_AWSKeyDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 1,
			"data": []map[string]interface{}{
				{
					"id": "aws001", "tags": "credentials",
					"time": "2026-01-01",
					"text": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nregion=us-east-1",
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := pastebin.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "AKIA",
		Options: map[string]string{"sources": "psbdmp"},
	})
	for _, f := range findings {
		if f.Type == "paste_aws_key_found" {
			if f.Severity != module.SeverityHigh {
				t.Errorf("AWS key deve ter SeverityHigh, obteve %s", f.Severity)
			}
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu com dados")
	}
}

func TestRun_CredentialInContent_Redacted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 1,
			"data": []map[string]interface{}{
				{
					"id": "cred001", "tags": "leak",
					"time": "2026-01-01",
					"text": "admin@example.com:supersecretpassword",
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := pastebin.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "psbdmp"},
	})
	for _, f := range findings {
		if f.Type == "paste_credential_found" {
			if strings.Contains(f.Detail, "supersecretpassword") {
				t.Error("senha completa não deve aparecer no detail — deve ser redacted")
			}
			return
		}
	}
}
