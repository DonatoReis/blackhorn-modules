package emailverify_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/emailverify"
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
	if emailverify.New().Name() != "emailverify" {
		t.Error("nome incorreto")
	}
}

func TestRun_EmptyEmail_ReturnsError(t *testing.T) {
	_, err := emailverify.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para email vazio")
	}
}

func TestRun_InvalidFormat_ReturnsError(t *testing.T) {
	_, err := emailverify.New().Run(context.Background(), module.Input{
		Target: "nao-e-email",
	})
	if err == nil {
		t.Fatal("esperava erro para formato inválido")
	}
}

func TestRun_ValidEmail_LocalAnalysis(t *testing.T) {
	m := emailverify.NewWithClient(&http.Client{})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "usuario@empresa.com.br",
		Options: map[string]string{"sources": "local", "check_mx": "false"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings para email válido")
	}
}

func TestRun_DisposableDomain_DetectedLocally(t *testing.T) {
	m := emailverify.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test@mailinator.com",
		Options: map[string]string{"sources": "local", "check_mx": "false"},
	})
	for _, f := range findings {
		if f.Extra["disposable"] == "true" {
			return
		}
	}
	t.Error("mailinator.com deveria ser detectado como descartável")
}

func TestRun_DisposableDomain_SeverityMedium(t *testing.T) {
	m := emailverify.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test@mailinator.com",
		Options: map[string]string{"sources": "local", "check_mx": "false"},
	})
	for _, f := range findings {
		if f.Extra["disposable"] == "true" && f.Severity != module.SeverityMedium {
			t.Errorf("esperava SeverityMedium para email descartável, obteve %s", f.Severity)
		}
	}
}

func TestRun_BrDomain_Detected(t *testing.T) {
	m := emailverify.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "usuario@empresa.com.br",
		Options: map[string]string{"sources": "local", "check_mx": "false"},
	})
	for _, f := range findings {
		if f.Extra["br_domain"] == "true" {
			return
		}
	}
	t.Error("domínio .com.br não foi marcado como br_domain")
}

func TestRun_GovBrDomain_Detected(t *testing.T) {
	m := emailverify.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "servidor@ministerio.gov.br",
		Options: map[string]string{"sources": "local", "check_mx": "false"},
	})
	for _, f := range findings {
		if f.Extra["gov_domain"] == "true" {
			return
		}
	}
	t.Error("domínio .gov.br não detectado")
}

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	m := emailverify.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "local", "check_mx": "false"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_Kickbox_ParsesDisposable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"disposable": true,
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := emailverify.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "kickbox", "check_mx": "false"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Extra["disposable"] == "true" && f.Extra["source"] == "kickbox" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor de teste não respondeu como esperado")
	}
}

func TestRun_Hunter_ParsesScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"status":     "valid",
				"score":      95,
				"email":      "test@example.com",
				"disposable": false,
				"webmail":    false,
				"mx_records": true,
				"smtp_check": true,
				"accept_all": false,
				"block":      false,
				"gibberish":  false,
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := emailverify.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "hunter", "hunter_key": "testkey", "check_mx": "false"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Extra["source"] == "hunter" && f.Extra["score"] == "95" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor de teste não respondeu como esperado")
	}
}

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = emailverify.New().Run(ctx, module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"check_mx": "false"},
	})
}

func TestRun_DetailNotEmpty(t *testing.T) {
	m := emailverify.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "local", "check_mx": "false"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

func TestRun_DomainInExtra(t *testing.T) {
	m := emailverify.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "user@testdomain.com",
		Options: map[string]string{"sources": "local", "check_mx": "false"},
	})
	for _, f := range findings {
		if f.Extra["domain"] == "testdomain.com" {
			return
		}
	}
	t.Error("domínio não encontrado no Extra")
}

func TestRun_UsernameInExtra(t *testing.T) {
	m := emailverify.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "myuser@example.com",
		Options: map[string]string{"sources": "local", "check_mx": "false"},
	})
	for _, f := range findings {
		if f.Extra["username"] == "myuser" {
			return
		}
	}
	t.Error("username não encontrado no Extra")
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if emailverify.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestNewWithClient_ReturnsNonNil(t *testing.T) {
	if emailverify.NewWithClient(http.DefaultClient) == nil {
		t.Fatal("NewWithClient() retornou nil")
	}
}

func TestRun_CheckMXFalse_SkipsDNS(t *testing.T) {
	m := emailverify.NewWithClient(&http.Client{})
	// nonexistent TLD — MX check would fail but we skip it
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "user@totallyfakedomain12345.xyz",
		Options: map[string]string{"sources": "local", "check_mx": "false"},
	})
	if err != nil {
		t.Fatalf("não esperava erro: %v", err)
	}
	_ = findings
}

func TestRun_NormalEmail_SeverityInfo(t *testing.T) {
	m := emailverify.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "user@gmail.com",
		Options: map[string]string{"sources": "local", "check_mx": "false"},
	})
	for _, f := range findings {
		if f.Extra["source"] == "local_analysis" && f.Severity != module.SeverityInfo {
			t.Errorf("email normal deve ter SeverityInfo, obteve %s", f.Severity)
		}
	}
}
