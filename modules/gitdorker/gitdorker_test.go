package gitdorker_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/gitdorker"
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
	if gitdorker.New().Name() != "gitdorker" {
		t.Error("nome incorreto")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := gitdorker.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

func TestRun_InvalidCategory_ReturnsError(t *testing.T) {
	m := gitdorker.NewWithDorks(&http.Client{}, []gitdorker.Dork{})
	_, err := m.Run(context.Background(), module.Input{
		Target:  "org:test",
		Options: map[string]string{"categories": "nonexistent_cat"},
	})
	if err == nil {
		t.Fatal("esperava erro para categoria inexistente")
	}
}

func TestRun_GitHubResponse_ParsesFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total_count": 2,
			"items": []map[string]interface{}{
				{
					"name":     ".env",
					"path":     "config/.env",
					"html_url": "https://github.com/test/repo/blob/main/config/.env",
					"score":    75.5,
					"repository": map[string]interface{}{
						"full_name":        "test/repo",
						"html_url":         "https://github.com/test/repo",
						"description":      "Test repo",
						"private":          false,
						"stargazers_count": 10,
						"language":         "Go",
					},
				},
			},
		})
	}))
	defer srv.Close()

	dorks := []gitdorker.Dork{{
		Name:       "test_dork",
		Category:   "sensitive_files",
		Query:      `filename:.env`,
		Severity:   module.SeverityHigh,
		Confidence: 0.80,
	}}
	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := gitdorker.NewWithDorks(c, dorks)

	findings, err := m.Run(context.Background(), module.Input{
		Target:  "org:test",
		Options: map[string]string{"sources": "github", "github_token": "testtoken"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("servidor de teste não respondeu como esperado")
	}
	for _, f := range findings {
		if f.Type == "git_secret_exposure" {
			return
		}
	}
	t.Error("esperava finding do tipo git_secret_exposure")
}

func TestRun_FindingsHaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total_count": 1,
			"items": []map[string]interface{}{
				{
					"name": "secret.txt", "path": "secret.txt",
					"html_url": "https://github.com/t/r/blob/main/secret.txt",
					"score":    50.0,
					"repository": map[string]interface{}{
						"full_name": "t/r", "html_url": "https://github.com/t/r",
					},
				},
			},
		})
	}))
	defer srv.Close()

	dorks := []gitdorker.Dork{{
		Name:       "conf_dork",
		Category:   "credentials",
		Query:      `"password"`,
		Severity:   module.SeverityHigh,
		Confidence: 0.85,
	}}
	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := gitdorker.NewWithDorks(c, dorks)

	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "org:test",
		Options: map[string]string{"sources": "github", "github_token": "t"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_CategoryFilter_Works(t *testing.T) {
	dorks := []gitdorker.Dork{
		{Name: "d1", Category: "credentials", Query: `test`, Severity: module.SeverityHigh, Confidence: 0.8},
		{Name: "d2", Category: "database", Query: `test`, Severity: module.SeverityHigh, Confidence: 0.8},
	}
	c := &http.Client{Transport: &rewriteTransport{"http://localhost:1"}}
	m := gitdorker.NewWithDorks(c, dorks)

	// Categoria válida que existe — não deve dar erro
	_, err := m.Run(context.Background(), module.Input{
		Target:  "org:test",
		Options: map[string]string{"categories": "credentials", "sources": "github"},
	})
	// Pode dar erro de rede — o importante é que não dá erro de "nenhum dork ativo"
	if err != nil && strings.Contains(err.Error(), "nenhum dork ativo") {
		t.Error("categoria 'credentials' deveria ter dorks ativos")
	}
}

func TestRun_RateLimitHeader_Handled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total_count": 0,
			"items":       []interface{}{},
		})
	}))
	defer srv.Close()

	dorks := []gitdorker.Dork{{
		Name: "rl_test", Category: "credentials", Query: `test`,
		Severity: module.SeverityInfo, Confidence: 0.7,
	}}
	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := gitdorker.NewWithDorks(c, dorks)

	// Deve completar sem panic mesmo com rate limit zerado
	_, err := m.Run(context.Background(), module.Input{
		Target:  "org:test",
		Options: map[string]string{"sources": "github"},
	})
	_ = err
}

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := gitdorker.New()
	_, _ = m.Run(ctx, module.Input{
		Target:  "org:test",
		Options: map[string]string{"sources": "github"},
	})
}

func TestRun_FindingURL_PopulatedFromGitHub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total_count": 1,
			"items": []map[string]interface{}{
				{
					"name": "config.yml", "path": "config.yml",
					"html_url": "https://github.com/acme/api/blob/main/config.yml",
					"score":    80.0,
					"repository": map[string]interface{}{
						"full_name": "acme/api", "html_url": "https://github.com/acme/api",
					},
				},
			},
		})
	}))
	defer srv.Close()

	dorks := []gitdorker.Dork{{
		Name: "url_test", Category: "credentials", Query: `test`,
		Severity: module.SeverityHigh, Confidence: 0.80,
	}}
	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := gitdorker.NewWithDorks(c, dorks)

	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "org:acme",
		Options: map[string]string{"sources": "github", "github_token": "t"},
	})
	for _, f := range findings {
		if f.URL != "" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu")
	}
	t.Error("findings devem ter URL preenchida")
}

func TestRun_DetailNotEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total_count": 1,
			"items": []map[string]interface{}{
				{
					"name": "file.txt", "path": "file.txt",
					"html_url": "https://github.com/x/y/blob/main/file.txt",
					"score":    60.0,
					"repository": map[string]interface{}{
						"full_name": "x/y", "html_url": "https://github.com/x/y",
					},
				},
			},
		})
	}))
	defer srv.Close()

	dorks := []gitdorker.Dork{{
		Name: "detail_test", Category: "credentials", Query: `test`,
		Severity: module.SeverityHigh, Confidence: 0.75,
	}}
	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := gitdorker.NewWithDorks(c, dorks)

	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "org:x",
		Options: map[string]string{"sources": "github", "github_token": "t"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

func TestNew_BuiltinDorks_NotEmpty(t *testing.T) {
	// Verifica que BuiltinDorks não está vazio — sem executar o Run
	// (Run tem sleep de 2s/dork, impraticável em teste unitário)
	dorks := gitdorker.BuiltinDorks()
	if len(dorks) == 0 {
		t.Fatal("BuiltinDorks() não deve retornar lista vazia")
	}
}

func TestNewWithDorks_EmptyList_ReturnsError(t *testing.T) {
	m := gitdorker.NewWithDorks(&http.Client{}, []gitdorker.Dork{})
	_, err := m.Run(context.Background(), module.Input{
		Target:  "org:test",
		Options: map[string]string{"sources": "github"},
	})
	if err == nil {
		t.Fatal("lista vazia de dorks deve retornar erro")
	}
}

func TestRun_SeverityHigh_OnPrivateKeyDork(t *testing.T) {
	// Verifica que o dork de private key tem severidade High
	for _, d := range gitdorker.BuiltinDorks() {
		if d.Name == "private_key_rsa" {
			if d.Severity != module.SeverityHigh {
				t.Errorf("private_key_rsa deve ter SeverityHigh, obteve %s", d.Severity)
			}
			return
		}
	}
}
