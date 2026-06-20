package googledork_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/googledork"
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
	if googledork.New().Name() != "googledork" {
		t.Error("nome incorreto")
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if googledork.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestBuiltinDorks_NotEmpty(t *testing.T) {
	if len(googledork.BuiltinDorks()) == 0 {
		t.Fatal("BuiltinDorks() retornou lista vazia")
	}
}

func TestBuiltinDorks_AllHaveFields(t *testing.T) {
	for _, d := range googledork.BuiltinDorks() {
		if d.Name == "" {
			t.Errorf("dork sem Name: %+v", d)
		}
		if d.Category == "" {
			t.Errorf("dork sem Category: %+v", d)
		}
		if d.Query == "" {
			t.Errorf("dork sem Query: %+v", d)
		}
	}
}

func TestBuiltinDorks_ExpectedCategoriesExist(t *testing.T) {
	wantCats := []string{
		"sensitive_files", "login_panels", "tech_stack",
		"data_exposure", "credentials", "brasil", "cloud",
	}
	cats := map[string]bool{}
	for _, d := range googledork.BuiltinDorks() {
		cats[d.Category] = true
	}
	for _, c := range wantCats {
		if !cats[c] {
			t.Errorf("categoria '%s' não encontrada nos dorks builtin", c)
		}
	}
}

// ─── target vazio ─────────────────────────────────────────────────────────────

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := googledork.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

// ─── categoria inválida ───────────────────────────────────────────────────────

func TestRun_InvalidCategory_ReturnsError(t *testing.T) {
	_, err := googledork.New().Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"categories": "categoria_inexistente_xyzabc"},
	})
	if err == nil {
		t.Fatal("esperava erro para categoria inexistente")
	}
}

// ─── SerpAPI ──────────────────────────────────────────────────────────────────

func serpHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"search_metadata": map[string]string{"status": "Success"},
		"organic_results": []map[string]string{
			{"title": "Exposed .env", "link": "https://example.com/.env", "snippet": "DB_PASSWORD=secret"},
			{"title": "Admin Panel", "link": "https://example.com/admin", "snippet": "login page"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func TestRun_SerpAPI_FindingsReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(serpHandler))
	defer srv.Close()

	m := googledork.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":     "serpapi",
			"serpapi_key": "test-key",
			"categories":  "sensitive_files",
			"max_results": "5",
		},
	})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava pelo menos 1 finding via SerpAPI")
	}
}

func TestRun_SerpAPI_FindingsHaveURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(serpHandler))
	defer srv.Close()

	m := googledork.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":     "serpapi",
			"serpapi_key": "test-key",
			"categories":  "sensitive_files",
		},
	})
	for _, f := range findings {
		if f.URL == "" {
			t.Error("finding sem URL")
		}
	}
}

func TestRun_SerpAPI_FindingsHaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(serpHandler))
	defer srv.Close()

	m := googledork.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":     "serpapi",
			"serpapi_key": "test-key",
			"categories":  "sensitive_files",
		},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_SerpAPI_FindingsHaveDorkMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(serpHandler))
	defer srv.Close()

	m := googledork.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":     "serpapi",
			"serpapi_key": "test-key",
			"categories":  "sensitive_files",
		},
	})
	for _, f := range findings {
		if f.Extra["dork_name"] == "" {
			t.Error("finding sem dork_name")
		}
		if f.Extra["dork_category"] == "" {
			t.Error("finding sem dork_category")
		}
		if f.Extra["dork_query"] == "" {
			t.Error("finding sem dork_query")
		}
	}
}

func TestRun_SerpAPI_NoKey_ReturnsZeroFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(serpHandler))
	defer srv.Close()

	m := googledork.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":    "serpapi",
			"categories": "sensitive_files",
			// sem serpapi_key
		},
	})
	if len(findings) != 0 {
		t.Errorf("sem chave SerpAPI esperava 0 findings, obteve %d", len(findings))
	}
}

func TestRun_SerpAPI_SeverityFromDork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(serpHandler))
	defer srv.Close()

	dorks := []googledork.Dork{
		{Name: "aws_keys", Category: "credentials", Query: `"AKIAIOSFODNN7EXAMPLE"`,
			Severity: module.SeverityCritical, Confidence: 0.93},
	}
	m := googledork.NewWithDorks(newTestClient(srv), dorks)
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":     "serpapi",
			"serpapi_key": "test-key",
			"categories":  "credentials",
		},
	})
	for _, f := range findings {
		if f.Severity != module.SeverityCritical {
			t.Errorf("aws_keys deve ser SeverityCritical, obteve %s", f.Severity)
		}
	}
}

// ─── Bing ─────────────────────────────────────────────────────────────────────

func bingHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"webPages": map[string]interface{}{
			"value": []map[string]string{
				{"name": "Config backup", "url": "https://example.com/config.bak", "snippet": "backup file"},
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func TestRun_Bing_FindingsReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(bingHandler))
	defer srv.Close()

	m := googledork.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":    "bing",
			"bing_key":   "test-key",
			"categories": "sensitive_files",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava pelo menos 1 finding via Bing")
	}
}

func TestRun_Bing_SourceTaggedCorrectly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(bingHandler))
	defer srv.Close()

	m := googledork.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":    "bing",
			"bing_key":   "test-key",
			"categories": "sensitive_files",
		},
	})
	for _, f := range findings {
		if f.Extra["source"] != "bing" {
			t.Errorf("source esperado 'bing', obteve '%s'", f.Extra["source"])
		}
	}
}

// ─── DuckDuckGo ───────────────────────────────────────────────────────────────

func ddgHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"Results": []map[string]string{
			{"FirstURL": "https://example.com/login", "Text": "login page exposed"},
		},
		"RelatedTopics": []map[string]string{},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func TestRun_DDG_FindingsReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(ddgHandler))
	defer srv.Close()

	m := googledork.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":    "ddg",
			"categories": "login_panels",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava pelo menos 1 finding via DDG")
	}
}

func TestRun_DDG_SourceTaggedCorrectly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(ddgHandler))
	defer srv.Close()

	m := googledork.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":    "ddg",
			"categories": "login_panels",
		},
	})
	for _, f := range findings {
		if f.Extra["source"] != "ddg" {
			t.Errorf("source esperado 'ddg', obteve '%s'", f.Extra["source"])
		}
	}
}

func TestRun_DDG_FindingsHaveDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(ddgHandler))
	defer srv.Close()

	m := googledork.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":    "ddg",
			"categories": "login_panels",
		},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

// ─── Brave ────────────────────────────────────────────────────────────────────

func braveHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"web": map[string]interface{}{
			"results": []map[string]string{
				{"title": "S3 exposed", "url": "https://bucket.s3.amazonaws.com/", "description": "open"},
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func TestRun_Brave_FindingsReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(braveHandler))
	defer srv.Close()

	m := googledork.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":    "brave",
			"brave_key":  "test-key",
			"categories": "cloud",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava pelo menos 1 finding via Brave")
	}
}

// ─── CategoryFilter ──────────────────────────────────────────────────────────

func TestRun_CategoryFilter_OnlyBrasil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(serpHandler))
	defer srv.Close()

	m := googledork.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":     "serpapi",
			"serpapi_key": "test-key",
			"categories":  "brasil",
		},
	})
	for _, f := range findings {
		if f.Extra["dork_category"] != "brasil" {
			t.Errorf("category filter falhou: esperava 'brasil', obteve '%s'", f.Extra["dork_category"])
		}
	}
}

// ─── site_operator ───────────────────────────────────────────────────────────

func TestRun_SiteOperatorFalse_QueryHasNoSitePrefix(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("q")
		resp := map[string]interface{}{
			"search_metadata": map[string]string{"status": "Success"},
			"organic_results": []map[string]string{},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	dorks := []googledork.Dork{
		{Name: "env_file", Category: "sensitive_files", Query: `".env"`,
			Severity: module.SeverityHigh, Confidence: 0.90},
	}
	m := googledork.NewWithDorks(newTestClient(srv), dorks)
	m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":       "serpapi",
			"serpapi_key":   "test-key",
			"categories":    "sensitive_files",
			"site_operator": "false",
		},
	})
	if strings.HasPrefix(gotQuery, "site:") {
		t.Errorf("site_operator=false mas query usa site:, query=%q", gotQuery)
	}
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestRun_Dedup_SameResultNotDuplicated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(serpHandler))
	defer srv.Close()

	// Um único dork para controlar o output
	dorks := []googledork.Dork{
		{Name: "test_dork", Category: "sensitive_files", Query: `".env"`,
			Severity: module.SeverityHigh, Confidence: 0.90},
	}
	m := googledork.NewWithDorks(newTestClient(srv), dorks)
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":     "serpapi",
			"serpapi_key": "test-key",
			"categories":  "sensitive_files",
		},
	})
	// serpHandler retorna 2 resultados distintos; dedup não deve duplicar
	urls := map[string]int{}
	for _, f := range findings {
		urls[f.URL]++
	}
	for u, count := range urls {
		if count > 1 {
			t.Errorf("URL '%s' duplicada %d vezes após dedup", u, count)
		}
	}
}

// ─── context cancelado ────────────────────────────────────────────────────────

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv := httptest.NewServer(http.HandlerFunc(serpHandler))
	defer srv.Close()

	m := googledork.NewWithClient(newTestClient(srv))
	_, _ = m.Run(ctx, module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":     "serpapi",
			"serpapi_key": "test-key",
		},
	})
}

// ─── NewWithDorks ────────────────────────────────────────────────────────────

func TestNewWithDorks_CustomDorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(serpHandler))
	defer srv.Close()

	custom := []googledork.Dork{
		{Name: "custom_dork", Category: "sensitive_files", Query: `"custom"`,
			Severity: module.SeverityMedium, Confidence: 0.77},
	}
	m := googledork.NewWithDorks(newTestClient(srv), custom)
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":     "serpapi",
			"serpapi_key": "test-key",
			"categories":  "sensitive_files",
		},
	})
	for _, f := range findings {
		if f.Extra["dork_name"] != "custom_dork" {
			t.Errorf("esperava custom_dork, obteve '%s'", f.Extra["dork_name"])
		}
	}
}
