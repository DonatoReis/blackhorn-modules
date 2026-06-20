package userlookup_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/userlookup"
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
	if userlookup.New().Name() != "userlookup" {
		t.Error("nome incorreto")
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if userlookup.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestBuiltinPlatforms_NotEmpty(t *testing.T) {
	if len(userlookup.BuiltinPlatforms()) == 0 {
		t.Fatal("BuiltinPlatforms() retornou lista vazia")
	}
}

func TestBuiltinPlatforms_AllHaveURL(t *testing.T) {
	for _, p := range userlookup.BuiltinPlatforms() {
		if p.URL == "" {
			t.Errorf("plataforma %q sem URL", p.Name)
		}
		if !strings.Contains(p.URL, "{account}") {
			t.Errorf("plataforma %q URL sem placeholder {account}: %s", p.Name, p.URL)
		}
		if p.Name == "" {
			t.Error("plataforma sem Name")
		}
		if p.Category == "" {
			t.Errorf("plataforma %q sem Category", p.Name)
		}
	}
}

func TestBuiltinPlatforms_CategoriesExist(t *testing.T) {
	wantCats := []string{"social", "coding", "gaming", "tech", "brasil"}
	cats := map[string]bool{}
	for _, p := range userlookup.BuiltinPlatforms() {
		cats[p.Category] = true
	}
	for _, c := range wantCats {
		if !cats[c] {
			t.Errorf("categoria '%s' não encontrada", c)
		}
	}
}

// ─── target vazio / inválido ──────────────────────────────────────────────────

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := userlookup.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

func TestRun_ShortUsername_ReturnsError(t *testing.T) {
	_, err := userlookup.New().Run(context.Background(), module.Input{Target: "a"})
	if err == nil {
		t.Fatal("esperava erro para username muito curto")
	}
}

func TestRun_AtPrefixStripped(t *testing.T) {
	// @github deve ser tratado igual a github
	platforms := []userlookup.Platform{
		{Name: "TestSite", Category: "test", URL: "https://example.com/{account}",
			ProbeType: userlookup.ProbeStatus, Confidence: 0.90},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := userlookup.NewWithPlatforms(newTestClient(srv), platforms)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "@testuser",
		Options: map[string]string{"found_only": "true"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Extra["username"], "@") {
			t.Error("username não deve conter @ após strip")
		}
	}
}

// ─── ProbeStatus ─────────────────────────────────────────────────────────────

func TestRun_ProbeStatus_Found_200(t *testing.T) {
	platforms := []userlookup.Platform{
		{Name: "GitHub", Category: "coding", URL: "https://github.com/{account}",
			ProbeType: userlookup.ProbeStatus, Confidence: 0.97},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := userlookup.NewWithPlatforms(newTestClient(srv), platforms)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"found_only": "true"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("esperava 1 finding (found), obteve %d", len(findings))
	}
	if findings[0].Type != "username_found" {
		t.Errorf("type esperado 'username_found', obteve '%s'", findings[0].Type)
	}
	if findings[0].Extra["found"] != "true" {
		t.Error("found deve ser 'true'")
	}
}

func TestRun_ProbeStatus_NotFound_404(t *testing.T) {
	platforms := []userlookup.Platform{
		{Name: "GitHub", Category: "coding", URL: "https://github.com/{account}",
			ProbeType: userlookup.ProbeStatus, Confidence: 0.97},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := userlookup.NewWithPlatforms(newTestClient(srv), platforms)
	// found_only=false para ver o not_found
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "notexistuser",
		Options: map[string]string{"found_only": "false"},
	})
	if len(findings) == 0 {
		t.Fatal("esperava finding (not_found)")
	}
	if findings[0].Type != "username_not_found" {
		t.Errorf("type esperado 'username_not_found', obteve '%s'", findings[0].Type)
	}
}

// ─── ProbeBodyContain ─────────────────────────────────────────────────────────

func TestRun_ProbeBodyContain_Found(t *testing.T) {
	platforms := []userlookup.Platform{
		{Name: "Keybase", Category: "tech", URL: "https://keybase.io/{account}",
			ProbeType:  userlookup.ProbeBodyContain,
			ClaimText:  `"status":{"code":0}`,
			Confidence: 0.92},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":{"code":0},"them":{"id":"abc"}}`))
	}))
	defer srv.Close()

	m := userlookup.NewWithPlatforms(newTestClient(srv), platforms)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"found_only": "true"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("ProbeBodyContain: esperava 1 finding")
	}
	if findings[0].Extra["found"] != "true" {
		t.Error("ProbeBodyContain: found deve ser 'true'")
	}
}

func TestRun_ProbeBodyContain_NotFound_ClaimTextAbsent(t *testing.T) {
	platforms := []userlookup.Platform{
		{Name: "Keybase", Category: "tech", URL: "https://keybase.io/{account}",
			ProbeType:  userlookup.ProbeBodyContain,
			ClaimText:  `"status":{"code":0}`,
			Confidence: 0.92},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":{"code":404},"them":null}`))
	}))
	defer srv.Close()

	m := userlookup.NewWithPlatforms(newTestClient(srv), platforms)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"found_only": "false"},
	})
	for _, f := range findings {
		if f.Extra["found"] == "true" {
			t.Error("ProbeBodyContain: claim text ausente deve resultar em not found")
		}
	}
}

// ─── ProbeBodyNotContain ─────────────────────────────────────────────────────

func TestRun_ProbeBodyNotContain_Found(t *testing.T) {
	platforms := []userlookup.Platform{
		{Name: "Reddit", Category: "social", URL: "https://reddit.com/user/{account}",
			ProbeType:    userlookup.ProbeBodyNotContain,
			NotFoundText: "page not found",
			Confidence:   0.93},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>User profile for testuser</body></html>`))
	}))
	defer srv.Close()

	m := userlookup.NewWithPlatforms(newTestClient(srv), platforms)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"found_only": "true"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("ProbeBodyNotContain: esperava 1 finding")
	}
}

func TestRun_ProbeBodyNotContain_NotFound_TextPresent(t *testing.T) {
	platforms := []userlookup.Platform{
		{Name: "Reddit", Category: "social", URL: "https://reddit.com/user/{account}",
			ProbeType:    userlookup.ProbeBodyNotContain,
			NotFoundText: "page not found",
			Confidence:   0.93},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>Sorry, this page not found.</body></html>`))
	}))
	defer srv.Close()

	m := userlookup.NewWithPlatforms(newTestClient(srv), platforms)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "nonexistentuser",
		Options: map[string]string{"found_only": "false"},
	})
	for _, f := range findings {
		if f.Extra["found"] == "true" {
			t.Error("ProbeBodyNotContain: not-found text presente deve resultar em not found")
		}
	}
}

// ─── category filter ─────────────────────────────────────────────────────────

func TestRun_CategoryFilter_OnlyBrasil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := userlookup.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"categories": "brasil", "found_only": "true"},
	})
	for _, f := range findings {
		if f.Extra["category"] != "brasil" {
			t.Errorf("category filter falhou: obteve '%s'", f.Extra["category"])
		}
	}
}

// ─── sites filter ────────────────────────────────────────────────────────────

func TestRun_SitesFilter_OnlyGitHub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := userlookup.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"sites": "github", "found_only": "false"},
	})
	for _, f := range findings {
		if !strings.EqualFold(f.Extra["site"], "github") {
			t.Errorf("sites filter falhou: obteve site '%s'", f.Extra["site"])
		}
	}
}

func TestRun_InvalidSiteFilter_ReturnsError(t *testing.T) {
	m := userlookup.New()
	_, err := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"sites": "sitequenaoexiste_xyz123"},
	})
	if err == nil {
		t.Fatal("esperava erro para filtro de site inválido")
	}
}

// ─── confidence ───────────────────────────────────────────────────────────────

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	platforms := []userlookup.Platform{
		{Name: "TestSite", Category: "test", URL: "https://example.com/{account}",
			ProbeType: userlookup.ProbeStatus, Confidence: 0.90},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := userlookup.NewWithPlatforms(newTestClient(srv), platforms)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"found_only": "false"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	platforms := []userlookup.Platform{
		{Name: "TestSite", Category: "test", URL: "https://example.com/{account}",
			ProbeType: userlookup.ProbeStatus, Confidence: 0.90},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := userlookup.NewWithPlatforms(newTestClient(srv), platforms)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"found_only": "false"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

func TestRun_AllFindings_HaveResponseTime(t *testing.T) {
	platforms := []userlookup.Platform{
		{Name: "TestSite", Category: "test", URL: "https://example.com/{account}",
			ProbeType: userlookup.ProbeStatus, Confidence: 0.90},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := userlookup.NewWithPlatforms(newTestClient(srv), platforms)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"found_only": "false"},
	})
	for _, f := range findings {
		if f.Extra["response_time_ms"] == "" {
			t.Error("finding sem response_time_ms")
		}
	}
}

// ─── context cancelado ────────────────────────────────────────────────────────

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := userlookup.NewWithClient(newTestClient(srv))
	_, _ = m.Run(ctx, module.Input{Target: "testuser"})
}

// ─── concurrência ────────────────────────────────────────────────────────────

func TestRun_MultiplePlatforms_AllProbed(t *testing.T) {
	platforms := make([]userlookup.Platform, 10)
	for i := range platforms {
		platforms[i] = userlookup.Platform{
			Name:       "Site" + string(rune('A'+i)),
			Category:   "test",
			URL:        "https://example.com/{account}",
			ProbeType:  userlookup.ProbeStatus,
			Confidence: 0.80,
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := userlookup.NewWithPlatforms(newTestClient(srv), platforms)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"found_only": "false", "concurrency": "5"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) != 10 {
		t.Errorf("esperava 10 findings (1 por plataforma), obteve %d", len(findings))
	}
}
