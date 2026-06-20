package socialscan_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/socialscan"
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
	if socialscan.New().Name() != "socialscan" {
		t.Error("nome incorreto")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := socialscan.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para username vazio")
	}
}

func TestRun_UsernameWithSpaces_ReturnsError(t *testing.T) {
	_, err := socialscan.New().Run(context.Background(), module.Input{Target: "john doe"})
	if err == nil {
		t.Fatal("esperava erro para username com espaços")
	}
}

func TestRun_InvalidPlatformFilter_ReturnsError(t *testing.T) {
	m := socialscan.NewWithPlatforms(&http.Client{}, []socialscan.Platform{})
	_, err := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"platforms": "nonexistent_platform"},
	})
	if err == nil {
		t.Fatal("esperava erro para plataforma inválida com lista vazia")
	}
}

func TestRun_ProbeStatus_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>Profile page</html>"))
	}))
	defer srv.Close()

	platforms := []socialscan.Platform{{
		Name:       "testplatform",
		Category:   "test",
		URL:        srv.URL + "/%s",
		Probe:      socialscan.ProbeStatus,
		Confidence: 0.90,
	}}

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := socialscan.NewWithPlatforms(c, platforms)
	findings, err := m.Run(context.Background(), module.Input{
		Target: "johndoe",
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding para perfil encontrado")
	}
	if findings[0].Type != "username_found" {
		t.Errorf("tipo incorreto: %s", findings[0].Type)
	}
}

func TestRun_ProbeBodyNotContain_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Page Not Found - User does not exist"))
	}))
	defer srv.Close()

	platforms := []socialscan.Platform{{
		Name:         "testplatform",
		Category:     "test",
		URL:          srv.URL + "/%s",
		Probe:        socialscan.ProbeBodyNotContain,
		NotFoundText: "User does not exist",
		Confidence:   0.85,
	}}

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := socialscan.NewWithPlatforms(c, platforms)
	findings, _ := m.Run(context.Background(), module.Input{Target: "unknownuser"})
	if len(findings) != 0 {
		t.Error("não esperava findings quando body contém texto de 'não encontrado'")
	}
}

func TestRun_ProbeBodyContain_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<title>johndoe profile page</title><span>johndoe</span>`))
	}))
	defer srv.Close()

	platforms := []socialscan.Platform{{
		Name:       "testplatform",
		Category:   "test",
		URL:        srv.URL + "/%s",
		Probe:      socialscan.ProbeBodyContain,
		ClaimText:  "%s profile page",
		Confidence: 0.88,
	}}

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := socialscan.NewWithPlatforms(c, platforms)
	findings, err := m.Run(context.Background(), module.Input{Target: "johndoe"})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding quando body contém ClaimText")
	}
}

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	platforms := []socialscan.Platform{{
		Name:       "testconf",
		Category:   "test",
		URL:        srv.URL + "/%s",
		Probe:      socialscan.ProbeStatus,
		Confidence: 0.91,
	}}

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := socialscan.NewWithPlatforms(c, platforms)
	findings, _ := m.Run(context.Background(), module.Input{Target: "user"})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	platforms := []socialscan.Platform{{
		Name:       "testdetail",
		Category:   "test",
		URL:        srv.URL + "/%s",
		Probe:      socialscan.ProbeStatus,
		Confidence: 0.85,
	}}

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := socialscan.NewWithPlatforms(c, platforms)
	findings, _ := m.Run(context.Background(), module.Input{Target: "user"})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

func TestRun_AllFindings_HaveURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	platforms := []socialscan.Platform{{
		Name:       "testurls",
		Category:   "test",
		URL:        srv.URL + "/%s",
		Probe:      socialscan.ProbeStatus,
		Confidence: 0.85,
	}}

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := socialscan.NewWithPlatforms(c, platforms)
	findings, _ := m.Run(context.Background(), module.Input{Target: "user"})
	for _, f := range findings {
		if f.URL == "" {
			t.Error("finding sem URL")
		}
	}
}

func TestRun_PlatformFilter_Works(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	platforms := []socialscan.Platform{
		{Name: "github", Category: "dev", URL: srv.URL + "/%s", Probe: socialscan.ProbeStatus, Confidence: 0.97},
		{Name: "twitter", Category: "social", URL: srv.URL + "/%s", Probe: socialscan.ProbeStatus, Confidence: 0.88},
	}

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := socialscan.NewWithPlatforms(c, platforms)

	// Filtra apenas github
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"platforms": "github"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Extra["platform"] == "twitter" {
			t.Error("twitter não deve aparecer quando filtro é 'github'")
		}
	}
}

func TestRun_CategoryFilter_Works(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	platforms := []socialscan.Platform{
		{Name: "github", Category: "dev", URL: srv.URL + "/%s", Probe: socialscan.ProbeStatus, Confidence: 0.97},
		{Name: "twitter", Category: "social", URL: srv.URL + "/%s", Probe: socialscan.ProbeStatus, Confidence: 0.88},
	}

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := socialscan.NewWithPlatforms(c, platforms)

	// Filtra por categoria "dev"
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"platforms": "dev"},
	})
	for _, f := range findings {
		if f.Extra["category"] != "dev" {
			t.Errorf("categoria incorreta quando filtro é 'dev': %s", f.Extra["category"])
		}
	}
}

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = socialscan.New().Run(ctx, module.Input{Target: "testuser"})
}

func TestRun_404_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	platforms := []socialscan.Platform{{
		Name:         "test404",
		Category:     "test",
		URL:          srv.URL + "/%s",
		Probe:        socialscan.ProbeBodyNotContain,
		NotFoundText: "user not found",
		Confidence:   0.85,
	}}

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := socialscan.NewWithPlatforms(c, platforms)
	findings, _ := m.Run(context.Background(), module.Input{Target: "user"})
	if len(findings) != 0 {
		t.Error("404 não deve gerar finding")
	}
}

func TestRun_ResponseTimeInExtra(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	platforms := []socialscan.Platform{{
		Name:       "timingtest",
		Category:   "test",
		URL:        srv.URL + "/%s",
		Probe:      socialscan.ProbeStatus,
		Confidence: 0.85,
	}}

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := socialscan.NewWithPlatforms(c, platforms)
	findings, _ := m.Run(context.Background(), module.Input{Target: "user"})
	for _, f := range findings {
		if f.Extra["response_time_ms"] == "" {
			t.Error("finding deve ter response_time_ms")
		}
	}
}

func TestBuiltinPlatforms_NotEmpty(t *testing.T) {
	platforms := socialscan.BuiltinPlatforms()
	if len(platforms) == 0 {
		t.Fatal("BuiltinPlatforms() não deve retornar lista vazia")
	}
	if len(platforms) < 30 {
		t.Errorf("esperava pelo menos 30 plataformas, obteve %d", len(platforms))
	}
}

func TestBuiltinPlatforms_AllHaveURL(t *testing.T) {
	for _, p := range socialscan.BuiltinPlatforms() {
		if !strings.Contains(p.URL, "%s") {
			t.Errorf("plataforma '%s' não tem %%s no URL", p.Name)
		}
	}
}

func TestBuiltinPlatforms_AllHaveConfidence(t *testing.T) {
	for _, p := range socialscan.BuiltinPlatforms() {
		if p.Confidence <= 0 || p.Confidence > 1 {
			t.Errorf("plataforma '%s' tem confidence inválido: %f", p.Name, p.Confidence)
		}
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if socialscan.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestNewWithClient_ReturnsNonNil(t *testing.T) {
	if socialscan.NewWithClient(http.DefaultClient) == nil {
		t.Fatal("NewWithClient() retornou nil")
	}
}
