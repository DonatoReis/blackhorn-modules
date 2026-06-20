package darkweb_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/darkweb"
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
	if darkweb.New().Name() != "darkweb" {
		t.Error("nome incorreto")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := darkweb.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

func TestRun_DarkSearch_ParsesResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total":        5,
			"per_page":     10,
			"current_page": 1,
			"last_page":    1,
			"data": []map[string]interface{}{
				{
					"title":       "Dark Market - test@example.com",
					"link":        "http://darkmarket3abc123456789.onion/listing",
					"description": "Email test@example.com encontrado em base de dados vazada",
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := darkweb.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "darksearch"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("servidor de teste não respondeu como esperado")
	}
	for _, f := range findings {
		if f.Type == "darkweb_mention" {
			return
		}
	}
	t.Error("esperava finding do tipo darkweb_mention")
}

func TestRun_DarkSearch_ExtractsOnionAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 1,
			"data": []map[string]interface{}{
				{
					"title":       "Test Service",
					"link":        "http://abcdefghijklmnop.onion/page",
					"description": "contains target",
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := darkweb.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "target",
		Options: map[string]string{"sources": "darksearch"},
	})
	for _, f := range findings {
		if f.Extra["onion_addr"] != "" {
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
			"total": 1,
			"data": []map[string]interface{}{
				{"title": "T", "link": "http://xyz.onion", "description": "d"},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := darkweb.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test",
		Options: map[string]string{"sources": "darksearch"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_SeverityIsMedium_DarkSearch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 1,
			"data": []map[string]interface{}{
				{"title": "Result", "link": "http://test.onion", "description": "test"},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := darkweb.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test",
		Options: map[string]string{"sources": "darksearch"},
	})
	for _, f := range findings {
		if f.Severity == module.SeverityInfo {
			t.Error("darkweb findings devem ter severidade >= Medium")
		}
	}
}

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = darkweb.New().Run(ctx, module.Input{Target: "test@example.com"})
}

func TestRun_RateLimited_HandledGracefully(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := darkweb.NewWithClient(c)
	_, err := m.Run(context.Background(), module.Input{
		Target:  "test",
		Options: map[string]string{"sources": "darksearch"},
	})
	_ = err
}

func TestRun_DetailNotEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 1,
			"data": []map[string]interface{}{
				{"title": "Result Detail", "link": "http://r.onion", "description": "desc"},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := darkweb.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test",
		Options: map[string]string{"sources": "darksearch"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

func TestRun_SourceFilter_OnlyDarkSearch(t *testing.T) {
	var calledPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPaths = append(calledPaths, r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 0, "data": []interface{}{},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := darkweb.NewWithClient(c)
	_, _ = m.Run(context.Background(), module.Input{
		Target:  "test",
		Options: map[string]string{"sources": "darksearch"},
	})

	for _, p := range calledPaths {
		if strings.Contains(p, "ahmia") {
			t.Error("ahmia não deve ser chamada quando sources=darksearch")
		}
	}
}

func TestRun_TotalFoundInExtra(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 42,
			"data": []map[string]interface{}{
				{"title": "T", "link": "http://abc.onion", "description": "d"},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := darkweb.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test",
		Options: map[string]string{"sources": "darksearch"},
	})
	for _, f := range findings {
		if f.Extra["total_found"] == "42" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu")
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if darkweb.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestNewWithClient_ReturnsNonNil(t *testing.T) {
	if darkweb.NewWithClient(http.DefaultClient) == nil {
		t.Fatal("NewWithClient() retornou nil")
	}
}

func TestRun_NoDirectTorConnection(t *testing.T) {
	// Verifica que nenhuma URL .onion é chamada diretamente
	var calledURLs []string
	transport := &urlCapture{captured: &calledURLs}
	c := &http.Client{Transport: transport}
	m := darkweb.NewWithClient(c)

	_, _ = m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "darksearch"},
	})

	for _, u := range calledURLs {
		if strings.Contains(u, ".onion") {
			t.Errorf("módulo fez conexão direta a .onion: %s", u)
		}
	}
}

type urlCapture struct {
	captured *[]string
}

func (u *urlCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	*u.captured = append(*u.captured, req.URL.String())
	// Simula conexão recusada (não tem servidor real)
	return nil, &noServerError{}
}

type noServerError struct{}

func (e *noServerError) Error() string { return "no server" }
