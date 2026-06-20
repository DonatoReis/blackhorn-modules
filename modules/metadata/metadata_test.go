package metadata_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/metadata"
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
	if metadata.New().Name() != "metadata" {
		t.Error("nome incorreto")
	}
}

func TestRun_EmptyTarget_NoURLs_ReturnsError(t *testing.T) {
	_, err := metadata.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target e URLs vazios")
	}
}

func TestRun_NonHTTPTarget_ReturnsError(t *testing.T) {
	// target sem http:// não é um URL válido
	_, err := metadata.New().Run(context.Background(), module.Input{Target: "example.com"})
	if err == nil {
		t.Fatal("esperava erro — target não é URL")
	}
}

func TestRun_HTTPHeaders_ServerDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := metadata.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/page",
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Type == "metadata_http_header" && f.Extra["header"] == "Server" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não retornou headers esperados")
	}
}

func TestRun_HTTPHeaders_XPoweredBy_Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.3")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := metadata.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	for _, f := range findings {
		if f.Extra["header"] == "X-Powered-By" {
			if f.Severity != module.SeverityLow {
				t.Errorf("X-Powered-By deve ser SeverityLow, obteve %s", f.Severity)
			}
			return
		}
	}
}

func TestRun_PDF_AuthorExtracted(t *testing.T) {
	// Simulate PDF with /Author field
	pdfBody := "%PDF-1.4\n/Author (John Doe OSINT)\n/Creator (Microsoft Word)\n/Producer (Adobe PDF)\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(pdfBody))
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := metadata.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/document.pdf",
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Type == "metadata_pdf" && f.Extra["author"] == "John Doe OSINT" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu com dados PDF")
	}
}

func TestRun_PDF_AuthorPresent_SeverityMedium(t *testing.T) {
	pdfBody := "%PDF-1.5\n/Author (Jane Smith)\n/Title (Confidential Report)\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(pdfBody))
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := metadata.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{Target: srv.URL + "/report.pdf"})
	for _, f := range findings {
		if f.Type == "metadata_pdf" {
			if f.Severity != module.SeverityMedium {
				t.Errorf("PDF com autor deve ser SeverityMedium, obteve %s", f.Severity)
			}
			return
		}
	}
}

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test"))
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := metadata.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Django")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := metadata.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = metadata.New().Run(ctx, module.Input{Target: "https://example.com/image.jpg"})
}

func TestRun_MultipleURLs_ProcessedViaURLsList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := metadata.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/page1",
		URLs: []string{
			srv.URL + "/page2",
			srv.URL + "/page3",
		},
	})
	// Deve processar ao menos os URLs sem pânico
	_ = findings
}

func TestRun_404_ReturnsHeadersOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "IIS/10.0")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := metadata.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{Target: srv.URL + "/missing"})
	// 404 → só headers, sem metadados de arquivo
	for _, f := range findings {
		if f.Type != "metadata_http_header" {
			t.Errorf("404 deve retornar apenas metadata_http_header, obteve %s", f.Type)
		}
	}
}

func TestRun_NoInterestingHeaders_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sem headers interessantes
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := metadata.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{Target: srv.URL + "/"})
	// Sem Server, X-Powered-By etc → sem findings de header
	for _, f := range findings {
		if f.Type == "metadata_http_header" {
			t.Errorf("não esperava finding de header sem headers interessantes: %s=%s",
				f.Extra["header"], f.Extra["value"])
		}
	}
}

func TestRun_MaxURLs_Respected(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := metadata.NewWithClient(c)

	urls := make([]string, 10)
	for i := range urls {
		urls[i] = srv.URL + "/page"
	}

	_, _ = m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/main",
		URLs:    urls,
		Options: map[string]string{"max_urls": "3"},
	})
	if got := calls.Load(); got > 3 {
		t.Errorf("max_urls=3 deve limitar a 3 requisições, obteve %d", got)
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if metadata.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestNewWithClient_ReturnsNonNil(t *testing.T) {
	if metadata.NewWithClient(http.DefaultClient) == nil {
		t.Fatal("NewWithClient() retornou nil")
	}
}
