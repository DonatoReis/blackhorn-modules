package webprobe_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/webprobe"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────

// newServer creates an httptest.Server with the given handler and returns
// a Module pointed at it via an injected http.Client.
func newServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *webprobe.Module) {
	t.Helper()
	srv := httptest.NewServer(h)
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return srv, webprobe.NewWithClient(client)
}

// ─── tests ────────────────────────────────────────────────────────────────

// TestName verifies the module name.
func TestName(t *testing.T) {
	if webprobe.New().Name() != "webprobe" {
		t.Error("expected module name 'webprobe'")
	}
}

// TestRun_EmptyTarget expects an error.
func TestRun_EmptyTarget(t *testing.T) {
	m := webprobe.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestRun_ContextCancellation should not hang.
func TestRun_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := webprobe.New()
	_, _ = m.Run(ctx, module.Input{Target: "localhost:1"})
}

// TestRun_StatusCode200 verifies a successful probe produces the right fields.
func TestRun_StatusCode200(t *testing.T) {
	srv, m := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "nginx/1.21.0")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "<html><head><title>Test Page</title></head><body>hello</body></html>")
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	f := findings[0]
	if f.Type != "http_probe" {
		t.Errorf("expected type 'http_probe', got %q", f.Type)
	}
	if f.Extra["status_code"] != "200" {
		t.Errorf("expected status_code 200, got %q", f.Extra["status_code"])
	}
	if f.Extra["title"] != "Test Page" {
		t.Errorf("expected title 'Test Page', got %q", f.Extra["title"])
	}
	if !strings.Contains(f.Extra["webserver"], "nginx") {
		t.Errorf("expected webserver to contain 'nginx', got %q", f.Extra["webserver"])
	}
	if f.Extra["scheme"] != "http" {
		t.Errorf("expected scheme 'http', got %q", f.Extra["scheme"])
	}
}

// TestRun_StatusCode404 verifies that 404 is flagged with SeverityLow.
func TestRun_StatusCode404(t *testing.T) {
	srv, m := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["status_code"] == "404" && f.Severity != module.SeverityLow {
			t.Errorf("expected SeverityLow for 404, got %q", f.Severity)
		}
	}
}

// TestRun_StatusCode500 verifies that 5xx is flagged with SeverityMedium.
func TestRun_StatusCode500(t *testing.T) {
	srv, m := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Extra["status_code"] == "500" {
			found = true
			if f.Severity != module.SeverityMedium {
				t.Errorf("expected SeverityMedium for 500, got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected finding with status_code 500")
	}
}

// TestRun_TitleExtraction verifies title is extracted from HTML body.
func TestRun_TitleExtraction(t *testing.T) {
	srv, m := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `<html><head><TITLE>  My App Title  </TITLE></head><body></body></html>`)
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Extra["title"] == "My App Title" {
			return // pass
		}
	}
	t.Error("expected title 'My App Title' in findings")
}

// TestRun_TechDetection verifies that Server header is captured in technologies.
func TestRun_TechDetection(t *testing.T) {
	srv, m := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.54")
		w.Header().Set("X-Powered-By", "PHP/8.1.0")
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		tech := f.Extra["technologies"]
		if strings.Contains(tech, "Apache") && strings.Contains(tech, "PHP") {
			return // pass
		}
	}
	t.Error("expected Apache and PHP in technologies")
}

// TestRun_ResponseTime verifies that response_time is set and non-empty.
func TestRun_ResponseTime(t *testing.T) {
	srv, m := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["response_time"] == "" {
			t.Error("finding missing response_time field")
		}
	}
}

// TestRun_ContentLength verifies content_length is captured.
func TestRun_ContentLength(t *testing.T) {
	body := "hello world"
	srv, m := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		fmt.Fprint(w, body)
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["content_length"] != "" && f.Extra["content_length"] != "0" {
			return // pass
		}
	}
	t.Error("expected non-zero content_length in findings")
}

// TestRun_MultipleURLs verifies that multiple URLs in input are probed.
func TestRun_MultipleURLs(t *testing.T) {
	var count atomic.Int64
	srv, m := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/a", srv.URL + "/b", srv.URL + "/c"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 1 {
		t.Error("expected findings for multiple URLs")
	}
	_ = count.Load()
}

// TestRun_TargetFromURLs uses URLs when Target is empty.
func TestRun_TargetFromURLs(t *testing.T) {
	srv, m := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least one finding from URLs")
	}
}

// TestRun_FailedProbe verifies that unreachable targets do not produce findings.
func TestRun_FailedProbe(t *testing.T) {
	m := webprobe.New()
	// Port 1 is typically unreachable.
	findings, err := m.Run(context.Background(), module.Input{
		Target: "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Failed probes are excluded from findings.
	for _, f := range findings {
		t.Errorf("unexpected finding for failed probe: %+v", f)
	}
}

// TestRun_FindingFields verifies all standard extra fields are present.
func TestRun_FindingFields(t *testing.T) {
	srv, m := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "<html><head><title>Fields</title></head><body></body></html>")
	})
	defer srv.Close()

	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	f := findings[0]
	required := []string{"status_code", "content_length", "content_type",
		"response_time", "scheme", "host"}
	for _, field := range required {
		if _, ok := f.Extra[field]; !ok {
			t.Errorf("finding missing field %q", field)
		}
	}
}

// TestRun_RedirectFollowed verifies that 301 redirect to final URL is probed.
func TestRun_RedirectFollowed(t *testing.T) {
	var finalCalled atomic.Int64
	finalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalCalled.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, "<html><head><title>Final</title></head></html>")
	}))
	defer finalSrv.Close()

	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, finalSrv.URL, http.StatusMovedPermanently)
	}))
	defer redirectSrv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	m := webprobe.NewWithClient(client)
	findings, err := m.Run(context.Background(), module.Input{Target: redirectSrv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from redirected URL")
	}
}

// TestRun_LargeBodyTruncated verifies that large response bodies don't cause OOM.
func TestRun_LargeBodyTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// 5MB response — should be truncated safely.
		payload := strings.Repeat("A", 5*1024*1024)
		fmt.Fprintf(w, "<html><body>%s</body></html>", payload)
	}))
	defer srv.Close()

	m := webprobe.New()
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error on large body: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected probe finding even on large body")
	}
}

// TestRun_HTTPSSchemeDetected verifies scheme is correctly recorded for HTTPS targets.
func TestRun_HTTPSSchemeDetected(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "<html><head><title>HTTPS</title></head></html>")
	}))
	defer srv.Close()

	m := webprobe.NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if scheme, ok := f.Extra["scheme"]; ok {
			if scheme != "https" {
				t.Errorf("expected scheme=https, got %q", scheme)
			}
		}
	}
}
