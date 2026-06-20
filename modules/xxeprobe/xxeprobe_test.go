package xxeprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func runProbe(t *testing.T, m *Module, urls []string) []module.Finding {
	t.Helper()
	findings, err := m.Run(context.Background(), module.Input{URLs: urls})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	return findings
}

func hasCheck(findings []module.Finding, check string) bool {
	for _, f := range findings {
		if f.Extra["check"] == check {
			return true
		}
	}
	return false
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "xxeprobe" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoInput(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestRun_TargetInput(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	_, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_InbandFileRead_Critical(t *testing.T) {
	// Server echoes the request body in the response (simulates XXE reflection).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If the request body contains an XXE payload targeting /etc/passwd,
		// simulate the server reflecting the file content.
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		reqStr := string(body[:n])
		if strings.Contains(reqStr, "file:///etc/passwd") {
			// Simulate XXE: server processed the entity and includes file content.
			w.WriteHeader(200)
			w.Write([]byte(`<?xml version="1.0"?><root><data>root:x:0:0:root:/root:/bin/bash</data></root>`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`<?xml version="1.0"?><root><data>ok</data></root>`))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runProbe(t, m, []string{srv.URL + "/api/xml"})
	if !hasCheck(findings, "inband-file-read") {
		t.Fatal("expected inband-file-read finding when server reflects /etc/passwd content")
	}
	for _, f := range findings {
		if f.Extra["check"] == "inband-file-read" {
			if f.Severity != module.SeverityCritical {
				t.Errorf("expected Critical severity, got %q", f.Severity)
			}
		}
	}
}

func TestRun_SSRFCloud_Critical(t *testing.T) {
	// Server reflects cloud metadata content when XXE SSRF payload is received.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		reqStr := string(body[:n])
		if strings.Contains(reqStr, "169.254.169.254") {
			w.WriteHeader(200)
			// Simulate: server fetched IMDS and returned the content.
			w.Write([]byte(`<root><data>ami-id=ami-12345678</data></root>`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`<root><data>ok</data></root>`))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runProbe(t, m, []string{srv.URL + "/api/xml"})
	if !hasCheck(findings, "ssrf-cloud-metadata") {
		t.Fatal("expected ssrf-cloud-metadata finding when IMDS content reflected")
	}
	for _, f := range findings {
		if f.Extra["check"] == "ssrf-cloud-metadata" {
			if f.Severity != module.SeverityCritical {
				t.Errorf("expected Critical severity, got %q", f.Severity)
			}
		}
	}
}

func TestRun_ErrorBased_Medium(t *testing.T) {
	// Server returns a verbose XML parser error.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error: javax.xml.parsers.SAXParseException: entity not found`))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runProbe(t, m, []string{srv.URL + "/parse"})
	if !hasCheck(findings, "error-based") {
		t.Fatal("expected error-based finding for verbose XML parser error")
	}
	for _, f := range findings {
		if f.Extra["check"] == "error-based" {
			if f.Severity != module.SeverityMedium {
				t.Errorf("expected Medium severity, got %q", f.Severity)
			}
		}
	}
}

func TestRun_NoVulnerability_NoFindings(t *testing.T) {
	// Normal server: returns 200 with generic XML response.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(200)
		w.Write([]byte(`<?xml version="1.0"?><root><status>ok</status></root>`))
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runProbe(t, m, []string{srv.URL + "/api/safe"})
	for _, f := range findings {
		if f.Extra["check"] == "inband-file-read" || f.Extra["check"] == "ssrf-cloud-metadata" {
			t.Errorf("safe server should not trigger %q finding", f.Extra["check"])
		}
	}
}

func TestRun_SVGPayload_Included(t *testing.T) {
	m := New()
	payloads := m.buildPayloads()
	hasSVG := false
	for _, p := range payloads {
		if p.name == "svg-xxe" {
			hasSVG = true
			break
		}
	}
	if !hasSVG {
		t.Fatal("expected SVG XXE payload to be included")
	}
}

func TestRun_OOBPayloads_WhenConfigured(t *testing.T) {
	m := New()
	m.OOBHost = "test.oast.me"
	payloads := m.buildPayloads()
	hasOOB := false
	for _, p := range payloads {
		if p.kind == "oob" {
			hasOOB = true
			break
		}
	}
	if !hasOOB {
		t.Fatal("expected OOB payloads when OOBHost is set")
	}
}

func TestRun_OOBPayloads_NotEmittedAsLocalFindings(t *testing.T) {
	// OOB probes should never produce local findings.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	m.OOBHost = "test.oast.me"
	findings := runProbe(t, m, []string{srv.URL + "/"})
	for _, f := range findings {
		if f.Extra["kind"] == "oob" {
			t.Fatal("OOB probes should not produce local findings")
		}
	}
}

func TestRun_PayloadCount(t *testing.T) {
	m := New()
	payloads := m.buildPayloads()
	if len(payloads) < 8 {
		t.Fatalf("expected at least 8 payloads, got %d", len(payloads))
	}
}

func TestRun_PayloadContentTypes(t *testing.T) {
	m := New()
	payloads := m.buildPayloads()
	ctypes := make(map[string]bool)
	for _, p := range payloads {
		ctypes[p.contentType] = true
	}
	if !ctypes["application/xml"] {
		t.Fatal("expected application/xml content type")
	}
	if !ctypes["text/xml"] {
		t.Fatal("expected text/xml content type")
	}
	if !ctypes["image/svg+xml"] {
		t.Fatal("expected image/svg+xml content type")
	}
}

func TestRun_RawContent_Input(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	_, err := m.Run(context.Background(), module.Input{
		RawContent: srv.URL + "/api1\n" + srv.URL + "/api2",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCollectURLs_OnlyHTTP(t *testing.T) {
	input := module.Input{
		URLs: []string{
			"https://example.com/api",
			"http://other.com/xml",
			"ftp://bad.com", // should be excluded
			"just-a-domain", // should be excluded
		},
	}
	urls := collectURLs(input)
	if len(urls) != 2 {
		t.Fatalf("expected 2 HTTP(S) URLs, got %d: %v", len(urls), urls)
	}
}

func TestCollectURLs_Dedup(t *testing.T) {
	input := module.Input{
		Target: "https://example.com/xml",
		URLs:   []string{"https://example.com/xml", "https://other.com/xml"},
	}
	urls := collectURLs(input)
	if len(urls) != 2 {
		t.Fatalf("expected 2 unique URLs, got %d", len(urls))
	}
}

func TestFileReadMarkers_NotEmpty(t *testing.T) {
	if len(fileReadMarkers) < 5 {
		t.Fatalf("expected at least 5 file read markers, got %d", len(fileReadMarkers))
	}
}

func TestCloudMetadataMarkers_NotEmpty(t *testing.T) {
	if len(cloudMetadataMarkers) < 4 {
		t.Fatalf("expected at least 4 cloud metadata markers, got %d", len(cloudMetadataMarkers))
	}
}

func TestIsXMLContentType(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"application/xml", true},
		{"text/xml; charset=utf-8", true},
		{"image/svg+xml", true},
		{"application/json", false},
		{"text/html", false},
	}
	for _, c := range cases {
		got := isXMLContentType(c.ct)
		if got != c.want {
			t.Errorf("isXMLContentType(%q) = %v, want %v", c.ct, got, c.want)
		}
	}
}

func TestWindowsPayloads_Included(t *testing.T) {
	m := New()
	payloads := m.buildPayloads()
	hasWindows := false
	for _, p := range payloads {
		if strings.Contains(p.name, "windows") {
			hasWindows = true
			break
		}
	}
	if !hasWindows {
		t.Fatal("expected Windows file read payloads to be included")
	}
}

func TestProcEnvironPayload_Included(t *testing.T) {
	m := New()
	payloads := m.buildPayloads()
	has := false
	for _, p := range payloads {
		if strings.Contains(p.xml, "/proc/self/environ") {
			has = true
			break
		}
	}
	if !has {
		t.Fatal("expected /proc/self/environ payload to be included")
	}
}
