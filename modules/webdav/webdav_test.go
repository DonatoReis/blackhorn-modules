package webdav_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/webdav"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// webdavServer: full WebDAV server (OPTIONS returns DAV, PROPFIND returns 207,
// PUT returns 201, MKCOL returns 201).
func webdavServer(t *testing.T) *httptest.Server {
	t.Helper()
	files := make(map[string]string)
	var filesMu sync.RWMutex
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "OPTIONS":
			w.Header().Set("DAV", "1, 2, ordered-collections")
			w.Header().Set("Allow", "OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK")
			w.Header().Set("MS-Author-Via", "DAV")
			w.WriteHeader(200)
		case "PROPFIND":
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(207)
			w.Write([]byte(`<?xml version="1.0"?><multistatus xmlns="DAV:"><response><href>/</href><propstat><prop><resourcetype><collection/></resourcetype></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>`))
		case "PUT":
			body, _ := io.ReadAll(r.Body)
			filesMu.Lock()
			files[r.URL.Path] = string(body)
			filesMu.Unlock()
			w.WriteHeader(201)
		case "DELETE":
			filesMu.Lock()
			delete(files, r.URL.Path)
			filesMu.Unlock()
			w.WriteHeader(204)
		case "MKCOL":
			w.WriteHeader(201)
		case "GET":
			filesMu.RLock()
			if content, ok := files[r.URL.Path]; ok {
				filesMu.RUnlock()
				w.WriteHeader(200)
				fmt.Fprint(w, content)
			} else {
				filesMu.RUnlock()
				w.WriteHeader(404)
			}
		default:
			w.WriteHeader(405)
		}
	}))
}

// optionsOnlyServer: returns OPTIONS with dangerous methods but no actual WebDAV.
func optionsOnlyServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("Allow", "OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND")
			w.WriteHeader(200)
			return
		}
		if r.Method == "PROPFIND" {
			w.WriteHeader(405) // Not actually WebDAV.
			return
		}
		w.WriteHeader(405)
	}))
}

// safeServer: only allows GET, HEAD.
func safeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("Allow", "OPTIONS, GET, HEAD")
			w.WriteHeader(200)
			return
		}
		if r.Method == "GET" {
			w.WriteHeader(200)
			w.Write([]byte(`OK`))
			return
		}
		w.WriteHeader(405)
	}))
}

// propfindServer: returns 207 only for PROPFIND.
func propfindServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PROPFIND" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(207)
			w.Write([]byte(`<?xml version="1.0"?><multistatus xmlns="DAV:"></multistatus>`))
			return
		}
		if r.Method == "OPTIONS" {
			w.Header().Set("Allow", "OPTIONS, GET, PROPFIND")
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`OK`))
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := webdav.New()
	if m.Name() != "webdav" {
		t.Fatalf("expected 'webdav', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = webdav.New()
}

// TestDAVHeaderDetected: OPTIONS returns DAV header.
func TestDAVHeaderDetected(t *testing.T) {
	srv := webdavServer(t)
	defer srv.Close()

	m := webdav.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "webdav_enabled" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected webdav_enabled finding, got: %v", findings)
	}
}

// TestDangerousMethodsDetected: Allow header has PUT/DELETE/PROPFIND.
func TestDangerousMethodsDetected(t *testing.T) {
	srv := optionsOnlyServer(t)
	defer srv.Close()

	m := webdav.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "webdav_dangerous_methods" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected webdav_dangerous_methods finding, got: %v", findings)
	}
}

// TestPropfindListingDetected: PROPFIND returns 207.
func TestPropfindListingDetected(t *testing.T) {
	srv := propfindServer(t)
	defer srv.Close()

	m := webdav.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "webdav_propfind_listing" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected webdav_propfind_listing finding, got: %v", findings)
	}
}

// TestPutUploadDetected: PUT returns 201.
func TestPutUploadDetected(t *testing.T) {
	srv := webdavServer(t)
	defer srv.Close()

	m := webdav.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "webdav_put_upload" {
			found = true
			if f.Severity != module.SeverityCritical {
				t.Errorf("PUT upload should be Critical, got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected webdav_put_upload finding, got: %v", findings)
	}
}

// TestMkcolDetected: MKCOL returns 201.
func TestMkcolDetected(t *testing.T) {
	srv := webdavServer(t)
	defer srv.Close()

	m := webdav.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "webdav_mkcol" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected webdav_mkcol finding, got: %v", findings)
	}
}

// TestNoVulnerability: safe server → no findings.
func TestNoVulnerability(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := webdav.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on safe server, got %d: %v", len(findings), findings)
	}
}

// TestEmptyInput: no targets → nil.
func TestEmptyInput(t *testing.T) {
	m := webdav.New()
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(findings))
	}
}

// TestContextCancellation: cancelled context does not panic.
func TestContextCancellation(t *testing.T) {
	srv := webdavServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := webdav.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{Target: srv.URL + "/"})
	_ = err
}

// TestDeduplication: same check on same URL not duplicated.
func TestDeduplication(t *testing.T) {
	srv := webdavServer(t)
	defer srv.Close()

	u := srv.URL + "/"
	m := webdav.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{u, u, u},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Type + "|" + f.Extra["check_id"]
		seen[key]++
	}
	for k, count := range seen {
		if count > 1 {
			t.Errorf("duplicate finding %q count=%d", k, count)
		}
	}
}

// TestFindingFields: all required fields populated.
func TestFindingFields(t *testing.T) {
	srv := webdavServer(t)
	defer srv.Close()

	m := webdav.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.URL == "" {
		t.Error("URL empty")
	}
	if f.Detail == "" {
		t.Error("Detail empty")
	}
	if f.Severity == "" {
		t.Error("Severity empty")
	}
	if f.Extra["check_id"] == "" {
		t.Error("Extra.check_id empty")
	}
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := webdav.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/",
		Options: map[string]string{"parallelism": "3"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := webdavServer(t)
	defer srv.Close()

	m := webdav.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from Target")
	}
}

// TestNewWithClient: does not panic.
func TestNewWithClient(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := webdav.NewWithClient(c)
	if m == nil || m.Name() != "webdav" {
		t.Fatal("NewWithClient failed")
	}
}

// TestDetailHasWebDAVPrefix: Detail starts with [WebDAV].
func TestDetailHasWebDAVPrefix(t *testing.T) {
	srv := webdavServer(t)
	defer srv.Close()

	m := webdav.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.Detail, "[WebDAV]") {
			t.Errorf("Detail %q missing '[WebDAV]'", f.Detail)
		}
	}
}

// TestMultipleURLs: multiple targets processed.
func TestMultipleURLs(t *testing.T) {
	srv := webdavServer(t)
	defer srv.Close()

	m := webdav.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/", srv.URL + "/uploads/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestAllFindingTypes: full WebDAV server produces multiple finding types.
func TestAllFindingTypes(t *testing.T) {
	srv := webdavServer(t)
	defer srv.Close()

	m := webdav.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	types := make(map[string]struct{})
	for _, f := range findings {
		types[f.Type] = struct{}{}
	}

	expected := []string{"webdav_enabled", "webdav_dangerous_methods", "webdav_propfind_listing", "webdav_put_upload", "webdav_mkcol"}
	for _, want := range expected {
		if _, ok := types[want]; !ok {
			t.Errorf("expected finding type %q", want)
		}
	}
}
