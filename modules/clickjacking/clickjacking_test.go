package clickjacking_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/clickjacking"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

func serverWithHeaders(t *testing.T, headers map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(200)
		w.Write([]byte("<html><body>Content</body></html>"))
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := clickjacking.New()
	if m.Name() != "clickjacking" {
		t.Fatalf("expected 'clickjacking', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = clickjacking.New()
}

// TestMissingBothHeaders: no XFO and no CSP → High finding.
func TestMissingBothHeaders(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{})
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for missing XFO and CSP")
	}
	for _, f := range findings {
		if strings.Contains(f.Extra["check"], "missing-xfo") && f.Severity != module.SeverityHigh {
			t.Errorf("expected High severity for missing headers, got %q", f.Severity)
		}
	}
}

// TestDENYIsProtected: X-Frame-Options: DENY → no missing-XFO finding.
func TestDENYIsProtected(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{"X-Frame-Options": "DENY"})
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["check"] == "missing-xfo-and-csp" {
			t.Errorf("should not flag missing XFO when DENY is set: %v", f)
		}
		if f.Extra["check"] == "xfo-unknown-value" {
			t.Errorf("DENY should not trigger unknown-value: %v", f)
		}
	}
}

// TestSAMEORIGINIsProtected: X-Frame-Options: SAMEORIGIN → no XFO finding.
func TestSAMEORIGINIsProtected(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{"X-Frame-Options": "SAMEORIGIN"})
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["check"] == "missing-xfo-and-csp" || f.Extra["check"] == "xfo-unknown-value" {
			t.Errorf("SAMEORIGIN should not trigger XFO findings: %v", f)
		}
	}
}

// TestCSPFrameAncestorsNone: CSP frame-ancestors 'none' (no XFO) → protected.
func TestCSPFrameAncestorsNone(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{
		"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
	})
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["check"] == "missing-xfo-and-csp" {
			t.Errorf("frame-ancestors 'none' should prevent missing-csp finding: %v", f)
		}
	}
}

// TestCSPFrameAncestorsWildcard: CSP frame-ancestors * → High finding.
func TestCSPFrameAncestorsWildcard(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{
		"Content-Security-Policy": "default-src 'self'; frame-ancestors *",
	})
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Extra["check"] == "csp-frame-ancestors-wildcard" {
			found = true
			if f.Severity != module.SeverityHigh {
				t.Errorf("expected High severity for frame-ancestors:*, got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected csp-frame-ancestors-wildcard finding")
	}
}

// TestXFOAllowAll: ALLOWALL triggers High finding.
func TestXFOAllowAll(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{"X-Frame-Options": "ALLOWALL"})
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Extra["check"] == "xfo-allowall" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected xfo-allowall finding")
	}
}

// TestXFOAllowFrom: ALLOW-FROM triggers Medium deprecated finding.
func TestXFOAllowFrom(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{"X-Frame-Options": "ALLOW-FROM https://trusted.example.com"})
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Extra["check"] == "xfo-allow-from-deprecated" {
			found = true
			if f.Severity != module.SeverityMedium {
				t.Errorf("expected Medium severity for ALLOW-FROM, got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected xfo-allow-from-deprecated finding")
	}
}

// TestXFOUnknownValue: unrecognized XFO value triggers Medium finding.
func TestXFOUnknownValue(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{"X-Frame-Options": "INVALID_VALUE"})
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Extra["check"] == "xfo-unknown-value" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected xfo-unknown-value finding")
	}
}

// TestConflictDenyPlusCspWildcard: DENY + frame-ancestors: * → conflict finding.
func TestConflictDenyPlusCspWildcard(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'self'; frame-ancestors *",
	})
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Extra["check"] == "xfo-csp-conflict" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected xfo-csp-conflict finding")
	}
}

// TestEmptyInput: no targets returns nil.
func TestEmptyInput(t *testing.T) {
	m := clickjacking.New()
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
	srv := serverWithHeaders(t, map[string]string{})
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := clickjacking.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{URLs: []string{srv.URL + "/"}})
	_ = err
}

// TestFindingFields: all required fields populated.
func TestFindingFields(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{})
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type != "clickjacking" {
		t.Errorf("Type = %q, want 'clickjacking'", f.Type)
	}
	if f.URL == "" {
		t.Error("URL empty")
	}
	if f.Detail == "" {
		t.Error("Detail empty")
	}
	if f.Severity == "" {
		t.Error("Severity empty")
	}
	if f.Extra["check"] == "" {
		t.Error("Extra.check empty")
	}
}

// TestDeduplication: same URL+finding key not duplicated.
func TestDeduplication(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{})
	defer srv.Close()

	u := srv.URL + "/"
	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{u, u, u},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Extra["check"]
		seen[key]++
	}
	for k, count := range seen {
		if count > 1 {
			t.Errorf("duplicate finding %q count=%d", k, count)
		}
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{})
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from Target field")
	}
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{})
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"parallelism": "5"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestNewWithClientReplaces: NewWithClient does not panic.
func TestNewWithClientReplaces(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := clickjacking.NewWithClient(c)
	if m == nil || m.Name() != "clickjacking" {
		t.Fatal("NewWithClient failed")
	}
}

// TestFindingType: all findings have Type == "clickjacking".
func TestFindingType(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{})
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type != "clickjacking" {
			t.Errorf("finding.Type = %q, want 'clickjacking'", f.Type)
		}
	}
}

// TestHTTPErrorSkipped: 4xx responses are not checked.
func TestHTTPErrorSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/notfound"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for 404, got %d", len(findings))
	}
}

// TestMultipleURLs: multiple URLs all checked.
func TestMultipleURLs(t *testing.T) {
	srv := serverWithHeaders(t, map[string]string{})
	defer srv.Close()

	m := clickjacking.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/", srv.URL + "/login", srv.URL + "/dashboard"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) < 3 {
		t.Errorf("expected at least 3 findings (one per URL), got %d", len(findings))
	}
}
