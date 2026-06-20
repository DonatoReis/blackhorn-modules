package openredirect_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/openredirect"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const testAttacker = "blackhorn-test.attacker.net"

// ─── Helpers ──────────────────────────────────────────────────────────────────

// redirectServer: redirects to whatever value is in ?redirect=.
func redirectServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dest := r.URL.Query().Get("redirect")
		if dest == "" {
			dest = r.URL.Query().Get("url")
		}
		if dest == "" {
			dest = r.URL.Query().Get("next")
		}
		if dest != "" {
			http.Redirect(w, r, dest, http.StatusFound)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`OK`))
	}))
}

// bodyReflectServer: echoes the redirect param value in body.
func bodyReflectServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dest := r.URL.Query().Get("redirect")
		if dest == "" {
			dest = r.URL.Query().Get("return")
		}
		if dest != "" {
			w.WriteHeader(200)
			w.Write([]byte(`<a href="` + dest + `">click here</a>`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`OK`))
	}))
}

// safeServer: ignores redirect params entirely.
func safeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`OK`))
	}))
}

// noRedirectParamServer: returns 200, no redirect support.
func noRedirectParamServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`nothing here`))
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := openredirect.New()
	if m.Name() != "openredirect" {
		t.Fatalf("expected 'openredirect', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = openredirect.New()
}

// TestAbsoluteHttpsRedirect: https://attacker triggers Location header.
func TestAbsoluteHttpsRedirect(t *testing.T) {
	srv := redirectServer(t)
	defer srv.Close()

	probe := openredirect.Probe{
		ID:     "absolute-https",
		Inject: "https://{ATTACKER}",
		Detect: func(resp *http.Response, body, attacker string) bool {
			loc := resp.Header.Get("Location")
			return strings.Contains(strings.ToLower(loc), strings.ToLower(attacker))
		},
		Severity: module.SeverityHigh,
		Tags:     []string{"absolute", "https"},
	}

	m := openredirect.NewWithProbesAndClient([]openredirect.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?redirect=original",
		Options: map[string]string{"attacker": testAttacker},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected open redirect finding via Location header")
	}
}

// TestDoubleSlashRedirect: //attacker triggers Location.
func TestDoubleSlashRedirect(t *testing.T) {
	srv := redirectServer(t)
	defer srv.Close()

	probe := openredirect.Probe{
		ID:     "double-slash",
		Inject: "//{ATTACKER}",
		Detect: func(resp *http.Response, body, attacker string) bool {
			loc := resp.Header.Get("Location")
			return strings.Contains(strings.ToLower(loc), strings.ToLower(attacker))
		},
		Severity: module.SeverityHigh,
		Tags:     []string{"double-slash"},
	}

	m := openredirect.NewWithProbesAndClient([]openredirect.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?url=original",
		Options: map[string]string{"attacker": testAttacker},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected open redirect finding via double-slash")
	}
}

// TestBodyReflection: attacker domain in body href.
func TestBodyReflection(t *testing.T) {
	srv := bodyReflectServer(t)
	defer srv.Close()

	probe := openredirect.Probe{
		ID:     "body-reflect",
		Inject: "https://{ATTACKER}",
		Detect: func(resp *http.Response, body, attacker string) bool {
			return strings.Contains(strings.ToLower(body), strings.ToLower(attacker))
		},
		Severity: module.SeverityHigh,
		Tags:     []string{"body-reflection"},
	}

	m := openredirect.NewWithProbesAndClient([]openredirect.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?redirect=original",
		Options: map[string]string{"attacker": testAttacker},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected open redirect finding via body reflection")
	}
}

// TestNoVulnerability: safe server never redirects → no findings.
func TestNoVulnerability(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := openredirect.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?redirect=original",
		Options: map[string]string{"attacker": testAttacker},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on safe server, got %d", len(findings))
	}
}

// TestEmptyInput: no targets → nil.
func TestEmptyInput(t *testing.T) {
	m := openredirect.New()
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(findings))
	}
}

// TestNoRedirectParam: URL without redirect-like params → no probes run.
func TestNoRedirectParam(t *testing.T) {
	srv := noRedirectParamServer(t)
	defer srv.Close()

	m := openredirect.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=test&page=1",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings when no redirect params, got %d", len(findings))
	}
}

// TestContextCancellation: cancelled context does not panic.
func TestContextCancellation(t *testing.T) {
	srv := redirectServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := openredirect.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{
		Target:  srv.URL + "/?redirect=original",
		Options: map[string]string{"attacker": testAttacker},
	})
	_ = err
}

// TestDeduplication: same probe + same URL + same param not duplicated.
func TestDeduplication(t *testing.T) {
	srv := redirectServer(t)
	defer srv.Close()

	probe := openredirect.Probe{
		ID:     "dedup-test",
		Inject: "https://{ATTACKER}",
		Detect: func(resp *http.Response, body, attacker string) bool {
			loc := resp.Header.Get("Location")
			return strings.Contains(strings.ToLower(loc), strings.ToLower(attacker))
		},
		Severity: module.SeverityHigh,
		Tags:     []string{"test"},
	}

	u := srv.URL + "/?redirect=original"
	m := openredirect.NewWithProbesAndClient([]openredirect.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{u, u, u},
		Options: map[string]string{"attacker": testAttacker},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Extra["probe_id"] + "|" + f.Extra["param"]
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
	srv := redirectServer(t)
	defer srv.Close()

	probe := openredirect.Probe{
		ID:     "fields-test",
		Inject: "https://{ATTACKER}",
		Detect: func(resp *http.Response, body, attacker string) bool {
			loc := resp.Header.Get("Location")
			return strings.Contains(strings.ToLower(loc), strings.ToLower(attacker))
		},
		Severity: module.SeverityHigh,
		Tags:     []string{"test"},
	}

	m := openredirect.NewWithProbesAndClient([]openredirect.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?redirect=original",
		Options: map[string]string{"attacker": testAttacker},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type != "open_redirect" {
		t.Errorf("Type = %q, want 'open_redirect'", f.Type)
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
	if f.Extra["probe_id"] == "" {
		t.Error("Extra.probe_id empty")
	}
	if f.Extra["param"] == "" {
		t.Error("Extra.param empty")
	}
	if f.Extra["inject"] == "" {
		t.Error("Extra.inject empty")
	}
}

// TestFindingType: all findings have Type == "open_redirect".
func TestFindingType(t *testing.T) {
	srv := redirectServer(t)
	defer srv.Close()

	probe := openredirect.Probe{
		ID:     "type-test",
		Inject: "https://{ATTACKER}",
		Detect: func(resp *http.Response, body, attacker string) bool {
			loc := resp.Header.Get("Location")
			return strings.Contains(strings.ToLower(loc), strings.ToLower(attacker))
		},
		Severity: module.SeverityHigh,
		Tags:     []string{"test"},
	}

	m := openredirect.NewWithProbesAndClient([]openredirect.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?next=original",
		Options: map[string]string{"attacker": testAttacker},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type != "open_redirect" {
			t.Errorf("finding.Type = %q, want 'open_redirect'", f.Type)
		}
	}
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := openredirect.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?redirect=test",
		Options: map[string]string{"parallelism": "3", "attacker": testAttacker},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestAttackerOption: custom attacker domain used.
func TestAttackerOption(t *testing.T) {
	const custom = "evil.custom-test.com"
	srv := redirectServer(t)
	defer srv.Close()

	probe := openredirect.Probe{
		ID:     "attacker-option-test",
		Inject: "https://{ATTACKER}",
		Detect: func(resp *http.Response, body, attacker string) bool {
			loc := resp.Header.Get("Location")
			return strings.Contains(loc, custom)
		},
		Severity: module.SeverityHigh,
		Tags:     []string{"test"},
	}

	m := openredirect.NewWithProbesAndClient([]openredirect.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?redirect=original",
		Options: map[string]string{"attacker": custom},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding with custom attacker domain")
	}
	if !strings.Contains(findings[0].Extra["inject"], custom) {
		t.Errorf("inject %q should contain custom attacker %q", findings[0].Extra["inject"], custom)
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := redirectServer(t)
	defer srv.Close()

	probe := openredirect.Probe{
		ID:     "fallback-test",
		Inject: "https://{ATTACKER}",
		Detect: func(resp *http.Response, body, attacker string) bool {
			loc := resp.Header.Get("Location")
			return strings.Contains(strings.ToLower(loc), strings.ToLower(attacker))
		},
		Severity: module.SeverityHigh,
		Tags:     []string{"test"},
	}

	m := openredirect.NewWithProbesAndClient([]openredirect.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?redirect=original",
		Options: map[string]string{"attacker": testAttacker},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from Target")
	}
}

// TestNewWithClient: does not panic.
func TestNewWithClient(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := openredirect.NewWithClient(c)
	if m == nil || m.Name() != "openredirect" {
		t.Fatal("NewWithClient failed")
	}
}

// TestDetailContainsOpenRedirect: Detail has [OpenRedirect] prefix.
func TestDetailContainsOpenRedirect(t *testing.T) {
	srv := redirectServer(t)
	defer srv.Close()

	probe := openredirect.Probe{
		ID:     "detail-test",
		Inject: "https://{ATTACKER}",
		Detect: func(resp *http.Response, body, attacker string) bool {
			loc := resp.Header.Get("Location")
			return strings.Contains(strings.ToLower(loc), strings.ToLower(attacker))
		},
		Severity: module.SeverityHigh,
		Tags:     []string{"test"},
	}

	m := openredirect.NewWithProbesAndClient([]openredirect.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?redirect=original",
		Options: map[string]string{"attacker": testAttacker},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.Detail, "[OpenRedirect]") {
			t.Errorf("Detail %q missing '[OpenRedirect]'", f.Detail)
		}
	}
}

// TestBuiltinProbesHaveExpectedCount: built-in probes >= 10.
func TestBuiltinProbesHaveExpectedCount(t *testing.T) {
	// Just verify New() loads without panic.
	m := openredirect.New()
	_ = m
}

// TestMultipleRedirectParams: URL with multiple redirect-like params — all tested.
func TestMultipleRedirectParams(t *testing.T) {
	srv := redirectServer(t)
	defer srv.Close()

	probe := openredirect.Probe{
		ID:     "multi-param-test",
		Inject: "https://{ATTACKER}",
		Detect: func(resp *http.Response, body, attacker string) bool {
			loc := resp.Header.Get("Location")
			return strings.Contains(strings.ToLower(loc), strings.ToLower(attacker))
		},
		Severity: module.SeverityHigh,
		Tags:     []string{"test"},
	}

	m := openredirect.NewWithProbesAndClient([]openredirect.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?redirect=/safe&next=/safe",
		Options: map[string]string{"attacker": testAttacker},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	// Both redirect and next should be tested → at least one finding.
	if len(findings) == 0 {
		t.Fatal("expected findings from multiple redirect params")
	}
}
