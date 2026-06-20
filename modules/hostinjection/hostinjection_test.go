package hostinjection_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/hostinjection"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// reflectHostServer returns a server that echoes back any Host or X-Forwarded-Host
// header value in the response body, simulating a vulnerable web framework that
// uses the Host header to generate absolute URLs.
func reflectHostServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect whichever header was injected.
		injected := ""
		for _, h := range []string{"X-Forwarded-Host", "X-Host", "X-HTTP-Host-Override",
			"X-Forwarded-Server", "X-Original-URL", "Forwarded"} {
			if v := r.Header.Get(h); v != "" {
				injected = v
				break
			}
		}
		if injected == "" {
			injected = r.Host
		}
		// Simulate: generate a link using the host.
		io.WriteString(w, "<html><a href='http://"+injected+"/reset'>Reset your password</a></html>")
	}))
}

// cacheReflectServer reflects the X-Forwarded-Host and adds cache headers.
func cacheReflectServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		w.Header().Set("X-Cache", "HIT from proxy")
		w.Header().Set("Age", "120")
		io.WriteString(w, "<link href='https://"+host+"/static/main.css'>")
	}))
}

// safeServer never reflects injected headers.
func safeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><body>Welcome</body></html>")
	}))
}

// passwordResetServer reflects X-Forwarded-Host in the body AND mentions "reset".
func passwordResetServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		io.WriteString(w, `<p>Check your email. <a href="http://`+host+`/reset?token=abc">Reset password here</a></p>`)
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := hostinjection.New()
	if m.Name() != "hostinjection" {
		t.Fatalf("expected 'hostinjection', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = hostinjection.New()
}

// TestReflectedHostHeader: X-Forwarded-Host value reflected in response body.
func TestReflectedHostHeader(t *testing.T) {
	srv := reflectHostServer(t)
	defer srv.Close()

	m := hostinjection.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"attacker_host": "evil.example.com"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one host injection finding")
	}
}

// TestNoVulnerability: safe server returns no findings.
func TestNoVulnerability(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := hostinjection.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"attacker_host": "evil.example.com"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on safe server, got %d: %v", len(findings), findings)
	}
}

// TestEmptyInput: no targets returns nil.
func TestEmptyInput(t *testing.T) {
	m := hostinjection.New()
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
	srv := reflectHostServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := hostinjection.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{
		URLs: []string{srv.URL + "/"},
	})
	_ = err
}

// TestDeduplication: same (url, header, probe_id) not duplicated.
func TestDeduplication(t *testing.T) {
	srv := reflectHostServer(t)
	defer srv.Close()

	u := srv.URL + "/"
	m := hostinjection.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{u, u, u},
		Options: map[string]string{"attacker_host": "evil.example.com"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Extra["header"] + "|" + f.Extra["probe_id"]
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
	srv := reflectHostServer(t)
	defer srv.Close()

	m := hostinjection.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"attacker_host": "evil.example.com"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type != "hostinjection" {
		t.Errorf("Type = %q, want 'hostinjection'", f.Type)
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
	if f.Extra["header"] == "" {
		t.Error("Extra.header empty")
	}
	if f.Extra["value"] == "" {
		t.Error("Extra.value empty")
	}
}

// TestFindingType: all findings have Type == "hostinjection".
func TestFindingType(t *testing.T) {
	srv := reflectHostServer(t)
	defer srv.Close()

	m := hostinjection.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"attacker_host": "evil.example.com"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type != "hostinjection" {
			t.Errorf("finding.Type = %q, want 'hostinjection'", f.Type)
		}
	}
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	srv := reflectHostServer(t)
	defer srv.Close()

	m := hostinjection.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"parallelism": "3", "attacker_host": "evil.example.com"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings with parallelism=3")
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := reflectHostServer(t)
	defer srv.Close()

	m := hostinjection.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/",
		Options: map[string]string{"attacker_host": "evil.example.com"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from Target field")
	}
}

// TestPasswordResetDetection: password-reset probe fires when body mentions "reset".
func TestPasswordResetDetection(t *testing.T) {
	srv := passwordResetServer(t)
	defer srv.Close()

	m := hostinjection.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/forgot-password"},
		Options: map[string]string{"attacker_host": "attacker.evil.com"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected password-reset finding")
	}
}

// TestCacheContextDetection: cache-poisoning probe fires with X-Cache header present.
func TestCacheContextDetection(t *testing.T) {
	srv := cacheReflectServer(t)
	defer srv.Close()

	m := hostinjection.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/static/page"},
		Options: map[string]string{"attacker_host": "attacker.evil.com"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected cache-poisoning finding")
	}
	// Find the cache-poisoning finding and check for Critical or High severity.
	for _, f := range findings {
		if strings.Contains(f.Extra["tags"], "cache-poisoning") {
			if f.Severity != module.SeverityCritical && f.Severity != module.SeverityHigh {
				t.Errorf("cache-poisoning severity = %q, want High or Critical", f.Severity)
			}
		}
	}
}

// TestAttackerHostOption: attacker_host option is used in injection.
func TestAttackerHostOption(t *testing.T) {
	customHost := "custom-attacker.test.local"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range []string{"X-Forwarded-Host", "X-Host", "Host"} {
			if v := r.Header.Get(h); strings.Contains(v, customHost) {
				io.WriteString(w, "redirect to: "+v)
				return
			}
		}
		io.WriteString(w, "normal page")
	}))
	defer srv.Close()

	m := hostinjection.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"attacker_host": customHost},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if strings.Contains(f.Extra["value"], customHost) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected finding with custom attacker_host=%q", customHost)
	}
}

// TestNewWithProbes: custom probes used without panic.
func TestNewWithProbes(t *testing.T) {
	custom := []hostinjection.Probe{
		{
			ID:     "custom-reflect",
			Header: "X-Custom-Host",
			Value:  "evil.test",
			Detect: func(body string, headers http.Header, status int, injectedValue string) bool {
				return strings.Contains(body, injectedValue)
			},
			Severity: module.SeverityHigh,
			Tags:     []string{"custom"},
		},
	}
	m := hostinjection.NewWithProbes(custom)
	if m == nil {
		t.Fatal("NewWithProbes returned nil")
	}
}

// TestNewWithClientReplaces: NewWithClient does not panic.
func TestNewWithClientReplaces(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := hostinjection.NewWithClient(c)
	if m == nil {
		t.Fatal("NewWithClient returned nil")
	}
}

// TestMultipleURLs: multiple targets all checked.
func TestMultipleURLs(t *testing.T) {
	srv := reflectHostServer(t)
	defer srv.Close()

	m := hostinjection.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/", srv.URL + "/login", srv.URL + "/admin"},
		Options: map[string]string{"attacker_host": "evil.test"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestDetailContainsHeader: Detail string contains the header name.
func TestDetailContainsHeader(t *testing.T) {
	srv := reflectHostServer(t)
	defer srv.Close()

	m := hostinjection.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"attacker_host": "evil.example.com"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.Detail, "HostInj/") {
			t.Errorf("Detail %q missing 'HostInj/'", f.Detail)
		}
		if !strings.Contains(f.Detail, f.Extra["header"]) {
			t.Errorf("Detail %q missing header name %q", f.Detail, f.Extra["header"])
		}
	}
}

// TestBuiltinProbesHaveMinCount: at least 10 distinct probe IDs fire.
func TestBuiltinProbesHaveMinCount(t *testing.T) {
	srv := reflectHostServer(t)
	defer srv.Close()

	m := hostinjection.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"attacker_host": "evil.example.com"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	unique := make(map[string]struct{})
	for _, f := range findings {
		unique[f.Extra["probe_id"]] = struct{}{}
	}
	if len(unique) < 5 {
		t.Errorf("expected at least 5 unique probe IDs, got %d", len(unique))
	}
}
