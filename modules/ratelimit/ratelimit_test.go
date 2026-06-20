package ratelimit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/ratelimit"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// openServer returns a server that never rate-limits (always 200).
func openServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
}

// rateLimitedServer returns 429 after the threshold request count.
func rateLimitedServer(t *testing.T, threshold int32) *httptest.Server {
	t.Helper()
	var count atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		// Reset on X-Forwarded-For header (simulate bypass on fake IPs)
		if r.Header.Get("X-Forwarded-For") != "" {
			w.WriteHeader(200)
			w.Write([]byte(`{"ok":true}`))
			return
		}
		if n > threshold {
			http.Error(w, "Too Many Requests", 429)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
}

// strictServer returns 429 for EVERY request (even with bypass headers).
func strictServer(t *testing.T, threshold int32) *httptest.Server {
	t.Helper()
	var count atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		if n > threshold {
			http.Error(w, "Too Many Requests", 429)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := ratelimit.New()
	if m.Name() != "ratelimit" {
		t.Fatalf("expected 'ratelimit', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = ratelimit.New()
}

// TestMissingRateLimit: open server triggers missing finding.
func TestMissingRateLimit(t *testing.T) {
	srv := openServer(t)
	defer srv.Close()

	m := ratelimit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/login"},
		Options: map[string]string{"burst_count": "5", "check": "missing"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected rate_limit_missing finding")
	}
	if findings[0].Type != "rate_limit_missing" {
		t.Errorf("expected type 'rate_limit_missing', got %q", findings[0].Type)
	}
}

// TestRateLimitPresent: server returns 429 → no missing finding.
func TestRateLimitPresent(t *testing.T) {
	srv := strictServer(t, 3)
	defer srv.Close()

	m := ratelimit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/login"},
		Options: map[string]string{"burst_count": "5", "check": "missing"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type == "rate_limit_missing" {
			t.Errorf("should not flag missing rate limit when 429 is returned: %v", f)
		}
	}
}

// TestBypassViaXForwardedFor: rate limit but bypass via X-Forwarded-For.
func TestBypassViaXForwardedFor(t *testing.T) {
	// threshold=1: first request is OK, second without bypass header returns 429.
	// Requests WITH X-Forwarded-For always return 200.
	srv := rateLimitedServer(t, 1)
	defer srv.Close()

	m := ratelimit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/api/login"},
		Options: map[string]string{"check": "bypass", "bypass_ips": "3"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected rate_limit_bypass_ip finding")
	}
	if findings[0].Type != "rate_limit_bypass_ip" {
		t.Errorf("expected type 'rate_limit_bypass_ip', got %q", findings[0].Type)
	}
}

// TestStrictBypassFails: strict server with no bypass → no bypass finding.
func TestStrictBypassFails(t *testing.T) {
	// Server returns 429 for all requests including bypass headers.
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&count, 1)
		if n > 3 {
			http.Error(w, "Too Many Requests", 429)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := ratelimit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"check": "bypass", "bypass_ips": "5"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type == "rate_limit_bypass_ip" {
			t.Errorf("bypass finding should not fire when server enforces strictly: %v", f)
		}
	}
}

// TestEmptyInput: no targets returns nil.
func TestEmptyInput(t *testing.T) {
	m := ratelimit.New()
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
	srv := openServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := ratelimit.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"burst_count": "3"},
	})
	_ = err
}

// TestDeduplication: same URL finding not duplicated.
func TestDeduplication(t *testing.T) {
	srv := openServer(t)
	defer srv.Close()

	u := srv.URL + "/api"
	m := ratelimit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{u, u, u},
		Options: map[string]string{"burst_count": "3", "check": "missing"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Type
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
	srv := openServer(t)
	defer srv.Close()

	m := ratelimit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/login"},
		Options: map[string]string{"burst_count": "5", "check": "missing"},
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
	if f.Extra["check"] == "" {
		t.Error("Extra.check empty")
	}
}

// TestBypassFindingFields: bypass finding has header and IP populated.
func TestBypassFindingFields(t *testing.T) {
	srv := rateLimitedServer(t, 2)
	defer srv.Close()

	m := ratelimit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"check": "bypass", "bypass_ips": "3"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type == "rate_limit_bypass_ip" {
			if f.Extra["bypass_header"] == "" {
				t.Error("bypass_header empty")
			}
			if f.Extra["bypass_ip"] == "" {
				t.Error("bypass_ip empty")
			}
		}
	}
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	srv := openServer(t)
	defer srv.Close()

	m := ratelimit.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"parallelism": "2", "burst_count": "3", "check": "missing"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := openServer(t)
	defer srv.Close()

	m := ratelimit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/api",
		Options: map[string]string{"burst_count": "5", "check": "missing"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from Target")
	}
}

// TestNewWithClientReplaces: NewWithClient does not panic.
func TestNewWithClientReplaces(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := ratelimit.NewWithClient(c)
	if m == nil || m.Name() != "ratelimit" {
		t.Fatal("NewWithClient failed")
	}
}

// TestMultipleURLs: all URLs checked.
func TestMultipleURLs(t *testing.T) {
	srv := openServer(t)
	defer srv.Close()

	m := ratelimit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/login", srv.URL + "/register", srv.URL + "/forgot"},
		Options: map[string]string{"burst_count": "3", "check": "missing"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) < 3 {
		t.Errorf("expected finding per URL (3), got %d", len(findings))
	}
}

// TestSeverityMediumForMissing: missing rate limit is Medium severity.
func TestSeverityMediumForMissing(t *testing.T) {
	srv := openServer(t)
	defer srv.Close()

	m := ratelimit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"burst_count": "3", "check": "missing"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type == "rate_limit_missing" && f.Severity != module.SeverityMedium {
			t.Errorf("expected Medium for missing rate limit, got %q", f.Severity)
		}
	}
}

// TestBurstDelayOption: burst_delay accepted without error.
func TestBurstDelayOption(t *testing.T) {
	srv := openServer(t)
	defer srv.Close()

	m := ratelimit.NewWithClient(clientFor(srv))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.Run(ctx, module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"burst_count": "3", "burst_delay": "10", "check": "missing"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDetailContainsBurstCount: Detail mentions burst count.
func TestDetailContainsBurstCount(t *testing.T) {
	srv := openServer(t)
	defer srv.Close()

	m := ratelimit.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL + "/"},
		Options: map[string]string{"burst_count": "7", "check": "missing"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type == "rate_limit_missing" && !strings.Contains(f.Detail, "7") {
			t.Errorf("Detail %q does not mention burst count 7", f.Detail)
		}
	}
}
