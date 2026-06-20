package credstuffing_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/credstuffing"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

func findByType(findings []module.Finding, typ string) []module.Finding {
	var out []module.Finding
	for _, f := range findings {
		if f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

func run(t *testing.T, srv *httptest.Server, opts map[string]string) []module.Finding {
	t.Helper()
	if opts == nil {
		opts = map[string]string{}
	}
	opts["authorized"] = "true"
	opts["login_url"] = "/login"
	opts["delay_ms"] = "0" // speed up tests

	m := credstuffing.NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: opts,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findings
}

func TestName(t *testing.T) {
	if credstuffing.New().Name() != "credstuffing" {
		t.Error("expected name 'credstuffing'")
	}
}

// TestAuthorizationGate: missing authorized=true → blocked.
func TestAuthorizationGate(t *testing.T) {
	m := credstuffing.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "https://example.com",
		Options: map[string]string{"creds": "admin:pass"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	blocked := findByType(findings, "credstuffing_unauthorized")
	if len(blocked) == 0 {
		t.Error("expected credstuffing_unauthorized when authorized=true not set")
	}
	if blocked[0].Severity != module.SeverityCritical {
		t.Errorf("expected Critical for unauthorized, got %v", blocked[0].Severity)
	}
}

// TestNoCredentials: no creds provided → info finding.
func TestNoCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := run(t, srv, map[string]string{})
	found := findByType(findings, "credstuffing_no_credentials")
	if len(found) == 0 {
		t.Error("expected credstuffing_no_credentials finding")
	}
}

// TestSuccessfulLogin: server responds with 200 + dashboard body → credstuffing_success.
// The probe classifies as success when the response body contains "dashboard".
func TestSuccessfulLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			// Successful login — return 200 with dashboard indicator
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"redirect":"/dashboard","status":"ok"}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := run(t, srv, map[string]string{
		"creds":         "admin:correct-pass",
		"success_codes": "200",
	})
	success := findByType(findings, "credstuffing_success")
	if len(success) == 0 {
		t.Error("expected credstuffing_success for 200 with dashboard in body")
	}
	if len(success) > 0 && success[0].Severity != module.SeverityCritical {
		t.Errorf("expected Critical for success, got %v", success[0].Severity)
	}
}

// TestLockoutDetected: server returns 429 → lockout finding.
func TestLockoutDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("too many attempts, account locked"))
	}))
	defer srv.Close()

	findings := run(t, srv, map[string]string{
		"creds": "user1:pass1,user2:pass2,user3:pass3",
	})
	lockouts := findByType(findings, "credstuffing_lockout_detected")
	if len(lockouts) == 0 {
		t.Error("expected credstuffing_lockout_detected for 429 response")
	}
}

// TestCaptchaDetected: server body contains "captcha" → captcha finding.
func TestCaptchaDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html>Please complete the captcha challenge to continue.</html>`))
	}))
	defer srv.Close()

	findings := run(t, srv, map[string]string{
		"creds": "user:pass",
	})
	captchas := findByType(findings, "credstuffing_captcha_detected")
	if len(captchas) == 0 {
		t.Error("expected credstuffing_captcha_detected")
	}
}

// TestMFADetected: server body contains "two-factor" → mfa finding.
func TestMFADetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"message":"Please enter your two-factor authentication code"}`))
	}))
	defer srv.Close()

	findings := run(t, srv, map[string]string{
		"creds": "user:pass",
	})
	mfa := findByType(findings, "credstuffing_mfa_required")
	if len(mfa) == 0 {
		t.Error("expected credstuffing_mfa_required")
	}
}

// TestSummaryFinding: always emitted.
func TestSummaryAlwaysEmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("invalid credentials"))
	}))
	defer srv.Close()

	findings := run(t, srv, map[string]string{
		"creds": "user1:wrong,user2:wrong,user3:wrong",
	})
	summary := findByType(findings, "credstuffing_summary")
	if len(summary) == 0 {
		t.Error("expected credstuffing_summary finding")
	}
}

// TestHighRiskSummary: no lockout/captcha/mfa + multiple creds tested → High risk.
func TestHighRiskSummaryNoProtection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("wrong password"))
	}))
	defer srv.Close()

	findings := run(t, srv, map[string]string{
		"creds": "user1:p1,user2:p2,user3:p3",
	})
	summary := findByType(findings, "credstuffing_summary")
	if len(summary) == 0 {
		t.Fatal("expected summary finding")
	}
	if summary[0].Severity != module.SeverityHigh {
		t.Errorf("no-protection summary should be High, got %v", summary[0].Severity)
	}
}

// TestJSONContentType: content_type=json sends JSON body.
func TestJSONContentType(t *testing.T) {
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			gotContentType = r.Header.Get("Content-Type")
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()

	run(t, srv, map[string]string{
		"creds":        "user:pass",
		"content_type": "json",
	})
	if !strings.Contains(gotContentType, "application/json") {
		t.Errorf("expected JSON content type, got %q", gotContentType)
	}
}

// TestFormContentType: default form encoding.
func TestFormContentType(t *testing.T) {
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			gotContentType = r.Header.Get("Content-Type")
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()

	run(t, srv, map[string]string{"creds": "user:pass"})
	if !strings.Contains(gotContentType, "application/x-www-form-urlencoded") {
		t.Errorf("expected form content type, got %q", gotContentType)
	}
}

// TestAbsoluteLoginURL: login_url as full URL.
func TestAbsoluteLoginURL(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth" {
			called = true
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()

	opts := map[string]string{
		"authorized": "true",
		"login_url":  srv.URL + "/api/auth",
		"creds":      "user:pass",
		"delay_ms":   "0",
	}
	m := credstuffing.NewWithClient(srv.Client())
	_, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: opts,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("expected absolute login_url to be called")
	}
}

// TestConfidencePresent: all findings have confidence.
func TestConfidencePresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("wrong"))
	}))
	defer srv.Close()

	findings := run(t, srv, map[string]string{"creds": "a:b,c:d"})
	for _, f := range findings {
		if f.Extra == nil || f.Extra["confidence"] == "" {
			t.Errorf("finding %q missing confidence", f.Type)
		}
	}
}

// TestContextCancellation: cancelled context must not panic.
func TestContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := credstuffing.NewWithClient(srv.Client())
	_, _ = m.Run(ctx, module.Input{
		Target: srv.URL,
		Options: map[string]string{
			"authorized": "true",
			"login_url":  "/login",
			"creds":      "user:pass",
			"delay_ms":   "0",
		},
	})
}
