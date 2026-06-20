package headeraudit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func runAudit(t *testing.T, m *Module, urls []string) []module.Finding {
	t.Helper()
	findings, err := m.Run(context.Background(), module.Input{URLs: urls})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	return findings
}

func hasCheck(findings []module.Finding, checkID string) bool {
	for _, f := range findings {
		if f.Extra["check"] == checkID {
			return true
		}
	}
	return false
}

func checkCount(findings []module.Finding, checkID string) int {
	n := 0
	for _, f := range findings {
		if f.Extra["check"] == checkID {
			n++
		}
	}
	return n
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "headeraudit" {
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

func TestRun_MissingHSTS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// No HSTS header set.
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL}) // srv.URL starts with https://
	if !hasCheck(findings, "missing-hsts") {
		t.Fatal("expected missing-hsts finding")
	}
	for _, f := range findings {
		if f.Extra["check"] == "missing-hsts" {
			if f.Severity != module.SeverityMedium {
				t.Errorf("expected medium severity for missing HSTS, got %q", f.Severity)
			}
		}
	}
}

func TestRun_HSTSShortMaxAge(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=3600")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if !hasCheck(findings, "hsts-short-max-age") {
		t.Fatal("expected hsts-short-max-age finding for max-age=3600")
	}
}

func TestRun_HSTSGoodMaxAge_NoShortFinding(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if hasCheck(findings, "missing-hsts") {
		t.Fatal("should not flag missing-hsts when HSTS is present")
	}
	if hasCheck(findings, "hsts-short-max-age") {
		t.Fatal("should not flag hsts-short-max-age for max-age=31536000")
	}
}

func TestRun_MissingCSP(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if !hasCheck(findings, "missing-csp") {
		t.Fatal("expected missing-csp finding")
	}
}

func TestRun_CSPUnsafeInline(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if !hasCheck(findings, "csp-unsafe-inline") {
		t.Fatal("expected csp-unsafe-inline finding")
	}
	for _, f := range findings {
		if f.Extra["check"] == "csp-unsafe-inline" {
			if f.Severity != module.SeverityMedium {
				t.Errorf("expected medium severity, got %q", f.Severity)
			}
		}
	}
}

func TestRun_CSPUnsafeEval(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'unsafe-eval'")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if !hasCheck(findings, "csp-unsafe-eval") {
		t.Fatal("expected csp-unsafe-eval finding")
	}
}

func TestRun_MissingXContentTypeOptions(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if !hasCheck(findings, "missing-x-content-type-options") {
		t.Fatal("expected missing-x-content-type-options finding")
	}
}

func TestRun_XContentTypeOptions_Valid(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if hasCheck(findings, "missing-x-content-type-options") {
		t.Fatal("should not flag when X-Content-Type-Options: nosniff is present")
	}
	if hasCheck(findings, "invalid-x-content-type-options") {
		t.Fatal("should not flag as invalid when nosniff is set")
	}
}

func TestRun_MissingXFrameOptions(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if !hasCheck(findings, "missing-x-frame-options") {
		t.Fatal("expected missing-x-frame-options finding")
	}
	for _, f := range findings {
		if f.Extra["check"] == "missing-x-frame-options" {
			if f.Severity != module.SeverityMedium {
				t.Errorf("expected medium severity, got %q", f.Severity)
			}
		}
	}
}

func TestRun_XFrameOptions_CSPFrameAncestors_NoDuplicate(t *testing.T) {
	// When CSP has frame-ancestors, X-Frame-Options missing should not be flagged.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if hasCheck(findings, "missing-x-frame-options") {
		t.Fatal("should not flag missing-x-frame-options when CSP frame-ancestors is present")
	}
}

func TestRun_ServerVersionDisclosure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Apache/2.4.51 (Ubuntu)")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if !hasCheck(findings, "server-version-disclosure") {
		t.Fatal("expected server-version-disclosure finding for Apache/2.4.51")
	}
	for _, f := range findings {
		if f.Extra["check"] == "server-version-disclosure" {
			if f.Severity != module.SeverityLow {
				t.Errorf("expected low severity, got %q", f.Severity)
			}
		}
	}
}

func TestRun_ServerNoVersion_NoFinding(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if hasCheck(findings, "server-version-disclosure") {
		t.Fatal("should not flag server header without version number")
	}
}

func TestRun_XPoweredByDisclosure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.1.0")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if !hasCheck(findings, "x-powered-by-disclosure") {
		t.Fatal("expected x-powered-by-disclosure finding")
	}
}

func TestRun_CORSWildcard_Medium(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if !hasCheck(findings, "cors-wildcard") {
		t.Fatal("expected cors-wildcard finding")
	}
	for _, f := range findings {
		if f.Extra["check"] == "cors-wildcard" {
			if f.Severity != module.SeverityMedium {
				t.Errorf("expected medium severity for CORS wildcard, got %q", f.Severity)
			}
		}
	}
}

func TestRun_CORSCredentialsWildcard_High(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if !hasCheck(findings, "cors-credentials-wildcard") {
		t.Fatal("expected cors-credentials-wildcard finding")
	}
	for _, f := range findings {
		if f.Extra["check"] == "cors-credentials-wildcard" {
			if f.Severity != module.SeverityHigh {
				t.Errorf("expected high severity, got %q", f.Severity)
			}
		}
	}
}

func TestRun_CookieMissingSecure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "session=abc123; Path=/; HttpOnly")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if !hasCheck(findings, "cookie-missing-secure") {
		t.Fatal("expected cookie-missing-secure finding for HTTPS response without Secure flag")
	}
}

func TestRun_CookieMissingHttpOnly(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "token=xyz; Path=/; Secure")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if !hasCheck(findings, "cookie-missing-httponly") {
		t.Fatal("expected cookie-missing-httponly finding")
	}
}

func TestRun_CookieMissingSameSite(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "csrf=tok; Path=/; Secure; HttpOnly")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})
	if !hasCheck(findings, "cookie-missing-samesite") {
		t.Fatal("expected cookie-missing-samesite finding")
	}
}

func TestRun_RawContent_Input(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	_, err := m.Run(context.Background(), module.Input{
		RawContent: srv.URL + "\n" + srv.URL + "/other",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_AllHeaders_Present_Fewer_Findings(t *testing.T) {
	// A well-hardened server: should produce fewer findings than a bare server.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=()")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings := runAudit(t, m, []string{srv.URL})

	// None of the major checks should fire.
	for _, checkID := range []string{
		"missing-hsts", "hsts-short-max-age", "missing-csp",
		"missing-x-content-type-options", "missing-x-frame-options",
		"missing-referrer-policy", "missing-permissions-policy",
	} {
		if hasCheck(findings, checkID) {
			t.Errorf("unexpected finding %q on well-hardened server", checkID)
		}
	}
}

// ─── unit tests for helpers ───────────────────────────────────────────────────

func TestExtractDirectiveValue(t *testing.T) {
	cases := []struct {
		header    string
		directive string
		want      string
	}{
		{"max-age=31536000; includeSubDomains", "max-age", "31536000"},
		{"max-age=3600", "max-age", "3600"},
		{"includeSubDomains; max-age=7200", "max-age", "7200"},
		{"max-age=", "max-age", ""},
		{"no-directive", "max-age", ""},
	}
	for _, c := range cases {
		got := extractDirectiveValue(c.header, c.directive)
		if got != c.want {
			t.Errorf("extractDirectiveValue(%q, %q) = %q, want %q", c.header, c.directive, got, c.want)
		}
	}
}

func TestParseInt(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"31536000", 31536000},
		{"3600", 3600},
		{"0", 0},
		{"", 0},
		{"abc", 0},
	}
	for _, c := range cases {
		if got := parseInt(c.in); got != c.want {
			t.Errorf("parseInt(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestContainsVersionNumber(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"Apache/2.4.51 (Ubuntu)", true},
		{"nginx/1.21.6", true},
		{"PHP/8.1.0", true},
		{"nginx", false},
		{"Apache", false},
		{"cloudflare", false},
		{"Microsoft-IIS/10.0", true},
	}
	for _, c := range cases {
		got := containsVersionNumber(c.s)
		if got != c.want {
			t.Errorf("containsVersionNumber(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestCookieName(t *testing.T) {
	cases := []struct {
		cookie string
		want   string
	}{
		{"session=abc123; Path=/", "session"},
		{"token=xyz; Secure; HttpOnly", "token"},
		{"noequals", "noequals"},
	}
	for _, c := range cases {
		got := cookieName(c.cookie)
		if got != c.want {
			t.Errorf("cookieName(%q) = %q, want %q", c.cookie, got, c.want)
		}
	}
}

func TestIsHTTPS(t *testing.T) {
	if !isHTTPS("https://example.com") {
		t.Fatal("expected true for https://")
	}
	if isHTTPS("http://example.com") {
		t.Fatal("expected false for http://")
	}
}

func TestAllChecks_NotEmpty(t *testing.T) {
	if len(allChecks) < 15 {
		t.Fatalf("expected at least 15 checks, got %d", len(allChecks))
	}
}
