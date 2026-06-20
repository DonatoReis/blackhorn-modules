package crlf_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/crlf"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// crlfServer reflects any injected header back in the response.
// This simulates a vulnerable server that echoes user-controlled header values.
func crlfServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check query params for CRLF-injected canary header.
		for _, vals := range r.URL.Query() {
			for _, v := range vals {
				// Detect URL-decoded form of %0d%0a or %0a followed by X-CRLF-Injected header.
				if strings.Contains(v, "\r\n") || strings.Contains(v, "\n") {
					// Echo any injected header from the value.
					lines := strings.Split(strings.ReplaceAll(v, "\r\n", "\n"), "\n")
					for _, line := range lines[1:] {
						if strings.Contains(line, ":") {
							parts := strings.SplitN(line, ":", 2)
							headerName := strings.TrimSpace(parts[0])
							headerVal := strings.TrimSpace(parts[1])
							if headerName != "" {
								w.Header().Set(headerName, headerVal)
							}
						}
					}
				}
			}
		}
		w.WriteHeader(200)
		w.Write([]byte(`OK`))
	}))
}

// headerCRLFServer: detects the canary marker in any request header value
// and echoes the marker as a response header. This simulates a vulnerable
// proxy/server that does not sanitize header values and reflects them back
// (the actual CRLF injection in requests is blocked by Go's HTTP client,
// so we detect the injected value substring instead).
func headerCRLFServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const canary = "crlftest"
		for _, hdr := range []string{"Referer", "User-Agent", "X-Forwarded-For"} {
			val := r.Header.Get(hdr)
			if strings.Contains(strings.ToLower(val), canary) {
				// Server naively reflects the X-CRLF-Injected header — simulating a
				// vulnerable location-redirect or log-injection scenario.
				w.Header().Set("X-CRLF-Injected", canary)
			}
		}
		w.WriteHeader(200)
		w.Write([]byte(`OK`))
	}))
}

// setCookieCRLFServer reflects CRLF in Set-Cookie header.
func setCookieCRLFServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, vals := range r.URL.Query() {
			for _, v := range vals {
				if strings.Contains(v, "\n") {
					lines := strings.Split(v, "\n")
					for _, line := range lines[1:] {
						line = strings.TrimSpace(line)
						if strings.HasPrefix(strings.ToLower(line), "set-cookie:") {
							cookieVal := strings.TrimSpace(line[len("set-cookie:"):])
							w.Header().Add("Set-Cookie", cookieVal)
						}
					}
				}
			}
		}
		w.WriteHeader(200)
		w.Write([]byte(`OK`))
	}))
}

// safeServer: strict URL validation — never reflects anything.
func safeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`OK`))
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := crlf.New()
	if m.Name() != "crlf" {
		t.Fatalf("expected 'crlf', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = crlf.New()
}

// TestPlainCRLFQueryInjection: plain %0d%0a query injection.
func TestPlainCRLFQueryInjection(t *testing.T) {
	srv := crlfServer(t)
	defer srv.Close()

	probe := crlf.Probe{
		ID:             "query-plain",
		Location:       crlf.LocationQuery,
		Inject:         "crlfpayload\r\nX-CRLF-Injected: crlftest",
		InjectedHeader: "X-CRLF-Injected",
		InjectedValue:  "crlftest",
		Severity:       module.SeverityHigh,
		Tags:           []string{"test"},
	}

	m := crlf.NewWithProbesAndClient([]crlf.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=test",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected CRLF finding for plain query injection")
	}
}

// TestLFOnlyQueryInjection: %0a (LF only) query injection.
func TestLFOnlyQueryInjection(t *testing.T) {
	srv := crlfServer(t)
	defer srv.Close()

	probe := crlf.Probe{
		ID:             "query-lf",
		Location:       crlf.LocationQuery,
		Inject:         "crlfpayload\nX-CRLF-Injected: crlftest",
		InjectedHeader: "X-CRLF-Injected",
		InjectedValue:  "crlftest",
		Severity:       module.SeverityHigh,
		Tags:           []string{"test"},
	}

	m := crlf.NewWithProbesAndClient([]crlf.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?name=user",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected CRLF finding for LF-only query injection")
	}
}

// TestNoVulnerability: safe server never reflects → no findings.
func TestNoVulnerability(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := crlf.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=test",
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
	m := crlf.New()
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
	srv := crlfServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := crlf.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{Target: srv.URL + "/?q=test"})
	_ = err
}

// TestDeduplication: same probe + same URL not duplicated.
func TestDeduplication(t *testing.T) {
	srv := crlfServer(t)
	defer srv.Close()

	probe := crlf.Probe{
		ID:             "query-plain-dedup",
		Location:       crlf.LocationQuery,
		Inject:         "crlfpayload\r\nX-CRLF-Injected: crlftest",
		InjectedHeader: "X-CRLF-Injected",
		InjectedValue:  "crlftest",
		Severity:       module.SeverityHigh,
		Tags:           []string{"test"},
	}

	u := srv.URL + "/?q=test"
	m := crlf.NewWithProbesAndClient([]crlf.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{u, u, u},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Type + "|" + f.Extra["probe_id"]
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
	srv := crlfServer(t)
	defer srv.Close()

	probe := crlf.Probe{
		ID:             "query-fields-test",
		Location:       crlf.LocationQuery,
		Inject:         "crlfpayload\r\nX-CRLF-Injected: crlftest",
		InjectedHeader: "X-CRLF-Injected",
		InjectedValue:  "crlftest",
		Severity:       module.SeverityHigh,
		Tags:           []string{"test"},
	}

	m := crlf.NewWithProbesAndClient([]crlf.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=test",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type != "crlf_injection" {
		t.Errorf("Type = %q, want 'crlf_injection'", f.Type)
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
	if f.Extra["injected_header"] == "" {
		t.Error("Extra.injected_header empty")
	}
}

// TestHeaderCRLFInjection: injection via request header (Referer).
// The probe injects the canary value into the Referer header.
// The server reflects it back as X-CRLF-Injected when it detects the canary.
func TestHeaderCRLFInjection(t *testing.T) {
	srv := headerCRLFServer(t)
	defer srv.Close()

	// Inject the canary directly in the header value (no literal CRLF needed —
	// the vulnerable server reflects any header value containing the canary).
	probe := crlf.Probe{
		ID:             "header-referer-plain",
		Location:       crlf.LocationHeader,
		Inject:         "https://attacker.example.com crlftest",
		TargetHeader:   "Referer",
		InjectedHeader: "X-CRLF-Injected",
		InjectedValue:  "crlftest",
		Severity:       module.SeverityHigh,
		Tags:           []string{"test"},
	}

	m := crlf.NewWithProbesAndClient([]crlf.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected CRLF finding for header injection")
	}
}

// TestSetCookieInjection: Set-Cookie injected via CRLF.
func TestSetCookieInjection(t *testing.T) {
	srv := setCookieCRLFServer(t)
	defer srv.Close()

	probe := crlf.Probe{
		ID:             "query-setcookie-test",
		Location:       crlf.LocationQuery,
		Inject:         "crlfpayload\nSet-Cookie: crlfcookie=injected",
		InjectedHeader: "Set-Cookie",
		InjectedValue:  "crlfcookie=injected",
		Severity:       module.SeverityHigh,
		Tags:           []string{"set-cookie"},
	}

	m := crlf.NewWithProbesAndClient([]crlf.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?redirect=test",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Set-Cookie CRLF finding")
	}
}

// TestLocationFilter: only query location probes run.
func TestLocationFilter(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	probes := []crlf.Probe{
		{ID: "q1", Location: crlf.LocationQuery, Inject: "test\nX-Test: v", InjectedHeader: "X-Test", InjectedValue: "v", Severity: module.SeverityHigh, Tags: []string{"test"}},
		{ID: "h1", Location: crlf.LocationHeader, Inject: "test\nX-Test: v", TargetHeader: "Referer", InjectedHeader: "X-Test", InjectedValue: "v", Severity: module.SeverityHigh, Tags: []string{"test"}},
	}

	m := crlf.NewWithProbesAndClient(probes, clientFor(srv))
	// Only "header" location runs — safe server means no findings, but should not crash.
	_, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/",
		Options: map[string]string{"location": "header"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := crlf.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL + "/?q=test",
		Options: map[string]string{"parallelism": "3"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestTargetFallback: input.Target used when URLs empty.
func TestTargetFallback(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := crlf.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=test",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestNewWithClient: does not panic.
func TestNewWithClient(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := crlf.NewWithClient(c)
	if m == nil || m.Name() != "crlf" {
		t.Fatal("NewWithClient failed")
	}
}

// TestNewWithProbes: custom probes override built-ins.
func TestNewWithProbes(t *testing.T) {
	probes := []crlf.Probe{
		{ID: "custom", Location: crlf.LocationQuery, Inject: "x", InjectedHeader: "X-Test", InjectedValue: "v", Severity: module.SeverityHigh, Tags: []string{"test"}},
	}
	m := crlf.NewWithProbes(probes)
	if m == nil || m.Name() != "crlf" {
		t.Fatal("NewWithProbes failed")
	}
}

// TestFindingDetail: Detail string contains expected content.
func TestFindingDetail(t *testing.T) {
	srv := crlfServer(t)
	defer srv.Close()

	probe := crlf.Probe{
		ID:             "query-detail-test",
		Location:       crlf.LocationQuery,
		Inject:         "crlfpayload\r\nX-CRLF-Injected: crlftest",
		InjectedHeader: "X-CRLF-Injected",
		InjectedValue:  "crlftest",
		Severity:       module.SeverityHigh,
		Tags:           []string{"test"},
	}

	m := crlf.NewWithProbesAndClient([]crlf.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=test",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.Detail, "[CRLF]") {
			t.Errorf("Detail %q missing '[CRLF]' prefix", f.Detail)
		}
	}
}

// TestFindingHasTags: finding.Extra.tags populated.
func TestFindingHasTags(t *testing.T) {
	srv := crlfServer(t)
	defer srv.Close()

	probe := crlf.Probe{
		ID:             "query-tags-test",
		Location:       crlf.LocationQuery,
		Inject:         "crlfpayload\r\nX-CRLF-Injected: crlftest",
		InjectedHeader: "X-CRLF-Injected",
		InjectedValue:  "crlftest",
		Severity:       module.SeverityHigh,
		Tags:           []string{"response-splitting"},
	}

	m := crlf.NewWithProbesAndClient([]crlf.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=test",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Extra["tags"] == "" {
			t.Errorf("Extra.tags empty for finding %v", f)
		}
	}
}

// TestMultipleParams: URL with multiple query params probes each one.
func TestMultipleParams(t *testing.T) {
	srv := crlfServer(t)
	defer srv.Close()

	probe := crlf.Probe{
		ID:             "query-multiparams",
		Location:       crlf.LocationQuery,
		Inject:         "crlfpayload\r\nX-CRLF-Injected: crlftest",
		InjectedHeader: "X-CRLF-Injected",
		InjectedValue:  "crlftest",
		Severity:       module.SeverityHigh,
		Tags:           []string{"test"},
	}

	m := crlf.NewWithProbesAndClient([]crlf.Probe{probe}, clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/?q=test&page=1&lang=en",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	// At minimum one param should trigger.
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from multi-param URL")
	}
}

// TestMultipleURLs: multiple targets processed.
func TestMultipleURLs(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	m := crlf.NewWithClient(clientFor(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv.URL + "/?q=a", srv.URL + "/?q=b"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestNoParamsUsesDefaultParam: URL with no query params still probes.
func TestNoParamsUsesDefaultParam(t *testing.T) {
	srv := safeServer(t)
	defer srv.Close()

	probe := crlf.Probe{
		ID:             "query-noparam",
		Location:       crlf.LocationQuery,
		Inject:         "crlfpayload\r\nX-CRLF-Injected: crlftest",
		InjectedHeader: "X-CRLF-Injected",
		InjectedValue:  "crlftest",
		Severity:       module.SeverityHigh,
		Tags:           []string{"test"},
	}

	m := crlf.NewWithProbesAndClient([]crlf.Probe{probe}, clientFor(srv))
	// safe server so no findings expected, but must not panic or error.
	_, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/page",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}
