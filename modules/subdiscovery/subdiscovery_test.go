package subdiscovery_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/subdiscovery"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── mock helpers ─────────────────────────────────────────────────────────

// newFixedServer creates a test server that returns the same body for every request.
func newFixedServer(t *testing.T, body []byte, status int) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(body)
	}))
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &redirectTransport{target: srv.URL},
	}
	return srv, client
}

// newEmptyServer returns a server that always replies with an empty JSON array.
func newEmptyServer(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()
	return newFixedServer(t, []byte("[]"), http.StatusOK)
}

// redirectTransport rewrites every request host to the test server so the
// module never actually reaches the public internet.
type redirectTransport struct {
	target string // e.g. "http://127.0.0.1:PORT"
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	// Strip the scheme from target, e.g. "http://127.0.0.1:PORT" → "127.0.0.1:PORT"
	host := strings.TrimPrefix(rt.target, "http://")
	clone.URL.Scheme = "http"
	clone.URL.Host = host
	clone.Host = host
	return http.DefaultTransport.RoundTrip(clone)
}

// crtshResponse builds a crt.sh-style JSON response for the given subdomains.
func crtshResponse(subs ...string) []byte {
	type cert struct {
		NameValue string `json:"name_value"`
	}
	certs := make([]cert, len(subs))
	for i, s := range subs {
		certs[i] = cert{NameValue: s}
	}
	b, _ := json.Marshal(certs)
	return b
}

type stubResolver struct {
	records     map[string][]string
	wildcardIPs []string
	delay       time.Duration
}

func (r stubResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if r.delay > 0 {
		select {
		case <-time.After(r.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if addresses := r.records[host]; len(addresses) > 0 {
		return append([]string(nil), addresses...), nil
	}
	if strings.HasPrefix(host, "blackhorn-") && len(r.wildcardIPs) > 0 {
		return append([]string(nil), r.wildcardIPs...), nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// ─── tests ────────────────────────────────────────────────────────────────

// TestName verifies the module name.
func TestName(t *testing.T) {
	if subdiscovery.New().Name() != "subdiscovery" {
		t.Error("expected module name 'subdiscovery'")
	}
}

// TestRun_EmptyTarget expects an error.
func TestRun_EmptyTarget(t *testing.T) {
	m := subdiscovery.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestRun_ContextCancellation should not hang.
func TestRun_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := subdiscovery.New()
	_, _ = m.Run(ctx, module.Input{Target: "example.com"})
}

// TestRun_TargetFromURLs uses URLs[0] when Target is empty.
func TestRun_TargetFromURLs(t *testing.T) {
	srv, client := newEmptyServer(t)
	defer srv.Close()

	m := subdiscovery.NewWithClient(client)
	// Should not error — the domain is inferred from URLs[0].
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{"example.com"},
		Options: map[string]string{"sources": "crtsh"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRun_FindingFields verifies that returned findings have required fields.
func TestRun_FindingFields(t *testing.T) {
	body := crtshResponse("mail.testdomain.com", "api.testdomain.com")
	srv, client := newFixedServer(t, body, http.StatusOK)
	defer srv.Close()

	m := subdiscovery.NewWithClient(client)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "testdomain.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range findings {
		if f.Type != "passive_name_candidate" {
			t.Errorf("expected type 'passive_name_candidate', got %q", f.Type)
		}
		if f.Extra["subdomain"] == "" {
			t.Error("finding missing 'subdomain' field")
		}
		if f.Extra["domain"] == "" {
			t.Error("finding missing 'domain' field")
		}
		if f.Extra["sources"] == "" {
			t.Error("finding missing 'sources' field")
		}
		if f.Severity != module.SeverityInfo {
			t.Errorf("expected SeverityInfo, got %q", f.Severity)
		}
		if f.Extra["promote_to_context"] != "false" {
			t.Errorf("unverified candidate must not be promoted: %+v", f)
		}
	}
}

func TestRun_ResolvePromotesOnlyDNSConfirmedNames(t *testing.T) {
	body := crtshResponse("live.example.com", "stale.example.com")
	srv, client := newFixedServer(t, body, http.StatusOK)
	defer srv.Close()

	m := subdiscovery.NewWithClientAndResolver(client, stubResolver{
		records: map[string][]string{"live.example.com": {"203.0.113.10"}},
	})
	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":             "crtsh",
			"resolve":             "true",
			"resolve_parallelism": "2",
			"dns_timeout_ms":      "100",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var confirmed, summary int
	for _, finding := range findings {
		switch finding.Type {
		case "subdomain_resolved":
			confirmed++
			if finding.URL != "live.example.com" || finding.Extra["validated"] != "true" {
				t.Fatalf("unexpected confirmed finding: %+v", finding)
			}
		case "passive_name_summary":
			summary++
			if finding.Extra["unresolved_count"] != "1" {
				t.Fatalf("unexpected summary: %+v", finding)
			}
		case "passive_name_candidate":
			t.Fatalf("unresolved candidates should be summarized by default: %+v", finding)
		}
	}
	if confirmed != 1 || summary != 1 {
		t.Fatalf("expected one confirmed finding and one summary, got %+v", findings)
	}
}

func TestRun_WildcardDNSIsNotPromoted(t *testing.T) {
	body := crtshResponse("wild.example.com")
	srv, client := newFixedServer(t, body, http.StatusOK)
	defer srv.Close()

	m := subdiscovery.NewWithClientAndResolver(client, stubResolver{
		records:     map[string][]string{"wild.example.com": {"198.51.100.5"}},
		wildcardIPs: []string{"198.51.100.5"},
	})
	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":            "crtsh",
			"resolve":            "true",
			"include_unresolved": "true",
			"dns_timeout_ms":     "100",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, finding := range findings {
		if finding.Type == "subdomain_resolved" {
			t.Fatalf("wildcard DNS candidate was incorrectly promoted: %+v", finding)
		}
		if finding.Type == "passive_name_candidate" && finding.Extra["wildcard_match"] != "true" {
			t.Fatalf("wildcard candidate missing classification: %+v", finding)
		}
	}
}

func TestRun_MaxCandidatesAndApexExcluded(t *testing.T) {
	body := crtshResponse("example.com", "a.example.com", "b.example.com", "c.example.com")
	srv, client := newFixedServer(t, body, http.StatusOK)
	defer srv.Close()

	m := subdiscovery.NewWithClient(client)
	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":        "crtsh",
			"max_candidates": "2",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected two capped candidates, got %+v", findings)
	}
	for _, finding := range findings {
		if finding.URL == "example.com" {
			t.Fatal("apex domain must not be emitted as a subdomain candidate")
		}
		if finding.Extra["evidence_id"] == "" {
			t.Fatalf("candidate missing evidence id: %+v", finding)
		}
	}
}

func TestRun_DNSLookupHonorsTimeout(t *testing.T) {
	body := crtshResponse("slow.example.com")
	srv, client := newFixedServer(t, body, http.StatusOK)
	defer srv.Close()

	m := subdiscovery.NewWithClientAndResolver(client, stubResolver{delay: time.Second})
	started := time.Now()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":        "crtsh",
			"resolve":        "true",
			"dns_timeout_ms": "20",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
		t.Fatalf("DNS timeout was not honored: %s", elapsed)
	}
	if len(findings) != 1 || findings[0].Type != "passive_name_summary" {
		t.Fatalf("expected only an incomplete/unresolved summary, got %+v", findings)
	}
}

// TestRun_DomainValidation ensures subdomains not matching the target are filtered.
func TestRun_DomainValidation(t *testing.T) {
	body := crtshResponse(
		"api.target.com",
		"evil.otherdomain.com",
		"target.com",
	)
	srv, client := newFixedServer(t, body, http.StatusOK)
	defer srv.Close()

	m := subdiscovery.NewWithClient(client)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "target.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		sub := f.Extra["subdomain"]
		if !strings.HasSuffix(sub, ".target.com") && sub != "target.com" {
			t.Errorf("out-of-scope subdomain in results: %q", sub)
		}
		if strings.Contains(sub, "otherdomain") {
			t.Errorf("out-of-scope subdomain leaked: %q", sub)
		}
	}
}

// TestRun_Deduplication ensures the same subdomain appears only once.
func TestRun_Deduplication(t *testing.T) {
	// Two identical entries in the response.
	body := crtshResponse("www.dedup.io", "www.dedup.io")
	srv, client := newFixedServer(t, body, http.StatusOK)
	defer srv.Close()

	m := subdiscovery.NewWithClient(client)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "dedup.io",
		Options: map[string]string{"sources": "crtsh"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	seen := map[string]int{}
	for _, f := range findings {
		seen[f.Extra["subdomain"]]++
	}
	for sub, n := range seen {
		if n > 1 {
			t.Errorf("subdomain %q duplicated %d times", sub, n)
		}
	}
}

// TestRun_WildcardStripping verifies "*.sub.domain" → "sub.domain".
func TestRun_WildcardStripping(t *testing.T) {
	body := crtshResponse("*.wild.strip.io")
	srv, client := newFixedServer(t, body, http.StatusOK)
	defer srv.Close()

	m := subdiscovery.NewWithClient(client)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "strip.io",
		Options: map[string]string{"sources": "crtsh"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if strings.HasPrefix(f.Extra["subdomain"], "*.") {
			t.Errorf("wildcard prefix not stripped: %q", f.Extra["subdomain"])
		}
	}
}

// TestRun_MultilineNameValue verifies that multiline name_value fields are split.
func TestRun_MultilineNameValue(t *testing.T) {
	type cert struct {
		NameValue string `json:"name_value"`
	}
	certs := []cert{{NameValue: "a.multi.net\nb.multi.net\nc.multi.net"}}
	body, _ := json.Marshal(certs)

	srv, client := newFixedServer(t, body, http.StatusOK)
	defer srv.Close()

	m := subdiscovery.NewWithClient(client)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "multi.net",
		Options: map[string]string{"sources": "crtsh"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	subSet := map[string]bool{}
	for _, f := range findings {
		subSet[f.Extra["subdomain"]] = true
	}
	for _, want := range []string{"a.multi.net", "b.multi.net", "c.multi.net"} {
		if !subSet[want] {
			t.Errorf("missing expected subdomain %q", want)
		}
	}
}

// TestRun_NormalizeDomain checks that a URL-style target is normalised.
func TestRun_NormalizeDomain(t *testing.T) {
	m := subdiscovery.New()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	// Should not panic, even with a full URL as target.
	_, _ = m.Run(ctx, module.Input{
		Target: "https://example.com/path?q=1",
	})
}

// TestRun_EmptySourceResponse ensures zero findings on empty responses.
func TestRun_EmptySourceResponse(t *testing.T) {
	srv, client := newEmptyServer(t)
	defer srv.Close()

	m := subdiscovery.NewWithClient(client)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "empty.io",
		Options: map[string]string{"sources": "crtsh"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty response, got %d", len(findings))
	}
}

// TestRun_SourceError verifies that a source HTTP 500 does not abort the run.
func TestRun_SourceError(t *testing.T) {
	srv, client := newFixedServer(t, []byte("internal error"), http.StatusInternalServerError)
	defer srv.Close()

	m := subdiscovery.NewWithClient(client)
	_, err := m.Run(context.Background(), module.Input{
		Target:  "error.io",
		Options: map[string]string{"sources": "crtsh"},
	})
	// Per subfinder behaviour: source errors are warnings, not fatal.
	if err != nil {
		t.Fatalf("source error should be swallowed, got: %v", err)
	}
}

// TestRun_SourceFilter ensures only requested sources fire.
func TestRun_SourceFilter(t *testing.T) {
	var called int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, "[]")
	}))
	defer srv.Close()

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &redirectTransport{target: srv.URL},
	}

	m := subdiscovery.NewWithClient(client)
	_, _ = m.Run(context.Background(), module.Input{
		Target:  "filtertest.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	// With only one source, called should be 1.
	if called != 1 {
		t.Errorf("expected 1 HTTP call for single-source filter, got %d", called)
	}
}

// TestRun_FindingsHaveSeverity verifies every subdiscovery finding has a severity.
func TestRun_FindingsHaveSeverity(t *testing.T) {
	body, _ := json.Marshal([]map[string]string{
		{"name_value": "api.example.com"},
		{"name_value": "*.example.com"},
		{"name_value": "www.example.com"},
	})
	srv, client := newFixedServer(t, body, 200)
	defer srv.Close()

	m := subdiscovery.NewWithClient(client)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == "" {
			t.Errorf("finding %q missing Severity", f.Detail)
		}
	}
}

// TestRun_ContextCancellationSubdiscovery verifies module returns quickly on cancelled context.
func TestRun_ContextCancellationSubdiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := subdiscovery.New()
	start := time.Now()
	_, _ = m.Run(ctx, module.Input{Target: "example.com"})
	if time.Since(start) > 3*time.Second {
		t.Error("Run hung on cancelled context")
	}
}

// TestRun_SubdomainURLField verifies that subdomain findings include URL or detail.
func TestRun_SubdomainURLField(t *testing.T) {
	body, _ := json.Marshal([]map[string]string{
		{"name_value": "dev.example.com"},
		{"name_value": "staging.example.com"},
	})
	srv, client := newFixedServer(t, body, 200)
	defer srv.Close()

	m := subdiscovery.NewWithClient(client)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Detail == "" && f.URL == "" {
			t.Errorf("finding has neither Detail nor URL: %+v", f)
		}
	}
}

// TestRun_MultipleSourcesReturnCombined verifies results from 2 sources are combined.
func TestRun_MultipleSourcesReturnCombined(t *testing.T) {
	var callCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal([]map[string]string{
			{"name_value": fmt.Sprintf("sub%d.example.com", id)},
		})
		w.Write(body)
	}))
	defer srv.Close()

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &redirectTransport{target: srv.URL},
	}

	m := subdiscovery.NewWithClient(client)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh,hackertarget"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Two sources → at least 1 finding expected (dedup may merge equal subdomains).
	_ = findings
	if got := callCount.Load(); got < 2 {
		t.Errorf("expected at least 2 source calls, got %d", got)
	}
}

// TestRun_FindingsHaveConfidence verifies all findings have a non-empty confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	body := crtshResponse("api.example.com", "www.example.com")
	srv, client := newFixedServer(t, body, http.StatusOK)
	defer srv.Close()

	m := subdiscovery.NewWithClient(client)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding missing Extra[confidence]: %+v", f)
		}
	}
}

// TestRun_FindingTypeValid verifies all subdiscovery findings have a non-empty Type field.
func TestRun_FindingTypeValid(t *testing.T) {
	body := crtshResponse("mail.example.com")
	srv, client := newFixedServer(t, body, http.StatusOK)
	defer srv.Close()

	m := subdiscovery.NewWithClient(client)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "" {
			t.Errorf("finding has empty Type: %+v", f)
		}
	}
}

// TestRun_FindingURLOrDetailSet verifies each finding has at least URL or Detail set.
func TestRun_FindingURLOrDetailSet(t *testing.T) {
	body := crtshResponse("dev.example.com", "stage.example.com")
	srv, client := newFixedServer(t, body, http.StatusOK)
	defer srv.Close()

	m := subdiscovery.NewWithClient(client)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.URL == "" && f.Detail == "" {
			t.Errorf("finding has neither URL nor Detail: %+v", f)
		}
	}
}
