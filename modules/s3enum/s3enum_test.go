package s3enum_test

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/s3enum"
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
	// redirectTransport intercepta qualquer URL e redireciona ao httptest server — sem rede real.
	m := s3enum.NewWithClient(&http.Client{Transport: &redirectTransport{target: srv.URL}})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "testcompany",
		Options: opts,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findings
}

func TestName(t *testing.T) {
	if s3enum.New().Name() != "s3enum" {
		t.Error("expected name 's3enum'")
	}
}

func TestEmptyTargetReturnsError(t *testing.T) {
	m := s3enum.New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Error("expected error for empty target")
	}
}

// TestPublicBucketDetected: bodyTransport responde 200+XML para todas as URLs → s3_public_bucket.
func TestPublicBucketDetected(t *testing.T) {
	type listBucketResult struct {
		XMLName  xml.Name `xml:"ListBucketResult"`
		KeyCount int      `xml:"KeyCount"`
	}
	xmlBody, _ := xml.Marshal(listBucketResult{KeyCount: 42})
	xmlResp := `<?xml version="1.0"?>` + string(xmlBody)

	// bodyTransport intercepta todas as URLs — evita conexões reais ao AWS/GCS.
	m := s3enum.NewWithClient(&http.Client{
		Transport: &bodyTransport{status: 200, body: xmlResp},
	})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "testcompany",
		Options: map[string]string{"extra_names": "testcompany", "providers": "aws-s3"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Finding type é "<provider_tag>_public_listing" — para aws-s3 é "aws_s3_public_listing".
	public := findByType(findings, "aws_s3_public_listing")
	if len(public) == 0 {
		t.Error("expected aws_s3_public_listing finding when server returns 200 with XML listing")
	}
	if len(public) > 0 && public[0].Severity != module.SeverityHigh {
		t.Errorf("expected High severity, got %v", public[0].Severity)
	}
}

// TestForbiddenBucketIsNotTargetFinding: 403 alone does not prove target ownership.
func TestForbiddenBucketIsNotTargetFinding(t *testing.T) {
	m := s3enum.NewWithClient(&http.Client{
		Transport: &bodyTransport{status: 403, body: ""},
	})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "company",
		Options: map[string]string{"extra_names": "company", "providers": "aws-s3"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no finding for unverified 403 bucket candidate, got %v", findings)
	}
}

// TestExtractKeyword: domain keyword extraction.
func TestExtractKeywordViaRun(t *testing.T) {
	targets := []string{
		"https://www.acme.com",
		"acme.com.br",
		"acme",
	}
	for _, target := range targets {
		m := s3enum.NewWithClient(&http.Client{Transport: &nullTransport{}})
		findings, err := m.Run(context.Background(), module.Input{Target: target})
		if err != nil {
			t.Fatalf("Run(%q): %v", target, err)
		}
		_ = findings // all 404 from null transport → no findings
	}
}

// nullTransport returns 404 for all requests.
type nullTransport struct{}

func (n *nullTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       http.NoBody,
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// TestDeduplication: multiple identical probes don't produce duplicate findings.
func TestDeduplication(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	// redirectTransport redireciona todas as URLs ao httptest server — sem rede real.
	m := s3enum.NewWithClient(&http.Client{Transport: &redirectTransport{target: srv.URL}})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test",
		Options: map[string]string{"extra_names": "dup,dup,dup"},
	})
	seen := map[string]int{}
	for _, f := range findings {
		key := f.Type + "|" + f.URL
		seen[key]++
		if seen[key] > 1 {
			t.Errorf("duplicate finding: %s", key)
		}
	}
}

// TestParallelismOption: parallelism=1 deve completar sem erro.
func TestParallelismOption(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<Error><Code>NoSuchBucket</Code></Error>`)
	}))
	defer srv.Close()

	m := s3enum.NewWithClient(&http.Client{Transport: &redirectTransport{target: srv.URL}})
	_, err := m.Run(context.Background(), module.Input{
		Target:  "test",
		Options: map[string]string{"parallelism": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestContextCancellation: contexto cancelado não deve causar panic.
func TestContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := s3enum.NewWithClient(&http.Client{Transport: &redirectTransport{target: srv.URL}})
	_, _ = m.Run(ctx, module.Input{Target: "test"})
}

// TestConfidenceInFindings: any finding that appears should have confidence set.
func TestConfidencePresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	// We can't inject our test server URL into the probe directly (probes go to aws),
	// but we can build findings via the HTTP handler and verify structure.
	// Use a custom client that redirects all requests to our test server.
	transport := &redirectTransport{target: srv.URL}
	m := s3enum.NewWithClient(&http.Client{Transport: transport})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testco.example",
		Options: map[string]string{"parallelism": "2"},
	})
	for _, f := range findings {
		if f.Extra == nil || f.Extra["confidence"] == "" {
			t.Errorf("finding %q missing confidence", f.Type)
		}
	}
}

// TestPublicListingFindingViaMockAWS: inject custom transport that mimics AWS 200.
func TestPublicListingFindingViaMockAWS(t *testing.T) {
	xmlResp := `<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><KeyCount>7</KeyCount></ListBucketResult>`
	transport := &bodyTransport{status: 200, body: xmlResp}
	m := s3enum.NewWithClient(&http.Client{Transport: transport})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "acme.io",
		Options: map[string]string{"parallelism": "1", "extra_names": "acme"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With all probes returning 200+XML, at least one public_listing finding should appear.
	found := false
	for _, f := range findings {
		if strings.Contains(f.Type, "public_listing") {
			found = true
			if f.Severity != module.SeverityHigh {
				t.Errorf("expected High severity for public listing, got %v", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected at least one public_listing finding")
	}
}

// TestForbiddenFindingViaMockAWS: unverified 403 candidates are discarded.
func TestForbiddenFindingViaMockAWS(t *testing.T) {
	transport := &bodyTransport{status: 403, body: ""}
	m := s3enum.NewWithClient(&http.Client{Transport: transport})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "corp.io",
		Options: map[string]string{"parallelism": "1", "extra_names": "corp"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Type, "exists_private") {
			t.Fatalf("403 candidate must not produce target finding: %+v", f)
		}
	}
}

// Test404ProducesNoFinding: HTTP 404 deve ser descartado silenciosamente.
// Antes produzia "possible_takeover" High — era um falso positivo crítico.
func Test404ProducesNoFinding(t *testing.T) {
	// Transport que retorna 404 com corpo vazio (como faria o AWS para bucket inexistente).
	m := s3enum.NewWithClient(&http.Client{
		Transport: &bodyTransport{status: 404, body: ""},
	})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "doesnotexist",
		Options: map[string]string{"providers": "aws-s3"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Type, "takeover") || strings.Contains(f.Type, "possible") {
			t.Errorf("404 should not produce takeover finding, got: %s (severity=%v)", f.Type, f.Severity)
		}
		if f.Severity == module.SeverityHigh && strings.Contains(f.Type, "404") {
			t.Errorf("404 should never produce High severity finding, got: %s", f.Type)
		}
	}
	// Total findings from 404 alone must be zero.
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for 404 response, got %d: %v", len(findings), findings)
	}
}

// TestMaxTargetsOption: max_targets limita número de candidatos provados.
func TestMaxTargetsOption(t *testing.T) {
	var callCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := s3enum.NewWithClient(&http.Client{Transport: &redirectTransport{target: srv.URL}})
	_, err := m.Run(context.Background(), module.Input{
		Target: "bigcompany",
		Options: map[string]string{
			"max_targets": "5",
			"providers":   "aws-s3",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With max_targets=5 and 1 provider, at most 5 HTTP calls should be made.
	// aws-s3 matches "aws-s3" and "aws-s3-us-east" (2 providers) × 5 targets = 10 max.
	got := callCount.Load()
	if got > 10 {
		t.Errorf("expected ≤10 HTTP calls with max_targets=5 and aws-s3 providers, got %d", got)
	}
	// And must be less than without the limit (default 100 candidates × 2 = 200 calls).
	if got >= 20 {
		t.Errorf("max_targets=5 should limit calls significantly, got %d", got)
	}
}

// TestGlobalBudget: max_runtime_seconds deve encerrar o módulo no prazo.
func TestGlobalBudget(t *testing.T) {
	// Server that immediately returns 403 — we test budget via context cancellation.
	// The actual budget is enforced by context.WithTimeout in the module.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	m := s3enum.NewWithClient(&http.Client{
		Transport: &redirectTransport{target: srv.URL},
		Timeout:   2 * time.Second,
	})
	start := time.Now()
	_, _ = m.Run(context.Background(), module.Input{
		Target: "test",
		Options: map[string]string{
			"max_runtime_seconds": "1",
			"providers":           "aws-s3",
			"max_targets":         "5",
		},
	})
	elapsed := time.Since(start)
	// Should complete within budget + small overhead.
	if elapsed > 4*time.Second {
		t.Errorf("module took too long: %v (budget was 1s)", elapsed)
	}
}

// ─── Transport helpers ────────────────────────────────────────────────────────

type redirectTransport struct{ target string }

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL := rt.target + req.URL.Path
	if req.URL.RawQuery != "" {
		newURL += "?" + req.URL.RawQuery
	}
	req2, _ := http.NewRequest(req.Method, newURL, req.Body)
	for k, vs := range req.Header {
		for _, v := range vs {
			req2.Header.Add(k, v)
		}
	}
	return http.DefaultTransport.RoundTrip(req2)
}

type bodyTransport struct {
	status int
	body   string
}

func (bt *bodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	rec.WriteHeader(bt.status)
	if bt.body != "" {
		rec.WriteString(bt.body)
	}
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}
