package shodanwatch_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/shodanwatch"
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

// newMockServer creates a test server that behaves like Shodan API.
// handler is called for all non-root paths.
func newMockServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

func run(t *testing.T, srv *httptest.Server, target string, opts map[string]string) []module.Finding {
	t.Helper()
	// Override shodanBase via transport that redirects all requests to test server.
	transport := &redirectTransport{baseURL: srv.URL}
	m := shodanwatch.NewWithClient(&http.Client{Transport: transport})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  target,
		Options: opts,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findings
}

type redirectTransport struct{ baseURL string }

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL := rt.baseURL + req.URL.Path
	if req.URL.RawQuery != "" {
		newURL += "?" + req.URL.RawQuery
	}
	req2, _ := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
	for k, vs := range req.Header {
		for _, v := range vs {
			req2.Header.Add(k, v)
		}
	}
	return http.DefaultTransport.RoundTrip(req2)
}

func TestName(t *testing.T) {
	if shodanwatch.New().Name() != "shodanwatch" {
		t.Error("expected name 'shodanwatch'")
	}
}

func TestEmptyTargetReturnsError(t *testing.T) {
	m := shodanwatch.New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Error("expected error for empty target")
	}
}

func TestInvalidMode(t *testing.T) {
	m := shodanwatch.New()
	_, err := m.Run(context.Background(), module.Input{
		Target:  "8.8.8.8",
		Options: map[string]string{"mode": "unknown"},
	})
	if err == nil {
		t.Error("expected error for invalid mode")
	}
}

// TestHostFound: Shodan returns host JSON → shodan_host finding.
func TestHostFound(t *testing.T) {
	hostJSON := map[string]any{
		"ip_str":       "8.8.8.8",
		"org":          "Google LLC",
		"asn":          "AS15169",
		"country_code": "US",
		"city":         "Mountain View",
		"hostnames":    []string{"dns.google"},
		"ports":        []int{53, 443},
		"vulns":        map[string]any{},
		"data":         []any{},
	}
	hostBytes, _ := json.Marshal(hostJSON)

	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/shodan/host/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(hostBytes)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer srv.Close()

	findings := run(t, srv, "8.8.8.8", map[string]string{
		"shodan_api_key": "testkey",
		"mode":           "host",
	})

	found := findByType(findings, "shodan_inventory_reference")
	if len(found) == 0 {
		t.Error("expected shodan_host finding")
	}
	if found[0].Extra["org"] != "Google LLC" {
		t.Errorf("unexpected org: %q", found[0].Extra["org"])
	}
}

// TestHostWithVulns: third-party CVE references are downgraded until confirmed.
func TestHostWithVulns(t *testing.T) {
	hostJSON := map[string]any{
		"ip_str":       "1.2.3.4",
		"org":          "TestOrg",
		"asn":          "AS1234",
		"country_code": "BR",
		"city":         "São Paulo",
		"hostnames":    []string{},
		"ports":        []int{443},
		"vulns": map[string]any{
			"CVE-2021-44228": map[string]any{
				"cvss":    10.0,
				"summary": "Log4Shell",
			},
			"CVE-2022-0001": map[string]any{
				"cvss":    7.5,
				"summary": "Another vuln",
			},
		},
		"data": []any{},
	}
	hostBytes, _ := json.Marshal(hostJSON)

	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(hostBytes)
	})
	defer srv.Close()

	findings := run(t, srv, "1.2.3.4", map[string]string{
		"shodan_api_key": "testkey",
		"mode":           "host",
	})

	vulns := findByType(findings, "shodan_vulnerability_reference")
	if len(vulns) < 2 {
		t.Errorf("expected 2 vuln findings, got %d", len(vulns))
	}
	// CVSS 10 remains high priority, but not Critical before direct validation.
	for _, v := range vulns {
		if v.Extra["cve"] == "CVE-2021-44228" && v.Severity != module.SeverityHigh {
			t.Errorf("unverified Log4Shell reference should be High, got %v", v.Severity)
		}
	}
}

// TestHostNotFound: absence from a third-party database is not a target finding.
func TestHostNotFound(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"No information available for that IP."}`))
	})
	defer srv.Close()

	findings := run(t, srv, "192.0.2.1", map[string]string{
		"shodan_api_key": "testkey",
		"mode":           "host",
	})

	if len(findings) != 0 {
		t.Fatalf("expected no finding for Shodan 404, got %+v", findings)
	}
}

// TestNoAPIKeySkipsSilently: missing configuration is not a target finding.
func TestNoAPIKeySkipsSilently(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer srv.Close()

	findings := run(t, srv, "8.8.8.8", map[string]string{"mode": "host"})
	if len(findings) != 0 {
		t.Fatalf("expected no findings when API key is absent, got %v", findings)
	}
}

// TestSearchMode: search returns total + asset findings.
func TestSearchMode(t *testing.T) {
	searchJSON := map[string]any{
		"total": 100,
		"matches": []map[string]any{
			{"ip_str": "1.1.1.1", "org": "Cloudflare", "country_code": "US", "ports": []int{80, 443}, "vulns": map[string]any{}},
		},
	}
	bytes, _ := json.Marshal(searchJSON)

	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(bytes)
	})
	defer srv.Close()

	findings := run(t, srv, "cloudflare query", map[string]string{
		"shodan_api_key": "testkey",
		"mode":           "search",
		"query":          "org:Cloudflare",
	})

	total := findByType(findings, "shodan_search_total")
	if len(total) == 0 {
		t.Error("expected shodan_search_total finding")
	}
	assets := findByType(findings, "shodan_asset_reference")
	if len(assets) == 0 {
		t.Error("expected shodan_asset findings")
	}
}

// TestOrgMode: org mode wraps query with org: prefix.
func TestOrgMode(t *testing.T) {
	var capturedQuery string
	searchJSON := map[string]any{"total": 0, "matches": []any{}}
	bytes, _ := json.Marshal(searchJSON)

	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query().Get("query")
		w.WriteHeader(http.StatusOK)
		w.Write(bytes)
	})
	defer srv.Close()

	run(t, srv, "Acme Corp", map[string]string{
		"shodan_api_key": "testkey",
		"mode":           "org",
		"org":            "Acme Corp",
	})

	if !strings.Contains(capturedQuery, "Acme Corp") {
		t.Errorf("expected org query to contain org name, got %q", capturedQuery)
	}
}

// TestHoneyScore: honeypot classification is informational, not a vulnerability.
func TestHoneyScore(t *testing.T) {
	hostJSON := map[string]any{
		"ip_str": "10.0.0.1", "org": "Test", "asn": "", "country_code": "US",
		"city": "", "hostnames": []string{}, "ports": []int{}, "vulns": map[string]any{}, "data": []any{},
	}
	honeyJSON := map[string]any{"probability": 0.85}
	hBytes, _ := json.Marshal(hostJSON)
	hhBytes, _ := json.Marshal(honeyJSON)

	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/labs/honeyscore") {
			w.WriteHeader(200)
			w.Write(hhBytes)
			return
		}
		w.WriteHeader(200)
		w.Write(hBytes)
	})
	defer srv.Close()

	findings := run(t, srv, "10.0.0.1", map[string]string{
		"shodan_api_key": "testkey",
		"mode":           "host",
		"honeyscore":     "true",
	})

	honey := findByType(findings, "shodan_honeyscore")
	if len(honey) == 0 {
		t.Error("expected shodan_honeyscore finding")
	}
	if honey[0].Severity != module.SeverityInfo {
		t.Errorf("honeypot classification should be Info, got %v", honey[0].Severity)
	}
}

func TestHostModeInvalidDomainReturnsError(t *testing.T) {
	m := shodanwatch.NewWithClient(http.DefaultClient)
	_, err := m.Run(context.Background(), module.Input{
		Target: "not a domain",
		Options: map[string]string{
			"shodan_api_key": "testkey",
			"mode":           "host",
		},
	})
	if err == nil {
		t.Fatal("expected invalid host target error")
	}
}

func TestHostReferenceCarriesPromotionVeto(t *testing.T) {
	hostJSON := map[string]any{
		"ip_str": "8.8.8.8", "org": "Google", "asn": "AS15169", "country_code": "US",
		"city": "", "hostnames": []string{}, "ports": []int{53}, "vulns": map[string]any{}, "data": []any{},
	}
	bytes, _ := json.Marshal(hostJSON)
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes)
	})
	defer srv.Close()

	findings := run(t, srv, "8.8.8.8", map[string]string{
		"shodan_api_key": "testkey",
		"mode":           "host",
	})
	host := findByType(findings, "shodan_inventory_reference")
	if len(host) != 1 || host[0].Extra["promote_to_context"] != "false" {
		t.Fatalf("third-party host reference must not be promoted: %+v", host)
	}
}

// TestConfidencePresent: all findings must have confidence.
func TestConfidencePresent(t *testing.T) {
	hostJSON := map[string]any{
		"ip_str": "8.8.8.8", "org": "Google", "asn": "AS15169", "country_code": "US",
		"city": "", "hostnames": []string{}, "ports": []int{53}, "vulns": map[string]any{}, "data": []any{},
	}
	bytes, _ := json.Marshal(hostJSON)

	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(bytes)
	})
	defer srv.Close()

	findings := run(t, srv, "8.8.8.8", map[string]string{
		"shodan_api_key": "testkey",
		"mode":           "host",
	})

	for _, f := range findings {
		if f.Extra == nil || f.Extra["confidence"] == "" {
			t.Errorf("finding %q missing confidence", f.Type)
		}
	}
}

// TestContextCancellation: cancelled context must not panic.
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	defer srv.Close()

	transport := &redirectTransport{baseURL: srv.URL}
	m := shodanwatch.NewWithClient(&http.Client{Transport: transport})
	_, _ = m.Run(ctx, module.Input{
		Target:  "8.8.8.8",
		Options: map[string]string{"shodan_api_key": "key", "mode": "host"},
	})
}
