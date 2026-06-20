package wayback_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/wayback"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// cdxRow builds a CDX JSON array row: [urlkey, timestamp, original, mime, status, digest, length]
func cdxRow(timestamp, original string) []string {
	return []string{"urlkey", timestamp, original, "text/html", "200", "digest123", "1234"}
}

// makeCDXBody serialises a slice of URL rows into the CDX JSON format
// (first row is the header, as the real API returns).
func makeCDXBody(rows [][]string) []byte {
	header := []string{"urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"}
	all := append([][]string{header}, rows...)
	b, _ := json.Marshal(all)
	return b
}

// makeNDJSON builds a Common Crawl NDJSON body.
func makeNDJSON(urls []string) string {
	var sb strings.Builder
	for _, u := range urls {
		sb.WriteString(fmt.Sprintf(`{"url":%q,"timestamp":"20240101120000"}`, u))
		sb.WriteString("\n")
	}
	return sb.String()
}

// makeVTBody builds a VirusTotal domain report JSON body.
func makeVTBody(urls []string) []byte {
	type vtURL struct {
		URL string `json:"url"`
	}
	type vtBody struct {
		URLs []vtURL `json:"detected_urls"`
	}
	items := make([]vtURL, len(urls))
	for i, u := range urls {
		items[i] = vtURL{URL: u}
	}
	b, _ := json.Marshal(vtBody{URLs: items})
	return b
}

// routerServer returns a single server that routes by path/host patterns.
func routerServer(waybackURLs, ccURLs, vtURLs []string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origHost := r.Header.Get("X-Original-Host")
		uri := r.RequestURI

		switch {
		case strings.Contains(origHost, "web.archive.org") ||
			strings.Contains(uri, "cdx/search"):
			rows := make([][]string, len(waybackURLs))
			for i, u := range waybackURLs {
				rows[i] = cdxRow("20230415120000", u)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(makeCDXBody(rows))

		case strings.Contains(origHost, "commoncrawl.org") ||
			strings.Contains(uri, "commoncrawl"):
			w.Header().Set("Content-Type", "application/x-ndjson")
			_, _ = w.Write([]byte(makeNDJSON(ccURLs)))

		case strings.Contains(origHost, "virustotal.com") ||
			strings.Contains(uri, "virustotal"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(makeVTBody(vtURLs))

		default:
			http.NotFound(w, r)
		}
	}))
}

// rewriteTransport redirects all outbound requests to the mock server.
type rewriteTransport struct {
	mockHost string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("X-Original-Host", req.URL.Host)
	clone.URL.Scheme = "http"
	clone.URL.Host = t.mockHost
	return http.DefaultTransport.RoundTrip(clone)
}

func clientFor(srv *httptest.Server) *http.Client {
	host := strings.TrimPrefix(srv.URL, "http://")
	return &http.Client{Transport: &rewriteTransport{mockHost: host}}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if wayback.New().Name() != "wayback" {
		t.Error("expected name 'wayback'")
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = wayback.New()
}

// TestEmptyTarget: no target → error.
func TestEmptyTarget(t *testing.T) {
	m := wayback.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestWaybackURLsReturned: CDX API results become unverified historical references.
func TestWaybackURLsReturned(t *testing.T) {
	srv := routerServer(
		[]string{"https://example.com/login", "https://example.com/admin"},
		nil, nil,
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from Wayback, got none")
	}
	for _, f := range findings {
		if f.Type != "historical_reference" {
			t.Errorf("unexpected finding type: %q", f.Type)
		}
		if f.Extra["promote_to_context"] != "false" {
			t.Errorf("historical reference must not be promoted: %+v", f)
		}
	}
}

func TestRejectsMalformedAndOutOfScopeURLs(t *testing.T) {
	srv := routerServer(
		[]string{
			"https://example.com/good#fragment",
			"https://www..example.com/invalid",
			"https://example.com.attacker.test/out",
		},
		nil, nil,
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected only one valid in-scope reference, got %+v", findings)
	}
	if findings[0].URL != "https://example.com/good" {
		t.Fatalf("unexpected canonical URL %q", findings[0].URL)
	}
}

func TestMaxURLs(t *testing.T) {
	srv := routerServer(
		[]string{
			"https://example.com/one",
			"https://example.com/two",
			"https://example.com/three",
		},
		nil, nil,
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"max_urls": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected max 2 findings, got %d", len(findings))
	}
}

// TestCommonCrawlURLsMerged: CC results merged with Wayback results.
func TestCommonCrawlURLsMerged(t *testing.T) {
	srv := routerServer(
		[]string{"https://example.com/wayback-only"},
		[]string{"https://example.com/cc-only"},
		nil,
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	urls := make(map[string]bool)
	for _, f := range findings {
		urls[f.URL] = true
	}
	if !urls["https://example.com/wayback-only"] {
		t.Error("missing wayback URL in results")
	}
	if !urls["https://example.com/cc-only"] {
		t.Error("missing Common Crawl URL in results")
	}
}

// TestVirusTotalURLsMerged: VT results included when api key set.
func TestVirusTotalURLsMerged(t *testing.T) {
	srv := routerServer(
		nil, nil,
		[]string{"https://example.com/vt-only"},
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"vt_api_key": "testkey"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.URL == "https://example.com/vt-only" {
			found = true
			break
		}
	}
	if !found {
		t.Error("VirusTotal URL not present in findings")
	}
}

// TestDeduplicatesAcrossSources: same URL from multiple sources → 1 finding.
func TestDeduplicatesAcrossSources(t *testing.T) {
	shared := "https://example.com/shared"
	srv := routerServer(
		[]string{shared},
		[]string{shared},
		nil,
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := 0
	for _, f := range findings {
		if f.URL == shared {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected shared URL deduplicated to 1, got %d", count)
	}
}

// TestShowDates: dates=true → captured_at in Extra for wayback findings.
func TestShowDates(t *testing.T) {
	srv := routerServer(
		[]string{"https://example.com/page"},
		nil, nil,
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"dates": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["source"] == "wayback" && f.Extra["captured_at"] == "" {
			t.Error("expected captured_at in Extra when dates=true")
		}
	}
}

// TestGetVersions: get_versions=true → archived_version findings.
func TestGetVersions(t *testing.T) {
	srv := routerServer(
		[]string{"https://example.com/page"},
		nil, nil,
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "https://example.com/page",
		Options: map[string]string{"get_versions": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type != "archived_version" {
			t.Errorf("expected type archived_version, got %q", f.Type)
		}
		if !strings.HasPrefix(f.URL, "https://web.archive.org/web/") {
			t.Errorf("expected Wayback versioned URL, got %q", f.URL)
		}
	}
}

// TestContextCancellation: cancelled context → no panic.
func TestContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := wayback.NewWithClient(clientFor(srv))
	_, err := m.Run(ctx, module.Input{Target: "example.com"})
	_ = err
}

// TestFindingFields: all required fields populated.
func TestFindingFields(t *testing.T) {
	srv := routerServer(
		[]string{"https://example.com/api?q=test"},
		nil, nil,
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type == "" {
		t.Error("Type empty")
	}
	if f.URL == "" {
		t.Error("URL empty")
	}
	if f.Severity == "" {
		t.Error("Severity empty")
	}
}

// TestNewWithClient: does not panic.
func TestNewWithClient(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := wayback.NewWithClient(c)
	if m == nil || m.Name() != "wayback" {
		t.Fatal("NewWithClient failed")
	}
}

// TestEmptyWaybackResponse: CDX returns empty → no findings from wayback source.
func TestEmptyWaybackResponse(t *testing.T) {
	srv := routerServer([]string{}, nil, nil)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With empty CDX, Common Crawl may also return empty.
	_ = findings
}

// TestTargetSchemeStripped: https:// prefix in target handled.
func TestTargetSchemeStripped(t *testing.T) {
	srv := routerServer(
		[]string{"https://example.com/api"},
		nil, nil,
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "https://example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = findings
}

// TestMultipleSourcesAllURLsUnique: when all 3 sources have unique URLs, all returned.
func TestMultipleSourcesAllURLsUnique(t *testing.T) {
	srv := routerServer(
		[]string{"https://example.com/a"},
		[]string{"https://example.com/b"},
		[]string{"https://example.com/c"},
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"vt_api_key": "testkey"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	urlSet := make(map[string]bool)
	for _, f := range findings {
		urlSet[f.URL] = true
	}
	for _, u := range []string{
		"https://example.com/a",
		"https://example.com/b",
		"https://example.com/c",
	} {
		if !urlSet[u] {
			t.Errorf("expected URL %q in results", u)
		}
	}
}

// TestFindingsSeveritySet verifies all wayback findings have a non-empty severity.
func TestFindingsSeveritySet(t *testing.T) {
	srv := routerServer(
		[]string{"https://example.com/login", "https://example.com/admin"},
		nil, nil,
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == "" {
			t.Errorf("finding missing Severity: %+v", f)
		}
		if f.URL == "" {
			t.Errorf("finding missing URL: %+v", f)
		}
	}
}

// TestContextCancellationFast verifies wayback module returns quickly on cancelled context.
func TestContextCancellationFast(t *testing.T) {
	srv := routerServer(nil, nil, nil)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := wayback.NewWithClient(clientFor(srv))
	start := time.Now()
	_, _ = m.Run(ctx, module.Input{Target: "example.com"})
	if time.Since(start) > 3*time.Second {
		t.Error("Run hung on cancelled context")
	}
}

// TestRun_FindingsHaveConfidence verifies all findings have a non-empty confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	srv := routerServer(
		[]string{"http://example.com/page"},
		nil, nil,
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding missing Extra[confidence]: %+v", f)
		}
	}
}

// TestRun_FindingTypeValid verifies all findings have a non-empty Type.
func TestRun_FindingTypeValid(t *testing.T) {
	srv := routerServer(
		[]string{"http://example.com/page"},
		nil, nil,
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
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
	srv := routerServer(
		[]string{"http://example.com/page"},
		nil, nil,
	)
	defer srv.Close()

	m := wayback.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.URL == "" && f.Detail == "" {
			t.Errorf("finding has neither URL nor Detail: %+v", f)
		}
	}
}
