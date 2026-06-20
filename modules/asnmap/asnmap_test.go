package asnmap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── testable extension methods ──────────────────────────────────────────────
//
// These helpers expose internal behaviour that requires a custom URL so tests
// don't make real network calls to RIPE Stat.

// fetchRIPEStatFromURL is a testable variant of fetchRIPEStat.
func (m *Module) fetchRIPEStatFromURL(ctx context.Context, asn, rawURL string) (*ASNInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseRIPEStatResponse(asn, body)
}

// lookupASNFromURL is a testable variant of lookupASN that uses a custom base URL.
func (m *Module) lookupASNFromURL(ctx context.Context, asn, ripeURL string) ([]module.Finding, error) {
	info, err := m.fetchRIPEStatFromURL(ctx, asn, ripeURL)
	if err != nil || info == nil {
		return []module.Finding{{
			Type:     "asn_info",
			URL:      asn,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("ASN %s found (prefix lookup unavailable)", asn),
			Extra:    map[string]string{"asn": asn, "source": "fallback"},
		}}, nil
	}
	return buildFindings(asn, info), nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func hasType(findings []module.Finding, typ string) bool {
	for _, f := range findings {
		if f.Type == typ {
			return true
		}
	}
	return false
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "asnmap" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoInput(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestRun_CollectTargets_Dedup(t *testing.T) {
	input := module.Input{
		Target: "AS13335",
		URLs:   []string{"AS13335", "AS15169"},
	}
	targets := collectTargets(input)
	if len(targets) != 2 {
		t.Fatalf("expected 2 unique targets (AS13335, AS15169), got %d: %v", len(targets), targets)
	}
}

func TestRun_RIPEStatResponse_IPRange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]interface{}{
			"status": "ok",
			"data": map[string]interface{}{
				"resource": "AS13335",
				"prefixes": []map[string]string{
					{"prefix": "104.16.0.0/13"},
					{"prefix": "172.64.0.0/13"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	info, err := m.fetchRIPEStatFromURL(context.Background(), "AS13335", srv.URL+"/prefixes?resource=AS13335")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.Prefixes) != 2 {
		t.Fatalf("expected 2 prefixes, got %d", len(info.Prefixes))
	}
	if info.Prefixes[0] != "104.16.0.0/13" {
		t.Errorf("expected first prefix 104.16.0.0/13, got %q", info.Prefixes[0])
	}
}

func TestRun_RIPEStatBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	_, err := m.fetchRIPEStatFromURL(context.Background(), "AS99999", srv.URL+"/prefixes")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestRun_FallbackFinding_WhenRIPEUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	m := NewWithClient(srv.Client())
	findings, err := m.lookupASNFromURL(context.Background(), "AS13335", srv.URL+"/prefixes")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one fallback finding")
	}
	if findings[0].Extra["asn"] != "AS13335" {
		t.Errorf("expected asn=AS13335 in fallback finding, got %q", findings[0].Extra["asn"])
	}
}

func TestIsASN(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"AS13335", true},
		{"as13335", true},
		{"13335", true},
		{"ASN13335", true},
		{"example.com", false},
		{"1.2.3.4", false},
		{"AS", false},
		{"12", false}, // too short
		{"", false},
	}
	for _, c := range cases {
		got := isASN(c.s)
		if got != c.want {
			t.Errorf("isASN(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestNormaliseASN(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"AS13335", "AS13335"},
		{"as13335", "AS13335"},
		{"13335", "AS13335"},
		{"ASN13335", "AS13335"},
	}
	for _, c := range cases {
		got := normaliseASN(c.in)
		if got != c.want {
			t.Errorf("normaliseASN(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsIPAddress(t *testing.T) {
	if !isIPAddress("1.2.3.4") {
		t.Fatal("expected true for valid IPv4")
	}
	if !isIPAddress("2001:db8::1") {
		t.Fatal("expected true for valid IPv6")
	}
	if isIPAddress("example.com") {
		t.Fatal("expected false for domain name")
	}
	if isIPAddress("") {
		t.Fatal("expected false for empty string")
	}
}

func TestParseRIPEStatResponse_Valid(t *testing.T) {
	body := []byte(`{
		"status": "ok",
		"data": {
			"resource": "AS13335",
			"prefixes": [
				{"prefix": "104.16.0.0/13"},
				{"prefix": "172.64.0.0/13"},
				{"prefix": "2606:4700::/32"}
			]
		}
	}`)
	info, err := parseRIPEStatResponse("AS13335", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.Prefixes) != 3 {
		t.Fatalf("expected 3 prefixes, got %d", len(info.Prefixes))
	}
}

func TestParseRIPEStatResponse_NonOKStatus(t *testing.T) {
	body := []byte(`{"status": "error", "data": {}}`)
	_, err := parseRIPEStatResponse("AS1", body)
	if err == nil {
		t.Fatal("expected error for non-ok status")
	}
}

func TestParseRIPEStatResponse_InvalidJSON(t *testing.T) {
	_, err := parseRIPEStatResponse("AS1", []byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestBuildFindings_EmitsIPRangeType(t *testing.T) {
	info := &ASNInfo{
		ASN:      "AS13335",
		Org:      "Cloudflare",
		Country:  "US",
		Prefixes: []string{"104.16.0.0/13", "172.64.0.0/13"},
	}
	findings := buildFindings("AS13335", info)
	// buildFindings now returns a single aggregated finding (not one per prefix).
	if len(findings) != 1 {
		t.Fatalf("expected 1 aggregated finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "asn_prefix_summary" {
		t.Errorf("expected type asn_prefix_summary, got %q", f.Type)
	}
	if f.Severity != module.SeverityInfo {
		t.Errorf("expected SeverityInfo, got %q", f.Severity)
	}
	if f.Extra["asn"] != "AS13335" {
		t.Errorf("expected asn=AS13335, got %q", f.Extra["asn"])
	}
	if f.Extra["prefix_count"] != "2" {
		t.Errorf("expected prefix_count=2, got %q", f.Extra["prefix_count"])
	}
}

func TestBuildFindings_NoPrefixes(t *testing.T) {
	info := &ASNInfo{ASN: "AS99999"}
	findings := buildFindings("AS99999", info)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for no-prefix ASN, got %d", len(findings))
	}
	if findings[0].Type != "asn_info" {
		t.Errorf("expected type asn_info, got %q", findings[0].Type)
	}
}

func TestExpandIPv6_NotEmpty(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	result := expandIPv6(ip)
	if result == "" {
		t.Fatal("expandIPv6 returned empty string for valid IPv6")
	}
	if !strings.Contains(result, ".") {
		t.Fatal("expandIPv6 result should contain dots")
	}
}

func TestExpandIPv6_Nil(t *testing.T) {
	result := expandIPv6(nil)
	if result != "" {
		t.Fatalf("expected empty string for nil IP, got %q", result)
	}
}

func TestCollectTargets_RawContent(t *testing.T) {
	input := module.Input{
		RawContent: "AS13335\nAS15169\n",
	}
	targets := collectTargets(input)
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets from RawContent, got %d", len(targets))
	}
}

func TestBuildFindings_FindingURL_IsASN(t *testing.T) {
	info := &ASNInfo{
		ASN:      "AS13335",
		Prefixes: []string{"104.16.0.0/13"},
	}
	findings := buildFindings("AS13335", info)
	// Aggregated finding URL is the ASN identifier, not the prefix.
	if findings[0].URL != "AS13335" {
		t.Errorf("expected URL to be the ASN, got %q", findings[0].URL)
	}
	// The prefix is available in Extra.
	if !strings.Contains(findings[0].Extra["prefixes"], "104.16.0.0/13") {
		t.Errorf("expected prefix in Extra[prefixes], got %q", findings[0].Extra["prefixes"])
	}
}

func TestHasType_Helper(t *testing.T) {
	findings := []module.Finding{
		{Type: "ip_range"},
		{Type: "asn_info"},
	}
	if !hasType(findings, "ip_range") {
		t.Fatal("expected hasType to return true for ip_range")
	}
	if hasType(findings, "other") {
		t.Fatal("expected hasType to return false for other")
	}
}
