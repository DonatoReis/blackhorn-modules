package vulnx

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func hasType(findings []module.Finding, t string) bool {
	for _, f := range findings {
		if f.Type == t {
			return true
		}
	}
	return false
}

func hasCVE(findings []module.Finding, cve string) bool {
	for _, f := range findings {
		if f.Extra["cve"] == cve {
			return true
		}
	}
	return false
}

func hasTech(findings []module.Finding, tech string) bool {
	for _, f := range findings {
		if strings.Contains(f.Extra["technology"], tech) {
			return true
		}
	}
	return false
}

// techSrv serves a response that fingerprints as the given technology.
func techSrv(t *testing.T, serverHeader, xPoweredBy, body string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if serverHeader != "" {
			w.Header().Set("Server", serverHeader)
		}
		if xPoweredBy != "" {
			w.Header().Set("X-Powered-By", xPoweredBy)
		}
		w.WriteHeader(200)
		fmt.Fprint(w, body)
	}))
}

// ─── basic ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "vulnx" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoTargets(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

// ─── tech override mode ──────────────────────────────────────────────────────

func TestTechOverride_WordPress(t *testing.T) {
	m := NewWithClient(http.DefaultClient)
	m.TechOverride = []string{"wordpress"}
	findings, err := m.Run(context.Background(), module.Input{Target: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "known_cve") {
		t.Fatal("expected known_cve findings for wordpress")
	}
	// Should include WordPress SQLi CVEs.
	if !hasCVE(findings, "CVE-2022-21661") {
		t.Fatal("expected CVE-2022-21661 (WordPress SQLi)")
	}
}

func TestTechOverride_Apache(t *testing.T) {
	m := NewWithClient(http.DefaultClient)
	m.TechOverride = []string{"apache"}
	findings, err := m.Run(context.Background(), module.Input{Target: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCVE(findings, "CVE-2021-41773") {
		t.Fatal("expected CVE-2021-41773 (Apache path traversal)")
	}
}

func TestTechOverride_Log4j(t *testing.T) {
	m := NewWithClient(http.DefaultClient)
	m.TechOverride = []string{"log4j"}
	findings, err := m.Run(context.Background(), module.Input{Target: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCVE(findings, "CVE-2021-44228") {
		t.Fatal("expected Log4Shell CVE-2021-44228")
	}
	for _, f := range findings {
		if f.Extra["cve"] == "CVE-2021-44228" && f.Severity != module.SeverityCritical {
			t.Errorf("expected Critical severity for Log4Shell, got %q", f.Severity)
		}
	}
}

func TestTechOverride_Multiple(t *testing.T) {
	m := NewWithClient(http.DefaultClient)
	m.TechOverride = []string{"wordpress", "nginx"}
	findings, err := m.Run(context.Background(), module.Input{Target: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	hasWP := false
	hasNginx := false
	for _, f := range findings {
		if strings.Contains(f.Extra["cve"], "2022-21661") {
			hasWP = true
		}
		if strings.Contains(f.Extra["technology"], "nginx") {
			hasNginx = true
		}
	}
	if !hasWP {
		t.Fatal("expected WordPress CVEs")
	}
	if !hasNginx {
		t.Fatal("expected nginx CVEs")
	}
}

func TestOptions_TechOverride(t *testing.T) {
	m := NewWithClient(http.DefaultClient)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "https://example.com",
		Options: map[string]string{"tech": "struts, spring"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCVE(findings, "CVE-2017-5638") {
		t.Fatal("expected Struts CVE-2017-5638")
	}
	if !hasCVE(findings, "CVE-2022-22965") {
		t.Fatal("expected Spring4Shell CVE-2022-22965")
	}
}

// ─── MinCVSS filtering ────────────────────────────────────────────────────────

func TestMinCVSS_Filter(t *testing.T) {
	m := NewWithClient(http.DefaultClient)
	m.TechOverride = []string{"redis"}
	m.MinCVSS = 9.0 // only critical
	findings, err := m.Run(context.Background(), module.Input{Target: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		cvss := 0.0
		fmt.Sscanf(f.Extra["cvss"], "%f", &cvss)
		if cvss < 9.0 {
			t.Errorf("finding with CVSS %.1f should have been filtered (minCVSS=9.0): %v", cvss, f.Extra["cve"])
		}
	}
}

func TestMinCVSS_Option(t *testing.T) {
	m := NewWithClient(http.DefaultClient)
	m.TechOverride = []string{"apache"}
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "https://example.com",
		Options: map[string]string{"min_cvss": "9.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		cvss := 0.0
		fmt.Sscanf(f.Extra["cvss"], "%f", &cvss)
		if cvss < 9.5 {
			t.Errorf("CVSS %.1f below min_cvss=9.5: %q", cvss, f.Extra["cve"])
		}
	}
}

// ─── fingerprinting via HTTP ──────────────────────────────────────────────────

func TestFingerprint_ApacheHeader(t *testing.T) {
	srv := techSrv(t, "Apache/2.4.49 (Unix)", "", "")
	defer srv.Close()

	m := NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	// Should match apache and find CVE-2021-41773.
	if !hasCVE(findings, "CVE-2021-41773") {
		t.Logf("All findings: %+v", findings)
		t.Fatal("expected CVE-2021-41773 from Apache/2.4.49 fingerprint")
	}
}

func TestFingerprint_NginxHeader(t *testing.T) {
	srv := techSrv(t, "nginx/1.14.0", "", "")
	defer srv.Close()

	m := NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !hasTech(findings, "nginx") {
		t.Fatal("expected nginx technology detected from Server header")
	}
}

func TestFingerprint_WordPressBody(t *testing.T) {
	srv := techSrv(t, "", "", `<link rel='stylesheet' href='/wp-content/themes/test/style.css'>`)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !hasTech(findings, "wordpress") {
		t.Fatal("expected wordpress detected from body wp-content")
	}
}

func TestFingerprint_PHPHeader(t *testing.T) {
	srv := techSrv(t, "", "PHP/8.2.1", "")
	defer srv.Close()

	m := NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !hasTech(findings, "php") {
		t.Fatal("expected php detected from X-Powered-By header")
	}
}

func TestFingerprint_JenkinsHeader(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Jenkins", "2.401.3")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !hasTech(findings, "jenkins") {
		t.Fatal("expected jenkins detected from X-Jenkins header")
	}
}

// ─── NVD lookup ───────────────────────────────────────────────────────────────

func TestNVDLookup_Enrichment(t *testing.T) {
	nvdSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := nvdResponse{}
		resp.Vulnerabilities = []struct {
			CVE struct {
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"cve"`
		}{
			{},
		}
		resp.Vulnerabilities[0].CVE.Descriptions = []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		}{{Lang: "en", Value: "NVD enrichment description"}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer nvdSrv.Close()

	m := NewWithClient(nvdSrv.Client())
	m.TechOverride = []string{"log4j"}
	m.EnableNVDLookup = true
	m.NVDBaseURL = nvdSrv.URL

	findings, err := m.Run(context.Background(), module.Input{Target: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Extra["nvd_detail"] == "NVD enrichment description" {
			return
		}
	}
	t.Fatal("expected NVD enrichment in at least one finding")
}

// ─── extra vulns ─────────────────────────────────────────────────────────────

func TestExtraVulns(t *testing.T) {
	m := NewWithClient(http.DefaultClient)
	m.TechOverride = []string{"myapp"}
	m.ExtraVulns = []VulnEntry{
		{
			CVE:         "CVE-2099-99999",
			Technology:  "myapp",
			Severity:    module.SeverityCritical,
			CVSS:        10.0,
			Description: "Test custom vulnerability",
		},
	}
	findings, err := m.Run(context.Background(), module.Input{Target: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCVE(findings, "CVE-2099-99999") {
		t.Fatal("expected custom CVE in extra vulns")
	}
}

func TestExtraVulns_InvalidRegex_Error(t *testing.T) {
	m := NewWithClient(http.DefaultClient)
	m.TechOverride = []string{"myapp"}
	m.ExtraVulns = []VulnEntry{
		{CVE: "CVE-X", Technology: "myapp", VersionRe: "[invalid"},
	}
	_, err := m.Run(context.Background(), module.Input{Target: "https://example.com"})
	if err == nil {
		t.Fatal("expected error for invalid VersionRe")
	}
}

// ─── dedup ────────────────────────────────────────────────────────────────────

func TestDedup_SameCVESameTarget(t *testing.T) {
	findings := []module.Finding{
		{Type: "known_cve", URL: "https://example.com", Extra: map[string]string{"cve": "CVE-2021-44228"}},
		{Type: "known_cve", URL: "https://example.com", Extra: map[string]string{"cve": "CVE-2021-44228"}},
		{Type: "known_cve", URL: "https://example.com", Extra: map[string]string{"cve": "CVE-2021-45046"}},
	}
	got := dedupFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected 2 after dedup, got %d", len(got))
	}
}

// ─── helpers unit tests ───────────────────────────────────────────────────────

func TestTechMatches(t *testing.T) {
	cases := []struct {
		detected string
		vuln     string
		want     bool
	}{
		{"apache", "apache", true},
		{"apache/2.4.49", "apache", true},
		{"nginx/1.18", "nginx", true},
		{"php", "apache", false},
	}
	for _, c := range cases {
		if techMatches(c.detected, c.vuln) != c.want {
			t.Errorf("techMatches(%q, %q) = %v, want %v", c.detected, c.vuln, !c.want, c.want)
		}
	}
}

func TestExtractVersion(t *testing.T) {
	if v := extractVersion("apache/2.4.49", "apache"); v != "2.4.49" {
		t.Errorf("expected 2.4.49, got %q", v)
	}
	if v := extractVersion("apache", "apache"); v != "" {
		t.Errorf("expected empty for no version, got %q", v)
	}
}

func TestExtractVersionFromString(t *testing.T) {
	if v := extractVersionFromString("Apache/2.4.51 (Unix)"); v != "2.4.51" {
		t.Errorf("expected 2.4.51, got %q", v)
	}
	if v := extractVersionFromString("nginx"); v != "" {
		t.Errorf("expected empty for no version, got %q", v)
	}
}

func TestCollectTargets_Dedup(t *testing.T) {
	input := module.Input{
		Target: "https://example.com",
		URLs:   []string{"https://example.com", "https://acme.org"},
	}
	targets := collectTargets(input)
	if len(targets) != 2 {
		t.Fatalf("expected 2 unique targets, got %d", len(targets))
	}
}
