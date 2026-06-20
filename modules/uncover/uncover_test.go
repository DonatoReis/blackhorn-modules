package uncover

import (
	"context"
	"encoding/json"
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

func hasSource(findings []module.Finding, src string) bool {
	for _, f := range findings {
		if f.Extra["source"] == src {
			return true
		}
	}
	return false
}

func shodanSrv(t *testing.T, ip string, ports []int, vulns []string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(shodanInternetDB{
			IP:    ip,
			Ports: ports,
			Vulns: vulns,
		})
	}))
}

func errorSrv(code int) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
	}))
}

func jsonSrv(t *testing.T, v any) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(v)
	}))
}

func newTestModule(c *http.Client) *Module {
	m := NewWithClient(c)
	return m
}

// ─── basic ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "uncover" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoQuery(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty query")
	}
}

func TestRun_NoSources(t *testing.T) {
	m := New()
	m.Sources = nil
	_, err := m.Run(context.Background(), module.Input{
		Target:  "1.1.1.1",
		Options: map[string]string{"sources": ""},
	})
	if err == nil {
		t.Fatal("expected error for empty sources")
	}
}

// ─── Shodan ───────────────────────────────────────────────────────────────────

func TestShodan_ExposedPorts(t *testing.T) {
	srv := shodanSrv(t, "1.2.3.4", []int{22, 80, 443}, nil)
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.ShodanBaseURL = srv.URL
	m.Sources = []string{"shodan"}

	findings, err := m.Run(context.Background(), module.Input{Target: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "external_inventory_reference") {
		t.Fatal("expected external inventory references from Shodan")
	}
	if !hasSource(findings, "shodan") {
		t.Fatal("expected source=shodan in findings")
	}
}

func TestShodan_KnownVulnerabilities(t *testing.T) {
	srv := shodanSrv(t, "1.2.3.4", []int{443}, []string{"CVE-2021-44228", "CVE-2022-0001"})
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.ShodanBaseURL = srv.URL
	m.Sources = []string{"shodan"}

	findings, err := m.Run(context.Background(), module.Input{Target: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "external_vulnerability_reference") {
		t.Fatal("expected external vulnerability references")
	}
	found := false
	for _, f := range findings {
		if f.Extra["cve"] == "CVE-2021-44228" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected CVE-2021-44228 in findings")
	}
}

func TestShodan_SensitivePort_RemainsInformationalUntilConfirmed(t *testing.T) {
	srv := shodanSrv(t, "1.2.3.4", []int{6379}, nil) // Redis
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.ShodanBaseURL = srv.URL
	m.Sources = []string{"shodan"}

	findings, err := m.Run(context.Background(), module.Input{Target: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Type == "external_inventory_reference" && strings.Contains(f.URL, ":6379") {
			if f.Severity != module.SeverityInfo {
				t.Errorf("expected Info severity before direct validation, got %q", f.Severity)
			}
			if f.Extra["promote_to_context"] != "false" {
				t.Error("external reference must not be promoted")
			}
		}
	}
}

func TestShodan_404_ReturnsEmpty(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.ShodanBaseURL = srv.URL
	m.Sources = []string{"shodan"}

	findings, err := m.Run(context.Background(), module.Input{Target: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for 404, got %d", len(findings))
	}
}

func TestShodan_500_SoftFail(t *testing.T) {
	srv := errorSrv(500)
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.ShodanBaseURL = srv.URL
	m.Sources = []string{"shodan"}

	// Soft failure — returns no findings, no error propagated.
	findings, err := m.Run(context.Background(), module.Input{Target: "1.2.3.4"})
	if err != nil {
		t.Fatalf("expected soft failure, got hard error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on 500, got %d", len(findings))
	}
}

// ─── Censys ───────────────────────────────────────────────────────────────────

func TestCensys_ExposedServices(t *testing.T) {
	resp := censysResponse{}
	resp.Result.Hits = []struct {
		IP       string `json:"ip"`
		Services []struct {
			Port           int    `json:"port"`
			TransportProto string `json:"transport_protocol"`
			ServiceName    string `json:"service_name"`
		} `json:"services"`
	}{
		{
			IP: "5.6.7.8",
			Services: []struct {
				Port           int    `json:"port"`
				TransportProto string `json:"transport_protocol"`
				ServiceName    string `json:"service_name"`
			}{
				{Port: 443, TransportProto: "TCP", ServiceName: "HTTPS"},
			},
		},
	}
	srv := jsonSrv(t, resp)
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.CensysBaseURL = srv.URL
	m.Sources = []string{"censys"}

	findings, err := m.Run(context.Background(), module.Input{Target: "5.6.7.8"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "external_inventory_reference") {
		t.Fatal("expected external inventory references from Censys")
	}
	if !hasSource(findings, "censys") {
		t.Fatal("expected source=censys in findings")
	}
}

func TestCensys_401_SoftFail(t *testing.T) {
	srv := errorSrv(401)
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.CensysBaseURL = srv.URL
	m.Sources = []string{"censys"}

	findings, err := m.Run(context.Background(), module.Input{Target: "test"})
	if err != nil {
		t.Fatal("expected soft failure for Censys 401")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on auth error, got %d", len(findings))
	}
}

// ─── FOFA ────────────────────────────────────────────────────────────────────

func TestFofa_NoCredentials_SoftFail(t *testing.T) {
	srv, _ := jsonSrv(t, fofaResponse{}), func() {}
	_ = srv
	m := newTestModule(srv.Client())
	m.FofaBaseURL = srv.URL
	m.Sources = []string{"fofa"}

	findings, err := m.Run(context.Background(), module.Input{Target: "test"})
	if err != nil {
		t.Fatal("expected soft failure for missing FOFA credentials")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without credentials, got %d", len(findings))
	}
}

func TestFofa_WithCredentials(t *testing.T) {
	resp := fofaResponse{
		Results: [][]string{
			{"example.com", "1.2.3.4", "443"},
		},
	}
	srv := jsonSrv(t, resp)
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.FofaBaseURL = srv.URL
	m.Sources = []string{"fofa"}

	findings, err := m.Run(context.Background(), module.Input{
		Target: "test",
		Options: map[string]string{
			"fofa_email": "test@example.com",
			"fofa_key":   "mykey",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "external_inventory_reference") {
		t.Fatal("expected external inventory references from FOFA")
	}
}

// ─── Hunter ───────────────────────────────────────────────────────────────────

func TestHunter_NoKey_SoftFail(t *testing.T) {
	srv := jsonSrv(t, hunterResponse{})
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.HunterBaseURL = srv.URL
	m.Sources = []string{"hunter"}

	findings, _ := m.Run(context.Background(), module.Input{Target: "test"})
	if len(findings) != 0 {
		t.Fatal("expected 0 findings without hunter_key")
	}
}

func TestHunter_WithKey(t *testing.T) {
	resp := hunterResponse{}
	resp.Data.Arr = []struct {
		IP      string `json:"ip"`
		Port    int    `json:"port"`
		Domain  string `json:"domain"`
		Company string `json:"company"`
	}{
		{IP: "10.0.0.1", Port: 8080, Domain: "test.example.com", Company: "ACME"},
	}
	srv := jsonSrv(t, resp)
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.HunterBaseURL = srv.URL
	m.Sources = []string{"hunter"}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  "test",
		Options: map[string]string{"hunter_key": "testkey"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasSource(findings, "hunter") {
		t.Fatal("expected source=hunter")
	}
}

// ─── ZoomEye ─────────────────────────────────────────────────────────────────

func TestZoomeye_NoKey_SoftFail(t *testing.T) {
	srv := jsonSrv(t, zoomeyeResponse{})
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.ZoomeyeBaseURL = srv.URL
	m.Sources = []string{"zoomeye"}

	findings, _ := m.Run(context.Background(), module.Input{Target: "test"})
	if len(findings) != 0 {
		t.Fatal("expected 0 findings without zoomeye_key")
	}
}

func TestZoomeye_WithKey(t *testing.T) {
	resp := zoomeyeResponse{
		Matches: []struct {
			IP       string `json:"ip"`
			PortInfo struct {
				Port int `json:"port"`
			} `json:"portinfo"`
		}{
			{IP: "9.9.9.9"},
		},
	}
	resp.Matches[0].PortInfo.Port = 9200
	srv := jsonSrv(t, resp)
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.ZoomeyeBaseURL = srv.URL
	m.Sources = []string{"zoomeye"}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  "elasticsearch",
		Options: map[string]string{"zoomeye_key": "testkey"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasSource(findings, "zoomeye") {
		t.Fatal("expected source=zoomeye")
	}
}

// ─── Netlas ───────────────────────────────────────────────────────────────────

func TestNetlas_NoKey_SoftFail(t *testing.T) {
	srv := jsonSrv(t, netlasResponse{})
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.NetlasBaseURL = srv.URL
	m.Sources = []string{"netlas"}

	findings, _ := m.Run(context.Background(), module.Input{Target: "test"})
	if len(findings) != 0 {
		t.Fatal("expected 0 findings without netlas_key")
	}
}

func TestNetlas_WithKey(t *testing.T) {
	resp := netlasResponse{
		Items: []struct {
			Data struct {
				IP   string `json:"ip"`
				Port int    `json:"port"`
			} `json:"data"`
		}{
			{},
		},
	}
	resp.Items[0].Data.IP = "8.8.8.8"
	resp.Items[0].Data.Port = 53
	srv := jsonSrv(t, resp)
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.NetlasBaseURL = srv.URL
	m.Sources = []string{"netlas"}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  "dns",
		Options: map[string]string{"netlas_key": "testkey"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasSource(findings, "netlas") {
		t.Fatal("expected source=netlas")
	}
}

// ─── PublicWWW ───────────────────────────────────────────────────────────────

func TestPublicwww_NoKey_SoftFail(t *testing.T) {
	srv := jsonSrv(t, publicwwwResponse{})
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.PublicwwwBaseURL = srv.URL
	m.Sources = []string{"publicwww"}

	findings, _ := m.Run(context.Background(), module.Input{Target: "test"})
	if len(findings) != 0 {
		t.Fatal("expected 0 findings without publicwww_key")
	}
}

func TestPublicwww_WithKey(t *testing.T) {
	resp := publicwwwResponse{
		Results: []struct {
			URL string `json:"url"`
		}{
			{URL: "https://target.com"},
		},
	}
	srv := jsonSrv(t, resp)
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.PublicwwwBaseURL = srv.URL
	m.Sources = []string{"publicwww"}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  "GA-12345",
		Options: map[string]string{"publicwww_key": "testkey"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "external_source_reference") {
		t.Fatal("expected external source reference from PublicWWW")
	}
}

func TestShodan_NonIPQueryIsSkipped(t *testing.T) {
	m := NewWithClient(http.DefaultClient)
	m.Sources = []string{"shodan"}
	findings, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("InternetDB only accepts IPs, got %+v", findings)
	}
}

// ─── multi-source ─────────────────────────────────────────────────────────────

func TestMultiSource_Options(t *testing.T) {
	srv := shodanSrv(t, "1.2.3.4", []int{80}, nil)
	defer srv.Close()

	m := newTestModule(srv.Client())
	m.ShodanBaseURL = srv.URL
	m.Sources = []string{"shodan"}

	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{
			"query":   "1.2.3.4",
			"sources": "shodan",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasSource(findings, "shodan") {
		t.Fatal("expected shodan source via Options")
	}
}

func TestDedup_SamePortTwice(t *testing.T) {
	// Simulate two sources returning same IP:port.
	findings := []module.Finding{
		{Type: "external_inventory_reference", URL: "1.2.3.4:80", Extra: map[string]string{"source": "a"}},
		{Type: "external_inventory_reference", URL: "1.2.3.4:80", Extra: map[string]string{"source": "b"}},
		{Type: "external_inventory_reference", URL: "1.2.3.4:443", Extra: map[string]string{"source": "a"}},
	}
	got := dedupFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected 2 after dedup, got %d", len(got))
	}
}

func TestClampLimit(t *testing.T) {
	if clampLimit(0, 50) != 50 {
		t.Error("clampLimit(0, 50) should return default 50")
	}
	if clampLimit(2000, 50) != 1000 {
		t.Error("clampLimit(2000, 50) should cap at 1000")
	}
	if clampLimit(25, 50) != 25 {
		t.Error("clampLimit(25, 50) should return 25")
	}
}

func TestEncodeBase64(t *testing.T) {
	// Standard base64 of "hello" is "aGVsbG8="
	got := encodeBase64("hello")
	if got != "aGVsbG8=" {
		t.Errorf("encodeBase64('hello') = %q, want 'aGVsbG8='", got)
	}
}

func TestUnknownSource_SoftFail(t *testing.T) {
	m := New()
	m.Sources = []string{"unknownsource"}
	findings, err := m.Run(context.Background(), module.Input{Target: "test"})
	if err != nil {
		t.Fatal("expected soft failure for unknown source")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for unknown source, got %d", len(findings))
	}
}
