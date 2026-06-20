package ipgeolocation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// rewriteTransport redireciona requests ao servidor de teste.
type rewriteTransport struct{ base string }

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(r.base, "http://")
	return http.DefaultTransport.RoundTrip(clone)
}

func clientFor(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: &rewriteTransport{base: srv.URL}}
}

// ─── isPrivateIP ──────────────────────────────────────────────────────────────

func TestIsPrivateIP(t *testing.T) {
	private := []string{
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.255.255",
		"127.0.0.1",
		"169.254.1.1",
	}
	for _, ip := range private {
		if !isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%q) deve ser true", ip)
		}
	}

	public := []string{
		"8.8.8.8", "1.1.1.1", "200.200.200.200",
		"45.33.32.156",
	}
	for _, ip := range public {
		if isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%q) deve ser false", ip)
		}
	}
}

// ─── abuseScoreToSeverity ─────────────────────────────────────────────────────

func TestAbuseScoreToSeverity(t *testing.T) {
	cases := []struct {
		score int
		want  module.Severity
	}{
		{100, module.SeverityMedium},
		{75, module.SeverityMedium},
		{74, module.SeverityLow},
		{50, module.SeverityLow},
		{49, module.SeverityLow},
		{25, module.SeverityLow},
		{24, module.SeverityInfo},
		{1, module.SeverityInfo},
		{0, module.SeverityInfo},
	}
	for _, tt := range cases {
		got := abuseScoreToSeverity(tt.score)
		if got != tt.want {
			t.Errorf("abuseScoreToSeverity(%d) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

// ─── fraudScoreToSeverity ─────────────────────────────────────────────────────

func TestFraudScoreToSeverity(t *testing.T) {
	if fraudScoreToSeverity(90) != module.SeverityMedium {
		t.Error("fraud 90 deve ser Medium")
	}
	if fraudScoreToSeverity(70) != module.SeverityLow {
		t.Error("fraud 70 deve ser Low")
	}
	if fraudScoreToSeverity(45) != module.SeverityLow {
		t.Error("fraud 45 deve ser Low")
	}
	if fraudScoreToSeverity(0) != module.SeverityInfo {
		t.Error("fraud 0 deve ser Info")
	}
}

// ─── Validações de entrada ────────────────────────────────────────────────────

func TestEmptyTarget(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Fatal("deve retornar erro para target vazio")
	}
}

func TestPrivateIP(t *testing.T) {
	m := New()
	findings, err := m.Run(context.Background(), module.Input{Target: "192.168.1.1"})
	if err != nil {
		t.Fatalf("IP privado não deve retornar erro: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("IP privado deve retornar 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "address_classification" {
		t.Errorf("tipo esperado 'address_classification', got '%s'", findings[0].Type)
	}
	if findings[0].Extra["is_private"] != "true" {
		t.Error("is_private deve ser 'true'")
	}
	if findings[0].Extra["validated"] != "true" {
		t.Error("classificação local deve ser validada")
	}
	if findings[0].Extra["promote_to_context"] != "false" {
		t.Error("classificação não deve promover o IP novamente")
	}
}

func TestRejectsHostnameInput(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{Target: "example.com"})
	if err == nil {
		t.Fatal("deve rejeitar hostname porque o contrato exige IP")
	}
}

// ─── ip-api.com ───────────────────────────────────────────────────────────────

func TestQueryIPAPIFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "success",
			"country":     "Brazil",
			"countryCode": "BR",
			"region":      "SP",
			"regionName":  "São Paulo",
			"city":        "São Paulo",
			"zip":         "01310-000",
			"lat":         -23.5505,
			"lon":         -46.6333,
			"timezone":    "America/Sao_Paulo",
			"isp":         "VIVO",
			"org":         "VIVO S.A.",
			"as":          "AS26599 VIVO S.A.",
			"hosting":     false,
			"proxy":       false,
			"mobile":      false,
			"query":       "177.0.0.1",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryIPAPI(context.Background(), "177.0.0.1")
	if err != nil {
		t.Fatalf("queryIPAPI: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("deve retornar 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "geolocation_reference" {
		t.Errorf("tipo esperado 'geolocation_reference', got '%s'", f.Type)
	}
	if f.Extra["country"] != "Brazil" {
		t.Errorf("country esperado 'Brazil', got '%s'", f.Extra["country"])
	}
	if f.Extra["confidence"] == "" {
		t.Error("finding sem confidence")
	}
	if f.Severity != module.SeverityInfo {
		t.Errorf("IP normal deve ser Info, got %s", f.Severity)
	}
}

func TestQueryIPAPIProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"country": "Netherlands",
			"city":    "Amsterdam",
			"isp":     "DataCenter Inc",
			"as":      "AS12345",
			"proxy":   true,
			"hosting": true,
			"mobile":  false,
			"query":   "1.2.3.4",
			"lat":     52.37,
			"lon":     4.89,
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryIPAPI(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("queryIPAPI proxy: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings")
	}
	if findings[0].Severity != module.SeverityInfo {
		t.Errorf("classificação proxy não prova vulnerabilidade e deve ser Info, got %s", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Extra["flags"], "PROXY") {
		t.Error("flags deve conter PROXY")
	}
}

func TestQueryIPAPIFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "fail",
			"message": "private range",
			"query":   "192.168.1.1",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.queryIPAPI(context.Background(), "192.168.1.1")
	if err == nil {
		t.Error("status fail deve retornar erro")
	}
}

// ─── ipinfo.io ────────────────────────────────────────────────────────────────

func TestQueryIPInfoFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":       "8.8.8.8",
			"city":     "Mountain View",
			"region":   "California",
			"country":  "US",
			"loc":      "37.3861,-122.0840",
			"org":      "AS15169 Google LLC",
			"postal":   "94035",
			"timezone": "America/Los_Angeles",
			"abuse": map[string]interface{}{
				"address": "1600 Amphitheatre Pkwy",
				"country": "US",
				"email":   "network-abuse@google.com",
				"name":    "Google LLC",
				"network": "8.8.8.0/24",
				"phone":   "+1-650-253-0000",
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryIPInfo(context.Background(), "8.8.8.8", "")
	if err != nil {
		t.Fatalf("queryIPInfo: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("deve retornar ip_info + abuse_contact, got %d", len(findings))
	}

	var hasInfo, hasAbuse bool
	for _, f := range findings {
		if f.Type == "geolocation_reference" {
			hasInfo = true
			if f.Extra["country"] != "US" {
				t.Errorf("country esperado 'US', got '%s'", f.Extra["country"])
			}
		}
		if f.Type == "abuse_contact_reference" {
			hasAbuse = true
			if f.Extra["abuse_email"] == "" {
				t.Error("abuse_contact sem email")
			}
		}
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
	}
	if !hasInfo {
		t.Error("deve ter finding 'geolocation_reference'")
	}
	if !hasAbuse {
		t.Error("deve ter finding 'abuse_contact_reference'")
	}
}

func TestQueryIPInfoNoAbuse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":      "1.2.3.4",
			"country": "BR",
			"city":    "São Paulo",
			"region":  "SP",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryIPInfo(context.Background(), "1.2.3.4", "")
	if err != nil {
		t.Fatalf("queryIPInfo no abuse: %v", err)
	}
	// Só deve ter a referência geográfica.
	for _, f := range findings {
		if f.Type == "abuse_contact_reference" {
			t.Error("não deve ter abuse_contact_reference sem email configurado")
		}
	}
}

// ─── AbuseIPDB ────────────────────────────────────────────────────────────────

func TestQueryAbuseIPDBClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"ipAddress":            "8.8.8.8",
				"isPublic":             true,
				"ipVersion":            4,
				"isWhitelisted":        true,
				"abuseConfidenceScore": 0,
				"countryCode":          "US",
				"isp":                  "Google LLC",
				"domain":               "google.com",
				"hostnames":            []string{"dns.google"},
				"totalReports":         0,
				"numDistinctUsers":     0,
				"lastReportedAt":       "",
				"reports":              []interface{}{},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryAbuseIPDB(context.Background(), "8.8.8.8", "test-key", 30)
	if err != nil {
		t.Fatalf("queryAbuseIPDB clean: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("IP limpo deve retornar 1 finding (summary), got %d", len(findings))
	}
	if findings[0].Type != "abuse_reputation_reference" {
		t.Errorf("tipo esperado 'abuse_reputation_reference', got '%s'", findings[0].Type)
	}
	if findings[0].Severity != module.SeverityInfo {
		t.Errorf("score 0 deve ser Info, got %s", findings[0].Severity)
	}
}

func TestQueryAbuseIPDBMalicious(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"ipAddress":            "1.2.3.4",
				"abuseConfidenceScore": 92,
				"totalReports":         150,
				"numDistinctUsers":     45,
				"lastReportedAt":       "2024-06-01T10:00:00+00:00",
				"countryCode":          "CN",
				"isp":                  "Bad ISP",
				"reports": []map[string]interface{}{
					{
						"reportedAt":          "2024-06-01",
						"comment":             "Port scan and brute force",
						"categories":          []int{14, 18},
						"reporterCountryCode": "US",
					},
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryAbuseIPDB(context.Background(), "1.2.3.4", "key", 30)
	if err != nil {
		t.Fatalf("queryAbuseIPDB malicious: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("deve retornar summary + report, got %d", len(findings))
	}
	if findings[0].Severity != module.SeverityMedium {
		t.Errorf("score externo 92 deve ser no máximo Medium, got %s", findings[0].Severity)
	}
}

// ─── Shodan InternetDB ────────────────────────────────────────────────────────

func TestQueryShodanInternetDBFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":        "1.2.3.4",
			"ports":     []int{22, 80, 443, 8080},
			"vulns":     []string{"CVE-2023-12345"},
			"hostnames": []string{"host1.example.com"},
			"tags":      []string{"cloud"},
			"cpes":      []string{"cpe:/a:openssl:openssl:1.1.1"},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryShodanInternetDB(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("queryShodanInternetDB: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("deve retornar summary + CVE finding, got %d", len(findings))
	}

	var hasDB, hasCVE bool
	for _, f := range findings {
		if f.Type == "external_inventory_reference" {
			hasDB = true
			if f.Extra["vuln_count"] == "" {
				t.Error("shodan_internetdb sem vuln_count")
			}
			if f.Severity != module.SeverityInfo {
				t.Errorf("inventário de terceiros deve ser Info, got %s", f.Severity)
			}
		}
		if f.Type == "external_vulnerability_reference" {
			hasCVE = true
			if f.Extra["cve"] == "" {
				t.Error("ip_vulnerability sem cve")
			}
		}
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
	}
	if !hasDB {
		t.Error("deve ter finding 'external_inventory_reference'")
	}
	if !hasCVE {
		t.Error("deve ter finding 'external_vulnerability_reference'")
	}
}

func TestQueryShodanInternetDBNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryShodanInternetDB(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("404 deve retornar nil: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("404 deve retornar 0 findings, got %d", len(findings))
	}
}

// ─── IPQS ────────────────────────────────────────────────────────────────────

func TestQueryIPQSVPN(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":         true,
			"fraud_score":     75,
			"country_code":    "NL",
			"ISP":             "NordVPN",
			"ASN":             12345,
			"organization":    "Tefincom S.A.",
			"proxy":           false,
			"vpn":             true,
			"tor":             false,
			"bot_status":      false,
			"recent_abuse":    false,
			"abuse_velocity":  "none",
			"mobile":          false,
			"connection_type": "VPN",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryIPQS(context.Background(), "1.2.3.4", "test-key")
	if err != nil {
		t.Fatalf("queryIPQS: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("deve retornar 1 finding, got %d", len(findings))
	}
	if findings[0].Extra["is_vpn"] != "true" {
		t.Error("is_vpn deve ser true")
	}
	if !strings.Contains(findings[0].Extra["flags"], "VPN") {
		t.Error("flags deve conter VPN")
	}
}

func TestQueryIPQSError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "invalid API key",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.queryIPQS(context.Background(), "1.2.3.4", "bad-key")
	if err == nil {
		t.Error("deve retornar erro para key inválida")
	}
}

// ─── VirusTotal ───────────────────────────────────────────────────────────────

func TestQueryVirusTotalMalicious(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") == "" {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id": "1.2.3.4",
				"attributes": map[string]interface{}{
					"country":    "CN",
					"asn":        12345,
					"as_owner":   "Bad ASN",
					"network":    "1.2.3.0/24",
					"reputation": -50,
					"last_analysis_stats": map[string]interface{}{
						"malicious":  8,
						"suspicious": 2,
						"harmless":   45,
						"undetected": 30,
					},
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryVirusTotal(context.Background(), "1.2.3.4", "test-key")
	if err != nil {
		t.Fatalf("queryVirusTotal: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("deve retornar 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != module.SeverityMedium {
		t.Errorf("reputação externa com 8 detecções deve ser no máximo Medium, got %s", findings[0].Severity)
	}
	if findings[0].Extra["malicious"] != "8" {
		t.Errorf("malicious esperado '8', got '%s'", findings[0].Extra["malicious"])
	}
}

// ─── Fluxo completo ───────────────────────────────────────────────────────────

func TestRunPublicIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"country": "Brazil",
			"city":    "São Paulo",
			"isp":     "Test ISP",
			"as":      "AS1234",
			"query":   "177.0.0.1",
			"lat":     -23.5,
			"lon":     -46.6,
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "177.0.0.1",
		Options: map[string]string{"sources": "ipapi"},
	})
	if err != nil {
		t.Fatalf("Run IP público: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings para IP público")
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
		if f.Extra["validated"] != "false" {
			t.Errorf("referência externa '%s' não deve ser marcada como confirmação local", f.Type)
		}
		if f.Extra["target_scope_validated"] != "true" {
			t.Errorf("referência externa '%s' deve estar vinculada ao IP consultado", f.Type)
		}
		if f.Extra["promote_to_context"] != "false" {
			t.Errorf("referência externa '%s' não deve promover ativos", f.Type)
		}
	}
}

func TestQueryIPAPIRejectsMismatchedIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"query":  "5.6.7.8",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	if _, err := m.queryIPAPI(context.Background(), "1.2.3.4"); err == nil {
		t.Fatal("deve rejeitar resposta vinculada a outro IP")
	}
}

func TestRunContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := New()
	findings, err := m.Run(ctx, module.Input{
		Target: "8.8.8.8",
	})
	// Com context cancelado, pode retornar erro de resolve ou 0 findings
	_ = err
	_ = findings
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestDedup(t *testing.T) {
	findings := []module.Finding{
		{Type: "geolocation_reference", URL: "https://ip-api.com/#1.2.3.4", Detail: "Brazil"},
		{Type: "geolocation_reference", URL: "https://ip-api.com/#1.2.3.4", Detail: "Brazil"},
		{Type: "geolocation_reference", URL: "https://ipinfo.io/1.2.3.4", Detail: "info"},
	}
	result := dedup(findings)
	if len(result) != 2 {
		t.Errorf("dedup: esperado 2 únicos, got %d", len(result))
	}
}
