package portscanner

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// rewriteTransport redireciona qualquer request ao servidor de teste.
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

// ─── parsePorts ──────────────────────────────────────────────────────────────

func TestParsePortsTop100(t *testing.T) {
	ports, err := parsePorts("top100")
	if err != nil {
		t.Fatalf("parsePorts top100: %v", err)
	}
	if len(ports) < 50 {
		t.Errorf("top100 deve retornar pelo menos 50 portas, got %d", len(ports))
	}
}

func TestParsePortsDefault(t *testing.T) {
	ports, err := parsePorts("")
	if err != nil {
		t.Fatalf("parsePorts empty: %v", err)
	}
	if len(ports) < 50 {
		t.Errorf("default deve retornar pelo menos 50 portas, got %d", len(ports))
	}
}

func TestParsePortsSingle(t *testing.T) {
	ports, err := parsePorts("80,443,8080")
	if err != nil {
		t.Fatalf("parsePorts single: %v", err)
	}
	if len(ports) != 3 {
		t.Errorf("deve retornar 3 portas, got %d", len(ports))
	}
	// Verifica ordenação
	if ports[0] != 80 || ports[1] != 443 || ports[2] != 8080 {
		t.Errorf("portas devem estar ordenadas: %v", ports)
	}
}

func TestParsePortsRange(t *testing.T) {
	ports, err := parsePorts("8080-8090")
	if err != nil {
		t.Fatalf("parsePorts range: %v", err)
	}
	if len(ports) != 11 {
		t.Errorf("range 8080-8090 deve retornar 11 portas, got %d", len(ports))
	}
	if ports[0] != 8080 || ports[10] != 8090 {
		t.Errorf("range incorreto: primeiro=%d, último=%d", ports[0], ports[len(ports)-1])
	}
}

func TestParsePortsMixed(t *testing.T) {
	ports, err := parsePorts("22,80-82,443")
	if err != nil {
		t.Fatalf("parsePorts mixed: %v", err)
	}
	// 22, 80, 81, 82, 443 = 5
	if len(ports) != 5 {
		t.Errorf("deve retornar 5 portas, got %d: %v", len(ports), ports)
	}
}

func TestParsePortsDedup(t *testing.T) {
	ports, err := parsePorts("80,80,80-82")
	if err != nil {
		t.Fatalf("parsePorts dedup: %v", err)
	}
	// 80, 81, 82 (sem duplicatas)
	if len(ports) != 3 {
		t.Errorf("deve deduplicar portas: %v", ports)
	}
}

func TestParsePortsInvalid(t *testing.T) {
	cases := []string{
		"0",     // porta 0 inválida
		"65536", // fora do range
		"abc",   // não é número
		"80-70", // range invertido
	}
	for _, input := range cases {
		_, err := parsePorts(input)
		if err == nil {
			t.Errorf("parsePorts(%q) deve retornar erro", input)
		}
	}
}

// ─── cleanBanner ─────────────────────────────────────────────────────────────

func TestCleanBanner(t *testing.T) {
	raw := "SSH-2.0-OpenSSH_8.9\r\nProtocol mismatch.\n"
	got := cleanBanner(raw)
	if strings.ContainsAny(got, "\r\n") {
		t.Error("cleanBanner não deve conter \\r ou \\n")
	}
	if !strings.Contains(got, "SSH") {
		t.Errorf("cleanBanner deve preservar texto: %s", got)
	}
}

func TestCleanBannerLong(t *testing.T) {
	long := strings.Repeat("A", 1000)
	got := cleanBanner(long)
	if len(got) > 512 {
		t.Errorf("cleanBanner deve truncar a 512 chars, got %d", len(got))
	}
}

func TestCleanBannerBinary(t *testing.T) {
	// Bytes binários devem ser removidos
	got := cleanBanner("\x00\x01\x02Hello\x03\x04\x05")
	if !strings.Contains(got, "Hello") {
		t.Errorf("cleanBanner deve preservar texto printável: %s", got)
	}
	if strings.ContainsAny(got, "\x00\x01\x02\x03\x04\x05") {
		t.Error("cleanBanner deve remover bytes não-printáveis")
	}
}

// ─── externalCVESeverity ──────────────────────────────────────────────────────

func TestExternalCVESeverity(t *testing.T) {
	cases := []struct {
		cvss float64
		want module.Severity
	}{
		{9.8, module.SeverityHigh},
		{9.0, module.SeverityHigh},
		{7.5, module.SeverityMedium},
		{7.0, module.SeverityMedium},
		{4.0, module.SeverityLow},
		{3.9, module.SeverityInfo},
		{0.0, module.SeverityInfo},
	}
	for _, tt := range cases {
		got := externalCVESeverity(tt.cvss)
		if got != tt.want {
			t.Errorf("externalCVESeverity(%.1f) = %v, want %v", tt.cvss, got, tt.want)
		}
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

func TestInvalidPorts(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{
		Target:  "127.0.0.1",
		Options: map[string]string{"ports": "invalid"},
	})
	if err == nil {
		t.Fatal("deve retornar erro para ports inválidos")
	}
}

func TestMaxPortsRejectsOversizedScan(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{
		Target: "127.0.0.1",
		Options: map[string]string{
			"ports":     "1-10",
			"max_ports": "5",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "excedem max_ports") {
		t.Fatalf("esperava erro de max_ports, obteve %v", err)
	}
}

// ─── scanPort (unit) ─────────────────────────────────────────────────────────

func TestScanPortOpen(t *testing.T) {
	// Cria um listener TCP para simular porta aberta
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("não foi possível criar listener TCP")
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte("TEST-BANNER\r\n")) //nolint:errcheck
		conn.Close()
	}()

	result := scanPort(context.Background(), "127.0.0.1", addr.Port, 2*time.Second, true)

	if !result.Open {
		t.Error("porta aberta deve retornar Open=true")
	}
	if result.Port != addr.Port {
		t.Errorf("porta incorreta: %d", result.Port)
	}
}

func TestScanPortClosed(t *testing.T) {
	// Porta que não está escutando (muito provavelmente fechada)
	result := scanPort(context.Background(), "127.0.0.1", 19999, 500*time.Millisecond, false)
	if result.Open {
		t.Skip("porta 19999 está aberta (skip)")
	}
	if result.Port != 19999 {
		t.Errorf("porta incorreta: %d", result.Port)
	}
}

// ─── buildLocalFindings ──────────────────────────────────────────────────────

func TestBuildLocalFindingsEmpty(t *testing.T) {
	findings := buildLocalFindings("target.com", "1.2.3.4", nil)
	if len(findings) != 1 {
		t.Fatalf("sem portas deve retornar 1 finding (summary), got %d", len(findings))
	}
	if findings[0].Type != "scan_summary" {
		t.Error("deve ter 'scan_summary'")
	}
	if findings[0].Extra["open_ports"] != "0" {
		t.Error("open_ports deve ser '0'")
	}
}

func TestBuildLocalFindingsPorts(t *testing.T) {
	openPorts := []ScanResult{
		{Port: 80, Open: true, Service: "HTTP", Latency: 5 * time.Millisecond},
		{Port: 22, Open: true, Service: "SSH", Latency: 3 * time.Millisecond},
		{Port: 3306, Open: true, Service: "MySQL", Latency: 2 * time.Millisecond, Banner: "5.7.44-MySQL"},
		{Port: 27017, Open: true, Service: "MongoDB", Latency: 1 * time.Millisecond},
	}

	findings := buildLocalFindings("example.com", "1.2.3.4", openPorts)

	// summary + 4 open_port findings
	if len(findings) != 5 {
		t.Fatalf("deve retornar 5 findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
	}

	// MongoDB deve ser Medium: porta confirmada é exposição, não prova de falha.
	var mongoFinding *module.Finding
	for i := range findings {
		if findings[i].Extra["port"] == "27017" {
			mongoFinding = &findings[i]
		}
	}
	if mongoFinding == nil {
		t.Fatal("deve ter finding para porta 27017")
	}
	if mongoFinding.Severity != module.SeverityMedium {
		t.Errorf("porta 27017 (risky) deve ser Medium, got %s", mongoFinding.Severity)
	}

	// HTTP porta 80 não é risky — ainda é uma exposição confirmada Low.
	var httpFinding *module.Finding
	for i := range findings {
		if findings[i].Extra["port"] == "80" {
			httpFinding = &findings[i]
		}
	}
	if httpFinding == nil {
		t.Fatal("deve ter finding para porta 80")
	}
	if httpFinding.Severity != module.SeverityLow {
		t.Errorf("porta 80 não-risky deve ser Low, got %s", httpFinding.Severity)
	}

	// Porta com banner deve incluir banner no extra
	var mysqlFinding *module.Finding
	for i := range findings {
		if findings[i].Extra["port"] == "3306" {
			mysqlFinding = &findings[i]
		}
	}
	if mysqlFinding == nil {
		t.Fatal("deve ter finding para porta 3306")
	}
	if mysqlFinding.Extra["banner"] == "" {
		t.Error("MySQL com banner deve ter 'banner' no extra")
	}
}

// ─── Shodan ──────────────────────────────────────────────────────────────────

func TestQueryShodanFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ip_str":       "1.2.3.4",
			"os":           "Linux 4.x",
			"org":          "Test ISP",
			"isp":          "Test ISP",
			"country_name": "Brazil",
			"city":         "São Paulo",
			"asn":          "AS12345",
			"last_update":  "2024-01-15",
			"ports":        []int{22, 80, 443},
			"data": []map[string]interface{}{
				{
					"port":      22,
					"transport": "tcp",
					"product":   "OpenSSH",
					"version":   "8.9",
					"data":      "SSH-2.0-OpenSSH_8.9",
					"vulns": map[string]interface{}{
						"CVE-2023-12345": map[string]interface{}{
							"cvss": 9.8,
						},
					},
				},
			},
			"vulns": []string{"CVE-2023-12345"},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryShodan(context.Background(), "1.2.3.4", "test-key")
	if err != nil {
		t.Fatalf("queryShodan: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("deve retornar host + CVE, got %d findings", len(findings))
	}

	var hasHost, hasCVE bool
	for _, f := range findings {
		if f.Type == "external_inventory_reference" {
			hasHost = true
			if f.Extra["confidence"] == "" {
				t.Error("external_inventory_reference sem confidence")
			}
			if f.Extra["promote_to_context"] != "false" {
				t.Error("inventário Shodan não deve ser promovido")
			}
		}
		if f.Type == "external_vulnerability_reference" {
			hasCVE = true
			if f.Extra["cve"] == "" {
				t.Error("referência Shodan sem CVE")
			}
			if f.Severity != module.SeverityHigh {
				t.Errorf("CVE externa com CVSS 9.8 deve ser High, got %s", f.Severity)
			}
		}
	}
	if !hasHost {
		t.Error("deve ter referência de inventário Shodan")
	}
	if !hasCVE {
		t.Error("deve ter referência de vulnerabilidade Shodan")
	}
}

func TestQueryShodanUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	_, err := m.queryShodan(context.Background(), "1.2.3.4", "bad-key")
	if err == nil {
		t.Error("deve retornar erro para key inválida")
	}
}

// ─── Censys ──────────────────────────────────────────────────────────────────

func TestQueryCensysFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"ip": "1.2.3.4",
				"autonomous_system": map[string]interface{}{
					"asn":          12345,
					"name":         "Test ASN",
					"bgp_prefix":   "1.2.3.0/24",
					"country_code": "BR",
				},
				"operating_system": map[string]interface{}{
					"product": "Linux",
					"version": "5.15",
				},
				"services": []map[string]interface{}{
					{"port": 22, "transport_protocol": "TCP", "service_name": "SSH", "extended_service_name": "OpenSSH"},
					{"port": 80, "transport_protocol": "TCP", "service_name": "HTTP", "extended_service_name": "nginx"},
				},
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryCensys(context.Background(), "1.2.3.4", "api-id", "api-secret")
	if err != nil {
		t.Fatalf("queryCensys: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings")
	}
	if findings[0].Type != "external_inventory_reference" {
		t.Errorf("tipo esperado 'external_inventory_reference', got '%s'", findings[0].Type)
	}
	if findings[0].Extra["confidence"] == "" {
		t.Error("censys_host sem confidence")
	}
	if findings[0].Extra["asn"] == "" {
		t.Error("censys_host sem asn")
	}
	if findings[0].Extra["promote_to_context"] != "false" {
		t.Error("inventário Censys não deve ser promovido")
	}
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestDedup(t *testing.T) {
	findings := []module.Finding{
		{Type: "open_port", URL: "http://1.2.3.4:80", Detail: "Porta 80"},
		{Type: "open_port", URL: "http://1.2.3.4:80", Detail: "Porta 80"},
		{Type: "scan_summary", URL: "", Detail: "1 porta aberta"},
	}
	result := dedup(findings)
	if len(result) != 2 {
		t.Errorf("dedup: esperado 2 únicos, got %d", len(result))
	}
}

// ─── clampInt ────────────────────────────────────────────────────────────────

func TestClampInt(t *testing.T) {
	if clampInt(500, 1, 100) != 100 {
		t.Error("clampInt deve limitar ao máximo")
	}
	if clampInt(0, 1, 100) != 1 {
		t.Error("clampInt deve manter no mínimo")
	}
	if clampInt(50, 1, 100) != 50 {
		t.Error("clampInt deve retornar valor dentro do range")
	}
}

// ─── Module interface ────────────────────────────────────────────────────────

func TestModuleName(t *testing.T) {
	m := New()
	if m.Name() != "portscanner" {
		t.Errorf("Name() = %q, want 'portscanner'", m.Name())
	}
}

func TestRunContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := New()
	// Com context já cancelado, resolve vai falhar
	_, err := m.Run(ctx, module.Input{
		Target:  "127.0.0.1",
		Options: map[string]string{"ports": "80"},
	})
	// Pode retornar erro (resolve falha) ou findings (análise local) — ambos são aceitáveis
	_ = err
}
