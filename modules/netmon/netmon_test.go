package netmon_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/netmon"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

type rewriteTransport struct{ base string }

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(r.base, "http://")
	return http.DefaultTransport.RoundTrip(clone)
}

func newTestClient(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: &rewriteTransport{srv.URL}}
}

// ─── estrutura ────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if netmon.New().Name() != "netmon" {
		t.Error("nome incorreto")
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if netmon.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := netmon.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

// ─── InternetDB (free, no key) ────────────────────────────────────────────────

func internetDBHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ip":        "1.2.3.4",
		"ports":     []int{80, 443, 8080},
		"tags":      []string{"cloud"},
		"vulns":     []string{"CVE-2021-44228"},
		"cpes":      []string{"cpe:/a:apache:log4j:2.14.1"},
		"hostnames": []string{"example.com"},
	})
}

func TestRun_InternetDB_IPFound_HostInfoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(internetDBHandler))
	defer srv.Close()

	m := netmon.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "1.2.3.4",
		Options: map[string]string{"sources": "internetdb"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava pelo menos 1 finding via InternetDB")
	}

	var found bool
	for _, f := range findings {
		if f.Type == "external_inventory_reference" && f.Extra["source"] == "internetdb" {
			found = true
			if f.Extra["port_count"] != "3" {
				t.Errorf("port_count esperado '3', obteve '%s'", f.Extra["port_count"])
			}
			if !strings.Contains(f.Extra["vulns"], "CVE-2021-44228") {
				t.Error("vulns deve conter CVE-2021-44228")
			}
			if f.Severity != module.SeverityInfo {
				t.Errorf("inventário externo deve ser informativo, obteve %s", f.Severity)
			}
			if f.Extra["promote_to_context"] != "false" {
				t.Error("inventário externo não deve ser promovido")
			}
		}
	}
	if !found {
		t.Error("esperava referência de inventário do internetdb")
	}
}

func TestRun_InternetDB_404_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := netmon.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "1.2.3.4",
		Options: map[string]string{"sources": "internetdb"},
	})
	if err != nil {
		t.Fatalf("404 não deve retornar erro: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("404 esperava 0 findings, obteve %d", len(findings))
	}
}

func TestRun_InternetDB_DomainTarget_NoFindings(t *testing.T) {
	// InternetDB só funciona para IP
	srv := httptest.NewServer(http.HandlerFunc(internetDBHandler))
	defer srv.Close()

	m := netmon.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "internetdb"},
	})
	if len(findings) != 0 {
		t.Errorf("internetdb para domain deve retornar 0 findings, obteve %d", len(findings))
	}
}

// ─── Shodan ───────────────────────────────────────────────────────────────────

func shodanHostHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ip_str":       "1.2.3.4",
		"hostnames":    []string{"example.com"},
		"country_name": "United States",
		"city":         "Seattle",
		"org":          "Amazon AWS",
		"isp":          "Amazon",
		"asn":          "AS16509",
		"ports":        []int{80, 443, 22},
		"tags":         []string{"cloud"},
		"vulns": map[string]interface{}{
			"CVE-2021-44228": map[string]interface{}{"cvss": 10.0},
		},
		"data": []map[string]interface{}{
			{"port": 80, "transport": "tcp", "product": "Apache httpd", "version": "2.4.50", "data": "HTTP/1.1"},
		},
	})
}

func TestRun_Shodan_IPFound_HostInfoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(shodanHostHandler))
	defer srv.Close()

	m := netmon.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "1.2.3.4",
		Options: map[string]string{
			"sources":    "shodan",
			"shodan_key": "test-key",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava findings via Shodan")
	}

	var hostFound, vulnFound bool
	for _, f := range findings {
		if f.Extra["source"] == "shodan" {
			switch f.Type {
			case "external_inventory_reference":
				hostFound = true
				if f.Extra["org"] != "Amazon AWS" {
					t.Errorf("org esperado 'Amazon AWS', obteve '%s'", f.Extra["org"])
				}
				if f.Extra["country"] != "United States" {
					t.Errorf("country esperado 'United States', obteve '%s'", f.Extra["country"])
				}
			case "external_vulnerability_reference":
				vulnFound = true
				if !strings.Contains(f.Extra["cve"], "CVE-2021-44228") {
					t.Error("vuln deve ser CVE-2021-44228")
				}
				if f.Severity != module.SeverityHigh {
					t.Errorf("referência CVSS 10.0 não confirmada deve ser High, obteve %s", f.Severity)
				}
			}
		}
	}
	if !hostFound {
		t.Error("esperava referência de inventário do shodan")
	}
	if !vulnFound {
		t.Error("esperava referência de vulnerabilidade do shodan")
	}
}

func TestRun_Shodan_NoKey_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(shodanHostHandler))
	defer srv.Close()

	m := netmon.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "1.2.3.4",
		Options: map[string]string{
			"sources": "shodan",
			// sem shodan_key
		},
	})
	if len(findings) != 0 {
		t.Errorf("sem shodan_key esperava 0 findings, obteve %d", len(findings))
	}
}

// ─── Censys ───────────────────────────────────────────────────────────────────

func censysHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"result": map[string]interface{}{
			"ip": "1.2.3.4",
			"services": []map[string]interface{}{
				{
					"port":               443,
					"transport_protocol": "TCP",
					"service_name":       "HTTPS",
					"tls": map[string]interface{}{
						"subject_dn":      "CN=example.com",
						"issuer":          map[string]string{"organization": "Let's Encrypt"},
						"validity_period": map[string]string{"end": "2025-12-31"},
					},
				},
				{
					"port":               80,
					"transport_protocol": "TCP",
					"service_name":       "HTTP",
				},
			},
			"autonomous_system": map[string]interface{}{
				"asn":          16509,
				"name":         "AMAZON-02",
				"country_code": "US",
			},
			"location": map[string]interface{}{
				"country": "United States",
				"city":    "Seattle",
			},
		},
	})
}

func TestRun_Censys_IPFound_HostInfoAndTLS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(censysHandler))
	defer srv.Close()

	m := netmon.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "1.2.3.4",
		Options: map[string]string{
			"sources":       "censys",
			"censys_id":     "test-id",
			"censys_secret": "test-secret",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}

	var hostFound, tlsFound bool
	for _, f := range findings {
		if f.Extra["source"] == "censys" {
			switch f.Type {
			case "external_inventory_reference":
				hostFound = true
				if f.Extra["asn_name"] != "AMAZON-02" {
					t.Errorf("asn_name esperado 'AMAZON-02', obteve '%s'", f.Extra["asn_name"])
				}
			case "external_tls_reference":
				tlsFound = true
				if !strings.Contains(f.Extra["subject"], "example.com") {
					t.Error("subject TLS deve conter example.com")
				}
			}
		}
	}
	if !hostFound {
		t.Error("esperava referência de inventário do censys")
	}
	if !tlsFound {
		t.Error("esperava referência TLS do censys")
	}
}

func TestRun_Censys_NoCredentials_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(censysHandler))
	defer srv.Close()

	m := netmon.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "1.2.3.4",
		Options: map[string]string{
			"sources": "censys",
			// sem censys_id/censys_secret
		},
	})
	if len(findings) != 0 {
		t.Errorf("sem credenciais censys esperava 0 findings, obteve %d", len(findings))
	}
}

// ─── confidence e detail ──────────────────────────────────────────────────────

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(internetDBHandler))
	defer srv.Close()

	m := netmon.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "1.2.3.4",
		Options: map[string]string{"sources": "internetdb"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(internetDBHandler))
	defer srv.Close()

	m := netmon.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "1.2.3.4",
		Options: map[string]string{"sources": "internetdb"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestRun_Dedup_NoDuplicateFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(internetDBHandler))
	defer srv.Close()

	m := netmon.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "1.2.3.4",
		Options: map[string]string{"sources": "internetdb"},
	})
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Extra["source"] + "|" + f.Extra["port"]
		if seen[key] {
			t.Errorf("finding duplicado: %s", key)
		}
		seen[key] = true
	}
}

// ─── context cancelado ────────────────────────────────────────────────────────

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv := httptest.NewServer(http.HandlerFunc(internetDBHandler))
	defer srv.Close()

	m := netmon.NewWithClient(newTestClient(srv))
	_, _ = m.Run(ctx, module.Input{
		Target:  "1.2.3.4",
		Options: map[string]string{"sources": "internetdb"},
	})
}

func TestRun_InvalidNumericIP_ReturnsError(t *testing.T) {
	_, err := netmon.New().Run(context.Background(), module.Input{
		Target:  "999.999.999.999",
		Options: map[string]string{"sources": "internetdb"},
	})
	if err == nil {
		t.Fatal("esperava erro para IP numérico inválido")
	}
}
