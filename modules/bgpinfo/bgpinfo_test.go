package bgpinfo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

// ─── Testes de detectTargetType ───────────────────────────────────────────────

func TestDetectTargetType(t *testing.T) {
	cases := map[string]TargetType{
		"AS12345":         TargetASN,
		"as12345":         TargetASN,
		"12345":           TargetASN,
		"198.51.100.0/24": TargetPrefix,
		"2001:db8::/32":   TargetPrefix,
		"198.51.100.1":    TargetIP,
		"example.com":     TargetDomain,
		"sub.example.co":  TargetDomain,
		"???":             TargetUnknown,
	}
	for target, want := range cases {
		if got := detectTargetType(target); got != want {
			t.Errorf("detectTargetType(%q) = %q, want %q", target, got, want)
		}
	}
}

// ─── Testes de validação ──────────────────────────────────────────────────────

func TestEmptyTarget(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Fatal("deve retornar erro para target vazio")
	}
}

// ─── Mock para RIPE NCC Stat ──────────────────────────────────────────────────

func ripeWhoisServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "whois") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"records": []interface{}{
						[]interface{}{
							map[string]string{"key": "aut-num", "value": "AS15169"},
							map[string]string{"key": "as-name", "value": "GOOGLE"},
							map[string]string{"key": "descr", "value": "Google LLC"},
							map[string]string{"key": "country", "value": "US"},
						},
					},
				},
				"status": "ok",
			})
			return
		}
		if strings.Contains(r.URL.Path, "announced-prefixes") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"asn": 15169,
					"prefixes": []map[string]interface{}{
						{"prefix": "8.8.8.0/24", "timelines": []interface{}{}},
						{"prefix": "8.8.4.0/24", "timelines": []interface{}{}},
					},
				},
				"status": "ok",
			})
			return
		}
		if strings.Contains(r.URL.Path, "prefix-overview") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"resource": "8.8.8.0/24",
					"asns": []map[string]interface{}{
						{"asn": 15169.0, "holder": "GOOGLE"},
					},
					"block": map[string]string{"desc": "Google"},
				},
				"status": "ok",
			})
			return
		}
		http.NotFound(w, r)
	}))
}

func TestQueryRIPEASN(t *testing.T) {
	srv := ripeWhoisServer()
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryRIPE(context.Background(), "AS15169", TargetASN, "AS15169", 50)
	if err != nil {
		t.Fatalf("queryRIPE ASN: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar pelo menos 1 finding para ASN")
	}

	hasASNInfo := false
	hasPrefixes := false
	for _, f := range findings {
		if f.Type == "asn_info" {
			hasASNInfo = true
		}
		if f.Type == "announced_prefix" {
			hasPrefixes = true
		}
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
	}
	if !hasASNInfo {
		t.Error("deve conter finding 'asn_info'")
	}
	if !hasPrefixes {
		t.Error("deve conter finding 'announced_prefix'")
	}
}

func TestQueryRIPEPrefix(t *testing.T) {
	srv := ripeWhoisServer()
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryRIPE(context.Background(), "8.8.8.0/24", TargetPrefix, "", 50)
	if err != nil {
		t.Fatalf("queryRIPE Prefix: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "prefix_origin" {
			found = true
			if f.Extra["asn"] == "" {
				t.Error("prefix_origin deve ter ASN no extra")
			}
		}
	}
	if !found {
		t.Error("deve conter finding 'prefix_origin' para prefixo")
	}
}

func TestPrefixTruncation(t *testing.T) {
	// Servidor que retorna 5 prefixos, mas max=2
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "whois") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data":   map[string]interface{}{"records": []interface{}{}},
				"status": "ok",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"asn": 12345,
				"prefixes": []map[string]interface{}{
					{"prefix": "1.0.0.0/24"},
					{"prefix": "1.1.0.0/24"},
					{"prefix": "1.2.0.0/24"},
					{"prefix": "1.3.0.0/24"},
					{"prefix": "1.4.0.0/24"},
				},
			},
			"status": "ok",
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryRIPE(context.Background(), "AS12345", TargetASN, "AS12345", 2)
	if err != nil {
		t.Fatalf("queryRIPE: %v", err)
	}

	prefixCount := 0
	hasTruncated := false
	for _, f := range findings {
		if f.Type == "announced_prefix" {
			prefixCount++
		}
		if f.Type == "prefixes_truncated" {
			hasTruncated = true
		}
	}
	if prefixCount != 2 {
		t.Errorf("com max_prefixes=2 deve mostrar 2 prefixos, got %d", prefixCount)
	}
	if !hasTruncated {
		t.Error("deve gerar finding 'prefixes_truncated' quando há mais que max")
	}
}

// ─── Mock para BGP.tools ──────────────────────────────────────────────────────

func bgpToolsServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"asn":            15169,
			"name":           "GOOGLE",
			"country":        "US",
			"prefixCount_v4": 500.0,
			"prefixCount_v6": 200.0,
			"peerCount":      150.0,
			"upstreams": []map[string]interface{}{
				{"asn": 1299.0, "name": "Arelion"},
				{"asn": 174.0, "name": "Cogent"},
			},
		})
	}))
}

func TestQueryBGPTools(t *testing.T) {
	srv := bgpToolsServer()
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryBGPTools(context.Background(), "AS15169")
	if err != nil {
		t.Fatalf("queryBGPTools: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings")
	}

	hasSummary := false
	hasUpstreams := false
	for _, f := range findings {
		if f.Type == "asn_bgp_summary" {
			hasSummary = true
			if f.Extra["peer_count"] == "" {
				t.Error("summary deve ter peer_count")
			}
		}
		if f.Type == "bgp_upstreams" {
			hasUpstreams = true
		}
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
	}
	if !hasSummary {
		t.Error("deve conter 'asn_bgp_summary'")
	}
	if !hasUpstreams {
		t.Error("deve conter 'bgp_upstreams'")
	}
}

// ─── Mock para Cloudflare Radar ───────────────────────────────────────────────

func cloudflareRadarServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(cfRadarBGPEventsResp{
			Result: struct {
				Events []struct {
					Type            string `json:"type"`
					Prefix          string `json:"prefix"`
					ASPath          string `json:"asPath"`
					Country         string `json:"country"`
					MaxLenViolation bool   `json:"maxLenViolation"`
				} `json:"events"`
			}{
				Events: []struct {
					Type            string `json:"type"`
					Prefix          string `json:"prefix"`
					ASPath          string `json:"asPath"`
					Country         string `json:"country"`
					MaxLenViolation bool   `json:"maxLenViolation"`
				}{
					{Type: "ROUTE_LEAK", Prefix: "8.8.8.0/24", ASPath: "15169 64501", Country: "US", MaxLenViolation: false},
					{Type: "HIJACK", Prefix: "8.8.4.0/24", ASPath: "99999", Country: "RU", MaxLenViolation: false},
				},
			},
			Success: true,
		})
	}))
}

func TestQueryCloudflareRadar(t *testing.T) {
	srv := cloudflareRadarServer()
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryCloudflareRadar(context.Background(), "AS15169")
	if err != nil {
		t.Fatalf("queryCloudflareRadar: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("esperado 2 eventos, got %d", len(findings))
	}

	for _, f := range findings {
		if f.Type != "bgp_event" {
			t.Errorf("tipo esperado 'bgp_event', got '%s'", f.Type)
		}
	}

	// ROUTE_LEAK deve ter severidade Medium
	if findings[0].Severity != module.SeverityMedium {
		t.Errorf("ROUTE_LEAK deve ter severidade Medium, got %s", findings[0].Severity)
	}
	// HIJACK deve ter severidade High
	if findings[1].Severity != module.SeverityHigh {
		t.Errorf("HIJACK deve ter severidade High, got %s", findings[1].Severity)
	}
}

// ─── Mock para IPinfo ────────────────────────────────────────────────────────

func ipinfoServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ipinfoResp{
			IP:      "8.8.8.8",
			Org:     "AS15169 Google LLC",
			City:    "Mountain View",
			Region:  "California",
			Country: "US",
			Abuse: struct {
				Address string `json:"address"`
				Country string `json:"country"`
				Email   string `json:"email"`
				Name    string `json:"name"`
				Network string `json:"network"`
				Phone   string `json:"phone"`
			}{
				Email:   "network-abuse@google.com",
				Name:    "Google LLC",
				Network: "8.8.8.0/24",
			},
		})
	}))
}

func TestQueryIPInfo(t *testing.T) {
	srv := ipinfoServer()
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryIPInfo(context.Background(), "8.8.8.8", TargetIP, "")
	if err != nil {
		t.Fatalf("queryIPInfo: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("esperado 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "asn_owner" {
		t.Errorf("tipo esperado 'asn_owner', got '%s'", f.Type)
	}
	if f.Extra["abuse_email"] == "" {
		t.Error("deve incluir abuse_email")
	}
}

// ─── Testes de segurança local ────────────────────────────────────────────────

func TestMoreSpecificPrefix(t *testing.T) {
	findings := analyzeSecurityLocally("198.51.100.0/28", TargetPrefix, nil)
	found := false
	for _, f := range findings {
		if f.Type == "more_specific_prefix" {
			found = true
			if f.Severity != module.SeverityMedium {
				t.Errorf("prefixo /28 deve ter severidade Medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("prefixo /28 (mais específico que /24) deve gerar finding 'more_specific_prefix'")
	}
}

func TestSlash24PrefixNoFlag(t *testing.T) {
	// /24 não deve gerar flag de mais específico
	findings := analyzeSecurityLocally("198.51.100.0/24", TargetPrefix, nil)
	for _, f := range findings {
		if f.Type == "more_specific_prefix" {
			t.Error("/24 não deve gerar 'more_specific_prefix'")
		}
	}
}

func TestLargeASNFootprint(t *testing.T) {
	existing := []module.Finding{
		{
			Type:  "asn_bgp_summary",
			Extra: map[string]string{"peer_count": "150"},
		},
	}
	findings := analyzeSecurityLocally("AS15169", TargetASN, existing)
	found := false
	for _, f := range findings {
		if f.Type == "large_asn_footprint" {
			found = true
		}
	}
	if !found {
		t.Error("ASN com 150 peers deve gerar 'large_asn_footprint'")
	}
}

func TestSmallASNNoFootprintFlag(t *testing.T) {
	existing := []module.Finding{
		{
			Type:  "asn_bgp_summary",
			Extra: map[string]string{"peer_count": "5"},
		},
	}
	findings := analyzeSecurityLocally("AS99999", TargetASN, existing)
	for _, f := range findings {
		if f.Type == "large_asn_footprint" {
			t.Error("ASN com 5 peers não deve gerar 'large_asn_footprint'")
		}
	}
}

// ─── Testes de fluxo completo ─────────────────────────────────────────────────

func TestRunASN(t *testing.T) {
	srv := ripeWhoisServer()
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "AS15169",
		Options: map[string]string{"sources": "ripe", "check_rpki": "false"},
	})
	if err != nil {
		t.Fatalf("Run ASN: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("deve retornar findings para ASN")
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding '%s' sem confidence", f.Type)
		}
	}
}

func TestRunContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			http.Error(w, "cancelled", 499)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := NewWithClient(clientFor(srv))
	// Contexto cancelado: módulo tolera falhas de rede
	_, err := m.Run(ctx, module.Input{
		Target:  "AS15169",
		Options: map[string]string{"sources": "ripe", "check_rpki": "false"},
	})
	// Run tolerante: não propaga erros das fontes, apenas logWarn
	if err != nil {
		t.Logf("Run com contexto cancelado retornou: %v", err)
	}
}

func TestDedup(t *testing.T) {
	findings := []module.Finding{
		{Type: "asn_info", URL: "https://ripe.net", Detail: "Info A"},
		{Type: "asn_info", URL: "https://ripe.net", Detail: "Info A"},
		{Type: "announced_prefix", URL: "https://ripe.net", Detail: "Prefix B"},
	}
	result := dedup(findings)
	if len(result) != 2 {
		t.Errorf("dedup: esperado 2 únicos, got %d", len(result))
	}
}

func TestToFloat(t *testing.T) {
	cases := []struct {
		input interface{}
		want  float64
	}{
		{150.0, 150.0},
		{100, 100.0},
		{"99.5", 99.5},
		{nil, 0.0},
	}
	for _, tt := range cases {
		if got := toFloat(tt.input); got != tt.want {
			t.Errorf("toFloat(%v) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
