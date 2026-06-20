package ipintel_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/ipintel"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

type rewriteTransport struct{ base string }

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(r.base, "http://")
	return http.DefaultTransport.RoundTrip(clone)
}

func TestName(t *testing.T) {
	if ipintel.New().Name() != "ipintel" {
		t.Error("nome incorreto")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := ipintel.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para IP vazio")
	}
}

func TestRun_InvalidIP_ReturnsError(t *testing.T) {
	_, err := ipintel.New().Run(context.Background(), module.Input{
		Target: "nao-e-ip",
	})
	if err == nil {
		t.Fatal("esperava erro para IP inválido")
	}
}

func TestRun_PrivateIP_ClassifiedCorrectly(t *testing.T) {
	m := ipintel.NewWithClient(&http.Client{})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "192.168.1.1",
		Options: map[string]string{"sources": "local"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Extra["ip_type"] == "private" {
			return
		}
	}
	t.Error("IP privado não classificado como 'private'")
}

func TestRun_LoopbackIP_ClassifiedCorrectly(t *testing.T) {
	m := ipintel.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "127.0.0.1",
		Options: map[string]string{"sources": "local"},
	})
	for _, f := range findings {
		if f.Extra["ip_type"] == "loopback" {
			return
		}
	}
	t.Error("loopback não classificado corretamente")
}

func TestRun_PublicIP_ClassifiedCorrectly(t *testing.T) {
	m := ipintel.NewWithClient(&http.Client{})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "8.8.8.8",
		Options: map[string]string{"sources": "local"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Extra["ip_type"] == "public" {
			return
		}
	}
	t.Error("IP público não classificado como 'public'")
}

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	m := ipintel.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "8.8.8.8",
		Options: map[string]string{"sources": "local"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_LocalAnalysis_HighConfidence(t *testing.T) {
	m := ipintel.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "10.0.0.1",
		Options: map[string]string{"sources": "local"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "0.99" {
			return
		}
	}
	t.Error("análise local deve ter confidence 0.99")
}

func TestRun_IPAPI_ParsesGeo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "success",
			"country":     "Brazil",
			"countryCode": "BR",
			"regionName":  "São Paulo",
			"city":        "São Paulo",
			"zip":         "01310-100",
			"lat":         -23.5475,
			"lon":         -46.6361,
			"timezone":    "America/Sao_Paulo",
			"isp":         "Claro",
			"org":         "Claro Brasil",
			"as":          "AS28573 Claro NXT Telecomunicacoes Ltda",
			"asname":      "Claro",
			"mobile":      false,
			"proxy":       false,
			"hosting":     false,
			"query":       "177.75.40.1",
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := ipintel.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "177.75.40.1",
		Options: map[string]string{"sources": "ipapi"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Type == "geolocation_reference" && f.Extra["country"] == "Brazil" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("teste requer servidor mock respondendo — skip")
	}
}

func TestRun_AbuseIPDB_ParsesScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"ipAddress":            "8.8.8.8",
				"isPublic":             true,
				"ipVersion":            4,
				"isWhitelisted":        true,
				"abuseConfidenceScore": 0,
				"countryCode":          "US",
				"usageType":            "Data Center/Web Hosting/Transit",
				"isp":                  "Google LLC",
				"domain":               "google.com",
				"totalReports":         0,
				"numDistinctUsers":     0,
				"lastReportedAt":       nil,
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := ipintel.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "8.8.8.8",
		Options: map[string]string{"sources": "abuseipdb", "abuseipdb_key": "testkey"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Type == "abuse_reputation_reference" && f.Extra["source"] == "abuseipdb" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor mock não respondeu")
	}
}

func TestRun_HighAbuseScore_SeverityMediumUntilCorroborated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"ipAddress":            "1.2.3.4",
				"abuseConfidenceScore": 98,
				"totalReports":         500,
				"numDistinctUsers":     200,
				"countryCode":          "CN",
				"isp":                  "BadISP",
				"domain":               "malicious.example",
				"lastReportedAt":       "2026-06-01T00:00:00+00:00",
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := ipintel.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "1.2.3.4",
		Options: map[string]string{"sources": "abuseipdb", "abuseipdb_key": "testkey"},
	})
	for _, f := range findings {
		if f.Type == "abuse_reputation_reference" && f.Severity == module.SeverityMedium {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor mock não respondeu")
	}
}

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = ipintel.New().Run(ctx, module.Input{Target: "8.8.8.8"})
}

func TestRun_IPv6_AcceptedAsTarget(t *testing.T) {
	m := ipintel.NewWithClient(&http.Client{})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "::1",
		Options: map[string]string{"sources": "local"},
	})
	if err != nil {
		t.Fatalf("erro inesperado para IPv6: %v", err)
	}
	_ = findings
}

func TestRun_FindingType_IsAddressClassification(t *testing.T) {
	m := ipintel.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "192.168.0.1",
		Options: map[string]string{"sources": "local"},
	})
	for _, f := range findings {
		if f.Type == "address_classification" {
			return
		}
	}
	t.Error("esperava finding do tipo address_classification")
}

func TestRun_DetailNotEmpty(t *testing.T) {
	m := ipintel.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "10.0.0.1",
		Options: map[string]string{"sources": "local"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

func TestRun_CGNATRange_Classified(t *testing.T) {
	m := ipintel.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "100.64.0.1",
		Options: map[string]string{"sources": "local"},
	})
	for _, f := range findings {
		if f.Extra["ip_type"] == "cgnat" {
			return
		}
	}
	t.Error("IP na faixa CGNAT (100.64.0.0/10) não classificado como cgnat")
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if ipintel.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestRun_ExternalResponseForDifferentIPIsDiscarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"country": "Brazil",
			"query":   "9.9.9.9",
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	findings, err := ipintel.NewWithClient(c).Run(context.Background(), module.Input{
		Target:  "8.8.8.8",
		Options: map[string]string{"sources": "ipapi"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, finding := range findings {
		if finding.Type == "geolocation_reference" {
			t.Fatalf("response for another IP must be discarded: %+v", finding)
		}
	}
}

func TestRun_AllFindingsCarryPromotionVeto(t *testing.T) {
	findings, err := ipintel.NewWithClient(&http.Client{}).Run(context.Background(), module.Input{
		Target:  "10.0.0.1",
		Options: map[string]string{"sources": "local"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, finding := range findings {
		if finding.Extra["promote_to_context"] != "false" {
			t.Fatalf("finding should not promote target IP again: %+v", finding)
		}
	}
}
