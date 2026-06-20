package threatintel_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/threatintel"
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
	if threatintel.New().Name() != "threatintel" {
		t.Error("nome incorreto")
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if threatintel.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := threatintel.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

// ─── VirusTotal ───────────────────────────────────────────────────────────────

func vtMaliciousHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"id":   "1.2.3.4",
			"type": "ip_address",
			"attributes": map[string]interface{}{
				"last_analysis_stats": map[string]int{
					"malicious":  15,
					"suspicious": 3,
					"harmless":   50,
					"undetected": 10,
				},
				"last_analysis_results": map[string]interface{}{
					"EngineA": map[string]string{"category": "malicious", "result": "trojan"},
					"EngineB": map[string]string{"category": "malicious", "result": "malware"},
				},
				"country":  "RU",
				"as_owner": "Malicious ASN",
			},
		},
	}
	json.NewEncoder(w).Encode(resp)
}

func TestRun_VT_IPMalicious_CappedExternalReference(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(vtMaliciousHandler))
	defer srv.Close()

	m := threatintel.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "1.2.3.4",
		Options: map[string]string{
			"sources": "virustotal",
			"vt_key":  "test-key",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava pelo menos 1 finding")
	}

	var found bool
	for _, f := range findings {
		if f.Type == "threat_detected" && f.Extra["source"] == "virustotal" {
			found = true
			if f.Severity != module.SeverityMedium {
				t.Errorf("reputação externa de IP deve ser limitada a Medium, obteve %s", f.Severity)
			}
			if f.Extra["malicious"] != "15" {
				t.Errorf("malicious esperado '15', obteve '%s'", f.Extra["malicious"])
			}
			if f.Extra["country"] != "RU" {
				t.Errorf("country esperado 'RU', obteve '%s'", f.Extra["country"])
			}
			if f.Extra["promote_to_context"] != "false" || f.Extra["validated"] != "false" {
				t.Error("inteligência externa não deve ser promovida como confirmação local")
			}
		}
	}
	if !found {
		t.Error("esperava finding 'threat_detected' do virustotal")
	}
}

func TestRun_VT_CleanTarget_InfoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"id":   "example.com",
				"type": "domain",
				"attributes": map[string]interface{}{
					"last_analysis_stats": map[string]int{
						"malicious":  0,
						"suspicious": 0,
						"harmless":   80,
						"undetected": 5,
					},
					"last_analysis_results": map[string]interface{}{},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	m := threatintel.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources": "virustotal",
			"vt_key":  "test-key",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}

	for _, f := range findings {
		if f.Extra["source"] == "virustotal" {
			if f.Type != "threat_clean" {
				t.Errorf("target limpo deve ser 'threat_clean', obteve '%s'", f.Type)
			}
			if f.Severity != module.SeverityInfo {
				t.Errorf("target limpo deve ser SeverityInfo, obteve %s", f.Severity)
			}
		}
	}
}

func TestRun_VT_NoKey_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(vtMaliciousHandler))
	defer srv.Close()

	m := threatintel.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "1.2.3.4",
		Options: map[string]string{
			"sources": "virustotal",
			// sem vt_key
		},
	})
	if len(findings) != 0 {
		t.Errorf("sem vt_key esperava 0 findings, obteve %d", len(findings))
	}
}

func TestRun_VT_HashTarget_TargetTypeHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"id":   "abc123",
				"type": "file",
				"attributes": map[string]interface{}{
					"last_analysis_stats": map[string]int{
						"malicious":  30,
						"suspicious": 5,
						"harmless":   0,
						"undetected": 0,
					},
					"last_analysis_results": map[string]interface{}{},
					"md5":                   "098f6bcd4621d373cade4e832627b4f6",
					"sha256":                "a" + strings.Repeat("0", 63),
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// Use a valid SHA256 hash (64 hex chars)
	hash := strings.Repeat("a", 64)
	m := threatintel.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: hash,
		Options: map[string]string{
			"sources": "virustotal",
			"vt_key":  "test-key",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Extra["source"] == "virustotal" {
			if f.Extra["target_type"] != "hash" {
				t.Errorf("hash deve ter target_type='hash', obteve '%s'", f.Extra["target_type"])
			}
		}
	}
}

// ─── ThreatFox ────────────────────────────────────────────────────────────────

func threatFoxHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"query_status": "ok",
		"data": []map[string]interface{}{
			{
				"ioc":               "1.2.3.4:8080",
				"ioc_type":          "ip:port",
				"threat_type":       "botnet_cc",
				"malware_printable": "Cobalt Strike",
				"confidence_level":  90,
				"first_seen":        "2024-01-01 00:00:00 UTC",
				"last_seen":         "2024-06-01 00:00:00 UTC",
				"tags":              []string{"cobalt-strike", "c2"},
			},
		},
	}
	json.NewEncoder(w).Encode(resp)
}

func TestRun_ThreatFox_IPPortMatchesTargetIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(threatFoxHandler))
	defer srv.Close()

	m := threatintel.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "1.2.3.4",
		Options: map[string]string{"sources": "threatfox"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava pelo menos 1 finding via ThreatFox")
	}

	for _, f := range findings {
		if f.Extra["source"] == "threatfox" {
			if f.Severity != module.SeverityMedium {
				t.Errorf("IOC externo vinculado ao IP deve ser no máximo Medium, obteve %s", f.Severity)
			}
			if f.Extra["malware"] != "Cobalt Strike" {
				t.Errorf("malware esperado 'Cobalt Strike', obteve '%s'", f.Extra["malware"])
			}
		}
	}
}

func TestRun_ThreatFox_NoResults_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"query_status": "no_result",
			"data":         []interface{}{},
		})
	}))
	defer srv.Close()

	m := threatintel.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "clean.example.com",
		Options: map[string]string{"sources": "threatfox"},
	})
	if len(findings) != 0 {
		t.Errorf("sem resultado ThreatFox esperava 0 findings, obteve %d", len(findings))
	}
}

// ─── MalwareBazaar ────────────────────────────────────────────────────────────

func malwareBazaarHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"query_status": "ok",
		"data": []map[string]interface{}{
			{
				"sha256_hash":    strings.Repeat("a", 64),
				"md5_hash":       strings.Repeat("b", 32),
				"file_name":      "malware.exe",
				"file_type_mime": "application/x-dosexec",
				"signature":      "Emotet",
				"first_seen":     "2024-01-01 00:00:00",
				"tags":           []string{"emotet", "banking-trojan"},
			},
		},
	}
	json.NewEncoder(w).Encode(resp)
}

func TestRun_MalwareBazaar_HashFound_CriticalFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(malwareBazaarHandler))
	defer srv.Close()

	hash := strings.Repeat("a", 64)
	m := threatintel.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  hash,
		Options: map[string]string{"sources": "malwarebazaar"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding via MalwareBazaar")
	}

	for _, f := range findings {
		if f.Extra["source"] == "malwarebazaar" {
			if f.Type != "malware_sample" {
				t.Errorf("type esperado 'malware_sample', obteve '%s'", f.Type)
			}
			if f.Severity != module.SeverityCritical {
				t.Errorf("malware deve ser SeverityCritical, obteve %s", f.Severity)
			}
			if f.Extra["malware_family"] != "Emotet" {
				t.Errorf("family esperada 'Emotet', obteve '%s'", f.Extra["malware_family"])
			}
		}
	}
}

func TestRun_MalwareBazaar_IPTarget_NoFindings(t *testing.T) {
	// MalwareBazaar só suporta hashes
	srv := httptest.NewServer(http.HandlerFunc(malwareBazaarHandler))
	defer srv.Close()

	m := threatintel.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "1.2.3.4",
		Options: map[string]string{"sources": "malwarebazaar"},
	})
	if len(findings) != 0 {
		t.Errorf("malwarebazaar para IP deve retornar 0 findings, obteve %d", len(findings))
	}
}

// ─── URLhaus ──────────────────────────────────────────────────────────────────

func urlhausHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"query_status": "is_listed",
		"url_status":   "online",
		"threat":       "malware_download",
		"date_added":   "2024-03-15 10:00:00 UTC",
		"tags":         []string{"malware", "downloader"},
		"payloads": []map[string]interface{}{
			{"response_md5": "abc123", "content_type": "application/x-dosexec", "signature": "Emotet"},
		},
	}
	json.NewEncoder(w).Encode(resp)
}

func TestRun_URLhaus_MaliciousURL_HighReference(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(urlhausHandler))
	defer srv.Close()

	m := threatintel.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "https://malicious.example.com/download.exe",
		Options: map[string]string{"sources": "urlhaus"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding via URLhaus")
	}

	for _, f := range findings {
		if f.Extra["source"] == "urlhaus" {
			if f.Type != "malicious_url" {
				t.Errorf("type esperado 'malicious_url', obteve '%s'", f.Type)
			}
			if f.Severity != module.SeverityHigh {
				t.Errorf("URL externa confirmada deve ser High, não Critical, obteve %s", f.Severity)
			}
		}
	}
}

// ─── PhishTank ────────────────────────────────────────────────────────────────

func phishTankHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"results": map[string]interface{}{
			"url":         "https://phishing.example.com/login",
			"in_database": true,
			"valid":       true,
			"verified":    true,
			"verified_at": "2024-03-15T10:00:00+00:00",
		},
	}
	json.NewEncoder(w).Encode(resp)
}

func TestRun_PhishTank_PhishingURL_HighReference(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(phishTankHandler))
	defer srv.Close()

	m := threatintel.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "https://phishing.example.com/login",
		Options: map[string]string{"sources": "phishtank"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("esperava finding via PhishTank")
	}

	for _, f := range findings {
		if f.Extra["source"] == "phishtank" {
			if f.Type != "phishing_url" {
				t.Errorf("type esperado 'phishing_url', obteve '%s'", f.Type)
			}
			if f.Severity != module.SeverityHigh {
				t.Errorf("phishing verificado por fonte externa deve ser High, obteve %s", f.Severity)
			}
			if f.Extra["verified"] != "true" {
				t.Error("verified deve ser 'true'")
			}
		}
	}
}

// ─── OTX ─────────────────────────────────────────────────────────────────────

func otxHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"pulse_info": map[string]interface{}{
			"count": 5,
			"pulses": []map[string]interface{}{
				{
					"name":        "Cobalt Strike C2",
					"description": "Cobalt Strike C2 server",
					"tags":        []string{"cobalt-strike"},
					"malware_families": []map[string]interface{}{
						{"display_name": "Cobalt Strike"},
					},
				},
			},
		},
		"general": map[string]interface{}{
			"country_name": "Russia",
			"asn":          "AS12345",
		},
	}
	json.NewEncoder(w).Encode(resp)
}

func TestRun_OTX_PulsesFound_HighFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(otxHandler))
	defer srv.Close()

	m := threatintel.NewWithClient(newTestClient(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: "1.2.3.4",
		Options: map[string]string{
			"sources": "otx",
			"otx_key": "test-key",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}

	for _, f := range findings {
		if f.Extra["source"] == "otx" {
			if f.Extra["pulse_count"] != "5" {
				t.Errorf("pulse_count esperado '5', obteve '%s'", f.Extra["pulse_count"])
			}
			if !strings.Contains(f.Extra["malware_families"], "Cobalt Strike") {
				t.Error("malware_families deve conter 'Cobalt Strike'")
			}
		}
	}
}

// ─── multi-source ─────────────────────────────────────────────────────────────

func TestRun_MultiSource_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(threatFoxHandler))
	defer srv.Close()

	m := threatintel.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "1.2.3.4",
		Options: map[string]string{"sources": "threatfox"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(threatFoxHandler))
	defer srv.Close()

	m := threatintel.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "1.2.3.4",
		Options: map[string]string{"sources": "threatfox"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

// ─── context cancelado ────────────────────────────────────────────────────────

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv := httptest.NewServer(http.HandlerFunc(threatFoxHandler))
	defer srv.Close()

	m := threatintel.NewWithClient(newTestClient(srv))
	_, _ = m.Run(ctx, module.Input{
		Target:  "1.2.3.4",
		Options: map[string]string{"sources": "threatfox"},
	})
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestRun_Dedup_NoDuplicateFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(threatFoxHandler))
	defer srv.Close()

	m := threatintel.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "1.2.3.4",
		Options: map[string]string{"sources": "threatfox"},
	})
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Extra["source"]
		if seen[key] {
			t.Errorf("finding duplicado: %s", key)
		}
		seen[key] = true
	}
}
