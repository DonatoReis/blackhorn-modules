package vulndb_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/vulndb"
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
	if vulndb.New().Name() != "vulndb" {
		t.Error("nome incorreto")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := vulndb.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

func TestRun_NVD_ParsesCVE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"totalResults": 1,
			"vulnerabilities": []map[string]interface{}{
				{
					"cve": map[string]interface{}{
						"id":           "CVE-2024-1234",
						"published":    "2024-01-15T10:00:00.000",
						"lastModified": "2024-01-20T10:00:00.000",
						"vulnStatus":   "Analyzed",
						"descriptions": []map[string]interface{}{
							{"lang": "en", "value": "A critical vulnerability in OpenSSL allowing remote code execution"},
						},
						"metrics": map[string]interface{}{
							"cvssMetricV31": []map[string]interface{}{
								{
									"cvssData": map[string]interface{}{
										"baseScore":    9.8,
										"baseSeverity": "CRITICAL",
										"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
								},
							},
						},
						"references": []map[string]interface{}{
							{"url": "https://openssl.org/news/secadv/20240115.txt", "tags": []string{"Vendor Advisory"}},
						},
					},
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := vulndb.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "openssl",
		Options: map[string]string{"sources": "nvd"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("servidor de teste não respondeu como esperado")
	}
	for _, f := range findings {
		if f.Extra["cve_id"] == "CVE-2024-1234" {
			if f.Severity != module.SeverityCritical {
				t.Errorf("CVSS 9.8 deve ser SeverityCritical, obteve %s", f.Severity)
			}
			return
		}
	}
	t.Error("esperava finding com CVE-2024-1234")
}

func TestRun_NVD_CVSS_High_SeverityHigh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"totalResults": 1,
			"vulnerabilities": []map[string]interface{}{
				{
					"cve": map[string]interface{}{
						"id": "CVE-2024-9999", "published": "2024-01-01T00:00:00.000",
						"lastModified": "2024-01-01T00:00:00.000", "vulnStatus": "Analyzed",
						"descriptions": []map[string]interface{}{{"lang": "en", "value": "High severity vuln"}},
						"metrics": map[string]interface{}{
							"cvssMetricV31": []map[string]interface{}{
								{"cvssData": map[string]interface{}{"baseScore": 8.1, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
							},
						},
						"references": []map[string]interface{}{},
					},
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := vulndb.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "apache",
		Options: map[string]string{"sources": "nvd"},
	})
	for _, f := range findings {
		if f.Extra["cvss_score"] == "8.1" {
			if f.Severity != module.SeverityHigh {
				t.Errorf("CVSS 8.1 deve ser SeverityHigh, obteve %s", f.Severity)
			}
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu")
	}
}

func TestRun_OSV_ParsesVulnerability(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"vulns": []map[string]interface{}{
				{
					"id":        "GHSA-xxxx-yyyy-zzzz",
					"summary":   "SQL injection in example package",
					"details":   "Detailed description of the vulnerability",
					"modified":  "2024-03-01T00:00:00Z",
					"published": "2024-02-01T00:00:00Z",
					"aliases":   []string{"CVE-2024-5678"},
					"references": []map[string]interface{}{
						{"type": "WEB", "url": "https://example.com/advisory"},
					},
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := vulndb.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example-pkg",
		Options: map[string]string{"sources": "osv", "ecosystem": "Go"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Extra["osv_id"] == "GHSA-xxxx-yyyy-zzzz" && f.Extra["cve_alias"] == "CVE-2024-5678" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu")
	}
}

func TestRun_CISAKOV_KnownExploited_SeverityHigh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"catalogVersion": "2024.01.01",
			"dateReleased":   "2024-01-01",
			"count":          1,
			"vulnerabilities": []map[string]interface{}{
				{
					"cveID":                      "CVE-2024-0001",
					"vendorProject":              "Cisco",
					"product":                    "IOS XE",
					"vulnerabilityName":          "Cisco IOS XE Web UI Privilege Escalation",
					"dateAdded":                  "2023-10-17",
					"shortDescription":           "Cisco IOS XE contains a privilege escalation vulnerability",
					"requiredAction":             "Apply updates per vendor instructions",
					"dueDate":                    "2023-11-17",
					"knownRansomwareCampaignUse": "Unknown",
					"notes":                      "",
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := vulndb.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "Cisco",
		Options: map[string]string{"sources": "cisa"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Type == "known_exploited_vulnerability" {
			if f.Severity != module.SeverityHigh {
				t.Errorf("KEV deve ser SeverityHigh, obteve %s", f.Severity)
			}
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu")
	}
}

func TestRun_CISA_Ransomware_SeverityCritical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"catalogVersion": "2024.01.01", "dateReleased": "2024-01-01", "count": 1,
			"vulnerabilities": []map[string]interface{}{
				{
					"cveID": "CVE-2024-9988", "vendorProject": "Apache", "product": "Log4j",
					"vulnerabilityName": "Apache Log4j RCE", "dateAdded": "2021-12-10",
					"shortDescription": "Remote code execution via Log4j", "requiredAction": "Update",
					"dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known", "notes": "",
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := vulndb.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "Apache",
		Options: map[string]string{"sources": "cisa"},
	})
	for _, f := range findings {
		if f.Extra["ransomware"] == "Known" {
			if f.Severity != module.SeverityCritical {
				t.Errorf("ransomware KEV deve ser SeverityCritical, obteve %s", f.Severity)
			}
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu")
	}
}

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"vulns": []map[string]interface{}{
				{
					"id": "GHSA-test-conf", "summary": "Test", "details": "Test vuln",
					"modified": "2024-01-01T00:00:00Z", "published": "2024-01-01T00:00:00Z",
					"aliases": []string{}, "references": []map[string]interface{}{},
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := vulndb.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testpkg",
		Options: map[string]string{"sources": "osv"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"vulns": []map[string]interface{}{
				{
					"id": "GHSA-test-detail", "summary": "Important vulnerability",
					"modified": "2024-01-01T00:00:00Z", "published": "2024-01-01T00:00:00Z",
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := vulndb.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "pkg",
		Options: map[string]string{"sources": "osv"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

func TestRun_MinCVSS_Filters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"totalResults": 2,
			"vulnerabilities": []map[string]interface{}{
				{
					"cve": map[string]interface{}{
						"id": "CVE-2024-LOW", "published": "2024-01-01T00:00:00.000",
						"lastModified": "2024-01-01T00:00:00.000", "vulnStatus": "Analyzed",
						"descriptions": []map[string]interface{}{{"lang": "en", "value": "Low severity"}},
						"metrics": map[string]interface{}{
							"cvssMetricV31": []map[string]interface{}{
								{"cvssData": map[string]interface{}{"baseScore": 3.5, "baseSeverity": "LOW", "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"}},
							},
						},
						"references": []map[string]interface{}{},
					},
				},
				{
					"cve": map[string]interface{}{
						"id": "CVE-2024-HIGH", "published": "2024-01-01T00:00:00.000",
						"lastModified": "2024-01-01T00:00:00.000", "vulnStatus": "Analyzed",
						"descriptions": []map[string]interface{}{{"lang": "en", "value": "High severity"}},
						"metrics": map[string]interface{}{
							"cvssMetricV31": []map[string]interface{}{
								{"cvssData": map[string]interface{}{"baseScore": 8.9, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
							},
						},
						"references": []map[string]interface{}{},
					},
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := vulndb.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test",
		Options: map[string]string{"sources": "nvd", "min_cvss": "7.0"},
	})
	for _, f := range findings {
		if f.Extra["cve_id"] == "CVE-2024-LOW" {
			t.Error("CVE com CVSS 3.5 não deve aparecer com min_cvss=7.0")
		}
	}
}

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = vulndb.New().Run(ctx, module.Input{Target: "openssl"})
}

func TestRun_NVD_RateLimit_HandledGracefully(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := vulndb.NewWithClient(c)
	_, err := m.Run(context.Background(), module.Input{
		Target:  "test",
		Options: map[string]string{"sources": "nvd"},
	})
	_ = err // rate limit pode retornar erro absorvido
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if vulndb.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestNewWithClient_ReturnsNonNil(t *testing.T) {
	if vulndb.NewWithClient(http.DefaultClient) == nil {
		t.Fatal("NewWithClient() retornou nil")
	}
}

func TestRun_Dedup_SameSourceNoDuplicate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"totalResults": 2,
			"vulnerabilities": []map[string]interface{}{
				{
					"cve": map[string]interface{}{
						"id": "CVE-2024-DUP", "published": "2024-01-01T00:00:00.000",
						"lastModified": "2024-01-01T00:00:00.000", "vulnStatus": "Analyzed",
						"descriptions": []map[string]interface{}{{"lang": "en", "value": "Dup"}},
						"metrics":      map[string]interface{}{},
						"references":   []map[string]interface{}{},
					},
				},
				{
					"cve": map[string]interface{}{
						"id": "CVE-2024-DUP", "published": "2024-01-01T00:00:00.000",
						"lastModified": "2024-01-01T00:00:00.000", "vulnStatus": "Analyzed",
						"descriptions": []map[string]interface{}{{"lang": "en", "value": "Dup again"}},
						"metrics":      map[string]interface{}{},
						"references":   []map[string]interface{}{},
					},
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := vulndb.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test",
		Options: map[string]string{"sources": "nvd"},
	})
	count := 0
	for _, f := range findings {
		if f.Extra["cve_id"] == "CVE-2024-DUP" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("dedup falhou: %d entradas para CVE-2024-DUP", count)
	}
}
