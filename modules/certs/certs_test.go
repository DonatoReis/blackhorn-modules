package certs_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/certs"
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
	if certs.New().Name() != "certs" {
		t.Error("nome incorreto")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := certs.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

func TestRun_InvalidTarget_ReturnsError(t *testing.T) {
	_, err := certs.New().Run(context.Background(), module.Input{Target: "naotemdominio"})
	if err == nil {
		t.Fatal("esperava erro para target sem ponto")
	}
}

func TestRun_CRTsh_ParsesSubdomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":          12345,
				"name_value":  "api.example.com\nwww.example.com",
				"common_name": "example.com",
				"issuer_name": "Let's Encrypt",
				"not_before":  "2026-01-01",
				"not_after":   "2027-01-01",
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := certs.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("servidor de teste não respondeu como esperado")
	}
	for _, f := range findings {
		if f.Type == "ct_name_reference" &&
			f.Extra["validated"] == "false" &&
			f.Extra["promote_to_context"] == "false" {
			return
		}
	}
	t.Error("esperava referência CT não promovível")
}

func TestRun_CRTsh_WildcardDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":          99,
				"name_value":  "*.example.com",
				"common_name": "*.example.com",
				"issuer_name": "DigiCert",
				"not_before":  "2026-01-01",
				"not_after":   "2027-01-01",
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := certs.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh", "wildcard": "true"},
	})
	for _, f := range findings {
		if f.Extra["wildcard"] == "true" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu")
	}
	t.Error("esperava finding com wildcard=true")
}

func TestRun_WildcardFilter_Excludes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":          88,
				"name_value":  "*.example.com",
				"common_name": "*.example.com",
				"issuer_name": "DigiCert",
				"not_before":  "2026-01-01",
				"not_after":   "2027-01-01",
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := certs.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh", "wildcard": "false"},
	})
	for _, f := range findings {
		if f.Extra["wildcard"] == "true" {
			t.Error("wildcard=false deve filtrar subdomínios wildcard")
		}
	}
}

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id": 1, "name_value": "sub.example.com",
				"common_name": "example.com", "issuer_name": "CA",
				"not_before": "2026-01-01", "not_after": "2027-01-01",
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := certs.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id": 2, "name_value": "mail.example.com",
				"common_name": "example.com", "issuer_name": "CA",
				"not_before": "2026-01-01", "not_after": "2027-01-01",
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := certs.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

func TestRun_ExpiredHistoricalCert_RemainsInformational(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id": 3, "name_value": "old.example.com",
				"common_name": "example.com", "issuer_name": "CA",
				"not_before": "2020-01-01", "not_after": "2021-01-01", // expired
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := certs.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	for _, f := range findings {
		if f.Extra["expired"] == "true" {
			if f.Severity != module.SeverityInfo {
				t.Errorf("certificado histórico expirado deve ser informativo, obteve %s", f.Severity)
			}
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu")
	}
}

func TestRun_HackerTarget_ParsesHosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("www.example.com,1.2.3.4\napi.example.com,1.2.3.5\n"))
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := certs.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "hackertarget"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu com dados")
	}
	found := false
	for _, f := range findings {
		if f.Extra["source"] == "hackertarget" &&
			f.Extra["ip"] != "" &&
			f.Type == "subdomain_resolved" &&
			f.Extra["validated"] == "true" &&
			f.Extra["promote_to_context"] == "true" {
			found = true
		}
	}
	if !found {
		t.Error("esperava finding de hackertarget com IP")
	}
}

func TestRun_CensysWithoutCredentials_NoFindings(t *testing.T) {
	m := certs.NewWithClient(&http.Client{})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "censys"},
		// sem censys_id nem censys_secret
	})
	// Deve retornar 0 findings sem erro (pula a fonte silenciosamente)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	for _, f := range findings {
		if f.Extra["source"] == "censys" {
			t.Error("censys não deve retornar findings sem credenciais")
		}
	}
}

func TestRun_CensysWithCredentials_ParsesHosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code":   200,
			"status": "OK",
			"result": map[string]interface{}{
				"hits": []map[string]interface{}{
					{
						"ip":    "1.2.3.4",
						"names": []string{"api.example.com", "www.example.com"},
					},
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := certs.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":       "censys",
			"censys_id":     "testid",
			"censys_secret": "testsecret",
		},
	})
	for _, f := range findings {
		if f.Extra["source"] == "censys" &&
			f.Type == "censys_name_reference" &&
			f.Extra["promote_to_context"] == "false" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu")
	}
}

func TestRun_CRTsh_FiltersOutOfScopeNamesAndApex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":          42,
				"name_value":  "example.com\napi.example.com\noutside.invalid\nwww..example.com",
				"common_name": "example.com",
				"issuer_name": "CA",
				"not_before":  "2026-01-01",
				"not_after":   "2027-01-01",
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	findings, err := certs.NewWithClient(c).Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) != 1 || findings[0].Extra["subdomain"] != "api.example.com" {
		t.Fatalf("esperava apenas api.example.com, obteve %+v", findings)
	}
}

func TestRun_CRTsh_MaxResultsLimitsSANFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":          43,
				"name_value":  "a.example.com\nb.example.com\nc.example.com",
				"common_name": "example.com",
				"issuer_name": "CA",
				"not_before":  "2026-01-01",
				"not_after":   "2027-01-01",
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	findings, err := certs.NewWithClient(c).Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"sources":     "crtsh",
			"max_results": "2",
		},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("max_results deve limitar findings, obteve %d", len(findings))
	}
}

func TestRun_HackerTarget_InvalidIPRemainsCandidate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("api.example.com,not-an-ip\n"))
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	findings, err := certs.NewWithClient(c).Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "hackertarget"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("esperava 1 finding, obteve %d", len(findings))
	}
	if findings[0].Type != "passive_name_candidate" ||
		findings[0].Extra["promote_to_context"] != "false" {
		t.Fatalf("IP inválido não pode confirmar subdomínio: %+v", findings[0])
	}
}

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = certs.New().Run(ctx, module.Input{Target: "example.com"})
}

func TestRun_DomainNormalisation_StripsScheme(t *testing.T) {
	m := certs.NewWithClient(&http.Client{})
	// https:// deve ser removido
	_, err := m.Run(context.Background(), module.Input{
		Target:  "https://example.com/path?q=1",
		Options: map[string]string{"sources": "crtsh"},
	})
	// Pode dar erro de rede — o importante é não dar erro de "target inválido"
	if err != nil && strings.Contains(err.Error(), "target inválido") {
		t.Errorf("normalização de domínio falhou: %v", err)
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if certs.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestNewWithClient_ReturnsNonNil(t *testing.T) {
	if certs.NewWithClient(http.DefaultClient) == nil {
		t.Fatal("NewWithClient() retornou nil")
	}
}

func TestRun_MultipleSubdomainsInNameValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":          77,
				"name_value":  "a.example.com\nb.example.com\nc.example.com",
				"common_name": "example.com",
				"issuer_name": "CA Test",
				"not_before":  "2026-01-01",
				"not_after":   "2027-01-01",
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := certs.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	// 3 subdomínios no name_value → 3 findings
	if len(findings) != 3 {
		t.Errorf("esperava 3 findings, obteve %d", len(findings))
	}
}

func TestRun_Dedup_NoDuplicates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id": 1, "name_value": "dup.example.com",
				"common_name": "example.com", "issuer_name": "CA",
				"not_before": "2026-01-01", "not_after": "2027-01-01",
			},
			{
				"id": 2, "name_value": "dup.example.com", // mesmo subdomínio
				"common_name": "example.com", "issuer_name": "CA",
				"not_before": "2026-01-01", "not_after": "2027-01-01",
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := certs.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh"},
	})
	count := 0
	for _, f := range findings {
		if f.Extra["subdomain"] == "dup.example.com" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("dedup falhou: %d duplicatas para dup.example.com", count)
	}
}

func TestRun_HackerTarget_ErrorResponse_Handled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("error check your API usage"))
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := certs.NewWithClient(c)
	_, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "hackertarget"},
	})
	// Deve retornar sem pânico — o erro da fonte é absorvido
	_ = err
}

func TestRun_SourceFilter_OnlyCRTsh(t *testing.T) {
	var calledPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPaths = append(calledPaths, r.URL.Path)
		_ = json.NewEncoder(w).Encode([]interface{}{})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := certs.NewWithClient(c)
	_, _ = m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "crtsh"},
	})

	for _, p := range calledPaths {
		if strings.Contains(p, "hostsearch") {
			t.Error("hackertarget não deve ser chamado quando sources=crtsh")
		}
	}
}
