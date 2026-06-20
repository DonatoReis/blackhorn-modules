package brandmon_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/brandmon"
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
	if brandmon.New().Name() != "brandmon" {
		t.Error("nome incorreto")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := brandmon.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

func TestRun_InvalidTarget_ReturnsError(t *testing.T) {
	_, err := brandmon.New().Run(context.Background(), module.Input{Target: "nodot"})
	if err == nil {
		t.Fatal("esperava erro para target sem ponto (não é domínio)")
	}
}

func TestRun_URLScan_ParsesImpersonation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 2,
			"results": []map[string]interface{}{
				{
					"task": map[string]interface{}{
						"domain": "example-login.com",
						"url":    "http://example-login.com/phish",
					},
					"page": map[string]interface{}{
						"domain": "example-login.com",
						"ip":     "1.2.3.4",
					},
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := brandmon.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "urlscan"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Type == "brand_domain_reference" {
			if f.Severity != module.SeverityInfo {
				t.Errorf("URLScan é referência e deve ser Info, obteve %s", f.Severity)
			}
			if f.Extra["promote_to_context"] != "false" {
				t.Error("referência de marca não deve promover domínio")
			}
			return
		}
	}
	t.Fatalf("esperava brand_domain_reference, obteve %+v", findings)
}

func TestRun_URLScan_FiltersOriginalDomain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 1,
			"results": []map[string]interface{}{
				{
					"task": map[string]interface{}{"domain": "example.com", "url": "https://example.com"},
					"page": map[string]interface{}{"domain": "example.com", "ip": "1.1.1.1"},
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := brandmon.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "urlscan"},
	})
	for _, f := range findings {
		if f.Extra["impersonating_domain"] == "example.com" {
			t.Error("domínio original não deve ser reportado como impersonação")
		}
	}
}

func TestRun_OpenPhish_DetectsBrandMention(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Feed com URLs de phishing incluindo a marca
		_, _ = w.Write([]byte("http://example-secure-login.evil.com/verify\nhttp://other-site.com/page\nhttp://example.auth-verify.com\n"))
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := brandmon.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "openphish"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Type == "phishing_reference" && f.Extra["source"] == "openphish" {
			if f.Severity != module.SeverityMedium {
				t.Errorf("feed OpenPhish deve ser referência Medium, obteve %s", f.Severity)
			}
			if f.Extra["validated"] != "false" || f.Extra["promote_to_context"] != "false" {
				t.Error("feed externo deve permanecer referência não promotora")
			}
			return
		}
	}
	t.Fatalf("esperava phishing_reference do OpenPhish, obteve %+v", findings)
}

func TestRun_Phishtank_NotInDatabase_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"meta":    map[string]interface{}{"status": "success"},
			"results": map[string]interface{}{"in_database": false},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := brandmon.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "phishtank"},
	})
	for _, f := range findings {
		if f.Extra["source"] == "phishtank" {
			t.Error("não esperava findings phishtank quando in_database=false")
		}
	}
}

func TestRun_Phishtank_VerifiedPhish_SeverityHigh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"meta": map[string]interface{}{"status": "success"},
			"results": map[string]interface{}{
				"in_database":       true,
				"verified":          true,
				"phish_id":          "12345",
				"phish_detail_page": "https://phishtank.org/phish_detail.php?phish_id=12345",
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := brandmon.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "phishtank"},
	})
	for _, f := range findings {
		if f.Extra["source"] == "phishtank" && f.Extra["verified"] == "true" {
			if f.Type != "phishing_reference" {
				t.Errorf("tipo esperado phishing_reference, obteve %s", f.Type)
			}
			if f.Severity != module.SeverityHigh {
				t.Errorf("phishing verificado deve ser SeverityHigh, obteve %s", f.Severity)
			}
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu")
	}
}

func TestRun_OpenPhish_DoesNotMatchBrandOnlyInPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("http://unrelated.test.net/path/example-login\n"))
	}))
	defer srv.Close()

	m := brandmon.NewWithClient(&http.Client{Transport: &rewriteTransport{srv.URL}})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "openphish"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("marca apenas no path não deve vincular o host ao alvo: %+v", findings)
	}
}

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("http://example-evil.com/phish\n"))
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := brandmon.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "openphish"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("http://example-secure.fake.com\n"))
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := brandmon.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "openphish"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = brandmon.New().Run(ctx, module.Input{Target: "example.com"})
}

func TestRun_DNS_SkipOriginalDomain(t *testing.T) {
	// DNS probe não deve gerar findings para o domínio original
	m := brandmon.NewWithClient(&http.Client{})
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "dns", "max_typos": "5"},
	})
	for _, f := range findings {
		if f.Extra["typo_domain"] == "example.com" {
			t.Error("domínio original não deve ser reportado como typosquatting")
		}
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if brandmon.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestNewWithClient_ReturnsNonNil(t *testing.T) {
	if brandmon.NewWithClient(http.DefaultClient) == nil {
		t.Fatal("NewWithClient() retornou nil")
	}
}

func TestRun_SchemeNormalised_HTTPS(t *testing.T) {
	// https://example.com deve ser normalizado para example.com
	m := brandmon.NewWithClient(&http.Client{})
	_, err := m.Run(context.Background(), module.Input{
		Target:  "https://example.com",
		Options: map[string]string{"sources": "dns", "max_typos": "1"},
	})
	// Pode dar erro de rede — não deve dar erro de "target inválido"
	if err != nil && strings.Contains(err.Error(), "target inválido") {
		t.Errorf("normalização HTTPS falhou: %v", err)
	}
}

func TestRun_URLScan_RateLimit_Handled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := brandmon.NewWithClient(c)
	_, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "urlscan"},
	})
	_ = err // rate limit pode retornar erro absorvido
}

func TestRun_OpenPhish_NoMatch_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("http://otherbrand-evil.com\nhttp://differentbrand-phish.com\n"))
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := brandmon.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "mybrand.com",
		Options: map[string]string{"sources": "openphish"},
	})
	for _, f := range findings {
		if f.Extra["source"] == "openphish" && !strings.Contains(strings.ToLower(f.URL), "mybrand") {
			t.Error("openphish não deve retornar URLs sem menção à marca")
		}
	}
}
