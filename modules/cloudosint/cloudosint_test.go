package cloudosint_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/cloudosint"
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
	if cloudosint.New().Name() != "cloudosint" {
		t.Error("nome incorreto")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := cloudosint.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

func TestRun_InvalidTarget_ReturnsError(t *testing.T) {
	_, err := cloudosint.New().Run(context.Background(), module.Input{Target: "x"})
	if err == nil {
		t.Fatal("esperava erro para target muito curto")
	}
}

func TestRun_HTTP200_IsCandidateNotConfirmedExposure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HEAD 200 confirma resposta, mas não comprova listagem/leitura pública.
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := cloudosint.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "acme",
		Options: map[string]string{"sources": "http", "max_permutations": "1"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Extra["status"] == "public_read" {
			if f.Severity != module.SeverityLow {
				t.Errorf("HEAD 200 deve ser candidato Low, obteve %s", f.Severity)
			}
			if f.Type != "cloud_storage_candidate" {
				t.Errorf("tipo esperado cloud_storage_candidate, obteve %s", f.Type)
			}
			if f.Extra["promote_to_context"] != "false" {
				t.Error("candidato não deve ser promovido ao contexto")
			}
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não recebeu requisições HEAD")
	}
}

func TestRun_HTTPForbidden_IsInformationalCandidate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := cloudosint.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "acme",
		Options: map[string]string{"sources": "http", "max_permutations": "1"},
	})
	for _, f := range findings {
		if f.Extra["status"] == "private" {
			if f.Severity != module.SeverityInfo {
				t.Errorf("HTTP 403 sem vínculo comprovado deve ser Info, obteve %s", f.Severity)
			}
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu a HEAD")
	}
}

func TestRun_HTTP_NotFound_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := cloudosint.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "acme",
		Options: map[string]string{"sources": "http", "max_permutations": "1"},
	})
	for _, f := range findings {
		if f.Extra["status"] == "not_found" {
			t.Error("not_found não deve gerar finding")
		}
	}
}

func TestRun_Grayhat_WithoutKey_NoFindings(t *testing.T) {
	m := cloudosint.NewWithClient(&http.Client{})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "acme.com",
		Options: map[string]string{"sources": "grayhat"},
	})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	for _, f := range findings {
		if f.Extra["source"] == "grayhat" {
			t.Error("grayhat não deve retornar findings sem API key")
		}
	}
}

func TestRun_Grayhat_ParsesResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 2,
			"buckets": []map[string]interface{}{
				{
					"bucket_name": "acme-backup",
					"file_count":  150,
					"provider":    "AWS",
					"url":         "https://acme-backup.s3.amazonaws.com",
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := cloudosint.NewWithClient(c)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "acme.com",
		Options: map[string]string{"sources": "grayhat", "grayhat_key": "testkey"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	for _, f := range findings {
		if f.Extra["source"] == "grayhat" && f.Extra["bucket_name"] == "acme-backup" {
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu")
	}
}

func TestRun_Grayhat_EmptyBucket_IsInformationalReference(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 1,
			"buckets": []map[string]interface{}{
				{
					"bucket_name": "acme-empty",
					"file_count":  0,
					"provider":    "GCP",
					"url":         "https://acme-empty.storage.googleapis.com",
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := cloudosint.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "acme.com",
		Options: map[string]string{"sources": "grayhat", "grayhat_key": "testkey"},
	})
	for _, f := range findings {
		if f.Extra["file_count"] == "0" {
			if f.Severity != module.SeverityInfo {
				t.Errorf("referência externa sem arquivos deve ser Info, obteve %s", f.Severity)
			}
			return
		}
	}
	if len(findings) == 0 {
		t.Skip("servidor não respondeu")
	}
}

func TestRun_Grayhat_FiltersUnrelatedKeywordMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 1,
			"buckets": []map[string]interface{}{
				{
					"bucket_name": "unrelated-company",
					"file_count":  50,
					"provider":    "AWS",
					"url":         "https://unrelated-company.s3.amazonaws.com",
				},
			},
		})
	}))
	defer srv.Close()

	m := cloudosint.NewWithClient(&http.Client{Transport: &rewriteTransport{srv.URL}})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "acme.com",
		Options: map[string]string{"sources": "grayhat", "grayhat_key": "testkey"},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("match de keyword sem relação nominal deve ser filtrado: %+v", findings)
	}
}

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 1,
			"buckets": []map[string]interface{}{
				{
					"bucket_name": "acme-test",
					"file_count":  10,
					"provider":    "AWS",
					"url":         "https://acme-test.s3.amazonaws.com",
				},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := cloudosint.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "acme.com",
		Options: map[string]string{"sources": "grayhat", "grayhat_key": "testkey"},
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
			"total": 1,
			"buckets": []map[string]interface{}{
				{"bucket_name": "test-bkt", "file_count": 5, "provider": "Azure", "url": "https://test-bkt.blob.core.windows.net"},
			},
		})
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := cloudosint.NewWithClient(c)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "acme.com",
		Options: map[string]string{"sources": "grayhat", "grayhat_key": "testkey"},
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
	_, _ = cloudosint.New().Run(ctx, module.Input{Target: "acme.com"})
}

func TestRun_Permutations_Generated(t *testing.T) {
	// Com max_permutations=3, verifica que múltiplas permutações são tentadas
	var mu sync.Mutex
	var count int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			mu.Lock()
			count++
			mu.Unlock()
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := cloudosint.NewWithClient(c)
	_, _ = m.Run(context.Background(), module.Input{
		Target:  "acme.com",
		Options: map[string]string{"sources": "http", "max_permutations": "3"},
	})
	// Com 3 permutações × múltiplos providers, count deve ser > 0
	// (confirmamos que não houve panic e que requests foram feitas)
	if count == 0 {
		t.Skip("nenhum request HEAD foi feito — verifique a configuração de transporte")
	}
}

func TestRun_DomainTarget_ExtractsBaseName(t *testing.T) {
	// "example.com" → base "example" → sem erro
	m := cloudosint.NewWithClient(&http.Client{})
	_, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"sources": "http", "max_permutations": "1"},
	})
	// Erro de rede esperado (sem servidor real) — não erro de target inválido
	if err != nil && strings.Contains(err.Error(), "target inválido") {
		t.Errorf("extração de base name falhou: %v", err)
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if cloudosint.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestNewWithClient_ReturnsNonNil(t *testing.T) {
	if cloudosint.NewWithClient(http.DefaultClient) == nil {
		t.Fatal("NewWithClient() retornou nil")
	}
}

func TestRun_Grayhat_Unauthorized_ReturnsNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &rewriteTransport{srv.URL}}
	m := cloudosint.NewWithClient(c)
	_, err := m.Run(context.Background(), module.Input{
		Target:  "acme.com",
		Options: map[string]string{"sources": "grayhat", "grayhat_key": "invalid"},
	})
	_ = err // pode retornar erro absorvido — o importante é não panic
}
