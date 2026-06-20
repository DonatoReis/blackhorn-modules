package repochecker_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/repochecker"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// rewriteTransport redireciona qualquer requisição ao servidor de teste.
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
	if repochecker.New().Name() != "repochecker" {
		t.Error("nome incorreto")
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if repochecker.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

// ─── target vazio ─────────────────────────────────────────────────────────────

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := repochecker.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

func TestRun_InvalidTarget_ReturnsError(t *testing.T) {
	_, err := repochecker.New().Run(context.Background(), module.Input{Target: "no-slash-here"})
	if err == nil {
		t.Fatal("esperava erro para target sem owner/repo")
	}
}

func TestRun_DomainTarget_IsNotApplicable(t *testing.T) {
	findings, err := repochecker.New().Run(context.Background(), module.Input{Target: "example.com"})
	if err != nil {
		t.Fatalf("domínio sem owner/repo deve ser ignorado: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("domínio genérico não deve produzir findings de repositório: %+v", findings)
	}
}

// ─── parseTarget (via Run sem erros de formato) ───────────────────────────────

func TestRun_GitHubURL_ParsedCorrectly(t *testing.T) {
	// Um servidor que retorna 200 vazio para não falhar por rede
	srv := ghMockServer(t, map[string]interface{}{
		"full_name": "owner/repo", "private": false, "archived": false,
		"stargazers_count": 0, "forks_count": 0, "default_branch": "main",
		"html_url": "https://github.com/owner/repo",
	}, nil, nil, nil)
	defer srv.Close()

	m := repochecker.NewWithClient(newTestClient(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target:  "https://github.com/owner/repo",
		Options: map[string]string{"checks": "meta"},
	})
	if err != nil {
		t.Fatalf("URL GitHub válida gerou erro: %v", err)
	}
}

func TestRun_OwnerSlashRepo_GitHub(t *testing.T) {
	srv := ghMockServer(t, map[string]interface{}{
		"full_name": "owner/repo", "private": false, "archived": false,
		"stargazers_count": 10, "forks_count": 2, "default_branch": "main",
		"html_url": "https://github.com/owner/repo",
	}, nil, nil, nil)
	defer srv.Close()

	m := repochecker.NewWithClient(newTestClient(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target:  "owner/repo",
		Options: map[string]string{"checks": "meta", "source": "github"},
	})
	if err != nil {
		t.Fatalf("owner/repo gerou erro: %v", err)
	}
}

// ─── meta findings ────────────────────────────────────────────────────────────

func TestRun_Meta_PublicRepo_FindingReturned(t *testing.T) {
	srv := ghMockServer(t, map[string]interface{}{
		"full_name": "owner/repo", "private": false, "archived": false,
		"stargazers_count": 42, "forks_count": 7, "default_branch": "main",
		"html_url": "https://github.com/owner/repo",
	}, nil, nil, nil)
	defer srv.Close()

	m := repochecker.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "owner/repo",
		Options: map[string]string{"checks": "meta"},
	})

	var found bool
	for _, f := range findings {
		if f.Type == "repo_public" {
			found = true
			if f.Extra["stars"] != "42" {
				t.Errorf("stars esperado '42', obteve '%s'", f.Extra["stars"])
			}
		}
	}
	if !found {
		t.Error("esperava finding 'repo_public'")
	}
}

func TestRun_Meta_ArchivedRepo_FindingReturned(t *testing.T) {
	srv := ghMockServer(t, map[string]interface{}{
		"full_name": "owner/repo", "private": false, "archived": true,
		"stargazers_count": 0, "forks_count": 0, "default_branch": "main",
		"html_url": "https://github.com/owner/repo",
	}, nil, nil, nil)
	defer srv.Close()

	m := repochecker.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "owner/repo",
		Options: map[string]string{"checks": "meta"},
	})

	var found bool
	for _, f := range findings {
		if f.Type == "repo_archived" {
			found = true
			if f.Severity != module.SeverityLow {
				t.Errorf("repo_archived deve ser SeverityLow, obteve %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("esperava finding 'repo_archived'")
	}
}

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	srv := ghMockServer(t, map[string]interface{}{
		"full_name": "owner/repo", "private": false, "archived": false,
		"stargazers_count": 1, "forks_count": 1, "default_branch": "main",
		"html_url": "https://github.com/owner/repo",
	}, nil, nil, nil)
	defer srv.Close()

	m := repochecker.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "owner/repo",
		Options: map[string]string{"checks": "meta"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	srv := ghMockServer(t, map[string]interface{}{
		"full_name": "owner/repo", "private": false, "archived": false,
		"stargazers_count": 1, "forks_count": 1, "default_branch": "main",
		"html_url": "https://github.com/owner/repo",
	}, nil, nil, nil)
	defer srv.Close()

	m := repochecker.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "owner/repo",
		Options: map[string]string{"checks": "meta"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

// ─── sensitive files ─────────────────────────────────────────────────────────

func TestRun_Files_SensitiveEnvFound(t *testing.T) {
	files := []map[string]interface{}{
		{"name": ".env", "path": ".env", "type": "file",
			"html_url": "https://github.com/owner/repo/blob/main/.env", "size": 512},
		{"name": "README.md", "path": "README.md", "type": "file",
			"html_url": "https://github.com/owner/repo/blob/main/README.md", "size": 1024},
	}
	srv := ghMockServer(t, nil, files, nil, nil)
	defer srv.Close()

	m := repochecker.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "owner/repo",
		Options: map[string]string{"checks": "files"},
	})

	var found bool
	for _, f := range findings {
		if f.Type == "sensitive_file_found" && f.Extra["file_name"] == ".env" {
			found = true
			if f.Severity != module.SeverityHigh {
				t.Errorf(".env deve ser SeverityHigh, obteve %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("esperava finding para .env")
	}
}

func TestRun_Files_PemKeyFound(t *testing.T) {
	files := []map[string]interface{}{
		{"name": "server.pem", "path": "server.pem", "type": "file",
			"html_url": "https://github.com/owner/repo/blob/main/server.pem", "size": 2048},
	}
	srv := ghMockServer(t, nil, files, nil, nil)
	defer srv.Close()

	m := repochecker.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "owner/repo",
		Options: map[string]string{"checks": "files"},
	})

	var found bool
	for _, f := range findings {
		if f.Type == "sensitive_file_found" && strings.HasSuffix(f.Extra["file_name"], ".pem") {
			found = true
		}
	}
	if !found {
		t.Error("esperava finding para server.pem")
	}
}

// ─── branches ────────────────────────────────────────────────────────────────

func TestRun_Branches_SuspiciousName_FindingReturned(t *testing.T) {
	branches := []map[string]interface{}{
		{"name": "feature/add-secret-key", "commit": map[string]string{"sha": "abc123"}},
		{"name": "main", "commit": map[string]string{"sha": "def456"}},
	}
	srv := ghMockServer(t, nil, nil, branches, nil)
	defer srv.Close()

	m := repochecker.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "owner/repo",
		Options: map[string]string{"checks": "branches"},
	})

	var found bool
	for _, f := range findings {
		if f.Type == "suspicious_branch_name" {
			found = true
			if f.Severity != module.SeverityMedium {
				t.Errorf("branch suspeita deve ser SeverityMedium, obteve %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("esperava finding para branch 'feature/add-secret-key'")
	}
}

// ─── workflows ───────────────────────────────────────────────────────────────

func TestRun_Workflows_FileFound(t *testing.T) {
	workflows := []map[string]interface{}{
		{"name": "ci.yml", "path": ".github/workflows/ci.yml", "type": "file",
			"html_url": "https://github.com/owner/repo/blob/main/.github/workflows/ci.yml", "size": 256},
	}
	srv := ghMockServer(t, nil, nil, nil, workflows)
	defer srv.Close()

	m := repochecker.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "owner/repo",
		Options: map[string]string{"checks": "workflows"},
	})

	var found bool
	for _, f := range findings {
		if f.Type == "workflow_file_found" {
			found = true
			if f.Severity != module.SeverityLow {
				t.Errorf("workflow_file deve ser SeverityLow, obteve %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("esperava finding para ci.yml")
	}
}

// ─── context cancelado ───────────────────────────────────────────────────────

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	srv := ghMockServer(t, map[string]interface{}{
		"full_name": "owner/repo", "private": false, "archived": false,
		"stargazers_count": 0, "forks_count": 0, "default_branch": "main",
		"html_url": "https://github.com/owner/repo",
	}, nil, nil, nil)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := repochecker.NewWithClient(newTestClient(srv))
	_, _ = m.Run(ctx, module.Input{
		Target:  "owner/repo",
		Options: map[string]string{"checks": "meta"},
	})
}

// ─── secret scan ─────────────────────────────────────────────────────────────

func TestRun_Secrets_CheckFilter_NoMeta(t *testing.T) {
	// With checks=secrets only, we do secret scan on findings
	// The secret scan runs over other existing findings — with no other checks, nothing to scan
	srv := ghMockServer(t, nil, nil, nil, nil)
	defer srv.Close()

	m := repochecker.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "owner/repo",
		Options: map[string]string{"checks": "secrets"},
	})
	// Not an error — just no findings from other checks
	_ = findings
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestRun_Dedup_NoDuplicateFindings(t *testing.T) {
	// meta + workflows — all should be unique
	files := []map[string]interface{}{
		{"name": ".env", "path": ".env", "type": "file",
			"html_url": "https://github.com/owner/repo/blob/main/.env", "size": 512},
	}
	srv := ghMockServer(t, map[string]interface{}{
		"full_name": "owner/repo", "private": false, "archived": false,
		"stargazers_count": 1, "forks_count": 0, "default_branch": "main",
		"html_url": "https://github.com/owner/repo",
	}, files, nil, nil)
	defer srv.Close()

	m := repochecker.NewWithClient(newTestClient(srv))
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "owner/repo",
		Options: map[string]string{"checks": "meta,files"},
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

// ─── mock server helper ──────────────────────────────────────────────────────

// ghMockServer creates a test server that routes GitHub-style API paths.
//
//   - repoMeta: response for /repos/owner/repo
//   - files:    response for /repos/owner/repo/contents/
//   - branches: response for /repos/owner/repo/branches
//   - workflows: response for /repos/owner/repo/contents/.github/workflows
func ghMockServer(t *testing.T,
	repoMeta interface{},
	files, branches, workflows []map[string]interface{},
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case strings.HasSuffix(path, "/contributors"):
			json.NewEncoder(w).Encode([]interface{}{})
		case strings.HasSuffix(path, "/commits"):
			json.NewEncoder(w).Encode([]interface{}{})
		case strings.Contains(path, "/contents/.github/workflows"):
			if workflows != nil {
				json.NewEncoder(w).Encode(workflows)
			} else {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
			}
		case strings.Contains(path, "/contents/config"):
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
		case strings.Contains(path, "/contents/deploy"):
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
		case strings.Contains(path, "/contents/scripts"):
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
		case strings.Contains(path, "/contents/docker"):
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
		case strings.Contains(path, "/contents/.github"):
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
		case strings.Contains(path, "/contents"):
			if files != nil {
				json.NewEncoder(w).Encode(files)
			} else {
				json.NewEncoder(w).Encode([]interface{}{})
			}
		case strings.HasSuffix(path, "/branches"):
			if branches != nil {
				json.NewEncoder(w).Encode(branches)
			} else {
				json.NewEncoder(w).Encode([]interface{}{})
			}
		default:
			// Repo meta
			if repoMeta != nil {
				json.NewEncoder(w).Encode(repoMeta)
			} else {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
			}
		}
	}))
}
