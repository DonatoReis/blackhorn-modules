package githistory_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/githistory"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Transport that redirects all GitHub API calls to test server ─────────────

type ghTransport struct{ baseURL string }

func (t *ghTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL := t.baseURL + req.URL.Path
	if req.URL.RawQuery != "" {
		newURL += "?" + req.URL.RawQuery
	}
	req2, _ := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
	for k, vs := range req.Header {
		for _, v := range vs {
			req2.Header.Add(k, v)
		}
	}
	return http.DefaultTransport.RoundTrip(req2)
}

func newModule(t *testing.T, srv *httptest.Server) *githistory.Module {
	t.Helper()
	return githistory.NewWithClient(&http.Client{Transport: &ghTransport{baseURL: srv.URL}})
}

func findByType(findings []module.Finding, typ string) []module.Finding {
	var out []module.Finding
	for _, f := range findings {
		if f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

// ─── Fixtures ─────────────────────────────────────────────────────────────────

var repoJSON = map[string]any{
	"default_branch": "main",
	"private":        false,
	"name":           "testrepo",
	"full_name":      "testuser/testrepo",
}

var commitsJSON = []map[string]any{
	{
		"sha":      "abc123def456",
		"html_url": "https://github.com/testuser/testrepo/commit/abc123",
		"commit": map[string]any{
			"message": "remove accidentally committed API key",
			"author": map[string]any{
				"name":  "Dev",
				"email": "dev@example.com",
				"date":  "2024-01-15T10:00:00Z",
			},
		},
	},
	{
		"sha":      "def789abc012",
		"html_url": "https://github.com/testuser/testrepo/commit/def789",
		"commit": map[string]any{
			"message": "feat: add new feature",
			"author": map[string]any{
				"name":  "Dev",
				"email": "dev@example.com",
				"date":  "2024-01-16T10:00:00Z",
			},
		},
	},
}

var treeJSON = map[string]any{
	"truncated": false,
	"tree": []map[string]any{
		{"path": "src/main.go", "type": "blob", "sha": "aaa"},
		{"path": ".env.production", "type": "blob", "sha": "bbb"},
		{"path": "config/credentials.json", "type": "blob", "sha": "ccc"},
		{"path": "README.md", "type": "blob", "sha": "ddd"},
	},
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if githistory.New().Name() != "githistory" {
		t.Error("expected name 'githistory'")
	}
}

func TestEmptyTargetReturnsError(t *testing.T) {
	m := githistory.New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Error("expected error for empty target")
	}
}

func TestInvalidRepoFormat(t *testing.T) {
	m := githistory.New()
	_, err := m.Run(context.Background(), module.Input{Target: "notarepo"})
	if err == nil {
		t.Error("expected error for invalid repo format")
	}
}

// TestRepoNotFound: 404 → githistory_repo_not_found.
func TestRepoNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "testuser/testrepoxyz",
		Options: map[string]string{"github_token": "testtoken"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := findByType(findings, "githistory_repo_not_found")
	if len(found) == 0 {
		t.Error("expected githistory_repo_not_found finding")
	}
}

// TestPrivateRepoRequiresToken: 401 → githistory_token_required.
func TestPrivateRepoRequiresToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, err := m.Run(context.Background(), module.Input{Target: "testuser/privaterepo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := findByType(findings, "githistory_token_required")
	if len(found) == 0 {
		t.Error("expected githistory_token_required finding")
	}
}

// TestSuspiciousCommitDetected: commit with "remove accidentally committed API key".
func TestSuspiciousCommitDetected(t *testing.T) {
	repoBytes, _ := json.Marshal(repoJSON)
	commitsBytes, _ := json.Marshal(commitsJSON)
	treeBytes, _ := json.Marshal(map[string]any{"truncated": false, "tree": []any{}})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/commits"):
			w.WriteHeader(200)
			w.Write(commitsBytes)
		case strings.Contains(r.URL.Path, "/git/trees/"):
			w.WriteHeader(200)
			w.Write(treeBytes)
		default:
			w.WriteHeader(200)
			w.Write(repoBytes)
		}
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "testuser/testrepo",
		Options: map[string]string{"github_token": "tok"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := findByType(findings, "githistory_suspicious_commit")
	if len(found) == 0 {
		t.Error("expected githistory_suspicious_commit finding")
	}
	if found[0].Severity != module.SeverityHigh {
		t.Errorf("expected High severity for suspicious commit, got %v", found[0].Severity)
	}
}

// TestSensitiveFilesDetected: tree contains .env.production + credentials.json.
func TestSensitiveFilesDetected(t *testing.T) {
	repoBytes, _ := json.Marshal(repoJSON)
	commitsBytes, _ := json.Marshal([]any{})
	treeBytes, _ := json.Marshal(treeJSON)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/commits"):
			w.WriteHeader(200)
			w.Write(commitsBytes)
		case strings.Contains(r.URL.Path, "/git/trees/"):
			w.WriteHeader(200)
			w.Write(treeBytes)
		default:
			w.WriteHeader(200)
			w.Write(repoBytes)
		}
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "testuser/testrepo",
		Options: map[string]string{"github_token": "tok"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sensitive := findByType(findings, "githistory_sensitive_file")
	if len(sensitive) < 2 {
		t.Errorf("expected at least 2 sensitive file findings (.env + credentials.json), got %d", len(sensitive))
	}
	for _, f := range sensitive {
		if f.Severity != module.SeverityHigh {
			t.Errorf("sensitive file should be High, got %v for %s", f.Severity, f.Extra["path"])
		}
	}
}

// TestSecretAlertsDetected: GitHub secret scanning alerts → githistory_secret_alert.
func TestSecretAlertsDetected(t *testing.T) {
	repoBytes, _ := json.Marshal(repoJSON)
	alertsJSON := []map[string]any{
		{
			"number":      1,
			"state":       "open",
			"secret_type": "github_personal_access_token",
			"secret":      "ghp_***",
			"html_url":    "https://github.com/testuser/testrepo/security/secret-scanning/1",
		},
	}
	alertsBytes, _ := json.Marshal(alertsJSON)
	emptyBytes, _ := json.Marshal([]any{})
	treeBytes, _ := json.Marshal(map[string]any{"truncated": false, "tree": []any{}})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/secret-scanning/alerts"):
			w.WriteHeader(200)
			w.Write(alertsBytes)
		case strings.HasSuffix(r.URL.Path, "/commits"):
			w.WriteHeader(200)
			w.Write(emptyBytes)
		case strings.Contains(r.URL.Path, "/git/trees/"):
			w.WriteHeader(200)
			w.Write(treeBytes)
		default:
			w.WriteHeader(200)
			w.Write(repoBytes)
		}
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target: "testuser/testrepo",
		Options: map[string]string{
			"github_token": "tok",
			"check_alerts": "true",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	alerts := findByType(findings, "githistory_secret_alert")
	if len(alerts) == 0 {
		t.Error("expected githistory_secret_alert finding")
	}
	if alerts[0].Severity != module.SeverityCritical {
		t.Errorf("secret alert should be Critical, got %v", alerts[0].Severity)
	}
}

// TestTruncatedTreeWarning: tree truncated=true → githistory_tree_truncated.
func TestTruncatedTreeWarning(t *testing.T) {
	repoBytes, _ := json.Marshal(repoJSON)
	treeBytes, _ := json.Marshal(map[string]any{"truncated": true, "tree": []any{}})
	emptyBytes, _ := json.Marshal([]any{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/git/trees/") {
			w.WriteHeader(200)
			w.Write(treeBytes)
		} else if strings.HasSuffix(r.URL.Path, "/commits") {
			w.WriteHeader(200)
			w.Write(emptyBytes)
		} else {
			w.WriteHeader(200)
			w.Write(repoBytes)
		}
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testuser/testrepo",
		Options: map[string]string{"github_token": "tok"},
	})
	found := findByType(findings, "githistory_tree_truncated")
	if len(found) == 0 {
		t.Error("expected githistory_tree_truncated warning")
	}
}

// TestParseRepoURL: various repo URL formats.
func TestParseRepoURL(t *testing.T) {
	repoBytes, _ := json.Marshal(repoJSON)
	treeBytes, _ := json.Marshal(map[string]any{"truncated": false, "tree": []any{}})
	emptyBytes, _ := json.Marshal([]any{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/git/trees/") {
			w.WriteHeader(200)
			w.Write(treeBytes)
		} else if strings.HasSuffix(r.URL.Path, "/commits") {
			w.WriteHeader(200)
			w.Write(emptyBytes)
		} else {
			w.WriteHeader(200)
			w.Write(repoBytes)
		}
	}))
	defer srv.Close()

	targets := []string{
		"https://github.com/testuser/testrepo",
		"https://github.com/testuser/testrepo.git",
		"github.com/testuser/testrepo",
		"testuser/testrepo",
	}
	for _, target := range targets {
		m := newModule(t, srv)
		_, err := m.Run(context.Background(), module.Input{
			Target:  target,
			Options: map[string]string{"github_token": "tok"},
		})
		if err != nil {
			t.Errorf("Run(%q): unexpected error: %v", target, err)
		}
	}
}

// TestConfidencePresent: all findings must have confidence.
func TestConfidencePresent(t *testing.T) {
	repoBytes, _ := json.Marshal(repoJSON)
	commitsBytes, _ := json.Marshal(commitsJSON)
	treeBytes, _ := json.Marshal(treeJSON)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/commits") {
			w.WriteHeader(200)
			w.Write(commitsBytes)
		} else if strings.Contains(r.URL.Path, "/git/trees/") {
			w.WriteHeader(200)
			w.Write(treeBytes)
		} else {
			w.WriteHeader(200)
			w.Write(repoBytes)
		}
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testuser/testrepo",
		Options: map[string]string{"github_token": "tok"},
	})
	for _, f := range findings {
		if f.Extra == nil || f.Extra["confidence"] == "" {
			t.Errorf("finding %q missing confidence", f.Type)
		}
	}
}

// TestContextCancellation: cancelled context must not panic.
func TestContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := newModule(t, srv)
	_, _ = m.Run(ctx, module.Input{
		Target:  "testuser/testrepo",
		Options: map[string]string{"github_token": "tok"},
	})
}
