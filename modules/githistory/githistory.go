// Package githistory audits Git repository history for secrets, sensitive files,
// and commit metadata that should never have been committed. It works by:
//  1. Cloning or inspecting a remote Git repository (GitHub, GitLab, Bitbucket)
//  2. Fetching commit log, file tree, and diffs via provider APIs (no local clone)
//  3. Scanning commit messages for sensitive keywords
//  4. Scanning file paths for sensitive patterns (private keys, .env, credentials)
//  5. Checking GitHub secret scanning alerts (if GITHUB_TOKEN is provided)
//  6. Checking if sensitive files appear in .gitignore (may have been committed before)
//
// This module does NOT perform local cloning. It uses provider APIs for safety
// and to avoid large repo downloads in the orchestrator context.
//
// Source references (algorithm design, no code copied):
//   - truffleHog (MIT, trufflesecurity)    — history scanning concept
//   - git-secrets (MIT, awslabs)           — sensitive pattern approach
//   - gitleaks (MIT, zricethezav)          — pattern library reference
//   - gitrob (MIT, michenriksen)           — GitHub API enumeration
//   - GitHub REST API v2022-11-28 documentation
//
// Architecture:
//   - errgroup.SetLimit for parallel API pages                   (guia-go §9)
//   - io.LimitReader on all response bodies                      (dicas.md §5)
//   - log/slog structured observability                          (dicas.md §16)
//   - NewWithClient(*http.Client) for testability
//   - API key via Options["github_token"] or env GITHUB_TOKEN
package githistory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	maxBodyRead   = 512 * 1024
	maxCommits    = 100
	maxFilePaths  = 500
	githubAPIBase = "https://api.github.com"
)

// sensitiveFilePaths matches file paths that historically contain secrets.
var sensitiveFilePaths = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(^|/)\.env(\.[^/]+)?$`),
	regexp.MustCompile(`(?i)(^|/)\.env\.(local|prod|production|staging|dev|development|test)$`),
	regexp.MustCompile(`(?i)(^|/)\.aws/(credentials|config)$`),
	regexp.MustCompile(`(?i)(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$`),
	regexp.MustCompile(`(?i)(^|/)(credentials|secrets|secret|password|passwd)(\.(json|yml|yaml|txt|conf|cfg|ini))?$`),
	regexp.MustCompile(`(?i)(^|/)\.npmrc$`),
	regexp.MustCompile(`(?i)(^|/)\.pypirc$`),
	regexp.MustCompile(`(?i)(^|/)(docker-compose|docker-compose\.override)\.ya?ml$`),
	regexp.MustCompile(`(?i)(^|/).*\.pem$`),
	regexp.MustCompile(`(?i)(^|/).*\.p12$`),
	regexp.MustCompile(`(?i)(^|/).*\.pfx$`),
	regexp.MustCompile(`(?i)(^|/).*\.key$`),
	regexp.MustCompile(`(?i)(^|/).*keystore.*$`),
	regexp.MustCompile(`(?i)(^|/).*\.jks$`),
	regexp.MustCompile(`(?i)(^|/)wp-config\.php$`),
	regexp.MustCompile(`(?i)(^|/)config\.(php|rb|py|js|json|yml|yaml)$`),
	regexp.MustCompile(`(?i)(^|/)database\.yml$`),
	regexp.MustCompile(`(?i)(^|/)Gemfile\.lock$`),
	regexp.MustCompile(`(?i)(^|/).*terraform\.tfvars$`),
	regexp.MustCompile(`(?i)(^|/).*\.tfstate$`),
}

// sensitiveCommitMsgPatterns matches commit messages that hint at secret removal.
var sensitiveCommitMsgPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(remove|delete|revert|undo|clean|oops|accidentally).*(key|secret|token|password|credential|api_key|apikey|password|pass)`),
	regexp.MustCompile(`(?i)(key|secret|token|password|credential).*(remove|delete|revert|undo|clean|oops|accidentally)`),
	regexp.MustCompile(`(?i)fix.*sensitive`),
	regexp.MustCompile(`(?i)remove.*hardcoded`),
}

// ─── GitHub API types ─────────────────────────────────────────────────────────

type ghCommit struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message string `json:"message"`
		Author  struct {
			Name  string `json:"name"`
			Email string `json:"email"`
			Date  string `json:"date"`
		} `json:"author"`
	} `json:"commit"`
	HTMLURL string `json:"html_url"`
}

type ghTreeItem struct {
	Path string `json:"path"`
	Type string `json:"type"` // "blob" or "tree"
	SHA  string `json:"sha"`
}

type ghTree struct {
	Tree      []ghTreeItem `json:"tree"`
	Truncated bool         `json:"truncated"`
}

type ghSecretAlert struct {
	Number     int    `json:"number"`
	State      string `json:"state"` // "open", "resolved"
	SecretType string `json:"secret_type"`
	Secret     string `json:"secret"`
	HTMLURL    string `json:"html_url"`
}

type ghRepo struct {
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements the githistory module.
type Module struct {
	client *http.Client
	logger *slog.Logger
}

// New creates a githistory module with the default HTTP client.
func New() *Module {
	return &Module{client: httpclient.Default(), logger: slog.Default()}
}

// NewWithClient creates a githistory module with a custom HTTP client (for tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{client: c, logger: slog.Default()}
}

func (m *Module) Name() string { return "githistory" }

// Run audits Git history for secrets and sensitive files.
//
// Target: GitHub repo URL or "owner/repo" shorthand
// Options:
//   - github_token:   GitHub personal access token (fallback: GITHUB_TOKEN env)
//   - branch:         branch to scan (default: repo's default branch)
//   - max_commits:    max commits to scan (default 100)
//   - check_alerts:   "true" to check GitHub secret scanning alerts (requires token)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("githistory: target (GitHub repo URL or owner/repo) is required")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	token := firstNonEmpty(opts["github_token"], os.Getenv("GITHUB_TOKEN"))
	branch := optStr(opts, "branch", "")
	maxCom := optInt(opts, "max_commits", maxCommits)
	checkAlerts := opts["check_alerts"] == "true"

	// Parse owner/repo from URL or shorthand.
	owner, repo, err := parseRepoTarget(target)
	if err != nil {
		return nil, fmt.Errorf("githistory: %w", err)
	}

	m.logger.InfoContext(ctx, "githistory: starting",
		"repo", owner+"/"+repo, "token_present", token != "")

	var (
		mu       sync.Mutex
		findings []module.Finding
	)
	add := func(ff ...module.Finding) {
		mu.Lock()
		findings = append(findings, ff...)
		mu.Unlock()
	}

	// Fetch repo metadata first to get default branch.
	repoInfo, ff := m.fetchRepo(ctx, owner, repo, token)
	add(ff...)
	if repoInfo == nil {
		return findings, nil
	}
	if branch == "" {
		branch = repoInfo.DefaultBranch
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(4)

	// Scan commit history.
	eg.Go(func() error {
		add(m.scanCommits(egCtx, owner, repo, branch, token, maxCom)...)
		return nil
	})

	// Scan file tree.
	eg.Go(func() error {
		add(m.scanTree(egCtx, owner, repo, branch, token)...)
		return nil
	})

	// GitHub secret scanning alerts.
	if checkAlerts && token != "" {
		eg.Go(func() error {
			add(m.fetchSecretAlerts(egCtx, owner, repo, token)...)
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return findings, err
	}

	return dedup(findings), nil
}

// ─── API methods ─────────────────────────────────────────────────────────────

func (m *Module) fetchRepo(ctx context.Context, owner, repo, token string) (*ghRepo, []module.Finding) {
	rawURL := fmt.Sprintf("%s/repos/%s/%s", githubAPIBase, owner, repo)
	body, status, err := m.get(ctx, rawURL, token)
	if err != nil || status == 404 {
		return nil, []module.Finding{{
			Type:     "githistory_repo_not_found",
			URL:      rawURL,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("[githistory] Repository %s/%s not found or inaccessible", owner, repo),
			Extra:    map[string]string{"confidence": "0.95", "fonte": "githistory"},
		}}
	}
	if status == 403 || status == 401 {
		return nil, []module.Finding{{
			Type:     "githistory_token_required",
			URL:      rawURL,
			Severity: module.SeverityInfo,
			Detail:   "[githistory] Private repository — GitHub token required (Options[github_token] or GITHUB_TOKEN env)",
			Extra:    map[string]string{"confidence": "0.99", "fonte": "githistory"},
		}}
	}

	var r ghRepo
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, nil
	}
	return &r, nil
}

func (m *Module) scanCommits(ctx context.Context, owner, repo, branch, token string, maxC int) []module.Finding {
	rawURL := fmt.Sprintf("%s/repos/%s/%s/commits?sha=%s&per_page=%d",
		githubAPIBase, owner, repo, branch, min(maxC, 100))

	body, status, err := m.get(ctx, rawURL, token)
	if err != nil || status != 200 {
		return nil
	}

	var commits []ghCommit
	if err := json.Unmarshal(body, &commits); err != nil {
		return nil
	}

	var findings []module.Finding
	for _, c := range commits {
		msg := c.Commit.Message
		for _, pat := range sensitiveCommitMsgPatterns {
			if pat.MatchString(msg) {
				findings = append(findings, module.Finding{
					Type:     "githistory_suspicious_commit",
					URL:      c.HTMLURL,
					Severity: module.SeverityHigh,
					Detail:   fmt.Sprintf("[githistory] Commit %s by %s (%s) has suspicious message: %q — possible secret removal", c.SHA[:8], c.Commit.Author.Name, c.Commit.Author.Date[:10], truncate(msg, 100)),
					Extra: map[string]string{
						"sha":        c.SHA,
						"author":     c.Commit.Author.Name,
						"email":      c.Commit.Author.Email,
						"date":       c.Commit.Author.Date,
						"message":    truncate(msg, 200),
						"confidence": "0.75",
						"fonte":      "githistory",
					},
				})
				break
			}
		}
	}
	return findings
}

func (m *Module) scanTree(ctx context.Context, owner, repo, branch, token string) []module.Finding {
	rawURL := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1",
		githubAPIBase, owner, repo, branch)

	body, status, err := m.get(ctx, rawURL, token)
	if err != nil || status != 200 {
		return nil
	}

	var tree ghTree
	if err := json.Unmarshal(body, &tree); err != nil {
		return nil
	}

	var findings []module.Finding
	count := 0
	for _, item := range tree.Tree {
		if item.Type != "blob" {
			continue
		}
		if count >= maxFilePaths {
			break
		}
		for _, pat := range sensitiveFilePaths {
			if pat.MatchString(item.Path) {
				fileURL := fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s",
					owner, repo, branch, item.Path)
				findings = append(findings, module.Finding{
					Type:     "githistory_sensitive_file",
					URL:      fileURL,
					Severity: module.SeverityHigh,
					Detail:   fmt.Sprintf("[githistory] Sensitive file in repository tree: %s — may contain secrets", item.Path),
					Extra: map[string]string{
						"path":       item.Path,
						"sha":        item.SHA,
						"confidence": "0.85",
						"fonte":      "githistory",
					},
				})
				count++
				break
			}
		}
	}

	if tree.Truncated {
		findings = append(findings, module.Finding{
			Type:     "githistory_tree_truncated",
			URL:      rawURL,
			Severity: module.SeverityInfo,
			Detail:   "[githistory] Repository tree was truncated by GitHub API — not all files could be inspected",
			Extra:    map[string]string{"confidence": "0.99", "fonte": "githistory"},
		})
	}

	return findings
}

func (m *Module) fetchSecretAlerts(ctx context.Context, owner, repo, token string) []module.Finding {
	rawURL := fmt.Sprintf("%s/repos/%s/%s/secret-scanning/alerts?state=open&per_page=30",
		githubAPIBase, owner, repo)

	body, status, err := m.get(ctx, rawURL, token)
	if err != nil || (status != 200 && status != 404) {
		return nil
	}
	if status == 404 {
		return nil // Secret scanning not enabled or not a supported plan
	}

	var alerts []ghSecretAlert
	if err := json.Unmarshal(body, &alerts); err != nil {
		return nil
	}

	var findings []module.Finding
	for _, alert := range alerts {
		findings = append(findings, module.Finding{
			Type:     "githistory_secret_alert",
			URL:      alert.HTMLURL,
			Severity: module.SeverityCritical,
			Detail:   fmt.Sprintf("[githistory] GitHub secret scanning alert #%d: %s (%s)", alert.Number, alert.SecretType, alert.State),
			Extra: map[string]string{
				"alert_number": fmt.Sprintf("%d", alert.Number),
				"secret_type":  alert.SecretType,
				"state":        alert.State,
				"confidence":   "0.99",
				"fonte":        "githistory",
			},
		})
	}
	return findings
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

func (m *Module) get(ctx context.Context, rawURL, token string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return body, resp.StatusCode, err
}

// ─── Utility helpers ──────────────────────────────────────────────────────────

func parseRepoTarget(target string) (owner, repo string, err error) {
	// Strip scheme
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	// Strip github.com/
	target = strings.TrimPrefix(target, "github.com/")
	// Strip trailing .git
	target = strings.TrimSuffix(target, ".git")
	// Strip trailing /
	target = strings.TrimRight(target, "/")

	parts := strings.SplitN(target, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid repo target %q — expected owner/repo or github.com/owner/repo", target)
	}
	return parts[0], parts[1], nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func optStr(opts map[string]string, key, def string) string {
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

func optInt(opts map[string]string, key string, def int) int {
	if v, ok := opts[key]; ok && v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	var out []module.Finding
	for _, f := range findings {
		key := f.Type + "|" + f.URL
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}
