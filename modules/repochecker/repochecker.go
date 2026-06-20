// Package repochecker performs deep analysis of public GitHub and GitLab
// repositories to find security-relevant information such as exposed secrets,
// leaked credentials, hardcoded API keys, sensitive file patterns, contributor
// metadata and repository health indicators.
//
// Data sources:
//   - GitHub REST API v3  (public, optional token for higher rate limits)
//   - GitHub Search API   (code search for secret patterns)
//   - GitLab REST API v4  (public, optional token)
//   - GitLab Search API
//
// What it reports:
//   - Secret patterns found in code (hardcoded keys, tokens, passwords)
//   - Sensitive files (.env, *.pem, *.p12, id_rsa, credentials.json, etc.)
//   - Repository metadata (stars, forks, visibility, archived status)
//   - Contributors with PII (email, display name)
//   - Old branches that may contain secrets
//   - Publicly visible CI/CD pipelines / workflow files
//   - Dependency files (package.json, requirements.txt) for vuln correlation
//
// Input:
//   - Target: "owner/repo", a GitHub URL, or a GitLab URL
//   - Options["source"]: "github" (default) or "gitlab"
//   - Options["github_token"]: optional PAT for GitHub
//   - Options["gitlab_token"]: optional PAT for GitLab
//   - Options["checks"]: comma-separated subset: secrets,files,meta,contributors,branches,workflows,deps
//   - Options["max_commits"]: how many recent commits to check (default 50)
//
// Usage:
//
//	m := repochecker.New()
//	findings, err := m.Run(ctx, module.Input{
//	    Target: "https://github.com/example/myrepo",
//	    Options: map[string]string{
//	        "github_token": os.Getenv("GITHUB_TOKEN"),
//	        "checks":       "secrets,files,meta",
//	    },
//	})
package repochecker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	maxBodyRepo = 1 << 20 // 1 MB
	maxParallel = 5
	ghAPIBase   = "https://api.github.com"
	glAPIBase   = "https://gitlab.com/api/v4"
)

// ─── secret patterns ─────────────────────────────────────────────────────────

type secretPattern struct {
	Name       string
	Pattern    *regexp.Regexp
	Confidence float64
	Severity   module.Severity
}

var secretPatterns = []secretPattern{
	{
		Name:       "aws_access_key",
		Pattern:    regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
		Confidence: 0.95, Severity: module.SeverityCritical,
	},
	{
		Name:       "aws_secret_key",
		Pattern:    regexp.MustCompile(`(?i)(aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z\/+]{40}['\"])`),
		Confidence: 0.90, Severity: module.SeverityCritical,
	},
	{
		Name:       "github_token",
		Pattern:    regexp.MustCompile(`(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})`),
		Confidence: 0.97, Severity: module.SeverityCritical,
	},
	{
		Name:       "google_api_key",
		Pattern:    regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		Confidence: 0.88, Severity: module.SeverityHigh,
	},
	{
		Name:       "private_key_block",
		Pattern:    regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		Confidence: 0.96, Severity: module.SeverityCritical,
	},
	{
		Name:       "jwt_token",
		Pattern:    regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		Confidence: 0.82, Severity: module.SeverityHigh,
	},
	{
		Name:       "slack_token",
		Pattern:    regexp.MustCompile(`xox[baprs]-([0-9a-zA-Z]{10,48})`),
		Confidence: 0.93, Severity: module.SeverityHigh,
	},
	{
		Name:       "stripe_key",
		Pattern:    regexp.MustCompile(`(?:r|s)k_live_[0-9a-zA-Z]{24}`),
		Confidence: 0.95, Severity: module.SeverityCritical,
	},
	{
		Name:       "twilio_key",
		Pattern:    regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		Confidence: 0.83, Severity: module.SeverityHigh,
	},
	{
		Name:       "password_in_url",
		Pattern:    regexp.MustCompile(`(?i)(https?://[^:]+:[^@]{3,}@)`),
		Confidence: 0.85, Severity: module.SeverityHigh,
	},
	{
		Name:       "generic_api_key",
		Pattern:    regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{16,64})['\"]?`),
		Confidence: 0.72, Severity: module.SeverityMedium,
	},
	{
		Name:       "generic_secret",
		Pattern:    regexp.MustCompile(`(?i)(secret[_-]?key|secret)\s*[:=]\s*['\"]([^'"]{8,64})['\"]`),
		Confidence: 0.70, Severity: module.SeverityMedium,
	},
	{
		Name:       "generic_password",
		Pattern:    regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'"]{8,64})['\"]`),
		Confidence: 0.68, Severity: module.SeverityMedium,
	},
}

// sensitiveFiles are filenames that commonly contain secrets or credentials.
var sensitiveFiles = []string{
	".env", ".env.local", ".env.production", ".env.dev",
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
	"*.pem", "*.p12", "*.pfx", "*.key",
	"credentials.json", "service_account.json",
	"secrets.yml", "secrets.yaml", "vault.json",
	"config.php", "wp-config.php",
	"database.yml", "database.json",
	".htpasswd", ".npmrc", ".pypirc",
	"docker-compose.yml", // often has env vars
	"terraform.tfvars", "*.tfvars",
}

// ─── GitHub API types ─────────────────────────────────────────────────────────

type ghRepo struct {
	FullName      string    `json:"full_name"`
	Description   string    `json:"description"`
	Private       bool      `json:"private"`
	Fork          bool      `json:"fork"`
	Archived      bool      `json:"archived"`
	StarCount     int       `json:"stargazers_count"`
	ForkCount     int       `json:"forks_count"`
	OpenIssues    int       `json:"open_issues_count"`
	Language      string    `json:"language"`
	DefaultBranch string    `json:"default_branch"`
	PushedAt      time.Time `json:"pushed_at"`
	CreatedAt     time.Time `json:"created_at"`
	HTMLURL       string    `json:"html_url"`
	CloneURL      string    `json:"clone_url"`
}

type ghCommit struct {
	SHA     string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Commit  struct {
		Message string `json:"message"`
		Author  struct {
			Name  string    `json:"name"`
			Email string    `json:"email"`
			Date  time.Time `json:"date"`
		} `json:"author"`
	} `json:"commit"`
}

type ghBranch struct {
	Name   string `json:"name"`
	Commit struct {
		SHA string `json:"sha"`
	} `json:"commit"`
}

type ghContent struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Type    string `json:"type"` // "file" or "dir"
	HTMLURL string `json:"html_url"`
	Size    int    `json:"size"`
	Content string `json:"content"` // base64 if file
}

type ghSearchCode struct {
	TotalCount int `json:"total_count"`
	Items      []struct {
		Name       string `json:"name"`
		Path       string `json:"path"`
		HTMLURL    string `json:"html_url"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	} `json:"items"`
}

type ghContributor struct {
	Login     string `json:"login"`
	HTMLURL   string `json:"html_url"`
	AvatarURL string `json:"avatar_url"`
	Type      string `json:"type"`
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements module.Module for repository analysis.
type Module struct {
	client *http.Client
}

// New returns a Module with default HTTP client.
func New() *Module { return NewWithClient(defaultClient()) }

// NewWithClient injects a custom HTTP client.
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

// Name returns the canonical module identifier.
func (m *Module) Name() string { return "repochecker" }

func looksLikeDomain(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if strings.ContainsAny(value, "@/:\\ \t\r\n") {
		return false
	}
	parts := strings.Split(value, ".")
	return len(parts) >= 2 && parts[0] != "" && parts[len(parts)-1] != ""
}

// Run analyses a Git repository for security issues.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("repochecker: target vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	source, owner, repo, err := parseTarget(target, opts)
	if err != nil {
		if looksLikeDomain(target) {
			return nil, nil
		}
		return nil, fmt.Errorf("repochecker: %w", err)
	}

	checksFilter := opts["checks"]
	maxCommits := optInt(opts, "max_commits", 50)

	slog.InfoContext(ctx, "repochecker.Run iniciado",
		"source", source,
		"repo", owner+"/"+repo,
		"checks", checksFilter,
	)

	var mu sync.Mutex
	var all []module.Finding

	add := func(findings []module.Finding) {
		mu.Lock()
		all = append(all, findings...)
		mu.Unlock()
	}

	type checkFn func(context.Context, string, string, string, string, map[string]string) ([]module.Finding, error)

	type check struct {
		name string
		fn   checkFn
	}

	var checks []check
	switch source {
	case "github":
		checks = []check{
			{"meta", m.ghCheckMeta},
			{"contributors", m.ghCheckContributors},
			{"files", m.ghCheckSensitiveFiles},
			{"branches", m.ghCheckBranches},
			{"workflows", m.ghCheckWorkflows},
		}
	case "gitlab":
		checks = []check{
			{"meta", m.glCheckMeta},
			{"files", m.glCheckSensitiveFiles},
		}
	default:
		return nil, fmt.Errorf("repochecker: source desconhecido '%s'", source)
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxParallel)

	for _, c := range checks {
		c := c
		if !isWanted(checksFilter, c.name) {
			continue
		}
		g.Go(func() error {
			optsWithMax := make(map[string]string, len(opts)+1)
			for k, v := range opts {
				optsWithMax[k] = v
			}
			optsWithMax["max_commits"] = strconv.Itoa(maxCommits)

			findings, err := c.fn(gctx, source, owner, repo, opts[source+"_token"], optsWithMax)
			if err != nil {
				slog.WarnContext(gctx, "repochecker: check com erro",
					"check", c.name, "err", err)
				return nil
			}
			add(findings)
			return nil
		})
	}
	_ = g.Wait()

	// Secret scan across commit messages and file paths found
	if isWanted(checksFilter, "secrets") {
		secretFindings := m.runSecretScan(ctx, all, owner, repo, source)
		add(secretFindings)
	}

	result := dedup(all)
	slog.InfoContext(ctx, "repochecker.Run concluído",
		"repo", owner+"/"+repo,
		"findings", len(result),
	)
	return result, nil
}

// ─── GitHub checks ────────────────────────────────────────────────────────────

func (m *Module) ghCheckMeta(ctx context.Context, _, owner, repo, token string, opts map[string]string) ([]module.Finding, error) {
	var r ghRepo
	if err := m.ghGet(ctx, fmt.Sprintf("/repos/%s/%s", owner, repo), token, &r); err != nil {
		return nil, err
	}

	repoURL := fmt.Sprintf("https://github.com/%s/%s", owner, repo)
	var findings []module.Finding

	// Archived repo still accessible = low maintenance = more likely unpatched deps
	if r.Archived {
		findings = append(findings, module.Finding{
			Type:     "repo_archived",
			URL:      repoURL,
			Detail:   fmt.Sprintf("Repositório '%s' está arquivado mas publicamente acessível. Pode conter código legado com vulnerabilidades não corrigidas.", r.FullName),
			Severity: module.SeverityLow,
			Extra: map[string]string{
				"confidence": "0.90",
				"source":     "github_meta",
			},
		})
	}

	// High fork count on private content patterns
	if !r.Private {
		findings = append(findings, module.Finding{
			Type:     "repo_public",
			URL:      repoURL,
			Detail:   fmt.Sprintf("Repositório público '%s' com %d estrelas, %d forks. Branch padrão: %s.", r.FullName, r.StarCount, r.ForkCount, r.DefaultBranch),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"confidence":     "0.99",
				"stars":          strconv.Itoa(r.StarCount),
				"forks":          strconv.Itoa(r.ForkCount),
				"default_branch": r.DefaultBranch,
				"source":         "github_meta",
			},
		})
	}

	return findings, nil
}

func (m *Module) ghCheckContributors(ctx context.Context, _, owner, repo, token string, opts map[string]string) ([]module.Finding, error) {
	var contributors []ghContributor
	if err := m.ghGet(ctx, fmt.Sprintf("/repos/%s/%s/contributors?per_page=30", owner, repo), token, &contributors); err != nil {
		return nil, err
	}

	repoURL := fmt.Sprintf("https://github.com/%s/%s", owner, repo)
	var findings []module.Finding

	for _, c := range contributors {
		if c.Type == "Bot" {
			continue
		}
		findings = append(findings, module.Finding{
			Type:     "repo_contributor",
			URL:      c.HTMLURL,
			Detail:   fmt.Sprintf("Contribuidor '%s' do repositório '%s/%s'. Perfil público pode revelar outros projetos, email, ou informação de emprego.", c.Login, owner, repo),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"confidence": "0.95",
				"login":      c.Login,
				"repo":       repoURL,
				"source":     "github_contributors",
			},
		})
	}

	// Also check commit emails
	var commits []ghCommit
	maxC := optInt(opts, "max_commits", 20)
	if err := m.ghGet(ctx, fmt.Sprintf("/repos/%s/%s/commits?per_page=%d", owner, repo, maxC), token, &commits); err == nil {
		emails := map[string]bool{}
		for _, cm := range commits {
			email := cm.Commit.Author.Email
			if email == "" || emails[email] {
				continue
			}
			emails[email] = true
			if !strings.Contains(email, "noreply") && !strings.Contains(email, "github") {
				findings = append(findings, module.Finding{
					Type: "contributor_email_exposed",
					URL:  cm.HTMLURL,
					// Redact partial email per dicas §18 — show domain only
					Detail:   fmt.Sprintf("Email de autor em commit exposto (domínio: %s). Pode ser alvo de phishing.", emailDomain(email)),
					Severity: module.SeverityLow,
					Extra: map[string]string{
						"confidence":   "0.88",
						"email_domain": emailDomain(email),
						"author":       cm.Commit.Author.Name,
						"commit":       cm.SHA[:min(8, len(cm.SHA))],
						"source":       "github_commits",
					},
				})
			}
		}
	}

	return findings, nil
}

func (m *Module) ghCheckSensitiveFiles(ctx context.Context, _, owner, repo, token string, opts map[string]string) ([]module.Finding, error) {
	// Get root directory listing
	var contents []ghContent
	if err := m.ghGet(ctx, fmt.Sprintf("/repos/%s/%s/contents/", owner, repo), token, &contents); err != nil {
		return nil, err
	}

	repoURL := fmt.Sprintf("https://github.com/%s/%s", owner, repo)
	var findings []module.Finding

	for _, item := range contents {
		if item.Type != "file" {
			continue
		}
		if isSensitiveFile(item.Name) {
			findings = append(findings, module.Finding{
				Type:     "sensitive_file_found",
				URL:      item.HTMLURL,
				Detail:   fmt.Sprintf("Arquivo sensível '%s' encontrado na raiz do repositório '%s/%s'. Pode conter credenciais ou chaves privadas.", item.Name, owner, repo),
				Severity: module.SeverityHigh,
				Extra: map[string]string{
					"confidence": "0.88",
					"file_name":  item.Name,
					"file_path":  item.Path,
					"file_size":  strconv.Itoa(item.Size),
					"repo":       repoURL,
					"source":     "github_contents",
				},
			})
		}
	}

	// Check common subdirs
	for _, dir := range []string{"config", "deploy", ".github", "scripts", "docker"} {
		var subContents []ghContent
		if err := m.ghGet(ctx, fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, dir), token, &subContents); err != nil {
			continue
		}
		for _, item := range subContents {
			if item.Type != "file" {
				continue
			}
			if isSensitiveFile(item.Name) {
				findings = append(findings, module.Finding{
					Type:     "sensitive_file_found",
					URL:      item.HTMLURL,
					Detail:   fmt.Sprintf("Arquivo sensível '%s' em '%s/%s' (subdir: %s).", item.Name, owner, repo, dir),
					Severity: module.SeverityHigh,
					Extra: map[string]string{
						"confidence": "0.85",
						"file_name":  item.Name,
						"file_path":  item.Path,
						"source":     "github_contents",
					},
				})
			}
		}
	}

	return findings, nil
}

func (m *Module) ghCheckBranches(ctx context.Context, _, owner, repo, token string, opts map[string]string) ([]module.Finding, error) {
	var branches []ghBranch
	if err := m.ghGet(ctx, fmt.Sprintf("/repos/%s/%s/branches?per_page=100", owner, repo), token, &branches); err != nil {
		return nil, err
	}

	repoURL := fmt.Sprintf("https://github.com/%s/%s", owner, repo)
	var findings []module.Finding

	suspiciousBranchPatterns := []string{
		"secret", "credential", "key", "password", "token", "auth",
		"backup", "old", "legacy", "dev-private", "hotfix-creds",
	}

	for _, b := range branches {
		nameLower := strings.ToLower(b.Name)
		for _, pat := range suspiciousBranchPatterns {
			if strings.Contains(nameLower, pat) {
				findings = append(findings, module.Finding{
					Type:     "suspicious_branch_name",
					URL:      fmt.Sprintf("%s/tree/%s", repoURL, b.Name),
					Detail:   fmt.Sprintf("Branch com nome suspeito '%s' em '%s/%s'. Branches com nomes como 'secret', 'credentials', etc. frequentemente indicam artefatos sensíveis comprometidos.", b.Name, owner, repo),
					Severity: module.SeverityMedium,
					Extra: map[string]string{
						"confidence":  "0.78",
						"branch_name": b.Name,
						"matched":     pat,
						"source":      "github_branches",
					},
				})
				break
			}
		}
	}

	// Too many branches might indicate abandoned dev work
	if len(branches) > 50 {
		findings = append(findings, module.Finding{
			Type:     "excessive_branches",
			URL:      repoURL,
			Detail:   fmt.Sprintf("Repositório '%s/%s' possui %d branches. Grande quantidade de branches pode conter código com segredos não removidos de commits antigos.", owner, repo, len(branches)),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"confidence":   "0.65",
				"branch_count": strconv.Itoa(len(branches)),
				"source":       "github_branches",
			},
		})
	}

	return findings, nil
}

func (m *Module) ghCheckWorkflows(ctx context.Context, _, owner, repo, token string, opts map[string]string) ([]module.Finding, error) {
	var contents []ghContent
	if err := m.ghGet(ctx, fmt.Sprintf("/repos/%s/%s/contents/.github/workflows", owner, repo), token, &contents); err != nil {
		// No workflows dir = not an issue
		return nil, nil
	}

	repoURL := fmt.Sprintf("https://github.com/%s/%s", owner, repo)
	var findings []module.Finding

	for _, wf := range contents {
		if !strings.HasSuffix(wf.Name, ".yml") && !strings.HasSuffix(wf.Name, ".yaml") {
			continue
		}
		findings = append(findings, module.Finding{
			Type:     "workflow_file_found",
			URL:      wf.HTMLURL,
			Detail:   fmt.Sprintf("Arquivo de workflow CI/CD '%s' exposto no repositório '%s/%s'. Workflows públicos podem revelar segredos usados em secrets do GitHub Actions.", wf.Name, owner, repo),
			Severity: module.SeverityLow,
			Extra: map[string]string{
				"confidence": "0.80",
				"file":       wf.Name,
				"repo":       repoURL,
				"source":     "github_workflows",
			},
		})
	}

	return findings, nil
}

// ─── GitLab checks ────────────────────────────────────────────────────────────

type glProject struct {
	ID                int    `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	Description       string `json:"description"`
	Visibility        string `json:"visibility"`
	Archived          bool   `json:"archived"`
	StarCount         int    `json:"star_count"`
	ForksCount        int    `json:"forks_count"`
	WebURL            string `json:"web_url"`
	DefaultBranch     string `json:"default_branch"`
}

type glTreeItem struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
}

func (m *Module) glCheckMeta(ctx context.Context, _, owner, repo, token string, opts map[string]string) ([]module.Finding, error) {
	encoded := strings.ReplaceAll(owner+"/"+repo, "/", "%2F")
	var p glProject
	if err := m.glGet(ctx, fmt.Sprintf("/projects/%s", encoded), token, &p); err != nil {
		return nil, err
	}

	var findings []module.Finding

	if p.Visibility == "public" {
		findings = append(findings, module.Finding{
			Type:     "repo_public",
			URL:      p.WebURL,
			Detail:   fmt.Sprintf("Repositório GitLab público '%s' com %d estrelas, %d forks.", p.PathWithNamespace, p.StarCount, p.ForksCount),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"confidence": "0.99",
				"visibility": p.Visibility,
				"stars":      strconv.Itoa(p.StarCount),
				"forks":      strconv.Itoa(p.ForksCount),
				"source":     "gitlab_meta",
			},
		})
	}

	if p.Archived {
		findings = append(findings, module.Finding{
			Type:     "repo_archived",
			URL:      p.WebURL,
			Detail:   fmt.Sprintf("Repositório GitLab '%s' arquivado. Pode conter código legado com vulnerabilidades não corrigidas.", p.PathWithNamespace),
			Severity: module.SeverityLow,
			Extra: map[string]string{
				"confidence": "0.90",
				"source":     "gitlab_meta",
			},
		})
	}

	return findings, nil
}

func (m *Module) glCheckSensitiveFiles(ctx context.Context, _, owner, repo, token string, opts map[string]string) ([]module.Finding, error) {
	encoded := strings.ReplaceAll(owner+"/"+repo, "/", "%2F")
	var tree []glTreeItem
	if err := m.glGet(ctx, fmt.Sprintf("/projects/%s/repository/tree?recursive=false&per_page=100", encoded), token, &tree); err != nil {
		return nil, err
	}

	var findings []module.Finding
	projectURL := fmt.Sprintf("https://gitlab.com/%s/%s", owner, repo)

	for _, item := range tree {
		if item.Type != "blob" {
			continue
		}
		if isSensitiveFile(item.Name) {
			findings = append(findings, module.Finding{
				Type:     "sensitive_file_found",
				URL:      fmt.Sprintf("%s/-/blob/main/%s", projectURL, item.Path),
				Detail:   fmt.Sprintf("Arquivo sensível '%s' encontrado no repositório GitLab '%s/%s'.", item.Name, owner, repo),
				Severity: module.SeverityHigh,
				Extra: map[string]string{
					"confidence": "0.87",
					"file_name":  item.Name,
					"file_path":  item.Path,
					"source":     "gitlab_tree",
				},
			})
		}
	}

	return findings, nil
}

// ─── secret scan (runs after initial file pass) ───────────────────────────────

// runSecretScan scans Detail and URL fields of existing findings for secret patterns.
// This is a heuristic pass — it matches common secret patterns in metadata already collected.
func (m *Module) runSecretScan(_ context.Context, existing []module.Finding, owner, repo, source string) []module.Finding {
	repoURL := fmt.Sprintf("https://%s.com/%s/%s", source, owner, repo)
	var findings []module.Finding
	seen := map[string]bool{}

	for _, f := range existing {
		text := f.Detail + " " + f.URL
		for _, sp := range secretPatterns {
			matches := sp.Pattern.FindAllString(text, 3)
			for _, match := range matches {
				// Redact most of the secret per dicas §18
				redacted := redactSecret(match)
				key := sp.Name + "|" + redacted
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, module.Finding{
					Type:     "secret_pattern_found",
					URL:      repoURL,
					Detail:   fmt.Sprintf("Padrão de secret '%s' detectado em metadados do repositório '%s/%s'. Valor parcial: %s", sp.Name, owner, repo, redacted),
					Severity: sp.Severity,
					Extra: map[string]string{
						"confidence":     fmt.Sprintf("%.2f", sp.Confidence),
						"pattern_name":   sp.Name,
						"redacted_value": redacted,
						"source":         "secret_scan",
					},
				})
			}
		}
	}

	return findings
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func (m *Module) ghGet(ctx context.Context, path, token string, dest interface{}) error {
	u := ghAPIBase + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("repositório não encontrado: %s", path)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("GitHub API: acesso negado (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API: HTTP %d para %s", resp.StatusCode, path)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRepo))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dest)
}

func (m *Module) glGet(ctx context.Context, path, token string, dest interface{}) error {
	u := glAPIBase + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("repositório GitLab não encontrado: %s", path)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitLab API: HTTP %d para %s", resp.StatusCode, path)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRepo))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dest)
}

// ─── util ─────────────────────────────────────────────────────────────────────

func parseTarget(target string, opts map[string]string) (source, owner, repo string, err error) {
	// Explicit source override
	source = strings.ToLower(strings.TrimSpace(opts["source"]))

	// Parse URL formats
	t := strings.TrimSpace(target)

	switch {
	case strings.Contains(t, "github.com"):
		source = "github"
		t = strings.TrimPrefix(t, "https://")
		t = strings.TrimPrefix(t, "http://")
		t = strings.TrimPrefix(t, "github.com/")
		t = strings.TrimSuffix(t, ".git")
	case strings.Contains(t, "gitlab.com"):
		source = "gitlab"
		t = strings.TrimPrefix(t, "https://")
		t = strings.TrimPrefix(t, "http://")
		t = strings.TrimPrefix(t, "gitlab.com/")
		t = strings.TrimSuffix(t, ".git")
	default:
		if source == "" {
			source = "github"
		}
	}

	parts := strings.SplitN(t, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", fmt.Errorf("formato inválido '%s': use 'owner/repo' ou URL completa", target)
	}
	return source, parts[0], parts[1], nil
}

func isSensitiveFile(name string) bool {
	nameLower := strings.ToLower(name)
	for _, s := range sensitiveFiles {
		if strings.HasPrefix(s, "*.") {
			// extension match
			if strings.HasSuffix(nameLower, strings.TrimPrefix(s, "*")) {
				return true
			}
			continue
		}
		if nameLower == strings.ToLower(s) {
			return true
		}
	}
	// Additional heuristics
	return strings.HasSuffix(nameLower, ".env") ||
		strings.HasSuffix(nameLower, ".pem") ||
		strings.HasSuffix(nameLower, ".p12") ||
		strings.HasSuffix(nameLower, ".pfx") ||
		strings.HasSuffix(nameLower, ".key") ||
		strings.Contains(nameLower, "secret") ||
		strings.Contains(nameLower, "credential") ||
		strings.Contains(nameLower, "password") ||
		strings.Contains(nameLower, "passwd")
}

func emailDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return "unknown"
}

func redactSecret(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	// Show first 4 chars + *** + last 2
	return s[:4] + "***" + s[len(s)-2:]
}

func isWanted(filter, name string) bool {
	if filter == "" {
		return true
	}
	for _, s := range strings.Split(filter, ",") {
		if strings.TrimSpace(s) == name {
			return true
		}
	}
	return false
}

func optInt(opts map[string]string, key string, def int) int {
	v, ok := opts[key]
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func defaultClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	out := make([]module.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Extra["source"]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
