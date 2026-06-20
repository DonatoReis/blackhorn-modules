// Package socialmedia realiza coleta de dados públicos de múltiplas redes sociais.
//
// AVISO: Este módulo acessa apenas dados PÚBLICOS e não requer autenticação
// para as fontes básicas. Algumas fontes premium requerem API keys.
// Uso exclusivo para fins de segurança autorizados e OSINT legítimo.
//
// Fontes suportadas:
//   - twitter_api    : Twitter/X API v2 (requer TWITTER_BEARER_TOKEN)
//   - instagram_api  : Instagram Graph API (requer INSTAGRAM_ACCESS_TOKEN)
//   - linkedin_api   : LinkedIn API (requer LINKEDIN_ACCESS_TOKEN)
//   - github_api     : GitHub API v3 (sem key = 60req/h; com key = 5000req/h)
//   - reddit_api     : Reddit API (pública, sem key necessária)
//   - youtube_api    : YouTube Data API v3 (requer YOUTUBE_API_KEY)
//   - tiktok_api     : TikTok Research API (requer TIKTOK_API_KEY)
//
// Tipos de target detectados automaticamente:
//   - username       : @username ou username simples
//   - email          : email@domain.com (busca por email público)
//   - hashtag        : #hashtag
//   - url            : https://... (perfil direto)
//   - keyword        : texto livre
//
// Options:
//
//	sources          : lista separada por vírgula (padrão: github_api,reddit_api)
//	twitter_token    : Bearer Token X/Twitter (ou env TWITTER_BEARER_TOKEN)
//	instagram_token  : Access Token Instagram (ou env INSTAGRAM_ACCESS_TOKEN)
//	linkedin_token   : Access Token LinkedIn (ou env LINKEDIN_ACCESS_TOKEN)
//	github_token     : Personal Access Token GitHub (ou env GITHUB_TOKEN)
//	youtube_key      : API Key YouTube (ou env YOUTUBE_API_KEY)
//	tiktok_key       : API Key TikTok (ou env TIKTOK_API_KEY)
//	max_posts        : máximo de posts/tweets a retornar (padrão: 10)
//	include_metrics  : incluir métricas de engajamento (padrão: true)
package socialmedia

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	maxBodyBytes   = 1024 * 1024 // 1 MB
	defaultTimeout = 25 * time.Second

	baseURLTwitter   = "https://api.twitter.com/2"
	baseURLGitHub    = "https://api.github.com"
	baseURLReddit    = "https://www.reddit.com"
	baseURLYouTube   = "https://www.googleapis.com/youtube/v3"
	baseURLInstagram = "https://graph.instagram.com"
)

var (
	reEmail    = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	reHashtag  = regexp.MustCompile(`^#[a-zA-Z0-9_]+$`)
	reUsername = regexp.MustCompile(`^@?[a-zA-Z0-9_.\-]{1,50}$`)
	reURL      = regexp.MustCompile(`^https?://`)
)

// TargetType classifica o tipo de busca.
type TargetType string

const (
	TargetUsername TargetType = "username"
	TargetEmail    TargetType = "email"
	TargetHashtag  TargetType = "hashtag"
	TargetURL      TargetType = "url"
	TargetKeyword  TargetType = "keyword"
)

// Module implementa module.Module para coleta de dados de redes sociais.
type Module struct {
	client *http.Client
}

// New cria um Module com cliente HTTP padrão.
func New() *Module { return &Module{client: &http.Client{Timeout: defaultTimeout}} }

// NewWithClient cria um Module com cliente HTTP injetado (útil em testes).
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "socialmedia" }

// Run executa as buscas em redes sociais e retorna os findings.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	if strings.TrimSpace(input.Target) == "" {
		return nil, fmt.Errorf("socialmedia: target não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	targetType := detectTargetType(input.Target)
	target := normalizeTarget(input.Target, targetType)
	sources := parseSources(optStr(opts, "sources", "github_api,reddit_api"))
	maxPosts := optInt(opts, "max_posts", 10)
	includeMetrics := optStr(opts, "include_metrics", "true") == "true"

	// Tokens de API
	tokens := map[string]string{
		"twitter":   firstNonEmpty(opts["twitter_token"], os.Getenv("TWITTER_BEARER_TOKEN")),
		"instagram": firstNonEmpty(opts["instagram_token"], os.Getenv("INSTAGRAM_ACCESS_TOKEN")),
		"linkedin":  firstNonEmpty(opts["linkedin_token"], os.Getenv("LINKEDIN_ACCESS_TOKEN")),
		"github":    firstNonEmpty(opts["github_token"], os.Getenv("GITHUB_TOKEN")),
		"youtube":   firstNonEmpty(opts["youtube_key"], os.Getenv("YOUTUBE_API_KEY")),
		"tiktok":    firstNonEmpty(opts["tiktok_key"], os.Getenv("TIKTOK_API_KEY")),
	}

	slog.InfoContext(ctx, "socialmedia: iniciando busca",
		"target_type", string(targetType),
		"target", safeTarget(target, targetType),
		"sources", sources,
	)

	type result struct {
		findings []module.Finding
	}

	ch := make(chan result, len(sources))
	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(5)

	for _, src := range sources {
		src := src
		eg.Go(func() error {
			var ff []module.Finding
			var err error

			switch src {
			case "twitter_api":
				if tokens["twitter"] == "" {
					slog.WarnContext(egCtx, "socialmedia: twitter ignorado — TWITTER_BEARER_TOKEN não configurado")
					return nil
				}
				ff, err = m.queryTwitter(egCtx, target, targetType, tokens["twitter"], maxPosts, includeMetrics)

			case "github_api":
				ff, err = m.queryGitHub(egCtx, target, targetType, tokens["github"], maxPosts)

			case "reddit_api":
				ff, err = m.queryReddit(egCtx, target, targetType, maxPosts)

			case "youtube_api":
				if tokens["youtube"] == "" {
					slog.WarnContext(egCtx, "socialmedia: youtube ignorado — YOUTUBE_API_KEY não configurada")
					return nil
				}
				ff, err = m.queryYouTube(egCtx, target, targetType, tokens["youtube"], maxPosts)

			case "instagram_api":
				if tokens["instagram"] == "" {
					slog.WarnContext(egCtx, "socialmedia: instagram ignorado — INSTAGRAM_ACCESS_TOKEN não configurado")
					return nil
				}
				ff, err = m.queryInstagram(egCtx, target, targetType, tokens["instagram"])

			case "tiktok_api":
				if tokens["tiktok"] == "" {
					slog.WarnContext(egCtx, "socialmedia: tiktok ignorado — TIKTOK_API_KEY não configurado")
					return nil
				}
				ff, err = m.queryTikTok(egCtx, target, targetType, tokens["tiktok"], maxPosts)
			}

			if err != nil {
				slog.WarnContext(egCtx, "socialmedia: fonte falhou",
					"source", src, "error", err.Error())
				return nil
			}
			if len(ff) > 0 {
				ch <- result{findings: ff}
			}
			return nil
		})
	}

	go func() {
		_ = eg.Wait()
		close(ch)
	}()

	var all []module.Finding
	for r := range ch {
		all = append(all, r.findings...)
	}

	return dedup(all), nil
}

// ─── Twitter/X API v2 ─────────────────────────────────────────────────────────

func (m *Module) queryTwitter(ctx context.Context, target string, targetType TargetType, token string, maxPosts int, includeMetrics bool) ([]module.Finding, error) {
	var apiURL string
	switch targetType {
	case TargetUsername:
		username := strings.TrimPrefix(target, "@")
		apiURL = fmt.Sprintf("%s/users/by/username/%s?user.fields=description,public_metrics,created_at,location,url,verified,entities",
			baseURLTwitter, url.PathEscape(username))
	case TargetHashtag:
		hashtag := strings.TrimPrefix(target, "#")
		apiURL = fmt.Sprintf("%s/tweets/search/recent?query=%%23%s&max_results=%d&tweet.fields=public_metrics,created_at,author_id,entities",
			baseURLTwitter, url.QueryEscape(hashtag), min(maxPosts, 10))
	case TargetKeyword:
		apiURL = fmt.Sprintf("%s/tweets/search/recent?query=%s&max_results=%d&tweet.fields=public_metrics,created_at,author_id",
			baseURLTwitter, url.QueryEscape(target), min(maxPosts, 10))
	default:
		return nil, nil
	}

	body, status, err := m.get(ctx, apiURL, map[string]string{
		"Authorization": "Bearer " + token,
	})
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, fmt.Errorf("twitter: token inválido")
	}
	if status == http.StatusTooManyRequests {
		return nil, fmt.Errorf("twitter: rate limit")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("twitter API HTTP %d", status)
	}

	var findings []module.Finding

	if targetType == TargetUsername {
		var resp struct {
			Data struct {
				ID            string `json:"id"`
				Name          string `json:"name"`
				Username      string `json:"username"`
				Description   string `json:"description"`
				Location      string `json:"location"`
				Verified      bool   `json:"verified"`
				CreatedAt     string `json:"created_at"`
				PublicMetrics struct {
					FollowersCount int `json:"followers_count"`
					FollowingCount int `json:"following_count"`
					TweetCount     int `json:"tweet_count"`
					ListedCount    int `json:"listed_count"`
				} `json:"public_metrics"`
				URL string `json:"url"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("twitter user JSON: %w", err)
		}

		d := resp.Data
		sev := module.SeverityInfo
		if d.Verified {
			sev = module.SeverityInfo
		}

		extra := map[string]string{
			"source":      "twitter_api",
			"confidence":  "0.95",
			"platform":    "Twitter/X",
			"user_id":     d.ID,
			"username":    d.Username,
			"name":        d.Name,
			"description": d.Description,
			"location":    d.Location,
			"verified":    strconv.FormatBool(d.Verified),
			"created_at":  d.CreatedAt,
			"profile_url": fmt.Sprintf("https://x.com/%s", d.Username),
		}
		if includeMetrics {
			extra["followers"] = strconv.Itoa(d.PublicMetrics.FollowersCount)
			extra["following"] = strconv.Itoa(d.PublicMetrics.FollowingCount)
			extra["tweets"] = strconv.Itoa(d.PublicMetrics.TweetCount)
			extra["lists"] = strconv.Itoa(d.PublicMetrics.ListedCount)
		}

		findings = append(findings, module.Finding{
			Type:     "social_profile",
			URL:      fmt.Sprintf("https://x.com/%s", d.Username),
			Detail:   fmt.Sprintf("Perfil Twitter/X @%s ('%s') — %d seguidores — %d tweets — verificado: %v", d.Username, d.Name, d.PublicMetrics.FollowersCount, d.PublicMetrics.TweetCount, d.Verified),
			Severity: sev,
			Extra:    extra,
		})
	} else {
		// Busca por hashtag ou keyword — retorna tweets
		var resp struct {
			Data []struct {
				ID            string `json:"id"`
				Text          string `json:"text"`
				CreatedAt     string `json:"created_at"`
				AuthorID      string `json:"author_id"`
				PublicMetrics struct {
					RetweetCount int `json:"retweet_count"`
					LikeCount    int `json:"like_count"`
					ReplyCount   int `json:"reply_count"`
				} `json:"public_metrics"`
			} `json:"data"`
			Meta struct {
				ResultCount int `json:"result_count"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("twitter search JSON: %w", err)
		}

		for _, t := range resp.Data {
			extra := map[string]string{
				"source":     "twitter_api",
				"confidence": "0.90",
				"platform":   "Twitter/X",
				"tweet_id":   t.ID,
				"author_id":  t.AuthorID,
				"created_at": t.CreatedAt,
				"text":       truncate(t.Text, 200),
			}
			if includeMetrics {
				extra["retweets"] = strconv.Itoa(t.PublicMetrics.RetweetCount)
				extra["likes"] = strconv.Itoa(t.PublicMetrics.LikeCount)
				extra["replies"] = strconv.Itoa(t.PublicMetrics.ReplyCount)
			}

			findings = append(findings, module.Finding{
				Type:     "social_post",
				URL:      fmt.Sprintf("https://x.com/i/web/status/%s", t.ID),
				Detail:   fmt.Sprintf("Tweet sobre '%s': %s (%s) — %d likes, %d RTs", target, truncate(t.Text, 100), t.CreatedAt, t.PublicMetrics.LikeCount, t.PublicMetrics.RetweetCount),
				Severity: module.SeverityInfo,
				Extra:    extra,
			})
		}
	}

	return findings, nil
}

// ─── GitHub API v3 ───────────────────────────────────────────────────────────

func (m *Module) queryGitHub(ctx context.Context, target string, targetType TargetType, token string, maxResults int) ([]module.Finding, error) {
	headers := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}

	var findings []module.Finding

	switch targetType {
	case TargetUsername:
		username := strings.TrimPrefix(target, "@")

		// Perfil do usuário
		userURL := fmt.Sprintf("%s/users/%s", baseURLGitHub, url.PathEscape(username))
		body, status, err := m.get(ctx, userURL, headers)
		if err != nil {
			return nil, err
		}
		if status == http.StatusNotFound {
			return nil, nil
		}
		if status == http.StatusForbidden {
			return nil, fmt.Errorf("github: rate limit atingido")
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("github user HTTP %d", status)
		}

		var user struct {
			Login       string `json:"login"`
			ID          int    `json:"id"`
			Name        string `json:"name"`
			Email       string `json:"email"`
			Bio         string `json:"bio"`
			Company     string `json:"company"`
			Location    string `json:"location"`
			Blog        string `json:"blog"`
			PublicRepos int    `json:"public_repos"`
			Followers   int    `json:"followers"`
			Following   int    `json:"following"`
			CreatedAt   string `json:"created_at"`
			UpdatedAt   string `json:"updated_at"`
			HTMLURL     string `json:"html_url"`
			Type        string `json:"type"`
			SiteAdmin   bool   `json:"site_admin"`
		}
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, fmt.Errorf("github user JSON: %w", err)
		}

		// Email público é dado sensível — inclui só se disponível
		emailSafe := ""
		if user.Email != "" {
			emailSafe = maskEmail(user.Email)
		}

		findings = append(findings, module.Finding{
			Type:     "social_profile",
			URL:      user.HTMLURL,
			Detail:   fmt.Sprintf("GitHub @%s ('%s') — %d repos públicos — %d seguidores — empresa: %s", user.Login, user.Name, user.PublicRepos, user.Followers, user.Company),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":       "github_api",
				"confidence":   "0.99",
				"platform":     "GitHub",
				"username":     user.Login,
				"user_id":      strconv.Itoa(user.ID),
				"name":         user.Name,
				"email":        emailSafe,
				"bio":          user.Bio,
				"company":      user.Company,
				"location":     user.Location,
				"blog":         user.Blog,
				"public_repos": strconv.Itoa(user.PublicRepos),
				"followers":    strconv.Itoa(user.Followers),
				"following":    strconv.Itoa(user.Following),
				"type":         user.Type,
				"created_at":   user.CreatedAt,
				"profile_url":  user.HTMLURL,
			},
		})

		// Repos públicos
		reposURL := fmt.Sprintf("%s/users/%s/repos?per_page=%d&sort=updated", baseURLGitHub, url.PathEscape(username), min(maxResults, 30))
		repoBody, repoStatus, err := m.get(ctx, reposURL, headers)
		if err == nil && repoStatus == http.StatusOK {
			var repos []struct {
				Name        string   `json:"name"`
				Description string   `json:"description"`
				Language    string   `json:"language"`
				Stars       int      `json:"stargazers_count"`
				Forks       int      `json:"forks_count"`
				Topics      []string `json:"topics"`
				HTMLURL     string   `json:"html_url"`
				UpdatedAt   string   `json:"updated_at"`
				Fork        bool     `json:"fork"`
			}
			if err := json.Unmarshal(repoBody, &repos); err == nil {
				for _, r := range repos {
					if r.Fork {
						continue // Ignora forks para reduzir ruído
					}
					sev := module.SeverityInfo
					if r.Stars >= 100 {
						sev = module.SeverityInfo // Repos populares podem ter mais exposição
					}
					findings = append(findings, module.Finding{
						Type:     "github_repository",
						URL:      r.HTMLURL,
						Detail:   fmt.Sprintf("Repositório GitHub %s/%s — linguagem: %s — %d stars — %s", user.Login, r.Name, r.Language, r.Stars, r.Description),
						Severity: sev,
						Extra: map[string]string{
							"source":      "github_api",
							"confidence":  "0.99",
							"platform":    "GitHub",
							"owner":       user.Login,
							"repo":        r.Name,
							"language":    r.Language,
							"stars":       strconv.Itoa(r.Stars),
							"forks":       strconv.Itoa(r.Forks),
							"topics":      strings.Join(r.Topics, ", "),
							"updated_at":  r.UpdatedAt,
							"description": truncate(r.Description, 200),
						},
					})
				}
			}
		}

	case TargetKeyword, TargetEmail:
		// Busca de usuário por keyword
		searchURL := fmt.Sprintf("%s/search/users?q=%s&per_page=%d", baseURLGitHub, url.QueryEscape(target), min(maxResults, 30))
		body, status, err := m.get(ctx, searchURL, headers)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("github search HTTP %d", status)
		}

		var resp struct {
			TotalCount int `json:"total_count"`
			Items      []struct {
				Login   string `json:"login"`
				HTMLURL string `json:"html_url"`
				Type    string `json:"type"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("github search JSON: %w", err)
		}

		for _, item := range resp.Items {
			findings = append(findings, module.Finding{
				Type:     "social_profile",
				URL:      item.HTMLURL,
				Detail:   fmt.Sprintf("GitHub: usuário '%s' encontrado na busca por '%s' (tipo: %s)", item.Login, target, item.Type),
				Severity: module.SeverityInfo,
				Extra: map[string]string{
					"source":      "github_api",
					"confidence":  "0.85",
					"platform":    "GitHub",
					"username":    item.Login,
					"type":        item.Type,
					"profile_url": item.HTMLURL,
					"total_found": strconv.Itoa(resp.TotalCount),
				},
			})
		}
	}

	return findings, nil
}

// ─── Reddit API ───────────────────────────────────────────────────────────────

func (m *Module) queryReddit(ctx context.Context, target string, targetType TargetType, maxResults int) ([]module.Finding, error) {
	var apiURL string
	switch targetType {
	case TargetUsername:
		username := strings.TrimPrefix(target, "@")
		apiURL = fmt.Sprintf("%s/user/%s/about.json", baseURLReddit, url.PathEscape(username))
	case TargetHashtag, TargetKeyword:
		// Hashtag no Reddit = subreddit por convenção
		query := strings.TrimPrefix(target, "#")
		apiURL = fmt.Sprintf("%s/search.json?q=%s&limit=%d&type=link", baseURLReddit, url.QueryEscape(query), min(maxResults, 25))
	default:
		return nil, nil
	}

	body, status, err := m.get(ctx, apiURL, map[string]string{
		"User-Agent": "blackhorn-modules/1.0",
	})
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status == http.StatusTooManyRequests {
		return nil, fmt.Errorf("reddit: rate limit")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("reddit API HTTP %d", status)
	}

	var findings []module.Finding

	if targetType == TargetUsername {
		var resp struct {
			Data struct {
				Name             string  `json:"name"`
				ID               string  `json:"id"`
				CommentKarma     int     `json:"comment_karma"`
				LinkKarma        int     `json:"link_karma"`
				TotalKarma       int     `json:"total_karma"`
				IsEmployee       bool    `json:"is_employee"`
				IsMod            bool    `json:"is_mod"`
				HasVerifiedEmail bool    `json:"has_verified_email"`
				Created          float64 `json:"created_utc"`
				IconImg          string  `json:"icon_img"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("reddit user JSON: %w", err)
		}

		d := resp.Data
		createdTime := time.Unix(int64(d.Created), 0).UTC().Format("2006-01-02")

		findings = append(findings, module.Finding{
			Type:     "social_profile",
			URL:      fmt.Sprintf("https://www.reddit.com/user/%s", strings.TrimPrefix(d.Name, "t2_")),
			Detail:   fmt.Sprintf("Reddit u/%s — karma total: %d (link: %d, comentário: %d) — desde %s — verificado: %v", d.Name, d.TotalKarma, d.LinkKarma, d.CommentKarma, createdTime, d.HasVerifiedEmail),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":         "reddit_api",
				"confidence":     "0.93",
				"platform":       "Reddit",
				"username":       d.Name,
				"user_id":        d.ID,
				"comment_karma":  strconv.Itoa(d.CommentKarma),
				"link_karma":     strconv.Itoa(d.LinkKarma),
				"total_karma":    strconv.Itoa(d.TotalKarma),
				"is_employee":    strconv.FormatBool(d.IsEmployee),
				"is_mod":         strconv.FormatBool(d.IsMod),
				"verified_email": strconv.FormatBool(d.HasVerifiedEmail),
				"created_at":     createdTime,
				"profile_url":    fmt.Sprintf("https://www.reddit.com/user/%s", d.Name),
			},
		})
	} else {
		// Posts da busca
		var resp struct {
			Data struct {
				Children []struct {
					Data struct {
						ID          string  `json:"id"`
						Title       string  `json:"title"`
						Author      string  `json:"author"`
						Subreddit   string  `json:"subreddit"`
						Score       int     `json:"score"`
						NumComments int     `json:"num_comments"`
						URL         string  `json:"url"`
						Permalink   string  `json:"permalink"`
						Created     float64 `json:"created_utc"`
					} `json:"data"`
				} `json:"children"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("reddit search JSON: %w", err)
		}

		for _, c := range resp.Data.Children {
			p := c.Data
			createdTime := time.Unix(int64(p.Created), 0).UTC().Format("2006-01-02")
			findings = append(findings, module.Finding{
				Type:     "social_post",
				URL:      "https://www.reddit.com" + p.Permalink,
				Detail:   fmt.Sprintf("Reddit r/%s — '%s' por u/%s (%s) — score: %d, %d comentários", p.Subreddit, truncate(p.Title, 100), p.Author, createdTime, p.Score, p.NumComments),
				Severity: module.SeverityInfo,
				Extra: map[string]string{
					"source":      "reddit_api",
					"confidence":  "0.93",
					"platform":    "Reddit",
					"post_id":     p.ID,
					"title":       truncate(p.Title, 200),
					"author":      p.Author,
					"subreddit":   p.Subreddit,
					"score":       strconv.Itoa(p.Score),
					"comments":    strconv.Itoa(p.NumComments),
					"created_at":  createdTime,
					"content_url": p.URL,
				},
			})
		}
	}

	return findings, nil
}

// ─── YouTube Data API v3 ──────────────────────────────────────────────────────

func (m *Module) queryYouTube(ctx context.Context, target string, targetType TargetType, apiKey string, maxResults int) ([]module.Finding, error) {
	params := url.Values{}
	params.Set("key", apiKey)
	params.Set("part", "snippet,statistics")
	params.Set("maxResults", strconv.Itoa(min(maxResults, 50)))

	switch targetType {
	case TargetUsername:
		// Busca canal por username
		params.Set("q", strings.TrimPrefix(target, "@"))
		params.Set("type", "channel")
	case TargetKeyword, TargetHashtag:
		params.Set("q", strings.TrimPrefix(target, "#"))
		params.Set("type", "video")
	default:
		return nil, nil
	}

	apiURL := fmt.Sprintf("%s/search?%s", baseURLYouTube, params.Encode())
	body, status, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusForbidden {
		return nil, fmt.Errorf("youtube: API key inválida ou quota atingida")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("youtube API HTTP %d", status)
	}

	var resp struct {
		Items []struct {
			ID struct {
				Kind      string `json:"kind"`
				ChannelID string `json:"channelId"`
				VideoID   string `json:"videoId"`
			} `json:"id"`
			Snippet struct {
				Title        string `json:"title"`
				Description  string `json:"description"`
				ChannelID    string `json:"channelId"`
				ChannelTitle string `json:"channelTitle"`
				PublishedAt  string `json:"publishedAt"`
			} `json:"snippet"`
		} `json:"items"`
		PageInfo struct {
			TotalResults int `json:"totalResults"`
		} `json:"pageInfo"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("youtube JSON: %w", err)
	}

	var findings []module.Finding
	for _, item := range resp.Items {
		s := item.Snippet
		if item.ID.ChannelID != "" {
			findings = append(findings, module.Finding{
				Type:     "social_profile",
				URL:      fmt.Sprintf("https://www.youtube.com/channel/%s", item.ID.ChannelID),
				Detail:   fmt.Sprintf("Canal YouTube '%s' — %s", s.Title, truncate(s.Description, 100)),
				Severity: module.SeverityInfo,
				Extra: map[string]string{
					"source":      "youtube_api",
					"confidence":  "0.90",
					"platform":    "YouTube",
					"channel_id":  item.ID.ChannelID,
					"name":        s.Title,
					"description": truncate(s.Description, 200),
					"created_at":  s.PublishedAt,
					"profile_url": fmt.Sprintf("https://www.youtube.com/channel/%s", item.ID.ChannelID),
				},
			})
		} else if item.ID.VideoID != "" {
			findings = append(findings, module.Finding{
				Type:     "social_post",
				URL:      fmt.Sprintf("https://www.youtube.com/watch?v=%s", item.ID.VideoID),
				Detail:   fmt.Sprintf("Vídeo YouTube de '%s': '%s' (%s)", s.ChannelTitle, truncate(s.Title, 100), s.PublishedAt),
				Severity: module.SeverityInfo,
				Extra: map[string]string{
					"source":      "youtube_api",
					"confidence":  "0.90",
					"platform":    "YouTube",
					"video_id":    item.ID.VideoID,
					"title":       s.Title,
					"channel":     s.ChannelTitle,
					"published":   s.PublishedAt,
					"description": truncate(s.Description, 200),
				},
			})
		}
	}
	return findings, nil
}

// ─── Instagram Graph API ──────────────────────────────────────────────────────

func (m *Module) queryInstagram(ctx context.Context, target string, targetType TargetType, token string) ([]module.Finding, error) {
	if targetType != TargetUsername {
		return nil, nil
	}
	// Instagram Graph API requer business/creator account
	// Endpoint de busca por username
	apiURL := fmt.Sprintf("%s/me?fields=id,username,name,biography,followers_count,follows_count,media_count,website,profile_picture_url&access_token=%s",
		baseURLInstagram, token)

	body, status, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, fmt.Errorf("instagram: token inválido")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("instagram API HTTP %d", status)
	}

	var resp struct {
		ID             string `json:"id"`
		Username       string `json:"username"`
		Name           string `json:"name"`
		Biography      string `json:"biography"`
		FollowersCount int    `json:"followers_count"`
		FollowsCount   int    `json:"follows_count"`
		MediaCount     int    `json:"media_count"`
		Website        string `json:"website"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("instagram JSON: %w", err)
	}

	f := module.Finding{
		Type:     "social_profile",
		URL:      fmt.Sprintf("https://www.instagram.com/%s/", resp.Username),
		Detail:   fmt.Sprintf("Instagram @%s ('%s') — %d seguidores — %d publicações — bio: %s", resp.Username, resp.Name, resp.FollowersCount, resp.MediaCount, truncate(resp.Biography, 100)),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":      "instagram_api",
			"confidence":  "0.95",
			"platform":    "Instagram",
			"user_id":     resp.ID,
			"username":    resp.Username,
			"name":        resp.Name,
			"biography":   truncate(resp.Biography, 200),
			"followers":   strconv.Itoa(resp.FollowersCount),
			"following":   strconv.Itoa(resp.FollowsCount),
			"media_count": strconv.Itoa(resp.MediaCount),
			"website":     resp.Website,
			"profile_url": fmt.Sprintf("https://www.instagram.com/%s/", resp.Username),
		},
	}
	return []module.Finding{f}, nil
}

// ─── TikTok Research API ──────────────────────────────────────────────────────

func (m *Module) queryTikTok(ctx context.Context, target string, targetType TargetType, apiKey string, maxResults int) ([]module.Finding, error) {
	if targetType != TargetUsername && targetType != TargetKeyword && targetType != TargetHashtag {
		return nil, nil
	}

	// TikTok Research API — endpoint de busca de vídeos
	var query string
	switch targetType {
	case TargetUsername:
		query = fmt.Sprintf("author.username = \"%s\"", strings.TrimPrefix(target, "@"))
	case TargetHashtag:
		query = fmt.Sprintf("hashtag_name = \"%s\"", strings.TrimPrefix(target, "#"))
	case TargetKeyword:
		query = fmt.Sprintf("keyword = \"%s\"", target)
	}

	reqBody, _ := json.Marshal(map[string]interface{}{
		"query": map[string]string{
			"and": query,
		},
		"max_count": min(maxResults, 20),
		"fields":    "id,create_time,author_info,desc,statistics,hashtag_names",
	})

	// TikTok Research API usa POST
	apiURL := "https://open.tiktokapis.com/v2/research/video/query/"
	body, status, err := m.post(ctx, apiURL, reqBody, map[string]string{
		"Authorization": "Bearer " + apiKey,
		"Content-Type":  "application/json",
	})
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, fmt.Errorf("tiktok: token inválido")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("tiktok API HTTP %d", status)
	}

	var resp struct {
		Data struct {
			Videos []struct {
				ID         string `json:"id"`
				CreateTime int64  `json:"create_time"`
				Desc       string `json:"desc"`
				AuthorInfo struct {
					UniqueID  string `json:"unique_id"`
					Nickname  string `json:"nickname"`
					AvatarURL string `json:"avatar_url"`
				} `json:"author_info"`
				Statistics struct {
					DiggCount    int `json:"digg_count"`
					ShareCount   int `json:"share_count"`
					CommentCount int `json:"comment_count"`
					PlayCount    int `json:"play_count"`
				} `json:"statistics"`
				HashtagNames []string `json:"hashtag_names"`
			} `json:"videos"`
			Cursor int `json:"cursor"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("tiktok JSON: %w", err)
	}

	var findings []module.Finding
	for _, v := range resp.Data.Videos {
		createdAt := time.Unix(v.CreateTime, 0).UTC().Format("2006-01-02")
		findings = append(findings, module.Finding{
			Type:     "social_post",
			URL:      fmt.Sprintf("https://www.tiktok.com/@%s/video/%s", v.AuthorInfo.UniqueID, v.ID),
			Detail:   fmt.Sprintf("TikTok de @%s: '%s' (%s) — %d views, %d likes", v.AuthorInfo.UniqueID, truncate(v.Desc, 100), createdAt, v.Statistics.PlayCount, v.Statistics.DiggCount),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":      "tiktok_api",
				"confidence":  "0.88",
				"platform":    "TikTok",
				"video_id":    v.ID,
				"author":      v.AuthorInfo.UniqueID,
				"description": truncate(v.Desc, 200),
				"plays":       strconv.Itoa(v.Statistics.PlayCount),
				"likes":       strconv.Itoa(v.Statistics.DiggCount),
				"shares":      strconv.Itoa(v.Statistics.ShareCount),
				"comments":    strconv.Itoa(v.Statistics.CommentCount),
				"created_at":  createdAt,
				"hashtags":    strings.Join(v.HashtagNames, ", "),
			},
		})
	}
	return findings, nil
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func (m *Module) get(ctx context.Context, apiURL string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "blackhorn-modules/1.0")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return body, resp.StatusCode, err
}

func (m *Module) post(ctx context.Context, apiURL string, bodyData []byte, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(string(bodyData)))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "blackhorn-modules/1.0")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return body, resp.StatusCode, err
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func detectTargetType(target string) TargetType {
	if reURL.MatchString(target) {
		return TargetURL
	}
	if reEmail.MatchString(target) {
		return TargetEmail
	}
	if reHashtag.MatchString(target) {
		return TargetHashtag
	}
	if reUsername.MatchString(target) {
		return TargetUsername
	}
	return TargetKeyword
}

func normalizeTarget(target string, tt TargetType) string {
	switch tt {
	case TargetUsername:
		return strings.TrimPrefix(target, "@")
	case TargetHashtag:
		return strings.TrimPrefix(target, "#")
	default:
		return target
	}
}

func safeTarget(target string, tt TargetType) string {
	if tt == TargetEmail {
		return maskEmail(target)
	}
	return target
}

func maskEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return "***@***"
	}
	local := parts[0]
	if len(local) <= 2 {
		return "**@" + parts[1]
	}
	return string(local[0]) + strings.Repeat("*", len(local)-2) + string(local[len(local)-1]) + "@" + parts[1]
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func parseSources(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func optStr(opts map[string]string, key, def string) string {
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

func optInt(opts map[string]string, key string, def int) int {
	if v, ok := opts[key]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	var out []module.Finding
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Extra["source"] + "|" + f.Extra["username"] + "|" + f.Extra["video_id"] + "|" + f.Extra["tweet_id"] + "|" + f.Extra["post_id"]
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}
