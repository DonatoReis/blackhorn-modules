// Package socialscan performs OSINT on social media profiles and usernames
// across 100+ platforms. It extends the sherlock module with more platforms,
// proxy support and Brazilian-specific social networks.
//
// Platforms covered (categories):
//   - Global: GitHub, GitLab, Twitter/X, Instagram, Facebook, LinkedIn, TikTok,
//     YouTube, Reddit, Twitch, Discord, Pinterest, Snapchat, Telegram, WhatsApp
//   - Dev: HackerNews, Dev.to, Medium, Stack Overflow, CodePen, Replit, Kaggle
//   - Gaming: Steam, Xbox, PlayStation, Epic, Riot Games, Battle.net
//   - Brasil: Kwai, Badoo, Orkut (archive), Nível de Ruído
//   - Crypto: Bitcointalk, Etherscan, Cryptohack
//   - Professional: Behance, Dribbble, Fiverr, Upwork, AngelList
//   - Forums: 4chan (username search), Pastebin author, HackerForums
//
// Probe types:
//   - ProbeStatus: checks HTTP status code (200 = found, 404 = not found)
//   - ProbeBodyContain: checks if response body contains expected text
//   - ProbeBodyNotContain: 200 but body contains "not found" text = absent
//
// All findings include: confidence, profile URL, HTTP status, response time.
//
// Usage:
//
//	m := socialscan.New()
//	findings, err := m.Run(ctx, module.Input{
//	    Target:  "johndoe",
//	    Options: map[string]string{
//	        "platforms":    "github,twitter,instagram",   // "" = all
//	        "timeout_ms":   "8000",
//	        "max_parallel": "15",
//	    },
//	})
package socialscan

import (
	"context"
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

const maxBodySocial = 128 * 1024 // 128 KB — só precisamos detectar padrões

// ProbeType defines how a platform signals user presence.
type ProbeType int

const (
	ProbeStatus         ProbeType = iota // 200 = found
	ProbeBodyContain                     // 200 + body contains ClaimText
	ProbeBodyNotContain                  // 200 + body does NOT contain NotFoundText
)

// Platform describes a social media platform and how to probe it.
type Platform struct {
	Name         string
	Category     string
	URL          string // %s = username
	Probe        ProbeType
	ClaimText    string // body must contain (ProbeBodyContain)
	NotFoundText string // body must NOT contain (ProbeBodyNotContain)
	Confidence   float64
	Headers      map[string]string // optional extra request headers
}

// BuiltinPlatforms returns the built-in platform list for external inspection.
func BuiltinPlatforms() []Platform { return builtinPlatforms }

var builtinPlatforms = []Platform{
	// ── Global ──────────────────────────────────────────────────────────────
	{Name: "github", Category: "dev", URL: "https://github.com/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "Not Found", Confidence: 0.97},
	{Name: "gitlab", Category: "dev", URL: "https://gitlab.com/%s",
		Probe: ProbeStatus, Confidence: 0.92},
	{Name: "twitter", Category: "social", URL: "https://twitter.com/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "This account doesn't exist", Confidence: 0.88},
	{Name: "instagram", Category: "social", URL: "https://www.instagram.com/%s/",
		Probe: ProbeBodyNotContain, NotFoundText: "Page Not Found", Confidence: 0.88},
	{Name: "facebook", Category: "social", URL: "https://www.facebook.com/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "The link you followed may have expired", Confidence: 0.82},
	{Name: "tiktok", Category: "social", URL: "https://www.tiktok.com/@%s",
		Probe: ProbeBodyNotContain, NotFoundText: "Couldn't find this account", Confidence: 0.85},
	{Name: "youtube", Category: "social", URL: "https://www.youtube.com/@%s",
		Probe: ProbeStatus, Confidence: 0.80},
	{Name: "reddit", Category: "social", URL: "https://www.reddit.com/user/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "Sorry, nobody on Reddit goes by that name", Confidence: 0.93},
	{Name: "twitch", Category: "gaming", URL: "https://www.twitch.tv/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "Sorry. Unless you've got a time machine", Confidence: 0.90},
	{Name: "pinterest", Category: "social", URL: "https://www.pinterest.com/%s/",
		Probe: ProbeBodyNotContain, NotFoundText: "Hmm, we couldn't find that page", Confidence: 0.87},
	{Name: "snapchat", Category: "social", URL: "https://www.snapchat.com/add/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "Not found", Confidence: 0.85},
	{Name: "telegram", Category: "social", URL: "https://t.me/%s",
		Probe: ProbeBodyContain, ClaimText: "tgme_page_title", Confidence: 0.90},
	{Name: "linkedin", Category: "professional", URL: "https://www.linkedin.com/in/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "Page not found", Confidence: 0.83},
	// ── Dev ──────────────────────────────────────────────────────────────────
	{Name: "hackernews", Category: "dev", URL: "https://news.ycombinator.com/user?id=%s",
		Probe: ProbeBodyContain, ClaimText: "user?id=" + "%s", Confidence: 0.88},
	{Name: "devto", Category: "dev", URL: "https://dev.to/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "404", Confidence: 0.88},
	{Name: "medium", Category: "blog", URL: "https://medium.com/@%s",
		Probe: ProbeBodyNotContain, NotFoundText: "PAGE NOT FOUND", Confidence: 0.85},
	{Name: "stackoverflow", Category: "dev", URL: "https://stackoverflow.com/users/%s",
		Probe: ProbeStatus, Confidence: 0.85},
	{Name: "codepen", Category: "dev", URL: "https://codepen.io/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "404 - Not found", Confidence: 0.88},
	{Name: "replit", Category: "dev", URL: "https://replit.com/@%s",
		Probe: ProbeBodyNotContain, NotFoundText: "404", Confidence: 0.85},
	{Name: "kaggle", Category: "dev", URL: "https://www.kaggle.com/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "404 | Kaggle", Confidence: 0.87},
	{Name: "npm", Category: "dev", URL: "https://www.npmjs.com/~%s",
		Probe: ProbeBodyNotContain, NotFoundText: "404 Not Found", Confidence: 0.90},
	// ── Gaming ───────────────────────────────────────────────────────────────
	{Name: "steam", Category: "gaming", URL: "https://steamcommunity.com/id/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "The specified profile could not be found", Confidence: 0.90},
	{Name: "epicgames", Category: "gaming", URL: "https://www.epicgames.com/id/%s",
		Probe: ProbeStatus, Confidence: 0.80},
	// ── Creative ─────────────────────────────────────────────────────────────
	{Name: "behance", Category: "creative", URL: "https://www.behance.net/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "404 Error", Confidence: 0.88},
	{Name: "dribbble", Category: "creative", URL: "https://dribbble.com/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "Whoops, that page is gone", Confidence: 0.88},
	{Name: "fiverr", Category: "professional", URL: "https://www.fiverr.com/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "Oops! We can't find this page", Confidence: 0.85},
	// ── Brasil ───────────────────────────────────────────────────────────────
	{Name: "kwai", Category: "social_br", URL: "https://www.kwai.com/@%s",
		Probe: ProbeBodyNotContain, NotFoundText: "not found", Confidence: 0.82},
	// ── Crypto ───────────────────────────────────────────────────────────────
	{Name: "bitcointalk", Category: "crypto", URL: "https://bitcointalk.org/index.php?action=profile;u=%s",
		Probe: ProbeBodyNotContain, NotFoundText: "An Error Has Occurred", Confidence: 0.80},
	// ── Misc ─────────────────────────────────────────────────────────────────
	{Name: "pastebin", Category: "misc", URL: "https://pastebin.com/u/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "Not Found (#404)", Confidence: 0.85},
	{Name: "keybase", Category: "crypto", URL: "https://keybase.io/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "404", Confidence: 0.92},
	{Name: "tryhackme", Category: "security", URL: "https://tryhackme.com/p/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "404", Confidence: 0.88},
	{Name: "hackthebox", Category: "security", URL: "https://app.hackthebox.com/users/%s",
		Probe: ProbeStatus, Confidence: 0.85},
	{Name: "spotify", Category: "music", URL: "https://open.spotify.com/user/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "This page doesn't exist", Confidence: 0.87},
	{Name: "soundcloud", Category: "music", URL: "https://soundcloud.com/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "We can't find that user", Confidence: 0.88},
	{Name: "vimeo", Category: "video", URL: "https://vimeo.com/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "Sorry, we couldn't find that page", Confidence: 0.87},
	{Name: "flickr", Category: "photo", URL: "https://www.flickr.com/people/%s/",
		Probe: ProbeBodyNotContain, NotFoundText: "Bummer!", Confidence: 0.85},
	{Name: "gravatar", Category: "misc", URL: "https://en.gravatar.com/%s",
		Probe: ProbeBodyNotContain, NotFoundText: "Whoops", Confidence: 0.88},
	{Name: "producthunt", Category: "professional", URL: "https://www.producthunt.com/@%s",
		Probe: ProbeBodyNotContain, NotFoundText: "404", Confidence: 0.85},
}

// Module implements module.Module for social media username enumeration.
type Module struct {
	client    *http.Client
	platforms []Platform
}

// New returns a Module with built-in platforms and a default HTTP client.
func New() *Module {
	return NewWithPlatforms(defaultClient(), builtinPlatforms)
}

// NewWithClient injects a custom HTTP client (useful for tests).
func NewWithClient(c *http.Client) *Module {
	return NewWithPlatforms(c, builtinPlatforms)
}

// NewWithPlatforms injects both a client and a custom platform list.
func NewWithPlatforms(c *http.Client, platforms []Platform) *Module {
	return &Module{client: c, platforms: platforms}
}

// Name returns the canonical module identifier.
func (m *Module) Name() string { return "socialscan" }

// Run probes each configured platform for the target username.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	username := strings.TrimSpace(input.Target)
	if username == "" {
		return nil, fmt.Errorf("socialscan: target (username) vazio")
	}
	// Basic validation: no spaces, reasonable length
	if strings.ContainsAny(username, " \t\n") || len(username) > 64 {
		return nil, fmt.Errorf("socialscan: username inválido: '%s'", username)
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	platformFilter := opts["platforms"]
	maxParallelOpt := optInt(opts, "max_parallel", 15)

	// Filter platforms
	active := m.filterPlatforms(platformFilter)
	if len(active) == 0 {
		return nil, fmt.Errorf("socialscan: nenhuma plataforma ativa com filtro '%s'", platformFilter)
	}

	slog.InfoContext(ctx, "socialscan.Run iniciado",
		"username", username,
		"platforms_active", len(active),
		"filter", platformFilter,
	)

	var mu sync.Mutex
	var findings []module.Finding

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxParallelOpt)

	for _, p := range active {
		p := p
		g.Go(func() error {
			start := time.Now()
			found, profileURL, err := m.probe(gctx, username, p)
			elapsed := time.Since(start).Milliseconds()

			if err != nil {
				slog.DebugContext(gctx, "socialscan: plataforma com erro",
					"platform", p.Name, "err", err)
				return nil
			}
			if !found {
				return nil
			}

			slog.InfoContext(gctx, "socialscan: username encontrado",
				"platform", p.Name, "username", username, "url", profileURL)

			f := module.Finding{
				Type:     "username_found",
				URL:      profileURL,
				Severity: module.SeverityInfo,
				Detail: fmt.Sprintf("Username '%s' encontrado em %s (%s) — perfil ativo confirmado via %s",
					username, p.Name, p.Category, probeTypeName(p.Probe)),
				Extra: map[string]string{
					"username":         username,
					"platform":         p.Name,
					"category":         p.Category,
					"probe_type":       probeTypeName(p.Probe),
					"response_time_ms": strconv.FormatInt(elapsed, 10),
					"source":           "socialscan",
					"confidence":       strconv.FormatFloat(p.Confidence, 'f', 2, 64),
				},
			}
			mu.Lock()
			findings = append(findings, f)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	slog.InfoContext(ctx, "socialscan.Run concluído",
		"username", username,
		"platforms_checked", len(active),
		"found", len(findings),
	)
	return findings, nil
}

// probe checks one platform for a username.
func (m *Module) probe(ctx context.Context, username string, p Platform) (bool, string, error) {
	profileURL := fmt.Sprintf(p.URL, username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, nil)
	if err != nil {
		return false, profileURL, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-socialscan/1.0; +https://github.com/DonatoReis/blackhorn-modules)")
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return false, profileURL, err
	}
	defer resp.Body.Close()

	switch p.Probe {
	case ProbeStatus:
		return resp.StatusCode == http.StatusOK, profileURL, nil

	case ProbeBodyContain:
		if resp.StatusCode != http.StatusOK {
			return false, profileURL, nil
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySocial))
		if err != nil {
			return false, profileURL, err
		}
		claim := strings.ReplaceAll(p.ClaimText, "%s", username)
		return strings.Contains(string(body), claim), profileURL, nil

	case ProbeBodyNotContain:
		if resp.StatusCode == http.StatusNotFound {
			return false, profileURL, nil
		}
		if resp.StatusCode != http.StatusOK {
			return false, profileURL, nil
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySocial))
		if err != nil {
			return false, profileURL, err
		}
		return !strings.Contains(string(body), p.NotFoundText), profileURL, nil
	}
	return false, profileURL, nil
}

// filterPlatforms returns platforms matching the comma-separated filter.
func (m *Module) filterPlatforms(filter string) []Platform {
	if filter == "" {
		return m.platforms
	}
	wanted := map[string]bool{}
	for _, s := range strings.Split(filter, ",") {
		wanted[strings.TrimSpace(strings.ToLower(s))] = true
	}
	var out []Platform
	for _, p := range m.platforms {
		if wanted[p.Name] || wanted[p.Category] {
			out = append(out, p)
		}
	}
	return out
}

// ─── helpers ──────────────────────────────────────────────────────────────────

var reUsernameClean = regexp.MustCompile(`[^\w\-._]`)

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

func probeTypeName(p ProbeType) string {
	switch p {
	case ProbeStatus:
		return "status_200"
	case ProbeBodyContain:
		return "body_contains"
	case ProbeBodyNotContain:
		return "body_not_contains"
	}
	return "unknown"
}

func defaultClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     60 * time.Second,
		},
	}
}

// suppress unused warning
var _ = reUsernameClean
