// Package sherlock performs username enumeration across social networks and
// online platforms, modelled after the sherlock-project/sherlock tool (MIT).
//
// Source reference: https://github.com/sherlock-project/sherlock
// Core logic (site list, probe strategy) reimplemented independently in Go;
// no Python source copied. Site definitions are compiled from the public
// data.json of sherlock-project (MIT) — reimplemented as Go structs.
//
// Probe strategy:
//   - Sends GET to each platform's profile URL with the target username
//   - Detects presence via: HTTP status code OR body keyword OR URL pattern
//   - Parallel probes with configurable concurrency (default: 40)
//   - Respects context cancellation for fast abort
//   - Confidence: url_probe=0.95, message_probe=0.80, status_probe=0.75
//
// Input options:
//   - "timeout"     — per-request timeout in seconds (default: 10)
//   - "concurrency" — max parallel requests (default: 40)
//   - "sites"       — comma-separated site names to check (default: all)
//   - "categories"  — comma-separated categories (social, coding, gaming, etc.)
//   - "found_only"  — "true" to return only found accounts (default: true)
//
// Architecture:
//   - Site registry compiled at init — zero runtime reflection
//   - errgroup.SetLimit for bounded parallelism
//   - io.LimitReader on all responses (maxBody = 256 KB)
//   - slog observability on every probe result
//   - confidence scoring per probe type
package sherlock

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	moduleName  = "sherlock"
	maxBody     = 256 << 10 // 256 KB
	defaultConc = 40
	defaultTO   = 10 * time.Second
)

// ─── Site definition ─────────────────────────────────────────────────────────

// ProbeType defines how presence is determined.
type ProbeType string

const (
	ProbeStatus  ProbeType = "status"  // present if HTTP 200
	ProbeMessage ProbeType = "message" // absent if body contains error_msg
	ProbeURL     ProbeType = "url"     // present if final URL matches pattern
	ProbeContain ProbeType = "contain" // present if body contains claim_text ({} replaced by username)
)

// Site describes one platform to check.
type Site struct {
	Name        string
	Category    string
	URLTemplate string // e.g. "https://github.com/{}"
	ProbeType   ProbeType
	ErrorMsg    string // for ProbeMessage: substring that means "not found"
	ClaimText   string // for ProbeContain: substring that means "found" ({} replaced by username)
	ErrorCode   int    // for ProbeStatus: expected status when NOT found (default 404)
	FoundCode   int    // for ProbeStatus: expected status when found (default 200)
	Headers     map[string]string
}

// url returns the profile URL for the given username.
func (s Site) url(username string) string {
	return strings.ReplaceAll(s.URLTemplate, "{}", username)
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements username enumeration across platforms.
type Module struct {
	client *http.Client
	logger *slog.Logger
	sites  []Site
}

// New returns a Module with all built-in sites and production defaults.
func New() *Module {
	return &Module{
		client: httpclient.New(httpclient.Options{Timeout: defaultTO}),
		logger: slog.Default().With("module", moduleName),
		sites:  builtinSites(),
	}
}

// NewWithClient returns a Module using the supplied HTTP client (testability).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// NewWithSites returns a Module with a custom site list (testability / extension).
func NewWithSites(c *http.Client, sites []Site) *Module {
	return &Module{
		client: c,
		logger: slog.Default().With("module", moduleName),
		sites:  sites,
	}
}

// Name satisfies module.Module.
func (m *Module) Name() string { return moduleName }

// Run probes all configured platforms for the target username.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	username := strings.TrimSpace(input.Target)
	if username == "" && len(input.URLs) > 0 {
		username = strings.TrimSpace(input.URLs[0])
	}
	if username == "" {
		return nil, fmt.Errorf("sherlock: username required as Target")
	}

	opts := input.Options
	conc := optInt(opts, "concurrency", defaultConc)
	to := time.Duration(optInt(opts, "timeout", int(defaultTO/time.Second))) * time.Second
	foundOnly := optStr(opts, "found_only", "true") != "false"
	sitesFilter := optStr(opts, "sites", "")
	catFilter := optStr(opts, "categories", "")

	m.logger.InfoContext(ctx, "sherlock: starting",
		"username", username,
		"sites_total", len(m.sites),
		"concurrency", conc,
		"timeout", to,
	)

	// Apply client timeout override
	client := m.client
	if to != defaultTO {
		client = &http.Client{
			Timeout:   to,
			Transport: m.client.Transport,
		}
	}

	// Filter sites
	sites := filterSites(m.sites, sitesFilter, catFilter)
	m.logger.DebugContext(ctx, "sherlock: sites after filter", "count", len(sites))

	var (
		mu      sync.Mutex
		results []module.Finding
	)

	add := func(f module.Finding) {
		mu.Lock()
		results = append(results, f)
		mu.Unlock()
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(conc)

	for _, site := range sites {
		site := site
		eg.Go(func() error {
			found, profileURL, conf, err := m.probe(egCtx, client, site, username)
			if err != nil {
				m.logger.DebugContext(egCtx, "sherlock: probe error",
					"site", site.Name, "err", err)
				if !foundOnly {
					add(module.Finding{
						Type:     "username_probe",
						URL:      site.url(username),
						Detail:   fmt.Sprintf("[Sherlock] %s — probe error: %v", site.Name, err),
						Severity: module.SeverityInfo,
						Extra: map[string]string{
							"site":       site.Name,
							"category":   site.Category,
							"username":   username,
							"status":     "error",
							"confidence": "0.00",
						},
					})
				}
				return nil
			}

			if found {
				m.logger.InfoContext(egCtx, "sherlock: account found",
					"site", site.Name, "url", profileURL, "confidence", conf)
				add(module.Finding{
					Type:     "username_found",
					URL:      profileURL,
					Detail:   fmt.Sprintf("[Sherlock] Username %q found on %s: %s", username, site.Name, profileURL),
					Severity: module.SeverityMedium,
					Extra: map[string]string{
						"site":        site.Name,
						"category":    site.Category,
						"username":    username,
						"profile_url": profileURL,
						"probe_type":  string(site.ProbeType),
						"confidence":  conf,
					},
				})
			} else if !foundOnly {
				add(module.Finding{
					Type:     "username_probe",
					URL:      site.url(username),
					Detail:   fmt.Sprintf("[Sherlock] Username %q NOT found on %s", username, site.Name),
					Severity: module.SeverityInfo,
					Extra: map[string]string{
						"site":       site.Name,
						"category":   site.Category,
						"username":   username,
						"status":     "not_found",
						"confidence": conf,
					},
				})
			}
			return nil
		})
	}

	_ = eg.Wait()

	// Sort: found first, then by site name
	sort.Slice(results, func(i, j int) bool {
		ti, tj := results[i].Type, results[j].Type
		if ti != tj {
			return ti == "username_found"
		}
		return results[i].Extra["site"] < results[j].Extra["site"]
	})

	found := 0
	for _, r := range results {
		if r.Type == "username_found" {
			found++
		}
	}
	m.logger.InfoContext(ctx, "sherlock: done",
		"username", username,
		"probed", len(sites),
		"found", found,
	)
	return results, nil
}

// probe checks one site for the given username.
// Returns (found, profileURL, confidence, error).
func (m *Module) probe(ctx context.Context, client *http.Client, site Site, username string) (bool, string, string, error) {
	profileURL := site.url(username)

	req, err := http.NewRequestWithContext(ctx, "GET", profileURL, nil)
	if err != nil {
		return false, profileURL, "0.00", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-sherlock/1.0)")
	for k, v := range site.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, profileURL, "0.00", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	finalURL := resp.Request.URL.String()

	switch site.ProbeType {
	case ProbeMessage:
		// Present if body does NOT contain the error message
		bodyStr := string(body)
		if site.ErrorMsg != "" && strings.Contains(bodyStr, site.ErrorMsg) {
			return false, profileURL, "0.80", nil
		}
		if resp.StatusCode == http.StatusOK {
			return true, finalURL, "0.80", nil
		}
		return false, profileURL, "0.80", nil

	case ProbeContain:
		// Present if body contains the claim text (with {} replaced by username)
		claimText := strings.ReplaceAll(site.ClaimText, "{}", username)
		bodyStr := string(body)
		if resp.StatusCode == http.StatusOK && strings.Contains(bodyStr, claimText) {
			return true, finalURL, "0.90", nil
		}
		return false, profileURL, "0.90", nil

	case ProbeURL:
		// Present if final URL still contains the username (no redirect to homepage)
		if strings.Contains(strings.ToLower(finalURL), strings.ToLower(username)) &&
			resp.StatusCode == http.StatusOK {
			return true, finalURL, "0.95", nil
		}
		return false, profileURL, "0.95", nil

	default: // ProbeStatus
		foundCode := site.FoundCode
		if foundCode == 0 {
			foundCode = http.StatusOK
		}
		if resp.StatusCode == foundCode {
			return true, finalURL, "0.75", nil
		}
		return false, profileURL, "0.75", nil
	}
}

// ─── Site registry ────────────────────────────────────────────────────────────
// Sites ported from sherlock-project/sherlock data.json (MIT).
// Covers the most relevant platforms across all categories.
// The full list is extensible — add new Site entries freely.

func builtinSites() []Site {
	return []Site{
		// ── Social ────────────────────────────────────────────────────────────
		// GitHub: 404 real quando não existe — ProbeStatus confiável
		{Name: "GitHub", Category: "coding", URLTemplate: "https://github.com/{}", ProbeType: ProbeStatus},
		{Name: "GitLab", Category: "coding", URLTemplate: "https://gitlab.com/{}", ProbeType: ProbeMessage, ErrorMsg: "not found"},
		{Name: "Twitter/X", Category: "social", URLTemplate: "https://x.com/{}", ProbeType: ProbeMessage, ErrorMsg: "This account doesn't exist"},
		{Name: "Instagram", Category: "social", URLTemplate: "https://www.instagram.com/{}/", ProbeType: ProbeMessage, ErrorMsg: "Sorry, this page"},
		// Facebook: SPA pura, HTML idêntico para existente/inexistente. Graph API requer token.
		// Removido para evitar falsos positivos.
		{Name: "LinkedIn", Category: "social", URLTemplate: "https://www.linkedin.com/in/{}", ProbeType: ProbeMessage, ErrorMsg: "Page not found"},
		// Reddit: /about.json retorna 403 para bots sem cookies — sem discriminador confiável.
		// Removido para evitar falsos positivos.
		// TikTok: SPA pura, HTML idêntico. Sem endpoint público sem auth. Removido.
		{Name: "Pinterest", Category: "social", URLTemplate: "https://www.pinterest.com/{}/", ProbeType: ProbeMessage, ErrorMsg: "Sorry! We couldn't find that page"},
		{Name: "Snapchat", Category: "social", URLTemplate: "https://www.snapchat.com/add/{}", ProbeType: ProbeMessage, ErrorMsg: "Sorry!"},
		{Name: "Tumblr", Category: "social", URLTemplate: "https://{}.tumblr.com/", ProbeType: ProbeMessage, ErrorMsg: "There's nothing here"},
		{Name: "Medium", Category: "social", URLTemplate: "https://medium.com/@{}", ProbeType: ProbeMessage, ErrorMsg: "Page not found"},
		{Name: "Mastodon", Category: "social", URLTemplate: "https://mastodon.social/@{}", ProbeType: ProbeMessage, ErrorMsg: "The page you"},
		// Bluesky: API ATProto requer handle com domínio (ex: user.bsky.social), não apenas username.
		// Sem domínio retorna InvalidRequest para ambos real e fake — sem discriminador confiável.
		// Removido para evitar falsos positivos.
		{Name: "Threads", Category: "social", URLTemplate: "https://www.threads.net/@{}", ProbeType: ProbeMessage, ErrorMsg: "Sorry, this page"},
		{Name: "BeReal", Category: "social", URLTemplate: "https://bere.al/{}", ProbeType: ProbeMessage, ErrorMsg: "Not Found"},
		{Name: "VK", Category: "social", URLTemplate: "https://vk.com/{}", ProbeType: ProbeMessage, ErrorMsg: "has deleted their page"},
		{Name: "OK.ru", Category: "social", URLTemplate: "https://ok.ru/{}", ProbeType: ProbeMessage, ErrorMsg: "not found"},

		// ── Gaming ────────────────────────────────────────────────────────────
		{Name: "Steam", Category: "gaming", URLTemplate: "https://steamcommunity.com/id/{}", ProbeType: ProbeMessage, ErrorMsg: "The specified profile could not be found"},
		// Twitch: SPA pura, HTML idêntico para existente/inexistente. API Helix requer Client-ID.
		// Removido para evitar falsos positivos.
		{Name: "Battle.net", Category: "gaming", URLTemplate: "https://us.battle.net/forums/en/overview/user/{}", ProbeType: ProbeStatus},
		// Epic Games: /id/{username} retorna 200 apenas quando existe
		{Name: "Epic Games", Category: "gaming", URLTemplate: "https://www.epicgames.com/id/{}", ProbeType: ProbeStatus},

		// ── Coding ────────────────────────────────────────────────────────────
		{Name: "HackerNews", Category: "coding", URLTemplate: "https://news.ycombinator.com/user?id={}", ProbeType: ProbeMessage, ErrorMsg: "No such user"},
		{Name: "DEV.to", Category: "coding", URLTemplate: "https://dev.to/{}", ProbeType: ProbeMessage, ErrorMsg: "404 | The page you were looking for"},
		{Name: "Stack Overflow", Category: "coding", URLTemplate: "https://stackoverflow.com/users/{}", ProbeType: ProbeMessage, ErrorMsg: "Page Not Found"},
		{Name: "Bitbucket", Category: "coding", URLTemplate: "https://bitbucket.org/{}/", ProbeType: ProbeMessage, ErrorMsg: "Repository not found"},
		{Name: "CodePen", Category: "coding", URLTemplate: "https://codepen.io/{}", ProbeType: ProbeMessage, ErrorMsg: "Sorry, we couldn't find"},
		// Replit: redireciona para /login para QUALQUER username (existente ou não) — sem discriminador. Removido.
		{Name: "Kaggle", Category: "coding", URLTemplate: "https://www.kaggle.com/{}", ProbeType: ProbeMessage, ErrorMsg: "404"},
		{Name: "HuggingFace", Category: "coding", URLTemplate: "https://huggingface.co/{}", ProbeType: ProbeMessage, ErrorMsg: "Page Not Found"},
		{Name: "npm", Category: "coding", URLTemplate: "https://www.npmjs.com/~{}", ProbeType: ProbeMessage, ErrorMsg: "npm | 404"},
		{Name: "PyPI", Category: "coding", URLTemplate: "https://pypi.org/user/{}/", ProbeType: ProbeStatus},

		// ── Professional ──────────────────────────────────────────────────────
		{Name: "AngelList", Category: "professional", URLTemplate: "https://angel.co/u/{}", ProbeType: ProbeMessage, ErrorMsg: "Page Not Found"},
		{Name: "ProductHunt", Category: "professional", URLTemplate: "https://www.producthunt.com/@{}", ProbeType: ProbeMessage, ErrorMsg: "Page not found"},
		{Name: "Gravatar", Category: "professional", URLTemplate: "https://en.gravatar.com/{}", ProbeType: ProbeMessage, ErrorMsg: "Gravatar Profile Not Found"},
		{Name: "Keybase", Category: "professional", URLTemplate: "https://keybase.io/{}", ProbeType: ProbeMessage, ErrorMsg: "404"},

		// ── Content ───────────────────────────────────────────────────────────
		{Name: "YouTube", Category: "content", URLTemplate: "https://www.youtube.com/@{}", ProbeType: ProbeMessage, ErrorMsg: "404 Not Found"},
		{Name: "Spotify", Category: "content", URLTemplate: "https://open.spotify.com/user/{}", ProbeType: ProbeMessage, ErrorMsg: "not found"},
		{Name: "SoundCloud", Category: "content", URLTemplate: "https://soundcloud.com/{}", ProbeType: ProbeMessage, ErrorMsg: "We can't find that user"},
		{Name: "Flickr", Category: "content", URLTemplate: "https://www.flickr.com/people/{}/", ProbeType: ProbeMessage, ErrorMsg: "page you are looking for"},
		{Name: "Vimeo", Category: "content", URLTemplate: "https://vimeo.com/{}", ProbeType: ProbeMessage, ErrorMsg: "Sorry, we couldn't find"},
		{Name: "Substack", Category: "content", URLTemplate: "https://{}.substack.com/", ProbeType: ProbeMessage, ErrorMsg: "page not found"},
		{Name: "Patreon", Category: "content", URLTemplate: "https://www.patreon.com/{}", ProbeType: ProbeMessage, ErrorMsg: "page doesn't exist"},
		{Name: "Buy Me a Coffee", Category: "content", URLTemplate: "https://www.buymeacoffee.com/{}", ProbeType: ProbeMessage, ErrorMsg: "404"},

		// ── Security / Bug Bounty ─────────────────────────────────────────────
		{Name: "HackerOne", Category: "security", URLTemplate: "https://hackerone.com/{}", ProbeType: ProbeMessage, ErrorMsg: "Page Not Found"},
		{Name: "Bugcrowd", Category: "security", URLTemplate: "https://bugcrowd.com/{}", ProbeType: ProbeMessage, ErrorMsg: "Sorry"},
		// Intigriti: /researcher/{} redireciona para login e retorna 200 sempre — falso positivo confirmado. Removido.
		{Name: "Exploit-DB", Category: "security", URLTemplate: "https://www.exploit-db.com/author/{}", ProbeType: ProbeMessage, ErrorMsg: "No Results"},
		{Name: "CTFtime", Category: "security", URLTemplate: "https://ctftime.org/user/{}", ProbeType: ProbeMessage, ErrorMsg: "No such user"},
		{Name: "TryHackMe", Category: "security", URLTemplate: "https://tryhackme.com/p/{}", ProbeType: ProbeMessage, ErrorMsg: "404"},
		// HackTheBox: API JSON retorna success:false quando não encontrado
		{Name: "HackTheBox", Category: "security", URLTemplate: "https://www.hackthebox.com/api/v4/user/profile/basic/{}", ProbeType: ProbeMessage, ErrorMsg: `"success":false`},

		// ── Messaging ─────────────────────────────────────────────────────────
		// Telegram: body real contém "tg://resolve?domain={username}" em al:ios:url.
		// Inexistente retorna HTML genérico sem esse link — ProbeContain confirma presença.
		{Name: "Telegram", Category: "messaging", URLTemplate: "https://t.me/{}", ProbeType: ProbeContain, ClaimText: "tg://resolve?domain={}"},
		// Signal: não tem perfil público por username — probe removido (falso positivo garantido)
		// Discord: URL /users/{id} requer ID numérico, não username — probe removido
		{Name: "Slack", Category: "messaging", URLTemplate: "https://{}.slack.com/", ProbeType: ProbeMessage, ErrorMsg: "page_gone"},

		// ── Gaming ────────────────────────────────────────────────────────────
		// Xbox: URL correta é /en-US/play/user?gamertag={} mas retorna 200 sempre — removido
		// PSN: /profile/{} requer autenticação — removido
		{Name: "Steam", Category: "gaming", URLTemplate: "https://steamcommunity.com/id/{}", ProbeType: ProbeMessage, ErrorMsg: "The specified profile could not be found"},
		// Kick: confirmado falso positivo pelo usuário — removido.

		// ── Content ───────────────────────────────────────────────────────────
		// Ko-fi: retorna 200 para qualquer path — probe removido (falso positivo)
		{Name: "Patreon", Category: "content", URLTemplate: "https://www.patreon.com/{}", ProbeType: ProbeMessage, ErrorMsg: "page doesn't exist"},
		{Name: "Buy Me a Coffee", Category: "content", URLTemplate: "https://www.buymeacoffee.com/{}", ProbeType: ProbeMessage, ErrorMsg: "404"},

		// ── Brazilian platforms ───────────────────────────────────────────────
		// 99Freelas: retorna mensagem de erro no corpo quando usuário não existe
		{Name: "99Freelas", Category: "freelance_br", URLTemplate: "https://www.99freelas.com.br/user/{}", ProbeType: ProbeMessage, ErrorMsg: "usuário não foi encontrado"},
		{Name: "Workana", Category: "freelance_br", URLTemplate: "https://www.workana.com/freelancer/{}", ProbeType: ProbeMessage, ErrorMsg: "not found"},
		{Name: "GetNinjas", Category: "freelance_br", URLTemplate: "https://www.getninjas.com.br/perfil/{}", ProbeType: ProbeMessage, ErrorMsg: "404"},
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func filterSites(sites []Site, sitesFilter, catFilter string) []Site {
	if sitesFilter == "" && catFilter == "" {
		return sites
	}
	var wantedSites, wantedCats map[string]bool
	if sitesFilter != "" {
		wantedSites = make(map[string]bool)
		for _, s := range strings.Split(sitesFilter, ",") {
			wantedSites[strings.ToLower(strings.TrimSpace(s))] = true
		}
	}
	if catFilter != "" {
		wantedCats = make(map[string]bool)
		for _, c := range strings.Split(catFilter, ",") {
			wantedCats[strings.ToLower(strings.TrimSpace(c))] = true
		}
	}
	var out []Site
	for _, s := range sites {
		if wantedSites != nil && !wantedSites[strings.ToLower(s.Name)] {
			continue
		}
		if wantedCats != nil && !wantedCats[strings.ToLower(s.Category)] {
			continue
		}
		out = append(out, s)
	}
	return out
}

func optStr(opts map[string]string, key, def string) string {
	if opts == nil {
		return def
	}
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

func optInt(opts map[string]string, key string, def int) int {
	s := optStr(opts, key, "")
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return def
	}
	return n
}
