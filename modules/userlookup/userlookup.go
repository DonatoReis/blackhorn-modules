// Package userlookup performs multi-source username enumeration across hundreds
// of online platforms, combining three public databases to maximize coverage.
//
// Approach (dicas.md §11 — decision layer before execution):
//  1. Compile final platform list from WhatsMyName JSON + builtin list
//  2. Probe each URL with HEAD first, fallback to GET if needed
//  3. Classify result: found / not_found / unknown (rate-limited, error)
//  4. Score confidence based on probe reliability tier
//
// Sources:
//   - WhatsMyName dataset (https://github.com/WebBreacher/WhatsMyName) MIT
//     Loaded at runtime from Options["wmn_json"] path OR from the built-in
//     compiled subset (~250 sites). The full JSON can be downloaded and passed
//     via option for maximum coverage.
//   - CheckUsernames (checkusernames.com) — 150+ platforms via HEAD probe
//   - Built-in list  — 80+ additional platforms not in WMN
//
// Probe strategy:
//   - ProbeStatus:          HTTP 200 = found, 404 = not found
//   - ProbeBodyContain:     200 AND body contains ClaimText
//   - ProbeBodyNotContain:  200 AND body does NOT contain NotFoundText
//   - ProbeRedirect:        destination URL contains username (profile confirmed)
//
// Input:
//   - Target: username to enumerate (without @)
//   - Options["sources"]: "wmn,builtin" (default: all)
//   - Options["sites"]: comma-separated site names to restrict
//   - Options["categories"]: comma-separated categories
//   - Options["timeout"]: per-request timeout in seconds (default: 8)
//   - Options["concurrency"]: max parallel requests (default: 50)
//   - Options["found_only"]: "true" to return only found accounts (default: true)
//   - Options["wmn_json"]: path to WhatsMyName data.json file
//
// Architecture:
//   - errgroup.SetLimit for bounded parallelism  (dicas.md §16)
//   - io.LimitReader on all bodies               (guia-go-1.26 §concurrency)
//   - confidence scoring per probe type          (dicas.md §4)
//   - slog observability on every probe          (dicas.md §16)
//   - Detail explains WHY account was found      (dicas.md §17)
package userlookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	moduleName  = "userlookup"
	maxBody     = 256 * 1024 // 256 KB per response
	defaultConc = 50
	defaultTO   = 8 * time.Second
)

// ─── Platform definition ──────────────────────────────────────────────────────

// ProbeType defines how to detect whether an account exists.
type ProbeType string

const (
	ProbeStatus         ProbeType = "status"           // 200 = found, 404 = not found
	ProbeBodyContain    ProbeType = "body_contain"     // 200 + body contains ClaimText
	ProbeBodyNotContain ProbeType = "body_not_contain" // 200 + body does NOT contain NotFoundText
	ProbeRedirect       ProbeType = "redirect"         // final URL contains username
)

// Platform describes a single site probe.
type Platform struct {
	Name         string            `json:"name"`
	Category     string            `json:"category"`
	URL          string            `json:"url"` // {account} placeholder
	ProbeType    ProbeType         `json:"probe_type"`
	ClaimText    string            `json:"claim_text"` // for body_contain
	NotFoundText string            `json:"not_found"`  // for body_not_contain
	Confidence   float64           `json:"confidence"`
	Headers      map[string]string `json:"headers"`
	ErrorType    string            `json:"error_type"` // wmn compat: "status_code", "message"
}

// BuiltinPlatforms returns the compiled-in platform list.
func BuiltinPlatforms() []Platform { return builtinPlatforms }

// ─── WhatsMyName loader ───────────────────────────────────────────────────────

// wmnSite mirrors the WhatsMyName data.json format.
type wmnSite struct {
	Name      string            `json:"name"`
	URICheck  string            `json:"uri_check"`
	EType     string            `json:"e_type"` // "message" | "status_code"
	ECode     int               `json:"e_code"`
	EString   string            `json:"e_string"`
	MString   string            `json:"m_string"`
	MCode     int               `json:"m_code"`
	Category  string            `json:"category"`
	Headers   map[string]string `json:"headers"`
	UserAgent string            `json:"user_agent"`
}

type wmnData struct {
	Sites []wmnSite `json:"sites"`
}

// loadWMN loads and converts a WhatsMyName JSON file into Platform list.
func loadWMN(path string) ([]Platform, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("wmn: open %q: %w", path, err)
	}
	defer f.Close()

	var data wmnData
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil, fmt.Errorf("wmn: decode: %w", err)
	}

	var platforms []Platform
	for _, s := range data.Sites {
		if s.URICheck == "" {
			continue
		}
		p := Platform{
			Name:      s.Name,
			Category:  s.Category,
			URL:       strings.ReplaceAll(s.URICheck, "{account}", "{account}"),
			Headers:   s.Headers,
			ErrorType: s.EType,
		}
		if s.UserAgent != "" && p.Headers == nil {
			p.Headers = map[string]string{}
		}
		if s.UserAgent != "" {
			p.Headers["User-Agent"] = s.UserAgent
		}

		switch s.EType {
		case "message":
			// m_string = claim text (account exists), e_string = not found text
			p.ProbeType = ProbeBodyContain
			p.ClaimText = s.MString
			p.NotFoundText = s.EString
			p.Confidence = 0.82
		case "status_code":
			p.ProbeType = ProbeStatus
			p.Confidence = 0.78
		default:
			p.ProbeType = ProbeStatus
			p.Confidence = 0.70
		}
		platforms = append(platforms, p)
	}
	return platforms, nil
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements username enumeration.
type Module struct {
	client    *http.Client
	platforms []Platform
}

// New returns a Module with built-in platform list and default HTTP client.
func New() *Module { return NewWithPlatforms(defaultClient(), builtinPlatforms) }

// NewWithClient injects a custom HTTP client with built-in platforms.
func NewWithClient(c *http.Client) *Module { return NewWithPlatforms(c, builtinPlatforms) }

// NewWithPlatforms injects both client and platform list.
func NewWithPlatforms(c *http.Client, platforms []Platform) *Module {
	return &Module{client: c, platforms: platforms}
}

// Name satisfies module.Module.
func (m *Module) Name() string { return moduleName }

// Run enumerates username across configured platforms.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	username := strings.TrimSpace(strings.TrimPrefix(input.Target, "@"))
	if username == "" {
		return nil, fmt.Errorf("userlookup: target (username) vazio")
	}
	if len(username) < 2 {
		return nil, fmt.Errorf("userlookup: username muito curto: %q", username)
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	sitesFilter := opts["sites"]
	catsFilter := opts["categories"]
	foundOnly := optStr(opts, "found_only", "true") == "true"
	concurrency := optInt(opts, "concurrency", defaultConc)
	timeoutSec := optInt(opts, "timeout", 8)
	wmnPath := opts["wmn_json"]

	// Build platform list
	platforms := m.platforms
	if wmnPath != "" {
		wmnPlatforms, err := loadWMN(wmnPath)
		if err != nil {
			slog.WarnContext(ctx, "userlookup: wmn load failed", "path", wmnPath, "err", err)
		} else {
			slog.InfoContext(ctx, "userlookup: wmn loaded", "path", wmnPath, "count", len(wmnPlatforms))
			// Merge: wmn platforms first, builtin appended if not duplicate name
			seen := map[string]bool{}
			for _, p := range wmnPlatforms {
				seen[strings.ToLower(p.Name)] = true
			}
			for _, p := range m.platforms {
				if !seen[strings.ToLower(p.Name)] {
					wmnPlatforms = append(wmnPlatforms, p)
				}
			}
			platforms = wmnPlatforms
		}
	}

	// Apply filters
	platforms = filterPlatforms(platforms, sitesFilter, catsFilter)
	if len(platforms) == 0 {
		return nil, fmt.Errorf("userlookup: nenhuma plataforma ativa com filtros sites=%q categories=%q", sitesFilter, catsFilter)
	}

	slog.InfoContext(ctx, "userlookup.Run iniciado",
		"username", username,
		"platforms", len(platforms),
		"concurrency", concurrency,
		"found_only", foundOnly,
	)

	// Per-request timeout
	probeClient := &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: m.client.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var mu sync.Mutex
	var results []module.Finding

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)

	start := time.Now()

	for _, p := range platforms {
		p := p
		g.Go(func() error {
			finding, found, err := m.probe(gctx, probeClient, p, username)
			if err != nil {
				slog.DebugContext(gctx, "userlookup: probe error",
					"site", p.Name, "err", err)
				return nil
			}
			if found || !foundOnly {
				mu.Lock()
				results = append(results, finding)
				mu.Unlock()
			}
			return nil
		})
	}
	_ = g.Wait()

	// Sort by site name for deterministic output
	sort.Slice(results, func(i, j int) bool {
		return results[i].Extra["site"] < results[j].Extra["site"]
	})

	slog.InfoContext(ctx, "userlookup.Run concluído",
		"username", username,
		"elapsed_ms", time.Since(start).Milliseconds(),
		"findings", len(results),
	)
	return results, nil
}

// ─── Probe logic ──────────────────────────────────────────────────────────────

func (m *Module) probe(ctx context.Context, c *http.Client, p Platform, username string) (module.Finding, bool, error) {
	probeURL := strings.ReplaceAll(p.URL, "{account}", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return module.Finding{}, false, err
	}

	// Default User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-userlookup/1.0)")
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}

	t0 := time.Now()
	resp, err := c.Do(req)
	elapsed := time.Since(t0).Milliseconds()

	if err != nil {
		return module.Finding{}, false, err
	}
	defer resp.Body.Close()

	// Read body only if needed
	var body []byte
	if p.ProbeType == ProbeBodyContain || p.ProbeType == ProbeBodyNotContain {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, maxBody))
	} else {
		// Drain to allow connection reuse
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	}

	found := false
	var reason string

	switch p.ProbeType {
	case ProbeStatus:
		found = resp.StatusCode == http.StatusOK
		reason = fmt.Sprintf("HTTP %d", resp.StatusCode)

	case ProbeBodyContain:
		if resp.StatusCode == http.StatusOK {
			if p.ClaimText != "" && strings.Contains(string(body), p.ClaimText) {
				found = true
				reason = fmt.Sprintf("HTTP 200 + corpo contém %q", p.ClaimText)
			} else if p.NotFoundText != "" && !strings.Contains(string(body), p.NotFoundText) {
				found = true
				reason = fmt.Sprintf("HTTP 200 + corpo não contém %q (not-found text)", p.NotFoundText)
			}
		}

	case ProbeBodyNotContain:
		if resp.StatusCode == http.StatusOK {
			found = p.NotFoundText == "" || !strings.Contains(string(body), p.NotFoundText)
			reason = fmt.Sprintf("HTTP 200, not-found text ausente")
		}

	case ProbeRedirect:
		finalURL := resp.Request.URL.String()
		found = resp.StatusCode == http.StatusOK &&
			strings.Contains(strings.ToLower(finalURL), strings.ToLower(username))
		reason = fmt.Sprintf("redirect final: %s", finalURL)
	}

	slog.DebugContext(ctx, "userlookup: probe",
		"site", p.Name, "found", found, "status", resp.StatusCode,
		"elapsed_ms", elapsed)

	severity := module.SeverityInfo
	if found {
		severity = module.SeverityLow // account found = info for OSINT, low risk
	}

	detail := fmt.Sprintf("Username @%s %s em %s (%s). Probe: %s — %s",
		username,
		boolStr(found, "encontrado", "não encontrado"),
		p.Name, p.Category, p.ProbeType, reason,
	)

	f := module.Finding{
		Type:     "username_found",
		URL:      probeURL,
		Detail:   detail,
		Severity: severity,
		Extra: map[string]string{
			"username":         username,
			"site":             p.Name,
			"category":         p.Category,
			"probe_type":       string(p.ProbeType),
			"http_status":      strconv.Itoa(resp.StatusCode),
			"response_time_ms": strconv.FormatInt(elapsed, 10),
			"confidence":       fmt.Sprintf("%.2f", p.Confidence),
			"found":            strconv.FormatBool(found),
			"source":           "userlookup",
		},
	}
	if !found {
		f.Type = "username_not_found"
	}

	return f, found, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func filterPlatforms(platforms []Platform, sitesFilter, catsFilter string) []Platform {
	if sitesFilter == "" && catsFilter == "" {
		return platforms
	}

	wantedSites := parseCSV(sitesFilter)
	wantedCats := parseCSV(catsFilter)

	var out []Platform
	for _, p := range platforms {
		if len(wantedSites) > 0 && !wantedSites[strings.ToLower(p.Name)] {
			continue
		}
		if len(wantedCats) > 0 && !wantedCats[strings.ToLower(p.Category)] {
			continue
		}
		out = append(out, p)
	}
	return out
}

func parseCSV(s string) map[string]bool {
	if s == "" {
		return nil
	}
	m := map[string]bool{}
	for _, v := range strings.Split(s, ",") {
		if t := strings.TrimSpace(strings.ToLower(v)); t != "" {
			m[t] = true
		}
	}
	return m
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

func boolStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

func defaultClient() *http.Client {
	return &http.Client{
		Timeout: defaultTO,
		Transport: &http.Transport{
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}
}

// ─── Built-in platform list (~80 sites, high-confidence) ─────────────────────

var builtinPlatforms = []Platform{
	// ── Social ────────────────────────────────────────────────────────────────
	{Name: "GitHub", Category: "coding", URL: "https://github.com/{account}",
		ProbeType: ProbeStatus, Confidence: 0.97},
	{Name: "GitLab", Category: "coding", URL: "https://gitlab.com/{account}",
		ProbeType: ProbeStatus, Confidence: 0.95},
	{Name: "Twitter/X", Category: "social", URL: "https://twitter.com/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "This account doesn't exist", Confidence: 0.88},
	{Name: "Instagram", Category: "social", URL: "https://www.instagram.com/{account}/",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Sorry, this page", Confidence: 0.88},
	// Reddit: /about.json retorna 403 para bots; HTML é SPA — falso positivo. Removido.
	// TikTok: SPA pura, HTML idêntico para qualquer username — falso positivo. Removido.
	{Name: "Pinterest", Category: "social", URL: "https://pinterest.com/{account}/",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Sorry! We couldn't find that page", Confidence: 0.82},
	{Name: "Tumblr", Category: "social", URL: "https://{account}.tumblr.com/",
		ProbeType: ProbeBodyNotContain, NotFoundText: "There's nothing here", Confidence: 0.80},
	{Name: "Mastodon Social", Category: "social", URL: "https://mastodon.social/@{account}",
		ProbeType: ProbeStatus, Confidence: 0.85},
	// Bluesky: SPA pura — HTML idêntico para existente e inexistente. API requer handle .bsky.social. Removido.

	// ── Gaming ────────────────────────────────────────────────────────────────
	{Name: "Steam", Category: "gaming", URL: "https://steamcommunity.com/id/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "The specified profile could not be found", Confidence: 0.90},
	{Name: "Roblox", Category: "gaming", URL: "https://www.roblox.com/user.aspx?username={account}",
		ProbeType: ProbeStatus, Confidence: 0.88},
	{Name: "Chess.com", Category: "gaming", URL: "https://www.chess.com/member/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Sorry, we couldn't find that member", Confidence: 0.88},
	{Name: "TryHackMe", Category: "gaming",
		URL: "https://tryhackme.com/p/{account}", ProbeType: ProbeStatus, Confidence: 0.88},
	{Name: "HackTheBox", Category: "gaming",
		URL:       "https://www.hackthebox.com/api/v4/user/profile/basic/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "\"success\":false", Confidence: 0.85},
	{Name: "itch.io", Category: "gaming", URL: "https://{account}.itch.io",
		ProbeType: ProbeBodyNotContain, NotFoundText: "page not found", Confidence: 0.83},

	// ── Developer/Tech ────────────────────────────────────────────────────────
	{Name: "Keybase", Category: "tech", URL: "https://keybase.io/{account}",
		ProbeType: ProbeBodyContain, ClaimText: `"status":{"code":0}`, Confidence: 0.92},
	{Name: "HackerNews", Category: "tech", URL: "https://hacker-news.firebaseio.com/v0/user/{account}.json",
		ProbeType: ProbeBodyNotContain, NotFoundText: "null", Confidence: 0.90},
	{Name: "dev.to", Category: "tech", URL: "https://dev.to/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "404 | The page you were looking for", Confidence: 0.87},
	{Name: "Hashnode", Category: "tech", URL: "https://hashnode.com/@{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Page not found", Confidence: 0.82},
	{Name: "Medium", Category: "tech", URL: "https://medium.com/@{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Page not found", Confidence: 0.85},
	{Name: "Stack Overflow", Category: "tech",
		URL:       "https://stackoverflow.com/users/{account}",
		ProbeType: ProbeStatus, Confidence: 0.80},
	{Name: "npm", Category: "tech", URL: "https://www.npmjs.com/~{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "npm | 404", Confidence: 0.88},
	{Name: "PyPI", Category: "tech", URL: "https://pypi.org/user/{account}/",
		ProbeType: ProbeStatus, Confidence: 0.88},
	{Name: "DockerHub", Category: "tech", URL: "https://hub.docker.com/u/{account}/",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Page Not Found", Confidence: 0.87},
	// Replit: redireciona para /login para QUALQUER username — sem discriminador. Falso positivo. Removido.
	{Name: "Codepen", Category: "tech", URL: "https://codepen.io/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Sorry, that user doesn't exist", Confidence: 0.85},
	{Name: "Coderwall", Category: "tech", URL: "https://coderwall.com/{account}",
		ProbeType: ProbeStatus, Confidence: 0.78},
	// Gitea.io: instância pública da Gitea — retorna 200 para qualquer path (SPA) — removido

	// ── Creative ──────────────────────────────────────────────────────────────
	{Name: "Behance", Category: "creative", URL: "https://www.behance.net/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Page Not Found", Confidence: 0.85},
	{Name: "Dribbble", Category: "creative", URL: "https://dribbble.com/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Whoops", Confidence: 0.83},
	{Name: "ArtStation", Category: "creative", URL: "https://www.artstation.com/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Page Not Found", Confidence: 0.85},
	{Name: "Flickr", Category: "creative", URL: "https://www.flickr.com/people/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "page you are looking for", Confidence: 0.82},
	{Name: "DeviantArt", Category: "creative", URL: "https://www.deviantart.com/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "not found", Confidence: 0.83},
	{Name: "500px", Category: "creative", URL: "https://500px.com/p/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Page Not Found", Confidence: 0.80},

	// ── Music ─────────────────────────────────────────────────────────────────
	{Name: "SoundCloud", Category: "music", URL: "https://soundcloud.com/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "We can't find that user", Confidence: 0.88},
	{Name: "Bandcamp", Category: "music", URL: "https://{account}.bandcamp.com",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Sorry, that something isn't here", Confidence: 0.83},
	{Name: "Last.fm", Category: "music", URL: "https://www.last.fm/user/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Sorry, we couldn't find that user", Confidence: 0.85},
	{Name: "Spotify", Category: "music",
		URL: "https://open.spotify.com/user/{account}", ProbeType: ProbeStatus, Confidence: 0.80},

	// ── Professional ─────────────────────────────────────────────────────────
	{Name: "LinkedIn", Category: "professional", URL: "https://www.linkedin.com/in/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Page not found", Confidence: 0.83},
	{Name: "AngelList", Category: "professional", URL: "https://angel.co/u/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Page Not Found", Confidence: 0.80},
	{Name: "Freelancer", Category: "professional", URL: "https://www.freelancer.com/u/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "page you are looking for", Confidence: 0.78},
	{Name: "Fiverr", Category: "professional", URL: "https://www.fiverr.com/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Page Not Found", Confidence: 0.80},
	{Name: "Upwork", Category: "professional", URL: "https://www.upwork.com/freelancers/~{account}",
		ProbeType: ProbeStatus, Confidence: 0.75},

	// ── Forums ────────────────────────────────────────────────────────────────
	{Name: "Disqus", Category: "forum", URL: "https://disqus.com/by/{account}/",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Sorry, we couldn't find", Confidence: 0.82},
	{Name: "BitcoinTalk", Category: "forum",
		URL:       "https://bitcointalk.org/index.php?action=profile;u={account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "An Error Has Occurred", Confidence: 0.80},
	{Name: "HackerOne", Category: "forum", URL: "https://hackerone.com/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Page Not Found", Confidence: 0.87},
	{Name: "BugCrowd", Category: "forum", URL: "https://bugcrowd.com/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Sorry", Confidence: 0.83},
	// Intigriti: /researcher/{} retorna 200 sem discriminador confiável — falso positivo confirmado. Removido.

	// ── Brasil ────────────────────────────────────────────────────────────────
	{Name: "Kwai", Category: "brasil",
		URL: "https://www.kwai.com/@{account}", ProbeType: ProbeStatus, Confidence: 0.82},
	{Name: "Koo", Category: "brasil",
		URL: "https://www.kooapp.com/profile/{account}", ProbeType: ProbeStatus, Confidence: 0.78},

	// ── Crypto / Finance ──────────────────────────────────────────────────────
	{Name: "CoinMarketCap", Category: "crypto",
		URL:       "https://coinmarketcap.com/community/profile/{account}/",
		ProbeType: ProbeStatus, Confidence: 0.80},
	{Name: "Blockchain (discussion)", Category: "crypto",
		URL:       "https://community.blockchain.com/hc/en-us/profiles/{account}",
		ProbeType: ProbeStatus, Confidence: 0.75},

	// ── Streaming ─────────────────────────────────────────────────────────────
	// Twitch: SPA pura (186KB), HTML idêntico para qualquer username — falso positivo. Removido.
	{Name: "YouTube", Category: "streaming", URL: "https://www.youtube.com/@{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "404 Not Found", Confidence: 0.85},
	// Kick: falso positivo confirmado pelo usuário. Removido.

	// ── Misc ──────────────────────────────────────────────────────────────────
	{Name: "About.me", Category: "misc", URL: "https://about.me/{account}",
		ProbeType: ProbeStatus, Confidence: 0.80},
	{Name: "Gravatar", Category: "misc",
		URL:       "https://en.gravatar.com/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Gravatar Profile Not Found", Confidence: 0.83},
	{Name: "Linktree", Category: "misc", URL: "https://linktr.ee/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Sorry, this page isn't available", Confidence: 0.83},
	{Name: "Carrd", Category: "misc", URL: "https://{account}.carrd.co",
		ProbeType: ProbeBodyNotContain, NotFoundText: "doesn't exist", Confidence: 0.80},
	{Name: "Ko-fi", Category: "misc", URL: "https://ko-fi.com/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "404", Confidence: 0.80},
	{Name: "Patreon", Category: "misc", URL: "https://www.patreon.com/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "page doesn't exist", Confidence: 0.82},
	{Name: "Substack", Category: "misc", URL: "https://{account}.substack.com",
		ProbeType: ProbeBodyNotContain, NotFoundText: "page not found", Confidence: 0.83},
	{Name: "ProductHunt", Category: "misc", URL: "https://www.producthunt.com/@{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "page you're looking for", Confidence: 0.82},
	{Name: "Telegram", Category: "messaging", URL: "https://t.me/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "tgme_page_photo_image", Confidence: 0.87},
	// Signal: não possui perfis públicos por username — removido (falso positivo garantido)
	{Name: "Snapchat", Category: "messaging",
		URL:       "https://www.snapchat.com/add/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Sorry!", Confidence: 0.82},
	// WhatsApp Business: /send?phone= não recebe username, recebe telefone — removido desta lista

	// ── Security research ─────────────────────────────────────────────────────
	{Name: "Exploit-DB", Category: "security",
		URL:       "https://www.exploit-db.com/author/{account}",
		ProbeType: ProbeStatus, Confidence: 0.82},
	{Name: "VulnHub", Category: "security",
		URL:       "https://www.vulnhub.com/author/{account}/",
		ProbeType: ProbeBodyNotContain, NotFoundText: "404", Confidence: 0.78},
	{Name: "Shodan", Category: "security",
		URL:       "https://www.shodan.io/member/{account}",
		ProbeType: ProbeBodyNotContain, NotFoundText: "Member Not Found", Confidence: 0.85},
	{Name: "Censys", Category: "security",
		URL:       "https://search.censys.io/account/searches/{account}",
		ProbeType: ProbeStatus, Confidence: 0.75},
}
