// Package telegramosint gathers open-source intelligence from public Telegram
// resources without requiring a user session or MTProto credentials.
//
// Data sources:
//   - t.me public preview pages (HTML scraping — no auth required)
//   - Telegram Bot API (optional bot_token for channel metadata)
//   - Fragment.io (Telegram username marketplace — public, no auth)
//   - ComBot.ru public statistics (channel member counts, categories)
//
// What it checks for a given @username or t.me URL:
//   - Entity type: channel, group, bot, or user
//   - Title, description, member count, subscriber count
//   - Verification status and scam flag
//   - Username availability and registration on Fragment
//   - Linked website presence (for further OSINT)
//   - Phone numbers, email addresses extracted from description
//   - Mentions of other Telegram accounts in description
//   - Bot-specific: bot commands, inline mode support
//
// Security notes (dicas §18):
//   - Never connects to .onion addresses
//   - No MTProto login — only public HTTP endpoints
//   - Phone numbers extracted from public descriptions are already public
//   - Redacts sensitive values from logs
//
// Usage:
//
//	m := telegramosint.New()
//	findings, err := m.Run(ctx, module.Input{
//	    Target: "@durov",      // or "https://t.me/durov" or "durov"
//	    Options: map[string]string{
//	        "bot_token": os.Getenv("TELEGRAM_BOT_TOKEN"), // optional
//	        "sources":   "preview,botapi,fragment",
//	    },
//	})
package telegramosint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	maxBodyTg    = 256 * 1024 // 256 KB
	maxParallel  = 4
	tmeBase      = "https://t.me"
	botAPIBase   = "https://api.telegram.org/bot"
	fragmentBase = "https://fragment.com"
)

// ─── regex patterns ───────────────────────────────────────────────────────────

var (
	// Extract phone numbers from public descriptions
	rePhone = regexp.MustCompile(`(?:\+\d{1,3}[\s\-]?)?\(?\d{2,4}\)?[\s\-]?\d{4,5}[\s\-]?\d{4}`)
	// Extract emails
	reEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	// Mentions of other Telegram accounts
	reMention = regexp.MustCompile(`@([a-zA-Z][a-zA-Z0-9_]{4,31})`)
	// t.me links in description
	reTmeLink = regexp.MustCompile(`(?i)t\.me/([a-zA-Z][a-zA-Z0-9_]{4,31})`)
	// Extract member count from HTML preview
	reMembers = regexp.MustCompile(`(?i)(\d[\d\s,\.]+)\s*(members?|subscribers?|подписчик)`)
	// t.me preview title
	reTitle = regexp.MustCompile(`(?i)<meta property="og:title" content="([^"]+)"`)
	// t.me preview description
	reDesc = regexp.MustCompile(`(?i)<meta property="og:description" content="([^"]+)"`)
	// t.me preview type
	reType = regexp.MustCompile(`(?i)tgme_page_extra">([^<]+)<`)
	// Scam flag
	reScam = regexp.MustCompile(`(?i)(scam|fraud|спам|скам)`)
	// Verification badge
	reVerified = regexp.MustCompile(`(?i)tgme_page_verified`)
)

// ─── Bot API types ────────────────────────────────────────────────────────────

type tgAPIResponse struct {
	OK          bool            `json:"ok"`
	Description string          `json:"description"`
	Result      json.RawMessage `json:"result"`
}

type tgChat struct {
	ID          int64  `json:"id"`
	Type        string `json:"type"` // "channel", "group", "supergroup", "private"
	Title       string `json:"title"`
	Username    string `json:"username"`
	Description string `json:"description"`
	MemberCount int    `json:"member_count"`
	InviteLink  string `json:"invite_link"`
	Photo       struct {
		SmallFileID string `json:"small_file_id"`
	} `json:"photo"`
	HasProtectedContent bool  `json:"has_protected_content"`
	IsForum             bool  `json:"is_forum"`
	LinkedChatID        int64 `json:"linked_chat_id"`
}

type tgMemberCount struct {
	Count int `json:"count"`
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements module.Module for Telegram OSINT.
type Module struct {
	client *http.Client
}

// New returns a Module with default HTTP client.
func New() *Module { return NewWithClient(defaultClient()) }

// NewWithClient injects a custom HTTP client.
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

// Name returns the canonical module identifier.
func (m *Module) Name() string { return "telegramosint" }

// Run gathers OSINT on a Telegram entity.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("telegramosint: target vazio")
	}

	username := normaliseTarget(target)
	if username == "" {
		return nil, fmt.Errorf("telegramosint: não foi possível extrair username de '%s'", target)
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	sourcesFilter := opts["sources"]

	slog.InfoContext(ctx, "telegramosint.Run iniciado",
		"username", username,
		"sources", sourcesFilter,
	)

	type sourceFunc struct {
		name string
		fn   func(context.Context, string, map[string]string) ([]module.Finding, error)
	}

	sources := []sourceFunc{
		{"preview", m.scrapePreview},
		{"botapi", m.queryBotAPI},
		{"fragment", m.scrapeFragment},
	}

	var mu sync.Mutex
	var all []module.Finding

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxParallel)

	for _, s := range sources {
		s := s
		if !isWanted(sourcesFilter, s.name) {
			continue
		}
		g.Go(func() error {
			findings, err := s.fn(gctx, username, opts)
			if err != nil {
				slog.WarnContext(gctx, "telegramosint: source com erro",
					"source", s.name, "username", username, "err", err)
				return nil
			}
			mu.Lock()
			all = append(all, findings...)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	result := dedup(all)
	slog.InfoContext(ctx, "telegramosint.Run concluído",
		"username", username,
		"findings", len(result),
	)
	return result, nil
}

// ─── t.me HTML preview scraper ────────────────────────────────────────────────

func (m *Module) scrapePreview(ctx context.Context, username string, opts map[string]string) ([]module.Finding, error) {
	pageURL := fmt.Sprintf("%s/%s", tmeBase, username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "TelegramBot (https://core.telegram.org/bots/api, 7.0)")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("preview: @%s não encontrado (404)", username)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("preview: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyTg))
	if err != nil {
		return nil, err
	}
	html := string(body)

	var findings []module.Finding

	// ── Extract title ──
	title := extractFirst(reTitle, html)
	desc := extractFirst(reDesc, html)
	entityType := extractEntityType(html)

	// ── Main entity finding ──
	if title != "" {
		severity := module.SeverityInfo
		confidence := "0.92"
		detail := fmt.Sprintf("Entidade Telegram @%s: tipo=%s, título='%s'", username, entityType, title)
		if desc != "" {
			detail += fmt.Sprintf(", descrição='%s'", truncate(desc, 200))
		}

		// Extract member count
		memberMatch := reMembers.FindStringSubmatch(html)
		memberCount := ""
		if len(memberMatch) >= 2 {
			memberCount = strings.ReplaceAll(strings.TrimSpace(memberMatch[1]), " ", "")
			detail += fmt.Sprintf(", membros/assinantes: %s", memberCount)
		}

		// Check for scam
		if reScam.MatchString(title + " " + desc) {
			severity = module.SeverityHigh
			detail += " [ALERTA: possível scam/fraude]"
			confidence = "0.72"
		}

		extra := map[string]string{
			"confidence":  confidence,
			"username":    username,
			"title":       title,
			"entity_type": entityType,
			"source":      "tme_preview",
			"url":         pageURL,
		}
		if desc != "" {
			extra["description"] = truncate(desc, 300)
		}
		if memberCount != "" {
			extra["member_count"] = memberCount
		}
		if reVerified.MatchString(html) {
			extra["verified"] = "true"
		}

		findings = append(findings, module.Finding{
			Type:     "telegram_entity",
			URL:      pageURL,
			Detail:   detail,
			Severity: severity,
			Extra:    extra,
		})
	}

	// ── Extract phones from description ──
	fullText := title + " " + desc
	for _, phone := range rePhone.FindAllString(fullText, 10) {
		phone = strings.TrimSpace(phone)
		if len(phone) < 8 {
			continue
		}
		findings = append(findings, module.Finding{
			Type:     "phone_number_exposed",
			URL:      pageURL,
			Detail:   fmt.Sprintf("Número de telefone '%s' encontrado na descrição pública do perfil Telegram @%s.", phone, username),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"confidence": "0.80",
				"phone":      phone,
				"source":     "tme_preview",
			},
		})
	}

	// ── Extract emails from description ──
	for _, email := range reEmail.FindAllString(fullText, 10) {
		// Redact full email per dicas §18 — show domain only in logs
		slog.DebugContext(ctx, "telegramosint: email extraído",
			"domain", emailDomain(email), "username", username)
		findings = append(findings, module.Finding{
			Type:     "email_exposed",
			URL:      pageURL,
			Detail:   fmt.Sprintf("Email (domínio: %s) encontrado na descrição pública do perfil Telegram @%s.", emailDomain(email), username),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"confidence":   "0.85",
				"email_domain": emailDomain(email),
				"source":       "tme_preview",
			},
		})
	}

	// ── Extract mentions of other accounts ──
	mentionsSeen := map[string]bool{}
	for _, m2 := range reMention.FindAllStringSubmatch(fullText, 20) {
		mentioned := strings.ToLower(m2[1])
		if mentioned == username || mentionsSeen[mentioned] {
			continue
		}
		mentionsSeen[mentioned] = true
		findings = append(findings, module.Finding{
			Type:     "telegram_mention",
			URL:      fmt.Sprintf("%s/%s", tmeBase, mentioned),
			Detail:   fmt.Sprintf("Perfil @%s menciona @%s na descrição pública. Pode indicar relação entre contas.", username, mentioned),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"confidence": "0.82",
				"mentioned":  "@" + mentioned,
				"by":         "@" + username,
				"source":     "tme_preview",
			},
		})
	}

	// ── t.me links in description ──
	for _, tmeMatch := range reTmeLink.FindAllStringSubmatch(fullText, 10) {
		linked := strings.ToLower(tmeMatch[1])
		if linked == username || mentionsSeen[linked] {
			continue
		}
		mentionsSeen[linked] = true
		findings = append(findings, module.Finding{
			Type:     "telegram_linked_account",
			URL:      fmt.Sprintf("%s/%s", tmeBase, linked),
			Detail:   fmt.Sprintf("Link para @%s encontrado na descrição de @%s.", linked, username),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"confidence": "0.88",
				"linked":     "@" + linked,
				"source":     "tme_preview",
			},
		})
	}

	return findings, nil
}

// ─── Telegram Bot API ─────────────────────────────────────────────────────────

func (m *Module) queryBotAPI(ctx context.Context, username string, opts map[string]string) ([]module.Finding, error) {
	botToken := opts["bot_token"]
	if botToken == "" {
		return nil, fmt.Errorf("botapi: bot_token não configurado")
	}

	// getChat
	chatURL := fmt.Sprintf("%s%s/getChat?chat_id=@%s", botAPIBase, botToken, username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, chatURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyTg))
	if err != nil {
		return nil, err
	}

	var apiResp tgAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("botapi: parse: %w", err)
	}

	if !apiResp.OK {
		return nil, fmt.Errorf("botapi: %s", apiResp.Description)
	}

	var chat tgChat
	if err := json.Unmarshal(apiResp.Result, &chat); err != nil {
		return nil, fmt.Errorf("botapi: parse chat: %w", err)
	}

	entityURL := fmt.Sprintf("%s/%s", tmeBase, username)
	var findings []module.Finding

	// Get member count separately
	countURL := fmt.Sprintf("%s%s/getChatMemberCount?chat_id=@%s", botAPIBase, botToken, username)
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, countURL, nil)
	resp2, err2 := m.client.Do(req2)
	memberCount := 0
	if err2 == nil {
		defer resp2.Body.Close()
		body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 64*1024))
		var cr tgAPIResponse
		if json.Unmarshal(body2, &cr) == nil && cr.OK {
			var mc tgMemberCount
			_ = json.Unmarshal(cr.Result, &mc)
			memberCount = mc.Count
		}
	}

	detail := fmt.Sprintf("Telegram @%s via Bot API: tipo=%s, título='%s'", username, chat.Type, chat.Title)
	if chat.Description != "" {
		detail += fmt.Sprintf(", descrição='%s'", truncate(chat.Description, 200))
	}
	if memberCount > 0 {
		detail += fmt.Sprintf(", membros=%d", memberCount)
	}

	extra := map[string]string{
		"confidence": "0.95",
		"chat_id":    fmt.Sprintf("%d", chat.ID),
		"chat_type":  chat.Type,
		"title":      chat.Title,
		"source":     "telegram_botapi",
	}
	if memberCount > 0 {
		extra["member_count"] = fmt.Sprintf("%d", memberCount)
	}
	if chat.InviteLink != "" {
		extra["invite_link"] = chat.InviteLink
	}
	if chat.HasProtectedContent {
		extra["protected_content"] = "true"
	}

	findings = append(findings, module.Finding{
		Type:     "telegram_entity",
		URL:      entityURL,
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra:    extra,
	})

	// Protected content = may be hiding something
	if chat.HasProtectedContent {
		findings = append(findings, module.Finding{
			Type:     "telegram_protected_content",
			URL:      entityURL,
			Detail:   fmt.Sprintf("Canal/grupo @%s tem conteúdo protegido habilitado (não permite encaminhar mensagens). Pode indicar informações sensíveis sendo compartilhadas.", username),
			Severity: module.SeverityLow,
			Extra: map[string]string{
				"confidence": "0.70",
				"source":     "telegram_botapi",
			},
		})
	}

	return findings, nil
}

// ─── Fragment.io scraper ──────────────────────────────────────────────────────

func (m *Module) scrapeFragment(ctx context.Context, username string, opts map[string]string) ([]module.Finding, error) {
	// Fragment.io shows if a username is listed for sale / recently auctioned
	pageURL := fmt.Sprintf("%s/username/%s", fragmentBase, username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-telegramosint/1.0)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Not on Fragment = fine, no finding
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fragment: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyTg))
	if err != nil {
		return nil, err
	}
	html := string(body)

	var findings []module.Finding

	// Check if username appears on Fragment (sold/available)
	// Fragment pages have "Available" or "Sold" or price info
	switch {
	case strings.Contains(html, "Available") || strings.Contains(html, "Auction"):
		findings = append(findings, module.Finding{
			Type:     "telegram_username_available_fragment",
			URL:      pageURL,
			Detail:   fmt.Sprintf("Username @%s está disponível ou em leilão no Fragment.com (marketplace de usernames Telegram).", username),
			Severity: module.SeverityLow,
			Extra: map[string]string{
				"confidence":   "0.82",
				"fragment_url": pageURL,
				"source":       "fragment",
			},
		})
	case strings.Contains(html, "Sold"):
		findings = append(findings, module.Finding{
			Type:     "telegram_username_sold_fragment",
			URL:      pageURL,
			Detail:   fmt.Sprintf("Username @%s foi vendido no Fragment.com. Pode indicar mudança recente de proprietário.", username),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"confidence":   "0.78",
				"fragment_url": pageURL,
				"source":       "fragment",
			},
		})
	}

	return findings, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func normaliseTarget(s string) string {
	// Strip URL prefix
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "https://t.me/")
	s = strings.TrimPrefix(s, "http://t.me/")
	s = strings.TrimPrefix(s, "t.me/")
	s = strings.TrimPrefix(s, "@")
	s = strings.Split(s, "?")[0]
	s = strings.Split(s, "/")[0]
	s = strings.TrimSpace(s)
	if len(s) < 5 {
		return ""
	}
	return strings.ToLower(s)
}

func extractFirst(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func extractEntityType(html string) string {
	if strings.Contains(html, "tgme_page_context_action") {
		if strings.Contains(html, "tgme_channel_info") || strings.Contains(html, "View Channel") {
			return "channel"
		}
		if strings.Contains(html, "View Group") || strings.Contains(html, "Join Group") {
			return "group"
		}
		if strings.Contains(html, "Open in Telegram") {
			return "user"
		}
	}
	return "unknown"
}

func emailDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return "unknown"
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
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

func defaultClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     60 * time.Second,
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
