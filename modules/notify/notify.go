// Package notify dispatches security findings to notification channels.
// Supported providers (all configurable, no API key required for webhook-based):
//   - slack:    Incoming Webhook POST (JSON payload)
//   - discord:  Webhook POST (JSON embed payload)
//   - telegram: Bot API sendMessage (requires token + chat_id)
//   - teams:    MS Teams Incoming Webhook (MessageCard JSON)
//   - webhook:  Generic HTTP POST with JSON body
//   - custom:   Arbitrary HTTP POST with Go text/template body
//
// Reference: projectdiscovery/notify (MIT) — API shape only, no code copied.
// License: MIT (blackhorn-modules).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	defaultTimeout  = 15 * time.Second
	maxResponseBody = 64 * 1024 // 64 KiB — notification responses are tiny
)

// ─── provider config ─────────────────────────────────────────────────────────

// Provider defines a single notification target.
type Provider struct {
	// Kind is one of: "slack", "discord", "telegram", "teams", "webhook", "custom".
	Kind string
	// WebhookURL is the full webhook URL (for slack, discord, teams, webhook).
	WebhookURL string
	// Token and ChatID are required for Telegram Bot API.
	Token  string // bot token  (e.g. "123456:AABB...")
	ChatID string // chat/group ID (e.g. "-100123")
	// Template is a Go text/template used only for Kind=="custom".
	// Template variables: .Type, .URL, .Detail, .Severity, .Extra (map[string]string).
	Template string
	// HTTPMethod overrides the HTTP method for Kind=="webhook" or "custom" (default POST).
	HTTPMethod string
	// Headers are additional HTTP headers to send with the request.
	Headers map[string]string
}

// ─── module ──────────────────────────────────────────────────────────────────

// Module dispatches module.Finding values to one or more notification Providers.
type Module struct {
	client    *http.Client
	Providers []Provider
	// MinSeverity filters findings below this severity (default: Info = no filter).
	MinSeverity module.Severity
}

// New returns a Module with production defaults.
func New(providers []Provider) *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		Providers:   providers,
		MinSeverity: module.SeverityInfo,
	}
}

// NewWithClient creates a Module using the provided HTTP client.
func NewWithClient(c *http.Client, providers []Provider) *Module {
	return &Module{
		client:      c,
		Providers:   providers,
		MinSeverity: module.SeverityInfo,
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "notify" }

// Run implements module.Module.
//
// Input.RawContent: newline-delimited pre-formatted messages to dispatch as-is.
// Otherwise, Run forwards each finding in input.Findings to all providers.
//
// Findings slice is passed via Input.Extra["findings_json"] as a JSON array,
// or as input.RawContent (one message per line for plain text dispatch).
//
// Returns one Finding per successful dispatch (type="notification_sent").
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	if len(m.Providers) == 0 {
		return nil, nil
	}

	// Build the list of messages to dispatch.
	messages, err := buildMessages(input)
	if err != nil {
		return nil, err
	}
	if len(messages) == 0 {
		return nil, nil
	}

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(len(m.Providers) * len(messages))

	for _, p := range m.Providers {
		for _, msg := range messages {
			p, msg := p, msg
			g.Go(func() error {
				err := m.dispatch(gctx, p, msg)
				if err != nil {
					slog.Warn("notify: dispatch failed", "provider", p.Kind, "err", err)
					return nil // soft failure — continue with other providers
				}
				mu.Lock()
				findings = append(findings, module.Finding{
					Type:     "notification_sent",
					URL:      webhookURL(p),
					Severity: module.SeverityInfo,
					Detail:   fmt.Sprintf("Notification dispatched via %s", p.Kind),
					Extra: map[string]string{
						"provider":   p.Kind,
						"message":    truncate(msg.text, 120),
						"confidence": "0.99",
					},
				})
				mu.Unlock()
				return nil
			})
		}
	}

	_ = g.Wait()
	return findings, nil
}

// ─── message model ────────────────────────────────────────────────────────────

type message struct {
	text    string            // plain/markdown text
	finding *module.Finding   // original finding (for template rendering)
	extra   map[string]string // arbitrary key-value for template
}

// buildMessages converts Input into a slice of messages ready to dispatch.
func buildMessages(input module.Input) ([]message, error) {
	var msgs []message

	// 1. RawContent: each non-empty line is a plain-text message.
	if input.RawContent != "" {
		for _, line := range strings.Split(input.RawContent, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				msgs = append(msgs, message{text: line})
			}
		}
		return msgs, nil
	}

	// 2. findings_json in Options: array of module.Finding serialized as JSON.
	if input.Options != nil {
		if raw, ok := input.Options["findings_json"]; ok && raw != "" {
			var ff []module.Finding
			if err := json.Unmarshal([]byte(raw), &ff); err != nil {
				return nil, fmt.Errorf("notify: invalid findings_json: %w", err)
			}
			for i := range ff {
				f := ff[i]
				msgs = append(msgs, message{
					text:    findingText(f),
					finding: &f,
				})
			}
			return msgs, nil
		}
	}

	// 3. Single Target as a plain message.
	if input.Target != "" {
		msgs = append(msgs, message{text: input.Target})
	}
	return msgs, nil
}

// findingText renders a finding as a compact human-readable string.
func findingText(f module.Finding) string {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("[%s] %s %s — %s", f.Severity, f.Type, f.URL, f.Detail))
	return sb.String()
}

// ─── dispatch ────────────────────────────────────────────────────────────────

func (m *Module) dispatch(ctx context.Context, p Provider, msg message) error {
	switch strings.ToLower(p.Kind) {
	case "slack":
		return m.dispatchSlack(ctx, p, msg)
	case "discord":
		return m.dispatchDiscord(ctx, p, msg)
	case "telegram":
		return m.dispatchTelegram(ctx, p, msg)
	case "teams":
		return m.dispatchTeams(ctx, p, msg)
	case "webhook":
		return m.dispatchWebhook(ctx, p, msg)
	case "custom":
		return m.dispatchCustom(ctx, p, msg)
	default:
		return fmt.Errorf("unknown provider kind: %q", p.Kind)
	}
}

// ── Slack ─────────────────────────────────────────────────────────────────────

type slackPayload struct {
	Text string `json:"text"`
}

func (m *Module) dispatchSlack(ctx context.Context, p Provider, msg message) error {
	payload := slackPayload{Text: msg.text}
	return m.postJSON(ctx, p, payload)
}

// ── Discord ───────────────────────────────────────────────────────────────────

type discordPayload struct {
	Content string `json:"content"`
}

func (m *Module) dispatchDiscord(ctx context.Context, p Provider, msg message) error {
	payload := discordPayload{Content: msg.text}
	return m.postJSON(ctx, p, payload)
}

// ── Telegram ──────────────────────────────────────────────────────────────────

type telegramPayload struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode,omitempty"`
}

func (m *Module) dispatchTelegram(ctx context.Context, p Provider, msg message) error {
	if p.Token == "" || p.ChatID == "" {
		return fmt.Errorf("telegram provider requires Token and ChatID")
	}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", p.Token)
	payload := telegramPayload{ChatID: p.ChatID, Text: msg.text, ParseMode: "Markdown"}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return m.doRequest(ctx, p, http.MethodPost, apiURL, body)
}

// ── MS Teams ──────────────────────────────────────────────────────────────────

// teamsPayload implements the legacy MessageCard format.
type teamsPayload struct {
	Type    string `json:"@type"`
	Context string `json:"@context"`
	Text    string `json:"text"`
}

func (m *Module) dispatchTeams(ctx context.Context, p Provider, msg message) error {
	payload := teamsPayload{
		Type:    "MessageCard",
		Context: "https://schema.org/extensions",
		Text:    msg.text,
	}
	return m.postJSON(ctx, p, payload)
}

// ── Generic webhook ───────────────────────────────────────────────────────────

type webhookPayload struct {
	Message string            `json:"message"`
	Extra   map[string]string `json:"extra,omitempty"`
}

func (m *Module) dispatchWebhook(ctx context.Context, p Provider, msg message) error {
	payload := webhookPayload{Message: msg.text, Extra: msg.extra}
	return m.postJSON(ctx, p, payload)
}

// ── Custom template ───────────────────────────────────────────────────────────

type templateVars struct {
	Type     string
	URL      string
	Detail   string
	Severity string
	Extra    map[string]string
	Message  string
}

func (m *Module) dispatchCustom(ctx context.Context, p Provider, msg message) error {
	if p.Template == "" {
		return fmt.Errorf("custom provider requires a Template")
	}
	tpl, err := template.New("notify").Parse(p.Template)
	if err != nil {
		return fmt.Errorf("custom template parse error: %w", err)
	}

	vars := templateVars{Message: msg.text}
	if msg.finding != nil {
		f := msg.finding
		vars.Type = f.Type
		vars.URL = f.URL
		vars.Detail = f.Detail
		vars.Severity = string(f.Severity)
		vars.Extra = f.Extra
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, vars); err != nil {
		return fmt.Errorf("custom template execute error: %w", err)
	}

	method := p.HTTPMethod
	if method == "" {
		method = http.MethodPost
	}
	return m.doRequest(ctx, p, method, p.WebhookURL, buf.Bytes())
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

// postJSON marshals v and POSTs it to p.WebhookURL.
func (m *Module) postJSON(ctx context.Context, p Provider, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return m.doRequest(ctx, p, http.MethodPost, p.WebhookURL, body)
}

// doRequest sends an HTTP request with the given method, URL, and body.
func (m *Module) doRequest(ctx context.Context, p Provider, method, rawURL string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "blackhorn-notify/1.0")
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Drain body to allow connection reuse.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify: provider %s returned HTTP %d", p.Kind, resp.StatusCode)
	}
	return nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func webhookURL(p Provider) string {
	if p.WebhookURL != "" {
		return p.WebhookURL
	}
	if p.Token != "" {
		return "telegram://bot" + p.Token
	}
	return p.Kind
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
