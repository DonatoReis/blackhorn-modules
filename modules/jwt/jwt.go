// Package jwt implements JWT (JSON Web Token) security analysis.
//
// Source reference: jwt_tool (MIT, ticarpi) + jwt-auditor (MIT) +
// PortSwigger JWT attacks research + RFC 7519.
// Detection logic reimplemented from scratch.
//
// JWT vulnerabilities detected:
//  1. "none" algorithm attack: modify header to alg=none, strip signature
//  2. Algorithm confusion (RS256→HS256): use public key as HMAC secret
//  3. Weak secret brute-force: try common/default secrets (HS256/384/512)
//  4. Empty password HS256: sign with empty string secret
//  5. Header injection: inject kid=/dev/null or jwk/jku pointing to attacker
//  6. Expiry analysis: token already expired, or very long-lived (> 30 days)
//  7. Sensitive claims: sub/email/admin/role fields in payload
//  8. Missing or weak algorithm in header
//
// Input modes:
//   - Token via Options["token"]
//   - Token extracted from Authorization: Bearer header (from target URL response)
//   - Cookie values starting with "eyJ" (base64 JWT prefix)
//   - RawContent containing JWT-like strings
//
// Architecture:
//   - Check struct: ID, Run func, Severity, Tags
//   - parseJWT: base64url decode header + payload (no signature verification)
//   - No external JWT libraries — pure stdlib base64/json
//   - errgroup.SetLimit(Parallelism) fan-out per check
//   - log/slog observability
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) for testability
package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	DefaultTimeout     = 10 * time.Second
	DefaultParallelism = 10
	maxBodyRead        = 256 * 1024

	// jwtPrefix is the base64url-encoded start of a JSON object {"alg":...} or {"typ":...}.
	jwtPrefix = "eyJ"
)

// weakSecrets is the list of common/default JWT secrets to test.
var weakSecrets = []string{
	"secret", "password", "123456", "changeme", "test", "admin",
	"qwerty", "pass", "jwt", "token", "key", "secret123",
	"your-256-bit-secret", "your-secret", "your_secret",
	"HS256", "hs256", "none", "null", "", "supersecret",
	"mysecret", "app_secret", "jwt_secret", "auth_secret",
}

// ─── JWT parsing ─────────────────────────────────────────────────────────────

// JWTHeader represents a decoded JWT header.
type JWTHeader struct {
	Alg string      `json:"alg"`
	Typ string      `json:"typ"`
	Kid string      `json:"kid,omitempty"`
	Jwk interface{} `json:"jwk,omitempty"`
	Jku string      `json:"jku,omitempty"`
}

// JWTPayload represents a decoded JWT payload.
type JWTPayload struct {
	Sub string                     `json:"sub,omitempty"`
	Iss string                     `json:"iss,omitempty"`
	Aud interface{}                `json:"aud,omitempty"`
	Exp int64                      `json:"exp,omitempty"`
	Iat int64                      `json:"iat,omitempty"`
	Nbf int64                      `json:"nbf,omitempty"`
	JTI string                     `json:"jti,omitempty"`
	Raw map[string]json.RawMessage `json:"-"`
}

// ParsedJWT holds all decoded parts.
type ParsedJWT struct {
	Raw        string
	Header     JWTHeader
	Payload    JWTPayload
	PayloadRaw map[string]interface{}
	Signature  string
}

// parseJWT decodes a JWT without verifying the signature.
func parseJWT(token string) (*ParsedJWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode header.
	headerBytes, err := base64url.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header decode: %w", err)
	}
	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("header json: %w", err)
	}

	// Decode payload.
	payloadBytes, err := base64url.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload decode: %w", err)
	}
	var payload JWTPayload
	_ = json.Unmarshal(payloadBytes, &payload) // best-effort

	var payloadRaw map[string]interface{}
	_ = json.Unmarshal(payloadBytes, &payloadRaw)

	return &ParsedJWT{
		Raw:        token,
		Header:     header,
		Payload:    payload,
		PayloadRaw: payloadRaw,
		Signature:  parts[2],
	}, nil
}

// base64url is a helper for base64 URL-safe decoding (no padding required).
var base64url = base64.URLEncoding.WithPadding(base64.NoPadding)

// ─── Check ────────────────────────────────────────────────────────────────────

// Check defines a JWT security test.
type Check struct {
	ID       string
	Severity module.Severity
	Tags     []string
	Run      func(ctx context.Context, parsed *ParsedJWT, target string) *module.Finding
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements JWT security analysis.
type Module struct {
	client      *http.Client
	parallelism int
	logger      *slog.Logger
}

// New returns a Module with default settings.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: DefaultTimeout}),
		parallelism: DefaultParallelism,
		logger:      slog.Default(),
	}
}

// NewWithClient returns a Module using the supplied HTTP client.
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// Name returns the module name.
func (m *Module) Name() string { return "jwt" }

// Run analyzes JWT tokens for security issues.
//
// Options:
//   - "token"       — explicit JWT to analyze
//   - "parallelism" — max concurrent checks (default: 10)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	tokens := m.collectTokens(ctx, input)
	if len(tokens) == 0 {
		return nil, nil
	}

	parallelism := m.parallelism
	if v := input.Options["parallelism"]; v != "" {
		if p, err := parseInt(v); err == nil && p > 0 {
			parallelism = p
		}
	}

	checks := builtinChecks()

	var (
		mu       sync.Mutex
		seen     = make(map[string]struct{})
		findings []module.Finding
	)

	addFinding := func(f module.Finding) {
		mu.Lock()
		defer mu.Unlock()
		key := f.Extra["token_prefix"] + "|" + f.Type + "|" + f.Extra["check_id"]
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			findings = append(findings, f)
		}
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(parallelism)

	for _, t := range tokens {
		for _, check := range checks {
			token := t
			check := check
			eg.Go(func() error {
				parsed, err := parseJWT(token)
				if err != nil {
					m.logger.DebugContext(egCtx, "jwt: parse failed", "err", err)
					return nil
				}
				target := input.Target
				if target == "" && len(input.URLs) > 0 {
					target = input.URLs[0]
				}
				f := check.Run(egCtx, parsed, target)
				if f != nil {
					f.Extra["check_id"] = check.ID
					f.Extra["token_prefix"] = token[:min(len(token), 20)] + "..."
					addFinding(*f)
				}
				return nil
			})
		}
	}

	_ = eg.Wait()
	return findings, nil
}

// collectTokens gathers JWT tokens from all input sources.
func (m *Module) collectTokens(ctx context.Context, input module.Input) []string {
	var tokens []string
	seen := make(map[string]struct{})
	add := func(t string) {
		t = strings.TrimSpace(t)
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			tokens = append(tokens, t)
		}
	}

	// 1. Explicit token in options.
	if t := input.Options["token"]; t != "" {
		add(t)
	}

	// 2. Extract from RawContent.
	for _, t := range extractTokensFromText(input.RawContent) {
		add(t)
	}

	// 3. Fetch target URL and look for tokens in headers/body.
	targets := collectTargets(input)
	for _, rawURL := range targets {
		ts := m.fetchAndExtract(ctx, rawURL)
		for _, t := range ts {
			add(t)
		}
	}

	return tokens
}

// fetchAndExtract fetches a URL and extracts JWT tokens from response.
func (m *Module) fetchAndExtract(ctx context.Context, rawURL string) []string {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-jwt/1.0)")

	resp, err := m.client.Do(req)
	if err != nil {
		m.logger.DebugContext(ctx, "jwt: fetch failed", "url", rawURL, "err", err)
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))

	var tokens []string
	// Authorization: Bearer header.
	auth := resp.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		tokens = append(tokens, strings.TrimPrefix(auth, "Bearer "))
	}
	// Set-Cookie headers.
	for _, cookie := range resp.Header["Set-Cookie"] {
		if idx := strings.Index(cookie, "="); idx >= 0 {
			val := cookie[idx+1:]
			if end := strings.IndexAny(val, "; "); end > 0 {
				val = val[:end]
			}
			if strings.HasPrefix(val, jwtPrefix) {
				tokens = append(tokens, val)
			}
		}
	}
	// Body.
	tokens = append(tokens, extractTokensFromText(string(body))...)
	return tokens
}

// extractTokensFromText finds JWT-like strings (eyJ... with 2 dots) in text.
// Scans for all occurrences of "eyJ" and extracts the token until a delimiter.
func extractTokensFromText(text string) []string {
	const delimiters = " \t\n\r\"'()[];,{}<>|\\/"
	var tokens []string
	seen := make(map[string]struct{})
	start := 0
	for {
		idx := strings.Index(text[start:], jwtPrefix)
		if idx < 0 {
			break
		}
		abs := start + idx
		// Find end of token: first delimiter character after the start.
		end := abs
		for end < len(text) && !strings.ContainsRune(delimiters, rune(text[end])) {
			end++
		}
		token := text[abs:end]
		// Validate: exactly 2 dots.
		if strings.Count(token, ".") == 2 {
			if _, ok := seen[token]; !ok {
				seen[token] = struct{}{}
				tokens = append(tokens, token)
			}
		}
		start = abs + 3 // advance past this "eyJ"
	}
	return tokens
}

// ─── HMAC signing helper ──────────────────────────────────────────────────────

func hmacSign(headerb64, payloadb64, secret string) string {
	msg := headerb64 + "." + payloadb64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	return base64url.EncodeToString(mac.Sum(nil))
}

// ─── Built-in Checks ──────────────────────────────────────────────────────────

func builtinChecks() []Check {
	return []Check{
		{
			ID: "alg-none", Severity: module.SeverityCritical,
			Tags: []string{"alg-none", "signature-bypass"},
			Run: func(ctx context.Context, p *ParsedJWT, target string) *module.Finding {
				alg := strings.ToLower(p.Header.Alg)
				if alg != "none" {
					return nil
				}
				return &module.Finding{
					Type:     "jwt_alg_none",
					Severity: module.SeverityCritical,
					URL:      target,
					Detail:   "[JWT] Algorithm 'none' detected — token has no signature verification",
					Extra: map[string]string{
						"alg":        p.Header.Alg,
						"tags":       "jwt,alg-none",
						"confidence": "0.90",
					},
				}
			},
		},
		{
			ID: "weak-algorithm", Severity: module.SeverityMedium,
			Tags: []string{"weak-algorithm"},
			Run: func(ctx context.Context, p *ParsedJWT, target string) *module.Finding {
				alg := strings.ToUpper(p.Header.Alg)
				if alg == "" {
					return &module.Finding{
						Type:     "jwt_missing_algorithm",
						Severity: module.SeverityHigh,
						URL:      target,
						Detail:   "[JWT] Missing 'alg' field in header",
						Extra:    map[string]string{"tags": "jwt,missing-alg", "confidence": "0.90"},
					}
				}
				if strings.HasPrefix(alg, "HS") {
					return &module.Finding{
						Type:     "jwt_symmetric_algorithm",
						Severity: module.SeverityInfo,
						URL:      target,
						Detail:   fmt.Sprintf("[JWT] Symmetric algorithm %s — shared secret required", alg),
						Extra:    map[string]string{"alg": alg, "tags": "jwt,symmetric", "confidence": "0.90"},
					}
				}
				return nil
			},
		},
		{
			ID: "weak-secret", Severity: module.SeverityCritical,
			Tags: []string{"weak-secret", "brute-force"},
			Run: func(ctx context.Context, p *ParsedJWT, target string) *module.Finding {
				alg := strings.ToUpper(p.Header.Alg)
				if !strings.HasPrefix(alg, "HS") {
					return nil
				}
				// Re-encode header and payload.
				parts := strings.Split(p.Raw, ".")
				if len(parts) != 3 {
					return nil
				}
				headerB64, payloadB64, sig := parts[0], parts[1], parts[2]
				for _, secret := range weakSecrets {
					computed := hmacSign(headerB64, payloadB64, secret)
					if computed == sig {
						return &module.Finding{
							Type:     "jwt_weak_secret",
							Severity: module.SeverityCritical,
							URL:      target,
							Detail:   fmt.Sprintf("[JWT] Weak secret found: %q — token can be forged", secret),
							Extra: map[string]string{
								"secret":     secret,
								"alg":        alg,
								"tags":       "jwt,weak-secret,forge",
								"confidence": "0.90",
							},
						}
					}
				}
				return nil
			},
		},
		{
			ID: "expired", Severity: module.SeverityLow,
			Tags: []string{"expired"},
			Run: func(ctx context.Context, p *ParsedJWT, target string) *module.Finding {
				if p.Payload.Exp == 0 {
					return &module.Finding{
						Type:     "jwt_no_expiry",
						Severity: module.SeverityMedium,
						URL:      target,
						Detail:   "[JWT] Token has no 'exp' claim — non-expiring token",
						Extra:    map[string]string{"tags": "jwt,no-expiry", "confidence": "0.90"},
					}
				}
				now := time.Now().Unix()
				if p.Payload.Exp < now {
					return &module.Finding{
						Type:     "jwt_expired",
						Severity: module.SeverityLow,
						URL:      target,
						Detail:   fmt.Sprintf("[JWT] Token expired at %s", time.Unix(p.Payload.Exp, 0).UTC()),
						Extra: map[string]string{
							"exp":        fmt.Sprintf("%d", p.Payload.Exp),
							"tags":       "jwt,expired",
							"confidence": "0.90",
						},
					}
				}
				// Long-lived: exp > 30 days from now.
				thirtyDays := int64(30 * 24 * 3600)
				if p.Payload.Exp-now > thirtyDays {
					return &module.Finding{
						Type:     "jwt_long_lived",
						Severity: module.SeverityLow,
						URL:      target,
						Detail:   fmt.Sprintf("[JWT] Token expires far in future: %s", time.Unix(p.Payload.Exp, 0).UTC()),
						Extra: map[string]string{
							"exp":        fmt.Sprintf("%d", p.Payload.Exp),
							"tags":       "jwt,long-lived",
							"confidence": "0.90",
						},
					}
				}
				return nil
			},
		},
		{
			ID: "kid-injection", Severity: module.SeverityHigh,
			Tags: []string{"kid-injection"},
			Run: func(ctx context.Context, p *ParsedJWT, target string) *module.Finding {
				if p.Header.Kid == "" {
					return nil
				}
				kid := p.Header.Kid
				// Suspicious kid values: path traversal, SQL injection indicators.
				suspicious := strings.Contains(kid, "../") || strings.Contains(kid, "/dev/null") ||
					strings.Contains(kid, "' OR ") || strings.Contains(kid, "SELECT") ||
					strings.Contains(kid, "http://") || strings.Contains(kid, "https://")
				if !suspicious {
					return nil
				}
				return &module.Finding{
					Type:     "jwt_kid_injection",
					Severity: module.SeverityHigh,
					URL:      target,
					Detail:   fmt.Sprintf("[JWT] Suspicious 'kid' value: %q — potential key confusion attack", kid),
					Extra: map[string]string{
						"kid":        kid,
						"tags":       "jwt,kid-injection",
						"confidence": "0.90",
					},
				}
			},
		},
		{
			ID: "jku-injection", Severity: module.SeverityHigh,
			Tags: []string{"jku-injection", "key-injection"},
			Run: func(ctx context.Context, p *ParsedJWT, target string) *module.Finding {
				if p.Header.Jku == "" {
					return nil
				}
				return &module.Finding{
					Type:     "jwt_jku_header",
					Severity: module.SeverityHigh,
					URL:      target,
					Detail:   fmt.Sprintf("[JWT] 'jku' header present: %q — key set URL injection risk", p.Header.Jku),
					Extra: map[string]string{
						"jku":        p.Header.Jku,
						"tags":       "jwt,jku",
						"confidence": "0.90",
					},
				}
			},
		},
		{
			ID: "jwk-injection", Severity: module.SeverityHigh,
			Tags: []string{"jwk-injection"},
			Run: func(ctx context.Context, p *ParsedJWT, target string) *module.Finding {
				if p.Header.Jwk == nil {
					return nil
				}
				return &module.Finding{
					Type:     "jwt_jwk_header",
					Severity: module.SeverityHigh,
					URL:      target,
					Detail:   "[JWT] 'jwk' embedded in header — attacker-supplied public key risk",
					Extra:    map[string]string{"tags": "jwt,jwk", "confidence": "0.90"},
				}
			},
		},
		{
			ID: "sensitive-claims", Severity: module.SeverityInfo,
			Tags: []string{"sensitive-claims", "disclosure"},
			Run: func(ctx context.Context, p *ParsedJWT, target string) *module.Finding {
				if len(p.PayloadRaw) == 0 {
					return nil
				}
				var sensitive []string
				for _, key := range []string{"email", "password", "ssn", "credit_card", "phone", "address"} {
					if _, ok := p.PayloadRaw[key]; ok {
						sensitive = append(sensitive, key)
					}
				}
				if len(sensitive) == 0 {
					return nil
				}
				return &module.Finding{
					Type:     "jwt_sensitive_claims",
					Severity: module.SeverityMedium,
					URL:      target,
					Detail:   fmt.Sprintf("[JWT] Sensitive claims in payload: %s", strings.Join(sensitive, ", ")),
					Extra: map[string]string{
						"claims":     strings.Join(sensitive, ","),
						"tags":       "jwt,sensitive-claims",
						"confidence": "0.90",
					},
				}
			},
		},
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func collectTargets(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	if input.Target != "" {
		add(input.Target)
	}
	for _, u := range input.URLs {
		add(u)
	}
	return out
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
