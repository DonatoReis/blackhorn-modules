package jwtaudit_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/jwtaudit"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// makeJWT creates a minimal signed JWT with the given alg, header extra claims,
// and payload claims. Secret is used for HMAC signing.
func makeJWT(t *testing.T, alg string, extraHeader, payload map[string]interface{}, secret string) string {
	t.Helper()

	header := map[string]interface{}{"alg": alg, "typ": "JWT"}
	for k, v := range extraHeader {
		header[k] = v
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	h := base64.RawURLEncoding.EncodeToString(headerJSON)
	p := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := h + "." + p

	var sig string
	if alg == "none" || alg == "NONE" || alg == "None" {
		sig = ""
	} else if strings.HasPrefix(alg, "HS") {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(signingInput))
		sig = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}

	return signingInput + "." + sig
}

func moduleNew(t *testing.T) *jwtaudit.Module {
	t.Helper()
	return jwtaudit.New()
}

func hasCheck(findings []module.Finding, check string) bool {
	for _, f := range findings {
		if f.Extra["check"] == check {
			return true
		}
	}
	return false
}

// ─── tests ────────────────────────────────────────────────────────────────────

// TestName verifies the module name.
func TestName(t *testing.T) {
	if jwtaudit.New().Name() != "jwtaudit" {
		t.Error("expected module name 'jwtaudit'")
	}
}

// TestRun_NoTargetNoToken expects an error.
func TestRun_NoTargetNoToken(t *testing.T) {
	m := jwtaudit.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error when no target or token provided")
	}
}

// TestRun_ContextCancellation should not hang.
func TestRun_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := jwtaudit.New()
	_, _ = m.Run(ctx, module.Input{Target: "http://localhost:1"})
}

// TestRun_NoneAlgorithm verifies CVE-2015-9235 detection.
func TestRun_NoneAlgorithm(t *testing.T) {
	tok := makeJWT(t, "none", nil, map[string]interface{}{"sub": "1234", "iss": "test"}, "")

	m := moduleNew(t)
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": tok},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "none-alg") {
		t.Error("expected none-alg check to fire for alg=none")
	}
}

// TestRun_NoneAlgorithm_NONE verifies case-insensitive none detection.
func TestRun_NoneAlgorithm_NONE(t *testing.T) {
	tok := makeJWT(t, "NONE", nil, map[string]interface{}{"sub": "test"}, "")

	m := moduleNew(t)
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": tok},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "none-alg") {
		t.Error("expected none-alg check to fire for alg=NONE")
	}
}

// TestRun_WeakSecret verifies brute-force detection of weak secrets.
func TestRun_WeakSecret(t *testing.T) {
	// Sign with a common secret from the wordlist.
	tok := makeJWT(t, "HS256", nil, map[string]interface{}{"sub": "user"}, "secret")

	m := moduleNew(t)
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": tok},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "weak-secret") {
		t.Error("expected weak-secret check to fire for common secret 'secret'")
	}

	// Verify the cracked secret is reported.
	for _, f := range findings {
		if f.Extra["check"] == "weak-secret" {
			if f.Extra["secret"] != "secret" {
				t.Errorf("expected cracked secret 'secret', got %q", f.Extra["secret"])
			}
		}
	}
}

// TestRun_StrongSecret verifies no weak-secret finding for a strong key.
func TestRun_StrongSecret(t *testing.T) {
	// Use a strong secret not in the wordlist.
	strongSecret := "xK9#mP2$vQ7&nR4@wS1%yT8*zU5!aB3"
	tok := makeJWT(t, "HS256", nil, map[string]interface{}{"sub": "user"}, strongSecret)

	m := jwtaudit.NewWithWordlist([]string{"password", "secret", "123456"})
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": tok},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["check"] == "weak-secret" {
			t.Error("strong secret should not trigger weak-secret check")
		}
	}
}

// TestRun_Expired verifies expiry detection.
func TestRun_Expired(t *testing.T) {
	// Token expired 1 hour ago.
	expiredTime := time.Now().Add(-1 * time.Hour).Unix()
	tok := makeJWT(t, "HS256", nil, map[string]interface{}{
		"sub": "user",
		"exp": expiredTime,
	}, "secret")

	m := moduleNew(t)
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": tok, "checks": "expiry"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "expiry") {
		t.Error("expected expiry check to fire for expired token")
	}
}

// TestRun_NoExp verifies no-expiry detection.
func TestRun_NoExp(t *testing.T) {
	tok := makeJWT(t, "HS256", nil, map[string]interface{}{"sub": "user"}, "strongsecret9876")

	m := moduleNew(t)
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": tok, "checks": "expiry"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "expiry") {
		t.Error("expected expiry check to fire when exp claim is missing")
	}
}

// TestRun_SensitivePayload verifies detection of secrets in payload.
func TestRun_SensitivePayload(t *testing.T) {
	tok := makeJWT(t, "HS256", nil, map[string]interface{}{
		"sub":      "user",
		"password": "hunter2",
	}, "strongsecret9876")

	m := moduleNew(t)
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": tok, "checks": "sensitive-payload"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "sensitive-payload") {
		t.Error("expected sensitive-payload check to fire")
	}
}

// TestRun_KIDInjection verifies path traversal in kid header.
func TestRun_KIDInjection(t *testing.T) {
	tok := makeJWT(t, "HS256",
		map[string]interface{}{"kid": "../../etc/passwd"},
		map[string]interface{}{"sub": "user"}, "strongsecret9876")

	m := moduleNew(t)
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": tok, "checks": "kid-injection"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "kid-injection") {
		t.Error("expected kid-injection check to fire for path traversal in kid")
	}
}

// TestRun_JWKInjection verifies jwk header parameter detection.
func TestRun_JWKInjection(t *testing.T) {
	tok := makeJWT(t, "RS256",
		map[string]interface{}{"jwk": map[string]interface{}{"kty": "RSA", "n": "abc", "e": "AQAB"}},
		map[string]interface{}{"sub": "user"}, "")

	m := moduleNew(t)
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": tok, "checks": "jwk-injection"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "jwk-injection") {
		t.Error("expected jwk-injection check to fire")
	}
}

// TestRun_AlgConfusion verifies RS256 algorithm confusion flag.
func TestRun_AlgConfusion(t *testing.T) {
	tok := makeJWT(t, "RS256", nil, map[string]interface{}{"sub": "user"}, "")

	m := moduleNew(t)
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": tok, "checks": "alg-confusion"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "alg-confusion") {
		t.Error("expected alg-confusion check to fire for RS256 token")
	}
}

// TestRun_MissingClaims verifies missing iss/aud/iat detection.
func TestRun_MissingClaims(t *testing.T) {
	// Token with only sub — missing iss, aud, iat.
	tok := makeJWT(t, "HS256", nil, map[string]interface{}{"sub": "user"}, "strongsecret9876")

	m := moduleNew(t)
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": tok, "checks": "missing-claims"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "missing-claims") {
		t.Error("expected missing-claims check to fire")
	}
}

// TestRun_FindingFields verifies all required fields on every finding.
func TestRun_FindingFields(t *testing.T) {
	tok := makeJWT(t, "none", nil, map[string]interface{}{"sub": "user"}, "")

	m := moduleNew(t)
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": tok},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range findings {
		if f.Type != "jwt_vuln" {
			t.Errorf("expected type 'jwt_vuln', got %q", f.Type)
		}
		if f.Extra["check"] == "" {
			t.Error("finding missing 'check' field")
		}
		if f.Severity == "" {
			t.Error("finding missing severity")
		}
		if f.Detail == "" {
			t.Error("finding missing detail")
		}
	}
}

// TestRun_RawContent verifies token extraction from raw content.
func TestRun_RawContent(t *testing.T) {
	tok := makeJWT(t, "none", nil, map[string]interface{}{"sub": "user"}, "")
	content := fmt.Sprintf(`{"Authorization": "Bearer %s"}`, tok)

	m := moduleNew(t)
	findings, err := m.Run(context.Background(), module.Input{
		RawContent: content,
		Options:    map[string]string{"checks": "none-alg"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "none-alg") {
		t.Error("expected none-alg check to fire when token extracted from raw content")
	}
}

// TestRun_HTTPTokenExtraction verifies token extraction from HTTP response headers.
func TestRun_HTTPTokenExtraction(t *testing.T) {
	tok := makeJWT(t, "none", nil, map[string]interface{}{"sub": "user"}, "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Authorization", "Bearer "+tok)
		fmt.Fprint(w, `{"status": "ok"}`)
	}))
	defer srv.Close()

	m := jwtaudit.NewWithClient(&http.Client{Timeout: 5 * time.Second})
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"checks": "none-alg"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheck(findings, "none-alg") {
		t.Error("expected none-alg check to fire when token found in response header")
	}
}

// TestRun_CheckFilter verifies that only specified checks run.
func TestRun_CheckFilter(t *testing.T) {
	tok := makeJWT(t, "none", nil, map[string]interface{}{"sub": "user"}, "")

	m := moduleNew(t)
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{
			"token":  tok,
			"checks": "expiry", // Only run expiry, not none-alg
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["check"] == "none-alg" {
			t.Error("none-alg check should not run when only 'expiry' is requested")
		}
	}
}
