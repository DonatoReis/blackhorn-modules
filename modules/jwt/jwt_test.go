package jwt_test

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

	"github.com/DonatoReis/blackhorn-modules/modules/jwt"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── JWT token helpers ────────────────────────────────────────────────────────

var b64url = base64.URLEncoding.WithPadding(base64.NoPadding)

func makeJWT(header, payload map[string]interface{}, secret string) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	hb64 := b64url.EncodeToString(h)
	pb64 := b64url.EncodeToString(p)
	msg := hb64 + "." + pb64

	if secret == "" || header["alg"] == "none" {
		// Unsigned / alg:none token.
		return msg + "."
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	sig := b64url.EncodeToString(mac.Sum(nil))
	return msg + "." + sig
}

func validHS256Token() string {
	return makeJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "user123", "exp": time.Now().Add(time.Hour).Unix()},
		"strongrandomsecret",
	)
}

func weakSecretToken() string {
	return makeJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "user123", "exp": time.Now().Add(time.Hour).Unix()},
		"secret", // weak!
	)
}

func algNoneToken() string {
	return makeJWT(
		map[string]interface{}{"alg": "none", "typ": "JWT"},
		map[string]interface{}{"sub": "admin", "exp": time.Now().Add(time.Hour).Unix()},
		"",
	)
}

func expiredToken() string {
	return makeJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "user123", "exp": time.Now().Add(-time.Hour).Unix()},
		"strongrandomsecret",
	)
}

func noExpToken() string {
	return makeJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "user123"},
		"strongrandomsecret",
	)
}

func kidInjectionToken() string {
	return makeJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT", "kid": "../../dev/null"},
		map[string]interface{}{"sub": "user123", "exp": time.Now().Add(time.Hour).Unix()},
		"strongrandomsecret",
	)
}

func jkuToken() string {
	return makeJWT(
		map[string]interface{}{"alg": "RS256", "typ": "JWT", "jku": "https://attacker.com/jwks.json"},
		map[string]interface{}{"sub": "user123", "exp": time.Now().Add(time.Hour).Unix()},
		"",
	)
}

func sensitiveClaimsToken() string {
	return makeJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "user123", "email": "admin@example.com", "exp": time.Now().Add(time.Hour).Unix()},
		"strongrandomsecret",
	)
}

// ─── Server helpers ───────────────────────────────────────────────────────────

// jwtBearerServer: returns a JWT in Authorization: Bearer header.
func jwtBearerServer(t *testing.T, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Authorization", "Bearer "+token)
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
	}))
}

// jwtCookieServer: returns a JWT in a Set-Cookie header.
func jwtCookieServer(t *testing.T, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "auth", Value: token})
		w.WriteHeader(200)
		w.Write([]byte(`OK`))
	}))
}

func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := jwt.New()
	if m.Name() != "jwt" {
		t.Fatalf("expected 'jwt', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = jwt.New()
}

// TestAlgNoneDetected: alg=none → Critical finding.
func TestAlgNoneDetected(t *testing.T) {
	m := jwt.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": algNoneToken()},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "jwt_alg_none" {
			found = true
			if f.Severity != module.SeverityCritical {
				t.Errorf("expected Critical, got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected jwt_alg_none finding, got: %v", findings)
	}
}

// TestWeakSecretDetected: HMAC with "secret" → Critical.
func TestWeakSecretDetected(t *testing.T) {
	m := jwt.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": weakSecretToken()},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "jwt_weak_secret" {
			found = true
			if f.Extra["secret"] != "secret" {
				t.Errorf("secret = %q, want 'secret'", f.Extra["secret"])
			}
		}
	}
	if !found {
		t.Fatalf("expected jwt_weak_secret finding, got: %v", findings)
	}
}

// TestStrongSecretNotFlagged: strong secret → no weak_secret finding.
func TestStrongSecretNotFlagged(t *testing.T) {
	m := jwt.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": validHS256Token()},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.Type == "jwt_weak_secret" {
			t.Errorf("strong secret should not trigger jwt_weak_secret: %v", f)
		}
	}
}

// TestExpiredTokenDetected.
func TestExpiredTokenDetected(t *testing.T) {
	m := jwt.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": expiredToken()},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "jwt_expired" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected jwt_expired finding, got: %v", findings)
	}
}

// TestNoExpiry: missing exp → jwt_no_expiry.
func TestNoExpiry(t *testing.T) {
	m := jwt.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": noExpToken()},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "jwt_no_expiry" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected jwt_no_expiry finding, got: %v", findings)
	}
}

// TestKidInjectionDetected.
func TestKidInjectionDetected(t *testing.T) {
	m := jwt.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": kidInjectionToken()},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "jwt_kid_injection" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected jwt_kid_injection finding, got: %v", findings)
	}
}

// TestJKUHeaderDetected.
func TestJKUHeaderDetected(t *testing.T) {
	m := jwt.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": jkuToken()},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "jwt_jku_header" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected jwt_jku_header finding, got: %v", findings)
	}
}

// TestSensitiveClaimsDetected.
func TestSensitiveClaimsDetected(t *testing.T) {
	m := jwt.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": sensitiveClaimsToken()},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "jwt_sensitive_claims" {
			found = true
			if !strings.Contains(f.Extra["claims"], "email") {
				t.Errorf("claims should mention 'email', got %q", f.Extra["claims"])
			}
		}
	}
	if !found {
		t.Errorf("expected jwt_sensitive_claims finding, got: %v", findings)
	}
}

// TestEmptyInput: no token → nil.
func TestEmptyInput(t *testing.T) {
	m := jwt.New()
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(findings))
	}
}

// TestContextCancellation: cancelled context does not panic.
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := jwt.New()
	_, err := m.Run(ctx, module.Input{Options: map[string]string{"token": algNoneToken()}})
	_ = err
}

// TestDeduplication: same finding not duplicated.
func TestDeduplication(t *testing.T) {
	token := algNoneToken()
	m := jwt.New()
	findings, err := m.Run(context.Background(), module.Input{
		RawContent: fmt.Sprintf("%s %s %s", token, token, token),
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.Extra["token_prefix"] + "|" + f.Type + "|" + f.Extra["check_id"]
		seen[key]++
	}
	for k, count := range seen {
		if count > 1 {
			t.Errorf("duplicate finding %q count=%d", k, count)
		}
	}
}

// TestFindingFields: all required fields populated.
func TestFindingFields(t *testing.T) {
	m := jwt.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": algNoneToken()},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Type == "" {
		t.Error("Type empty")
	}
	if f.Detail == "" {
		t.Error("Detail empty")
	}
	if f.Severity == "" {
		t.Error("Severity empty")
	}
	if f.Extra["check_id"] == "" {
		t.Error("Extra.check_id empty")
	}
}

// TestRawContentExtraction: token in RawContent is analyzed.
func TestRawContentExtraction(t *testing.T) {
	token := algNoneToken()
	m := jwt.New()
	findings, err := m.Run(context.Background(), module.Input{
		RawContent: `{"token":"` + token + `"}`,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from RawContent token extraction")
	}
}

// TestBearerTokenExtraction: token from Authorization: Bearer response header.
func TestBearerTokenExtraction(t *testing.T) {
	token := algNoneToken()
	srv := jwtBearerServer(t, token)
	defer srv.Close()

	m := jwt.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "jwt_alg_none" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected jwt_alg_none from Bearer token, got: %v", findings)
	}
}

// TestCookieTokenExtraction: token from Set-Cookie header.
func TestCookieTokenExtraction(t *testing.T) {
	token := weakSecretToken()
	srv := jwtCookieServer(t, token)
	defer srv.Close()

	m := jwt.NewWithClient(clientFor(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "jwt_weak_secret" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected jwt_weak_secret from cookie token, got: %v", findings)
	}
}

// TestNewWithClient: does not panic.
func TestNewWithClient(t *testing.T) {
	c := &http.Client{Timeout: 1 * time.Second}
	m := jwt.NewWithClient(c)
	if m == nil || m.Name() != "jwt" {
		t.Fatal("NewWithClient failed")
	}
}

// TestDetailHasPrefix: all findings have [JWT] in detail.
func TestDetailHasPrefix(t *testing.T) {
	m := jwt.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": algNoneToken()},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.Detail, "[JWT]") {
			t.Errorf("Detail %q missing '[JWT]'", f.Detail)
		}
	}
}

// TestSymmetricAlgorithmInfo: HS256 emits Info finding.
func TestSymmetricAlgorithmInfo(t *testing.T) {
	m := jwt.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"token": validHS256Token()},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "jwt_symmetric_algorithm" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected jwt_symmetric_algorithm for HS256 token, got: %v", findings)
	}
}
