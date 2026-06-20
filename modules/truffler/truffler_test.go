package truffler_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/truffler"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func moduleWithClient(t *testing.T) *truffler.Module {
	t.Helper()
	return truffler.NewWithClient(&http.Client{Timeout: 5 * time.Second})
}

func hasDetector(findings []module.Finding, name string) bool {
	for _, f := range findings {
		if strings.EqualFold(f.Extra["detector"], name) {
			return true
		}
	}
	return false
}

// contentServer serves static content.
func contentServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
}

// ─── tests ────────────────────────────────────────────────────────────────────

// TestName verifies the module name.
func TestName(t *testing.T) {
	if truffler.New().Name() != "truffler" {
		t.Error("expected module name 'truffler'")
	}
}

// TestRun_EmptyTarget expects an error when neither target nor raw content is provided.
func TestRun_EmptyTarget(t *testing.T) {
	m := truffler.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestRun_ContextCancellation should not hang.
func TestRun_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := truffler.New()
	_, _ = m.Run(ctx, module.Input{Target: "http://localhost:1"})
}

// TestRun_DetectsAWSKey verifies AWS Access Key ID detection.
func TestRun_DetectsAWSKey(t *testing.T) {
	body := `config:
  aws_access_key_id: AKIAIOSFODNN7EXAMPLE
  region: us-east-1`

	srv := contentServer(t, body)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasDetector(findings, "AWS Access Key ID") {
		t.Error("expected AWS Access Key ID to be detected")
	}
}

// TestRun_DetectsGitHubToken verifies GitHub PAT detection.
func TestRun_DetectsGitHubToken(t *testing.T) {
	body := `const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg123"`

	srv := contentServer(t, body)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasDetector(findings, "GitHub Personal Access Token (classic)") {
		t.Error("expected GitHub PAT to be detected")
	}
}

// TestRun_DetectsPrivateKey verifies RSA private key detection.
func TestRun_DetectsPrivateKey(t *testing.T) {
	body := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4m...
-----END RSA PRIVATE KEY-----`

	srv := contentServer(t, body)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasDetector(findings, "RSA Private Key") {
		t.Error("expected RSA Private Key to be detected")
	}
}

// TestRun_DetectsStripeKey verifies Stripe secret key detection.
func TestRun_DetectsStripeKey(t *testing.T) {
	body := "STRIPE_SECRET_KEY=" + strings.Join(
		[]string{"sk", "live", "ABCDEFGHIJKLMNOPQRSTUVWXyz1234"},
		"_",
	)

	srv := contentServer(t, body)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasDetector(findings, "Stripe Secret Key") {
		t.Error("expected Stripe Secret Key to be detected")
	}
}

// TestRun_DetectsSlackToken verifies Slack bot token detection.
func TestRun_DetectsSlackToken(t *testing.T) {
	body := "slack_token=" + strings.Join(
		[]string{"xoxb", "123456789012", "123456789012", "ABCDEFGHIJKLMNOPQRSTUVwx"},
		"-",
	)

	srv := contentServer(t, body)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasDetector(findings, "Slack Bot Token") {
		t.Error("expected Slack Bot Token to be detected")
	}
}

// TestRun_NoSecretsNoFindings verifies that clean content produces no findings.
func TestRun_NoSecretsNoFindings(t *testing.T) {
	body := `<html><body><p>Hello, World! This is a normal page.</p></body></html>`

	srv := contentServer(t, body)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for clean content, got %d", len(findings))
	}
}

// TestRun_RawContent verifies scanning raw content directly (no HTTP fetch).
func TestRun_RawContent(t *testing.T) {
	content := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA...
-----END OPENSSH PRIVATE KEY-----`

	m := truffler.New()
	findings, err := m.Run(context.Background(), module.Input{
		RawContent: content,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasDetector(findings, "OpenSSH Private Key") {
		t.Error("expected OpenSSH Private Key to be detected in raw content")
	}
}

// TestRun_FindingFields verifies all required fields on every finding.
func TestRun_FindingFields(t *testing.T) {
	body := `aws_key: AKIAIOSFODNN7EXAMPLE`

	srv := contentServer(t, body)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range findings {
		if f.Type != "secret" {
			t.Errorf("expected type 'secret', got %q", f.Type)
		}
		if f.Extra["detector"] == "" {
			t.Error("finding missing 'detector' field")
		}
		if f.Extra["line"] == "" {
			t.Error("finding missing 'line' field")
		}
		if f.Extra["entropy"] == "" {
			t.Error("finding missing 'entropy' field")
		}
		if f.Extra["masked"] == "" {
			t.Error("finding missing 'masked' field")
		}
		if f.URL == "" {
			t.Error("finding missing URL")
		}
		if f.Severity == "" {
			t.Error("finding missing severity")
		}
		if f.Detail == "" {
			t.Error("finding missing detail")
		}
	}
}

// TestRun_DetectorFilter verifies that only specified detectors run.
func TestRun_DetectorFilter(t *testing.T) {
	body := `key: AKIAIOSFODNN7EXAMPLE
token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg123`

	srv := contentServer(t, body)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"detectors": "AWS Access Key ID"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["detector"] != "AWS Access Key ID" {
			t.Errorf("unexpected detector %q fired when only 'AWS Access Key ID' was requested", f.Extra["detector"])
		}
	}
}

// TestRun_TagFilter verifies that only detectors with matching tags run.
func TestRun_TagFilter(t *testing.T) {
	body := `key: AKIAIOSFODNN7EXAMPLE
private_key: -----BEGIN RSA PRIVATE KEY-----`

	srv := contentServer(t, body)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"tags": "private-key"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		tags := f.Extra["tags"]
		if !strings.Contains(tags, "private-key") {
			t.Errorf("finding with tags %q should not fire for private-key tag filter", tags)
		}
	}
}

// TestRun_SecretMasked verifies that secrets are masked in the finding output.
func TestRun_SecretMasked(t *testing.T) {
	body := `token: AKIAIOSFODNN7EXAMPLE`

	srv := contentServer(t, body)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["detector"] == "AWS Access Key ID" {
			masked := f.Extra["masked"]
			// Must not contain the full key — only partial.
			if strings.Contains(masked, "AKIAIOSFODNN7EXAMPLE") {
				t.Error("secret should be masked in finding output, not exposed in full")
			}
			if masked == "" {
				t.Error("masked field should not be empty")
			}
		}
	}
}

// TestRun_ContextLines verifies that surrounding context is included.
func TestRun_ContextLines(t *testing.T) {
	body := `line one
line two — before
aws_key: AKIAIOSFODNN7EXAMPLE
line four — after
line five`

	srv := contentServer(t, body)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["detector"] == "AWS Access Key ID" {
			if f.Extra["context"] == "" {
				t.Error("finding should include context lines")
			}
		}
	}
}

// TestRun_ShannonEntropy verifies the entropy function directly via custom detector.
func TestRun_ShannonEntropy(t *testing.T) {
	// Custom detector: matches "lowsecret:" prefix, requires high entropy.
	det := truffler.Detector{
		Name:             "TestHighEntropy",
		Tags:             []string{"test"},
		Pattern:          mustCompile(`lowsecret:[a-z]{20}`),
		EntropyThreshold: 4.5, // "aaaaaaa..." has entropy ≈ 0 — should NOT fire
		Severity:         module.SeverityHigh,
		Description:      "test detector",
	}

	body2 := "lowsecret:" + strings.Repeat("a", 20)
	srv := contentServer(t, body2)
	defer srv.Close()

	m := truffler.NewWithClientAndDetectors(&http.Client{Timeout: 5 * time.Second}, []truffler.Detector{det})
	findings, err := m.Run(context.Background(), module.Input{Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("low-entropy match should not produce findings, got %d", len(findings))
	}
}

// TestRun_MultipleURLs verifies that multiple URLs are all scanned.
func TestRun_MultipleURLs(t *testing.T) {
	body1 := `key: AKIAIOSFODNN7EXAMPLE`
	body2 := `-----BEGIN RSA PRIVATE KEY-----`

	srv1 := contentServer(t, body1)
	defer srv1.Close()
	srv2 := contentServer(t, body2)
	defer srv2.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{
		URLs: []string{srv1.URL, srv2.URL},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hasAWS := hasDetector(findings, "AWS Access Key ID")
	hasKey := hasDetector(findings, "RSA Private Key")
	if !hasAWS || !hasKey {
		t.Errorf("expected both AWS key and RSA key detected, aws=%v rsa=%v", hasAWS, hasKey)
	}
}

// mustCompile compiles a regex — used in test helpers.
func mustCompile(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}

// TestRun_DetectsOpenAIProjectKey verifies the new sk-proj- format is detected.
func TestRun_DetectsOpenAIProjectKey(t *testing.T) {
	// Realistic sk-proj- key format (sk-proj- + 100+ alphanumeric chars)
	skProjKey := "sk-proj-" + strings.Repeat("ABCDEFGHabcdefgh12345678", 5)

	srv := contentServer(t, skProjKey)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{URLs: []string{srv.URL}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Extra["detector"]), "openai") ||
			strings.Contains(strings.ToLower(f.Detail), "openai") ||
			strings.Contains(strings.ToLower(f.Type), "openai") {
			found = true
		}
	}
	if !found {
		t.Error("expected OpenAI Project API key (sk-proj-) to be detected")
	}
}

// TestRun_DetectsOpenAILegacyKey verifies the original sk- format is still detected.
func TestRun_DetectsOpenAILegacyKey(t *testing.T) {
	// Original OpenAI key format: sk- + 48 alphanumeric chars (total 51 chars)
	legacyKey := "sk-" + strings.Repeat("ABCDEFGHabcdefgh12345678", 2) // 48 chars
	legacyKey = legacyKey[:51]                                         // sk- (3) + 48 chars = 51

	srv := contentServer(t, legacyKey)
	defer srv.Close()

	m := moduleWithClient(t)
	findings, err := m.Run(context.Background(), module.Input{URLs: []string{srv.URL}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Extra["detector"]), "openai") ||
			strings.Contains(strings.ToLower(f.Detail), "openai") {
			found = true
		}
	}
	if !found {
		t.Error("expected OpenAI legacy API key (sk-) to be detected")
	}
}
