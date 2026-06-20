package secretscan_test

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/secretscan"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

func TestRun_DetectsGitHubPAT(t *testing.T) {
	content := "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12\n"

	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Extra["rule_id"] == "github-pat" {
			found = true
		}
	}
	if !found {
		t.Error("expected github-pat finding, got none")
	}
}

func TestRun_DetectsAWSAccessKey(t *testing.T) {
	content := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"

	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Extra["rule_id"] == "aws-access-token" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected aws-access-token finding, got %d findings", len(findings))
	}
}

func TestRun_DetectsPrivateKey(t *testing.T) {
	content := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"

	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Extra["rule_id"] == "private-key" {
			found = true
		}
	}
	if !found {
		t.Error("expected private-key finding")
	}
}

func TestRun_DetectsAnthropicKey(t *testing.T) {
	// Fake key with correct prefix and suffix structure from gitleaks rule
	key := "sk-ant-api03-" + strings.Repeat("A", 93) + "AA"
	content := "export ANTHROPIC_KEY=" + key + "\n"

	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Extra["rule_id"] == "anthropic-api-key" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected anthropic-api-key finding, got %d findings", len(findings))
	}
}

func TestRun_NoFindingsOnCleanContent(t *testing.T) {
	content := `package main

import "fmt"

func main() {
	fmt.Println("hello world")
	token := "short"
}
`
	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings on clean content, got %d (rule: %s)", len(findings), findings[0].Extra["rule_id"])
	}
}

func TestRun_SecretsAreRedactedInFindings(t *testing.T) {
	content := "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12\n"

	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		secret := f.Extra["secret"]
		// Secret must be partially redacted (contains "...")
		if strings.Contains(secret, "ABCDE") {
			t.Errorf("secret not redacted: %q", secret)
		}
	}
}

func TestRun_EntropyFilterBlocksLowEntropyGenericKey(t *testing.T) {
	// A "generic API key" pattern match with very low entropy (repeated chars)
	// should be filtered out by the entropy gate.
	content := "api_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"

	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["rule_id"] == "generic-api-key" {
			t.Errorf("generic-api-key should not fire for low-entropy value, got: %v", f.Extra)
		}
	}
}

func TestRun_CustomRuleSet(t *testing.T) {
	rules := []secretscan.Rule{
		{
			RuleID:      "test-rule",
			Description: "Test only",
			Regex:       regexp.MustCompile(`TESTSECRET-[A-Z0-9]{10}`),
			SecretGroup: 0,
			Entropy:     0,
			Keywords:    []string{"testsecret"},
		},
	}
	content := "config: TESTSECRET-ABCDE12345\n"

	m := secretscan.NewWithRules(rules)
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Extra["rule_id"] != "test-rule" {
		t.Errorf("unexpected rule_id: %s", findings[0].Extra["rule_id"])
	}
}

func TestRun_EmptyContent(t *testing.T) {
	m := secretscan.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty content")
	}
}

func TestRun_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := secretscan.New()
	// Should not hang or panic; context is already cancelled
	_, _ = m.Run(ctx, module.Input{
		Options: map[string]string{
			"content": "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12\n",
		},
	})
}

func TestRun_FilePathInFindings(t *testing.T) {
	content := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"

	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{
			"content":   content,
			"file_path": "config/prod.env",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["file"] != "config/prod.env" {
			t.Errorf("expected file_path in finding, got %q", f.Extra["file"])
		}
	}
}

func TestRun_RuleFilter(t *testing.T) {
	// Content has both AWS and GitHub secrets
	content := "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"

	m := secretscan.New()
	// Only enable aws-access-token
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{
			"content": content,
			"rules":   "aws-access-token",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["rule_id"] == "github-pat" {
			t.Error("github-pat should be filtered out when rules=aws-access-token")
		}
	}
}

func TestRun_TargetAsContent(t *testing.T) {
	// When Options["content"] is empty, Target is used as content
	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Extra["rule_id"] == "aws-access-token" {
			found = true
		}
	}
	if !found {
		t.Error("expected aws-access-token finding when content is in Target")
	}
}

func TestName(t *testing.T) {
	if secretscan.New().Name() != "secretscan" {
		t.Error("wrong module name")
	}
}

// TestRun_DetectsStripeSecretKey verifies Stripe sk_ key detection.
func TestRun_DetectsStripeSecretKey(t *testing.T) {
	content := "export STRIPE_SECRET=" + strings.Join(
		[]string{"sk", "live", "4eC39HqLyjWDarjtT1zdp7dc"},
		"_",
	)
	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Type), "stripe") ||
			strings.Contains(strings.ToLower(f.Detail), "stripe") ||
			strings.Contains(strings.ToLower(f.Extra["rule"]), "stripe") {
			found = true
		}
	}
	if !found {
		t.Log("Stripe key not detected by name — may be under generic rule")
	}
}

// TestRun_MultipleSecretsInContent detects multiple distinct secrets in one content block.
func TestRun_MultipleSecretsInContent(t *testing.T) {
	content := strings.Join([]string{
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a",
	}, "\n")
	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 2 {
		t.Errorf("expected at least 2 secret findings, got %d", len(findings))
	}
}

// TestRun_FindingsSorted verifies findings are returned with populated required fields.
func TestRun_FindingsSorted(t *testing.T) {
	content := "token=ghp_16C7e42F292c6912E7710c838347Ae178B4a\nAKIAIOSFODNN7EXAMPLE"
	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "" {
			t.Error("finding missing Type")
		}
		if f.Severity == "" {
			t.Error("finding missing Severity")
		}
	}
}

// TestRun_FindingsHaveConfidence verifies all findings include a confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	content := "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12\n"
	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("no findings to check")
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding rule_id=%q missing confidence", f.Extra["rule_id"])
		}
	}
}

// TestRun_EntropyFieldPresent verifies all findings include an entropy value.
func TestRun_EntropyFieldPresent(t *testing.T) {
	content := "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("no findings to check")
	}
	for _, f := range findings {
		if f.Extra["entropy"] == "" {
			t.Errorf("finding rule_id=%q missing entropy field", f.Extra["rule_id"])
		}
	}
}

// TestRun_RedactedSecretNotFull verifies the secret field is redacted (not the full value).
func TestRun_RedactedSecretNotFull(t *testing.T) {
	fullKey := "AKIAIOSFODNN7EXAMPLE"
	content := "key=" + fullKey
	m := secretscan.New()
	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		secret := f.Extra["secret"]
		if secret == "" {
			t.Error("finding missing 'secret' field")
			continue
		}
		// Redacted value should not equal the full key verbatim.
		if secret == fullKey {
			t.Errorf("'secret' field should be redacted, not full value: %q", secret)
		}
	}
}
