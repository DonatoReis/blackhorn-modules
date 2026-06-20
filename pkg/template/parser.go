package template

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ─── Parser options ───────────────────────────────────────────────────────────

// ParseOptions controls template loading behaviour.
type ParseOptions struct {
	// StrictSignature requires a valid ed25519 signature on every template.
	// When false (default), unsigned templates are accepted.
	StrictSignature bool

	// TrustedKeys is the set of hex-encoded ed25519 public keys that are
	// considered trusted signers. Required when StrictSignature is true.
	TrustedKeys []string

	// SkipValidation skips structural validation after parsing.
	// Useful for loading partial/draft templates.
	SkipValidation bool

	// SkipCompile skips regex compilation after parsing.
	// Useful when you only need the schema data, not execution.
	SkipCompile bool
}

// DefaultParseOptions returns sensible defaults.
func DefaultParseOptions() ParseOptions {
	return ParseOptions{
		StrictSignature: false,
		SkipValidation:  false,
		SkipCompile:     false,
	}
}

// ─── Parse from bytes ─────────────────────────────────────────────────────────

// ParseYAML parses a YAML template from a byte slice.
// Mirrors nuclei template loading (yaml.Unmarshal → validate → compile).
func ParseYAML(data []byte, opts ParseOptions) (*Template, error) {
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("template: yaml parse: %w", err)
	}
	return finalize(&t, data, opts)
}

// ParseJSON parses a JSON template from a byte slice.
func ParseJSON(data []byte, opts ParseOptions) (*Template, error) {
	var t Template
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("template: json parse: %w", err)
	}
	return finalize(&t, data, opts)
}

// ParseReader parses a template from an io.Reader.
// Auto-detects YAML vs JSON from the first non-whitespace byte.
func ParseReader(r io.Reader, opts ParseOptions) (*Template, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("template: read: %w", err)
	}
	return ParseBytes(data, opts)
}

// ParseBytes auto-detects format (YAML/JSON) and parses.
func ParseBytes(data []byte, opts ParseOptions) (*Template, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") {
		return ParseJSON(data, opts)
	}
	return ParseYAML(data, opts)
}

// ─── Parse from file ──────────────────────────────────────────────────────────

// ParseFile loads a template from a file path.
// Supports .yaml, .yml, and .json extensions.
func ParseFile(path string, opts ParseOptions) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("template: read file %q: %w", path, err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return ParseJSON(data, opts)
	default: // .yaml, .yml, or no extension → assume YAML
		return ParseYAML(data, opts)
	}
}

// ParseDirectory loads all templates from a directory (recursive).
// Returns all successfully parsed templates and a map of path→error for failures.
func ParseDirectory(dir string, opts ParseOptions) ([]*Template, map[string]error) {
	var templates []*Template
	errors := map[string]error{}

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			errors[path] = err
			return nil
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}
		t, err := ParseFile(path, opts)
		if err != nil {
			errors[path] = err
			return nil
		}
		templates = append(templates, t)
		return nil
	})
	if err != nil {
		errors[dir] = err
	}

	return templates, errors
}

// ─── Inline template construction ────────────────────────────────────────────

// MustCompile parses and compiles a YAML template string, panicking on error.
// Intended for use in package-level var declarations (builtin templates).
func MustCompile(yamlStr string) *Template {
	t, err := ParseYAML([]byte(yamlStr), DefaultParseOptions())
	if err != nil {
		panic(fmt.Sprintf("template.MustCompile: %v", err))
	}
	return t
}

// ─── Internal finalization ────────────────────────────────────────────────────

func finalize(t *Template, raw []byte, opts ParseOptions) (*Template, error) {
	// Set schema version if not present.
	if t.Version == "" {
		t.Version = SchemaVersion
	}

	// Signature verification.
	if opts.StrictSignature {
		if t.Signature == nil {
			return nil, fmt.Errorf("template %q: strict mode requires a signature", t.ID)
		}
		if err := verifyWithTrustedKeys(t.Signature, raw, opts.TrustedKeys); err != nil {
			return nil, fmt.Errorf("template %q: %w", t.ID, err)
		}
	}

	// Structural validation.
	if !opts.SkipValidation {
		if err := t.Validate(); err != nil {
			return nil, err
		}
	}

	// Regex compilation.
	if !opts.SkipCompile {
		if err := t.Compile(); err != nil {
			return nil, err
		}
	}

	return t, nil
}

// verifyWithTrustedKeys verifies a signature against any trusted key.
func verifyWithTrustedKeys(sig *SignedBundle, content []byte, trustedKeys []string) error {
	if len(trustedKeys) == 0 {
		// No trusted keys configured — verify against the embedded key only.
		return sig.Verify(content)
	}
	// The embedded public key must be in the trusted set.
	for _, trusted := range trustedKeys {
		if strings.EqualFold(sig.PublicKey, trusted) {
			return sig.Verify(content)
		}
	}
	return fmt.Errorf("signer %q is not in the trusted key set", sig.PublicKey)
}
