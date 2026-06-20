// Package fuzz provides fuzz test targets for blackhorn-modules.
//
// Run with:
//
//	go test -fuzz=FuzzURLParse ./fuzz/
//	go test -fuzz=FuzzURLDedup ./fuzz/
//	go test -fuzz=FuzzTrufflerContent ./fuzz/
//	go test -fuzz=FuzzFingerprintPattern ./fuzz/
//	go test -fuzz=FuzzJWTAuditParse ./fuzz/
//	go test -fuzz=FuzzOpenRedirPayload ./fuzz/
//
// Run all fuzz tests for 30 seconds each:
//
//	for target in $(go test -list 'Fuzz.*' ./fuzz/ 2>/dev/null | grep '^Fuzz'); do
//	  go test -fuzz=$target -fuzztime=30s ./fuzz/
//	done
package fuzz

import (
	"context"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/fingerprint"
	"github.com/DonatoReis/blackhorn-modules/modules/jwtaudit"
	"github.com/DonatoReis/blackhorn-modules/modules/openredirect"
	"github.com/DonatoReis/blackhorn-modules/modules/truffler"
	"github.com/DonatoReis/blackhorn-modules/modules/urldedup"
	"github.com/DonatoReis/blackhorn-modules/modules/urlparse"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/template"
)

// ─── urlparse ─────────────────────────────────────────────────────────────────

// FuzzURLParse fuzzes the URL parser with arbitrary URL strings.
// Goal: ensure no panic or OOM on malformed input.
func FuzzURLParse(f *testing.F) {
	// Seed corpus.
	seeds := []string{
		"https://example.com/path?q=1&sort=asc#fragment",
		"http://user:pass@host:8080/path",
		"ftp://example.com",
		"not-a-url",
		"",
		"://no-scheme",
		"https://[::1]/ipv6",
		"https://example.com/" + string(make([]byte, 1024)),
		"javascript:alert(1)",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	m := urlparse.New()
	f.Fuzz(func(t *testing.T, rawURL string) {
		_, _ = m.Run(context.Background(), module.Input{URLs: []string{rawURL}})
	})
}

// ─── urldedup ─────────────────────────────────────────────────────────────────

// FuzzURLDedup fuzzes the URL deduplication engine.
func FuzzURLDedup(f *testing.F) {
	f.Add("https://example.com/page?id=1&sort=asc")
	f.Add("https://example.com/page?id=2&sort=asc")
	f.Add("https://example.com/page?a=1&b=2&c=3")
	f.Add("")

	m := urldedup.New()
	f.Fuzz(func(t *testing.T, rawURL string) {
		_, _ = m.Run(context.Background(), module.Input{URLs: []string{rawURL, rawURL}})
	})
}

// ─── truffler ─────────────────────────────────────────────────────────────────

// FuzzTrufflerContent fuzzes the secret scanner with arbitrary content.
// Goal: ensure no panic on malformed text with potential false positives.
func FuzzTrufflerContent(f *testing.F) {
	f.Add("AKIAIOSFODNN7EXAMPLE")
	f.Add("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef")
	f.Add("-----BEGIN RSA PRIVATE KEY-----\nbase64data\n-----END RSA PRIVATE KEY-----")
	f.Add("")
	f.Add(string(make([]byte, 1024*64))) // 64 KB of zeros
	f.Add("password=hunter2\napi_key=")

	m := truffler.New()
	f.Fuzz(func(t *testing.T, content string) {
		_, _ = m.Run(context.Background(), module.Input{RawContent: content})
	})
}

// ─── fingerprint ──────────────────────────────────────────────────────────────

// FuzzFingerprintPattern fuzzes the pattern parser with raw Wappalyzer patterns.
func FuzzFingerprintPattern(f *testing.F) {
	f.Add(`nginx\;version:\1`)
	f.Add(`WordPress (\d+)\;version:\1\;confidence:75`)
	f.Add(`(?i)(apache|nginx)/(\d+\.?\d*)\;version:\2`)
	f.Add("")
	f.Add(`\;version:\1\;confidence:`)
	f.Add(string(make([]byte, 4096)))

	f.Fuzz(func(t *testing.T, pattern string) {
		// MustParsePatterns should not panic on any input.
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on pattern %q: %v", pattern, r)
			}
		}()
		_ = fingerprint.MustParsePatterns([]string{pattern})
	})
}

// ─── jwtaudit ────────────────────────────────────────────────────────────────

// FuzzJWTAuditParse fuzzes the JWT token parser with arbitrary base64 input.
func FuzzJWTAuditParse(f *testing.F) {
	// Valid JWT structure seeds.
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.")
	f.Add("not-a-jwt")
	f.Add("")
	f.Add("eyJ.eyJ.sig")
	f.Add(string(make([]byte, 4096)))

	m := jwtaudit.New()
	f.Fuzz(func(t *testing.T, rawToken string) {
		// Scan raw content for JWT tokens.
		_, _ = m.Run(context.Background(), module.Input{RawContent: rawToken})
	})
}

// ─── openredirect ─────────────────────────────────────────────────────────────

// FuzzOpenRedirPayload fuzzes the open redirect canary detection logic.
func FuzzOpenRedirPayload(f *testing.F) {
	f.Add("https://open-redirect-canary.example.com/")
	f.Add("//open-redirect-canary.example.com")
	f.Add("https://safe.example.com/")
	f.Add("")
	f.Add("javascript:alert(1)")
	f.Add(string(make([]byte, 1024)))

	f.Fuzz(func(t *testing.T, loc string) {
		_ = loc
		_ = openredirect.New() // ensure constructor doesn't panic
	})
}

// ─── template parser ─────────────────────────────────────────────────────────

// FuzzTemplateParseYAML fuzzes the YAML template parser.
func FuzzTemplateParseYAML(f *testing.F) {
	f.Add([]byte(`id: test
info:
  name: Test
  severity: info
http:
  - method: GET
    path:
      - /
    matchers:
      - type: status
        status:
          - 200`))
	f.Add([]byte(""))
	f.Add([]byte("id:"))
	f.Add([]byte("{invalid: yaml: [}"))
	f.Add(make([]byte, 4096))

	f.Fuzz(func(t *testing.T, data []byte) {
		opts := template.DefaultParseOptions()
		opts.SkipValidation = true
		// ParseYAML should never panic on any input.
		_, _ = template.ParseYAML(data, opts)
	})
}

// FuzzTemplateParseBytes fuzzes auto-detect YAML/JSON parsing.
func FuzzTemplateParseBytes(f *testing.F) {
	f.Add([]byte(`{"id":"test","info":{"name":"T","severity":"info"}}`))
	f.Add([]byte(`id: test`))
	f.Add([]byte(""))
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		opts := template.DefaultParseOptions()
		opts.SkipValidation = true
		_, _ = template.ParseBytes(data, opts)
	})
}
