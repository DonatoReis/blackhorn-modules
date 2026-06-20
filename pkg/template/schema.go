// Package template implements the BLACKHORN internal template engine.
//
// This package is a superset of the Nuclei template format (MIT).
// Source reference: projectdiscovery/nuclei (MIT)
//
//	https://github.com/projectdiscovery/nuclei/blob/main/pkg/templates/
//
// What is copied/ported (MIT — allowed):
//   - YAML field names and struct layout from nuclei/pkg/templates/template.go
//   - Matcher field names from nuclei/pkg/operators/matchers/matchers.go
//   - Extractor field names from nuclei/pkg/operators/extractors/extractors.go
//   - Severity constants from nuclei/pkg/model/types/severity/severity.go
//
// BLACKHORN extensions (new, not in Nuclei):
//   - SignedBundle: ed25519 signature over template content
//   - ConfidenceScore: pre-computed detection confidence (0–100)
//   - TagSet: typed tag list with Contains/MatchesAny helpers
//   - Engine field: explicit target engine ("http","dns","tcp","udp","file")
//   - Version field: template schema version for forward compatibility
//   - Metadata.Source: origin ("builtin" | "community" | "custom")
//   - UDPRequest: not present in Nuclei
//
// Design rules (guia-go §8):
//   - All structs use typed fields, zero map[string]any in hot paths
//   - encoding/json v1 (v2 still experimental per guia-go)
//   - YAML tags identical to Nuclei for drop-in compatibility
package template

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ─── Schema version ───────────────────────────────────────────────────────────

// SchemaVersion is the current BLACKHORN template schema version.
// Bumped on breaking schema changes.
const SchemaVersion = "1.0"

// ─── Template ─────────────────────────────────────────────────────────────────

// Template is the top-level BLACKHORN template document.
// YAML tags are a superset of Nuclei's template format; all Nuclei HTTP
// templates load without modification.
type Template struct {
	// ID is the unique template identifier (e.g. "cve-2021-44228", "missing-hsts").
	// Mirrors nuclei template.ID.
	ID string `yaml:"id" json:"id"`

	// Info contains template metadata. Mirrors nuclei template.Info.
	Info Info `yaml:"info" json:"info"`

	// Engine is the protocol this template targets.
	// "http" | "dns" | "tcp" | "udp" | "file"
	// BLACKHORN extension — Nuclei uses separate top-level keys per protocol.
	Engine string `yaml:"engine,omitempty" json:"engine,omitempty"`

	// Version is the template schema version. BLACKHORN extension.
	Version string `yaml:"version,omitempty" json:"version,omitempty"`

	// HTTP is the list of HTTP request definitions.
	// Mirrors nuclei requests[] (also accepted as "http:").
	HTTP []HTTPRequest `yaml:"http,omitempty" json:"http,omitempty"`

	// DNS is the list of DNS request definitions.
	// Mirrors nuclei dns[] field.
	DNS []DNSRequest `yaml:"dns,omitempty" json:"dns,omitempty"`

	// TCP is the list of raw TCP probe definitions.
	// Mirrors nuclei network[] field (renamed for clarity).
	TCP []TCPRequest `yaml:"tcp,omitempty" json:"tcp,omitempty"`

	// UDP is the list of UDP probe definitions.
	// BLACKHORN extension.
	UDP []UDPRequest `yaml:"udp,omitempty" json:"udp,omitempty"`

	// File is the list of file-analysis definitions.
	// Mirrors nuclei file[] field.
	File []FileRequest `yaml:"file,omitempty" json:"file,omitempty"`

	// Signature holds the ed25519 signature over the template body.
	// BLACKHORN extension — not present in Nuclei.
	Signature *SignedBundle `yaml:"signature,omitempty" json:"signature,omitempty"`

	// compiled is set to true after Compile() succeeds.
	compiled bool
}

// ─── Info ─────────────────────────────────────────────────────────────────────

// Info holds template metadata.
// Field names mirror nuclei/pkg/model/info.go exactly.
type Info struct {
	// Name is the human-readable template name. Mirrors nuclei Info.Name.
	Name string `yaml:"name" json:"name"`

	// Author is the template author(s). Mirrors nuclei Info.Author.
	Author string `yaml:"author,omitempty" json:"author,omitempty"`

	// Severity is the finding severity. Mirrors nuclei Info.Severity.
	Severity Severity `yaml:"severity" json:"severity"`

	// Description explains what the template detects. Mirrors nuclei Info.Description.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// Remediation describes how to fix the issue. Mirrors nuclei Info.Remediation.
	Remediation string `yaml:"remediation,omitempty" json:"remediation,omitempty"`

	// Reference is a list of reference URLs. Mirrors nuclei Info.Reference.
	Reference []string `yaml:"reference,omitempty" json:"reference,omitempty"`

	// Tags is the typed tag list. Mirrors nuclei Info.Tags (StringSlice).
	Tags TagSet `yaml:"tags,omitempty" json:"tags,omitempty"`

	// Classification holds CVE/CWE/CVSS data. Mirrors nuclei Info.Classification.
	Classification *Classification `yaml:"classification,omitempty" json:"classification,omitempty"`

	// Metadata holds additional key-value data. Mirrors nuclei Info.Metadata.
	Metadata Metadata `yaml:"metadata,omitempty" json:"metadata,omitempty"`

	// ConfidenceScore is the pre-computed detection confidence 0–100.
	// BLACKHORN extension.
	ConfidenceScore int `yaml:"confidence,omitempty" json:"confidence,omitempty"`
}

// Classification mirrors nuclei classification struct.
type Classification struct {
	CVEID       []string `yaml:"cve-id,omitempty" json:"cve-id,omitempty"`
	CWEID       []string `yaml:"cwe-id,omitempty" json:"cwe-id,omitempty"`
	CVSSMetrics string   `yaml:"cvss-metrics,omitempty" json:"cvss-metrics,omitempty"`
	CVSSScore   float64  `yaml:"cvss-score,omitempty" json:"cvss-score,omitempty"`
}

// Metadata holds template metadata key-value pairs.
// Typed for BLACKHORN extensions; extra pairs go in Extra.
type Metadata struct {
	// Source indicates template origin: "builtin" | "community" | "custom".
	// BLACKHORN extension.
	Source string `yaml:"source,omitempty" json:"source,omitempty"`

	// Verified indicates manual verification. Mirrors nuclei verified field.
	Verified bool `yaml:"verified,omitempty" json:"verified,omitempty"`

	// MaxRequest is the maximum number of requests this template makes.
	// Mirrors nuclei max-request metadata.
	MaxRequest int `yaml:"max-request,omitempty" json:"max-request,omitempty"`

	// Extra holds arbitrary additional metadata.
	Extra map[string]string `yaml:"extra,omitempty" json:"extra,omitempty"`
}

// ─── Severity ─────────────────────────────────────────────────────────────────

// Severity mirrors nuclei/pkg/model/types/severity/severity.go constants exactly.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
	SeverityUnknown  Severity = "unknown"
)

// Valid returns true if the severity is a known value.
func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// ─── TagSet ───────────────────────────────────────────────────────────────────

// TagSet is a typed tag slice with helpers.
// Mirrors nuclei StringSlice — BLACKHORN adds Contains/MatchesAny.
type TagSet []string

// Contains returns true if the tag is present (case-insensitive).
func (ts TagSet) Contains(tag string) bool {
	tag = strings.ToLower(tag)
	for _, t := range ts {
		if strings.ToLower(t) == tag {
			return true
		}
	}
	return false
}

// MatchesAny returns true if at least one tag in filter is present.
func (ts TagSet) MatchesAny(filter []string) bool {
	for _, f := range filter {
		if ts.Contains(f) {
			return true
		}
	}
	return false
}

// ─── HTTP Request ─────────────────────────────────────────────────────────────

// HTTPRequest defines a single HTTP probe.
// Field names mirror nuclei/pkg/protocols/http/request.go exactly.
type HTTPRequest struct {
	// Method is the HTTP method. Mirrors nuclei Method field.
	Method string `yaml:"method,omitempty" json:"method,omitempty"`

	// Path is the list of request paths. Supports {{BaseURL}} variables.
	// Mirrors nuclei path field.
	Path []string `yaml:"path,omitempty" json:"path,omitempty"`

	// Headers is a map of additional headers. Mirrors nuclei headers field.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`

	// Body is the request body for POST/PUT. Mirrors nuclei body field.
	Body string `yaml:"body,omitempty" json:"body,omitempty"`

	// Redirects controls redirect following. Mirrors nuclei redirects field.
	Redirects bool `yaml:"redirects,omitempty" json:"redirects,omitempty"`

	// MaxRedirects is the max redirects to follow. Mirrors nuclei max-redirects.
	MaxRedirects int `yaml:"max-redirects,omitempty" json:"max-redirects,omitempty"`

	// Matchers is the list of response matchers. Mirrors nuclei matchers field.
	Matchers []Matcher `yaml:"matchers,omitempty" json:"matchers,omitempty"`

	// MatchersCondition is "and" | "or" (default: "or").
	// Mirrors nuclei matchers-condition field.
	MatchersCondition string `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"`

	// Extractors is the list of response extractors. Mirrors nuclei extractors field.
	Extractors []Extractor `yaml:"extractors,omitempty" json:"extractors,omitempty"`

	// StopAtFirstMatch stops after first matching path. Mirrors nuclei stop-at-first-match.
	StopAtFirstMatch bool `yaml:"stop-at-first-match,omitempty" json:"stop-at-first-match,omitempty"`

	// Timeout overrides per-request timeout in seconds. BLACKHORN extension.
	Timeout int `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// ─── DNS Request ──────────────────────────────────────────────────────────────

// DNSRequest defines a DNS probe.
// Field names mirror nuclei/pkg/protocols/dns/request.go exactly.
type DNSRequest struct {
	// Name is the DNS name to query. Supports {{FQDN}} variable.
	Name string `yaml:"name" json:"name"`

	// Type is the DNS record type (A, AAAA, CNAME, MX, NS, TXT, PTR, SOA).
	// Mirrors nuclei type field.
	Type string `yaml:"type,omitempty" json:"type,omitempty"`

	// Class is the DNS class (default: "inet"). Mirrors nuclei class field.
	Class string `yaml:"class,omitempty" json:"class,omitempty"`

	// Retries is the query retry count. Mirrors nuclei retries field.
	Retries int `yaml:"retries,omitempty" json:"retries,omitempty"`

	// Recursion controls recursive lookup. Mirrors nuclei recursion field.
	Recursion *bool `yaml:"recursion,omitempty" json:"recursion,omitempty"`

	// Resolvers overrides default resolvers. BLACKHORN extension.
	Resolvers []string `yaml:"resolvers,omitempty" json:"resolvers,omitempty"`

	// Matchers for the DNS response.
	Matchers []Matcher `yaml:"matchers,omitempty" json:"matchers,omitempty"`

	// MatchersCondition is "and" | "or".
	MatchersCondition string `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"`

	// Extractors for the DNS response.
	Extractors []Extractor `yaml:"extractors,omitempty" json:"extractors,omitempty"`
}

// ─── TCP Request ──────────────────────────────────────────────────────────────

// TCPRequest defines a raw TCP probe.
// Field names mirror nuclei/pkg/protocols/network/request.go exactly.
type TCPRequest struct {
	// Address is the list of host:port targets. Supports {{Hostname}}:{{Port}}.
	Address []string `yaml:"address,omitempty" json:"address,omitempty"`

	// Inputs is the list of data to send. Mirrors nuclei inputs field.
	Inputs []NetworkInput `yaml:"inputs,omitempty" json:"inputs,omitempty"`

	// ReadSize is the bytes to read from the response. Mirrors nuclei read-size.
	ReadSize int `yaml:"read-size,omitempty" json:"read-size,omitempty"`

	// Matchers for the response.
	Matchers []Matcher `yaml:"matchers,omitempty" json:"matchers,omitempty"`

	// MatchersCondition is "and" | "or".
	MatchersCondition string `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"`

	// Extractors for the response.
	Extractors []Extractor `yaml:"extractors,omitempty" json:"extractors,omitempty"`
}

// UDPRequest defines a raw UDP probe. BLACKHORN extension.
// Mirrors TCPRequest structure for consistency.
type UDPRequest struct {
	Address           []string       `yaml:"address,omitempty" json:"address,omitempty"`
	Inputs            []NetworkInput `yaml:"inputs,omitempty" json:"inputs,omitempty"`
	ReadSize          int            `yaml:"read-size,omitempty" json:"read-size,omitempty"`
	Matchers          []Matcher      `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	MatchersCondition string         `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"`
	Extractors        []Extractor    `yaml:"extractors,omitempty" json:"extractors,omitempty"`
}

// NetworkInput mirrors nuclei network input struct.
type NetworkInput struct {
	// Data is the hex-encoded or raw data to send.
	Data string `yaml:"data,omitempty" json:"data,omitempty"`

	// Type is "hex" | "text" (default: "text"). Mirrors nuclei type field.
	Type string `yaml:"type,omitempty" json:"type,omitempty"`

	// Read is the bytes to read after sending. Mirrors nuclei read field.
	Read int `yaml:"read,omitempty" json:"read,omitempty"`
}

// ─── File Request ─────────────────────────────────────────────────────────────

// FileRequest defines a file-based analysis request.
// Mirrors nuclei/pkg/protocols/file/request.go.
type FileRequest struct {
	// Extensions is the list of file extensions to match (e.g. ".log", ".env").
	Extensions []string `yaml:"extensions,omitempty" json:"extensions,omitempty"`

	// DenyList is the list of extensions to exclude.
	DenyList []string `yaml:"denylist,omitempty" json:"denylist,omitempty"`

	// Matchers for file content.
	Matchers []Matcher `yaml:"matchers,omitempty" json:"matchers,omitempty"`

	// MatchersCondition is "and" | "or".
	MatchersCondition string `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"`

	// Extractors for file content.
	Extractors []Extractor `yaml:"extractors,omitempty" json:"extractors,omitempty"`
}

// ─── Matcher ──────────────────────────────────────────────────────────────────

// MatcherType mirrors nuclei matcher type constants exactly.
type MatcherType string

const (
	StatusMatcher MatcherType = "status" // mirrors nuclei StatusMatcher
	WordMatcher   MatcherType = "word"   // mirrors nuclei WordsMatcher
	RegexMatcher  MatcherType = "regex"  // mirrors nuclei RegexMatcher
	SizeMatcher   MatcherType = "size"   // mirrors nuclei SizeMatcher
	BinaryMatcher MatcherType = "binary" // mirrors nuclei BinaryMatcher
	DSLMatcher    MatcherType = "dsl"    // mirrors nuclei DSLMatcher
)

// MatcherPart mirrors nuclei matcher part constants exactly.
type MatcherPart string

const (
	PartBody       MatcherPart = "body"
	PartHeader     MatcherPart = "header"
	PartAll        MatcherPart = "all"
	PartRaw        MatcherPart = "raw"
	PartStatusCode MatcherPart = "status_code"
	// DNS-specific parts — mirrors nuclei DNS matcher parts.
	PartAnswer     MatcherPart = "answer"
	PartAuthority  MatcherPart = "authority"
	PartAdditional MatcherPart = "additional"
	PartQuestion   MatcherPart = "question"
	// Network-specific.
	PartData MatcherPart = "data"
)

// Matcher defines a single match condition.
// Field names and YAML/JSON tags mirror nuclei/pkg/operators/matchers/matchers.go exactly.
type Matcher struct {
	// Type is the matcher type. Mirrors nuclei Matcher.Type.
	Type MatcherType `yaml:"type" json:"type"`

	// Part specifies which response part to match. Mirrors nuclei Matcher.Part.
	Part MatcherPart `yaml:"part,omitempty" json:"part,omitempty"`

	// Condition is "and" | "or" for multi-value matchers. Mirrors nuclei Matcher.Condition.
	Condition string `yaml:"condition,omitempty" json:"condition,omitempty"`

	// Negative inverts the match result. Mirrors nuclei Matcher.Negative.
	Negative bool `yaml:"negative,omitempty" json:"negative,omitempty"`

	// CaseSensitive disables case-insensitive matching for word matchers.
	CaseSensitive bool `yaml:"case-sensitive,omitempty" json:"case-sensitive,omitempty"`

	// Status is a list of HTTP status codes to match. Mirrors nuclei Matcher.Status.
	Status []int `yaml:"status,omitempty" json:"status,omitempty"`

	// Words is a list of strings to match. Mirrors nuclei Matcher.Words.
	Words []string `yaml:"words,omitempty" json:"words,omitempty"`

	// Regex is a list of regular expressions to match. Mirrors nuclei Matcher.Regex.
	Regex []string `yaml:"regex,omitempty" json:"regex,omitempty"`

	// Size is a list of response sizes to match. Mirrors nuclei Matcher.Size.
	Size []int `yaml:"size,omitempty" json:"size,omitempty"`

	// Binary is a list of hex-encoded binary strings. Mirrors nuclei Matcher.Binary.
	Binary []string `yaml:"binary,omitempty" json:"binary,omitempty"`

	// DSL is a list of DSL expressions. Mirrors nuclei Matcher.DSL.
	DSL []string `yaml:"dsl,omitempty" json:"dsl,omitempty"`

	// compiled holds pre-compiled regex objects after Compile() is called.
	compiled []*regexp.Regexp
}

// CompiledRegexes returns the compiled regexes for a RegexMatcher.
func (m *Matcher) CompiledRegexes() []*regexp.Regexp { return m.compiled }

// ─── Extractor ────────────────────────────────────────────────────────────────

// ExtractorType mirrors nuclei extractor type constants exactly.
type ExtractorType string

const (
	RegexExtractor ExtractorType = "regex" // mirrors nuclei RegexExtractor
	KVExtractor    ExtractorType = "kval"  // mirrors nuclei KValExtractor
	JSONExtractor  ExtractorType = "json"  // mirrors nuclei JSONExtractor
	XPathExtractor ExtractorType = "xpath" // mirrors nuclei XPathExtractor
	DSLExtractor   ExtractorType = "dsl"   // mirrors nuclei DSLExtractor
)

// Extractor defines a single extraction rule.
// Field names and YAML/JSON tags mirror nuclei/pkg/operators/extractors/extractors.go exactly.
type Extractor struct {
	// Name is the extractor name (used as variable in subsequent requests).
	Name string `yaml:"name,omitempty" json:"name,omitempty"`

	// Type is the extractor type. Mirrors nuclei Extractor.Type.
	Type ExtractorType `yaml:"type" json:"type"`

	// Part specifies which response part to extract from.
	Part MatcherPart `yaml:"part,omitempty" json:"part,omitempty"`

	// Regex is a list of extraction regexes. Mirrors nuclei Extractor.Regex.
	Regex []string `yaml:"regex,omitempty" json:"regex,omitempty"`

	// Group is the regex capture group to use (default 0). Mirrors nuclei Extractor.Group.
	Group int `yaml:"group,omitempty" json:"group,omitempty"`

	// KVal is a list of header/cookie keys to extract values from.
	KVal []string `yaml:"kval,omitempty" json:"kval,omitempty"`

	// JSON is a list of JQ-style JSON paths. Mirrors nuclei Extractor.JSON.
	JSON []string `yaml:"json,omitempty" json:"json,omitempty"`

	// XPath is a list of XPath expressions. Mirrors nuclei Extractor.XPath.
	XPath []string `yaml:"xpath,omitempty" json:"xpath,omitempty"`

	// DSL is a list of DSL expressions. Mirrors nuclei Extractor.DSL.
	DSL []string `yaml:"dsl,omitempty" json:"dsl,omitempty"`

	// Internal marks the value as internal only (not emitted in findings).
	Internal bool `yaml:"internal,omitempty" json:"internal,omitempty"`

	// compiled holds pre-compiled regex objects after Compile() is called.
	compiled []*regexp.Regexp
}

// CompiledRegexes returns the compiled regexes for a RegexExtractor.
func (e *Extractor) CompiledRegexes() []*regexp.Regexp { return e.compiled }

// ─── Signed bundle (BLACKHORN extension) ─────────────────────────────────────

// SignedBundle holds the ed25519 signature over template content.
// Enables trusted template distribution: in strict mode, only templates signed
// by known public keys are loaded.
// BLACKHORN extension — not present in Nuclei.
type SignedBundle struct {
	// PublicKey is the hex-encoded ed25519 public key.
	PublicKey string `yaml:"public-key" json:"public-key"`

	// Signature is the base64-encoded ed25519 signature over the template body.
	Signature string `yaml:"signature" json:"signature"`

	// SignedAt is the RFC 3339 timestamp of signing.
	SignedAt time.Time `yaml:"signed-at,omitempty" json:"signed-at,omitempty"`

	// SignerID is a human-readable signer identifier (e.g. "blackhorn-core").
	SignerID string `yaml:"signer-id,omitempty" json:"signer-id,omitempty"`
}

// Verify verifies the ed25519 signature over the given content bytes.
func (sb *SignedBundle) Verify(content []byte) error {
	if sb == nil {
		return fmt.Errorf("template: no signature bundle")
	}
	pubKeyBytes, err := hex.DecodeString(sb.PublicKey)
	if err != nil {
		return fmt.Errorf("template: decode public key: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("template: public key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(pubKeyBytes))
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sb.Signature)
	if err != nil {
		// Try URL encoding.
		sigBytes, err = base64.URLEncoding.DecodeString(sb.Signature)
		if err != nil {
			return fmt.Errorf("template: decode signature: %w", err)
		}
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), content, sigBytes) {
		return fmt.Errorf("template: signature verification failed")
	}
	return nil
}

// ─── Validation ───────────────────────────────────────────────────────────────

// Validate performs structural validation of the template.
// Mirrors nuclei template validation logic.
func (t *Template) Validate() error {
	if t.ID == "" {
		return fmt.Errorf("template: id is required")
	}
	if t.Info.Name == "" {
		return fmt.Errorf("template %q: info.name is required", t.ID)
	}
	if !t.Info.Severity.Valid() {
		return fmt.Errorf("template %q: invalid severity %q", t.ID, t.Info.Severity)
	}
	hasRequests := len(t.HTTP) > 0 || len(t.DNS) > 0 ||
		len(t.TCP) > 0 || len(t.UDP) > 0 || len(t.File) > 0
	if !hasRequests {
		return fmt.Errorf("template %q: at least one request definition is required", t.ID)
	}
	for i, req := range t.HTTP {
		for j, m := range req.Matchers {
			if err := m.Validate(); err != nil {
				return fmt.Errorf("template %q: http[%d].matchers[%d]: %w", t.ID, i, j, err)
			}
		}
	}
	return nil
}

// Validate checks matcher structural validity.
func (m *Matcher) Validate() error {
	switch m.Type {
	case StatusMatcher:
		if len(m.Status) == 0 {
			return fmt.Errorf("status matcher requires at least one status code")
		}
	case WordMatcher:
		if len(m.Words) == 0 {
			return fmt.Errorf("word matcher requires at least one word")
		}
	case RegexMatcher:
		if len(m.Regex) == 0 {
			return fmt.Errorf("regex matcher requires at least one pattern")
		}
	case SizeMatcher:
		if len(m.Size) == 0 {
			return fmt.Errorf("size matcher requires at least one size value")
		}
	case BinaryMatcher:
		if len(m.Binary) == 0 {
			return fmt.Errorf("binary matcher requires at least one hex string")
		}
	case DSLMatcher:
		if len(m.DSL) == 0 {
			return fmt.Errorf("dsl matcher requires at least one expression")
		}
	default:
		return fmt.Errorf("unknown matcher type %q", m.Type)
	}
	return nil
}

// ─── Compile ──────────────────────────────────────────────────────────────────

// Compile pre-compiles all regex patterns in the template for efficient execution.
// Must be called before the template is passed to the engine.
// Mirrors nuclei template compilation step.
func (t *Template) Compile() error {
	for i := range t.HTTP {
		if err := compileMatcherSlice(t.HTTP[i].Matchers); err != nil {
			return fmt.Errorf("template %q http[%d]: %w", t.ID, i, err)
		}
		if err := compileExtractorSlice(t.HTTP[i].Extractors); err != nil {
			return fmt.Errorf("template %q http[%d] extractors: %w", t.ID, i, err)
		}
	}
	for i := range t.DNS {
		if err := compileMatcherSlice(t.DNS[i].Matchers); err != nil {
			return fmt.Errorf("template %q dns[%d]: %w", t.ID, i, err)
		}
	}
	for i := range t.TCP {
		if err := compileMatcherSlice(t.TCP[i].Matchers); err != nil {
			return fmt.Errorf("template %q tcp[%d]: %w", t.ID, i, err)
		}
	}
	for i := range t.UDP {
		if err := compileMatcherSlice(t.UDP[i].Matchers); err != nil {
			return fmt.Errorf("template %q udp[%d]: %w", t.ID, i, err)
		}
	}
	for i := range t.File {
		if err := compileMatcherSlice(t.File[i].Matchers); err != nil {
			return fmt.Errorf("template %q file[%d]: %w", t.ID, i, err)
		}
		if err := compileExtractorSlice(t.File[i].Extractors); err != nil {
			return fmt.Errorf("template %q file[%d] extractors: %w", t.ID, i, err)
		}
	}
	t.compiled = true
	return nil
}

// IsCompiled returns true if Compile() completed successfully.
func (t *Template) IsCompiled() bool { return t.compiled }

func compileMatcherSlice(matchers []Matcher) error {
	for i := range matchers {
		if matchers[i].Type != RegexMatcher {
			continue
		}
		matchers[i].compiled = make([]*regexp.Regexp, 0, len(matchers[i].Regex))
		for _, pattern := range matchers[i].Regex {
			// Try case-insensitive first (standard for security tools).
			re, err := regexp.Compile(`(?i)` + pattern)
			if err != nil {
				// Pattern may already contain flags — compile as-is.
				re, err = regexp.Compile(pattern)
				if err != nil {
					return fmt.Errorf("compile regex %q: %w", pattern, err)
				}
			}
			matchers[i].compiled = append(matchers[i].compiled, re)
		}
	}
	return nil
}

func compileExtractorSlice(extractors []Extractor) error {
	for i := range extractors {
		if extractors[i].Type != RegexExtractor {
			continue
		}
		extractors[i].compiled = make([]*regexp.Regexp, 0, len(extractors[i].Regex))
		for _, pattern := range extractors[i].Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("compile extractor regex %q: %w", pattern, err)
			}
			extractors[i].compiled = append(extractors[i].compiled, re)
		}
	}
	return nil
}
