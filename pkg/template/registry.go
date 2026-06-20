package template

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── Registry ─────────────────────────────────────────────────────────────────

// Registry is the central template store.
// It holds compiled templates and supports filtering, signing, and
// community feed pulls.
//
// Thread-safe: all methods are safe for concurrent use.
//
// BLACKHORN extension — Nuclei has no equivalent runtime registry.
type Registry struct {
	mu          sync.RWMutex
	templates   map[string]*Template // id → template
	trustedKeys []ed25519.PublicKey  // keys allowed to sign templates
	logger      *slog.Logger
	httpClient  *http.Client
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		templates:  make(map[string]*Template),
		logger:     slog.Default().With("component", "template-registry"),
		httpClient: defaultHTTPClient(),
	}
}

// NewRegistryWithLogger creates a Registry with a custom logger.
func NewRegistryWithLogger(logger *slog.Logger) *Registry {
	r := NewRegistry()
	r.logger = logger
	return r
}

// ─── Registration ─────────────────────────────────────────────────────────────

// Add adds a compiled template to the registry.
// Returns an error if the template ID is already registered.
func (r *Registry) Add(t *Template) error {
	if t == nil {
		return fmt.Errorf("registry: cannot add nil template")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.templates[t.ID]; exists {
		return fmt.Errorf("registry: template %q already registered", t.ID)
	}
	r.templates[t.ID] = t
	r.logger.Debug("template registered", "id", t.ID, "engine", t.Engine)
	return nil
}

// AddOrReplace adds or replaces a template in the registry.
func (r *Registry) AddOrReplace(t *Template) {
	if t == nil {
		return
	}
	r.mu.Lock()
	r.templates[t.ID] = t
	r.mu.Unlock()
	r.logger.Debug("template added/replaced", "id", t.ID)
}

// Remove removes a template by ID.
func (r *Registry) Remove(id string) {
	r.mu.Lock()
	delete(r.templates, id)
	r.mu.Unlock()
}

// Get returns a template by ID, or nil if not found.
func (r *Registry) Get(id string) *Template {
	r.mu.RLock()
	t := r.templates[id]
	r.mu.RUnlock()
	return t
}

// Len returns the number of registered templates.
func (r *Registry) Len() int {
	r.mu.RLock()
	n := len(r.templates)
	r.mu.RUnlock()
	return n
}

// ─── Querying ─────────────────────────────────────────────────────────────────

// FilterOptions controls template selection.
type FilterOptions struct {
	// IDs selects specific template IDs. Empty = all.
	IDs []string

	// Tags selects templates that have at least one matching tag. Empty = all.
	Tags []string

	// Severity selects templates with the given severity. Empty = all.
	Severity Severity

	// Engine selects templates for a specific engine. Empty = all.
	Engine string

	// Source selects templates by metadata source ("builtin","community","custom"). Empty = all.
	Source string
}

// Filter returns all templates matching the given options, sorted by ID.
func (r *Registry) Filter(opts FilterOptions) []*Template {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*Template
	for _, t := range r.templates {
		if !matchesFilter(t, opts) {
			continue
		}
		result = append(result, t)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result
}

// All returns all registered templates sorted by ID.
func (r *Registry) All() []*Template {
	return r.Filter(FilterOptions{})
}

func matchesFilter(t *Template, opts FilterOptions) bool {
	// ID filter.
	if len(opts.IDs) > 0 {
		found := false
		for _, id := range opts.IDs {
			if strings.EqualFold(t.ID, id) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// Tag filter.
	if len(opts.Tags) > 0 && !t.Info.Tags.MatchesAny(opts.Tags) {
		return false
	}
	// Severity filter.
	if opts.Severity != "" && t.Info.Severity != opts.Severity {
		return false
	}
	// Engine filter.
	if opts.Engine != "" && !strings.EqualFold(t.Engine, opts.Engine) {
		return false
	}
	// Source filter.
	if opts.Source != "" && !strings.EqualFold(t.Info.Metadata.Source, opts.Source) {
		return false
	}
	return true
}

// ─── Bulk loading ─────────────────────────────────────────────────────────────

// LoadDirectory loads all templates from a directory and registers them.
// Returns the count of loaded templates and any per-file errors.
func (r *Registry) LoadDirectory(dir string, opts ParseOptions) (int, map[string]error) {
	templates, errors := ParseDirectory(dir, opts)
	for _, t := range templates {
		if err := r.Add(t); err != nil {
			errors[t.ID] = err
		}
	}
	r.logger.Info("directory loaded",
		"dir", dir,
		"loaded", len(templates),
		"errors", len(errors),
	)
	return len(templates), errors
}

// LoadBuiltin registers a slice of pre-compiled builtin templates.
// Panics if any template is nil or fails Add() — builtins must always succeed.
func (r *Registry) LoadBuiltin(templates []*Template) {
	for _, t := range templates {
		if t == nil {
			panic("template: LoadBuiltin: nil template")
		}
		if err := r.Add(t); err != nil {
			// Duplicate IDs in builtins are a programming error.
			panic(fmt.Sprintf("template: LoadBuiltin: %v", err))
		}
	}
	r.logger.Info("builtins loaded", "count", len(templates))
}

// ─── Community feed (Componente 5) ───────────────────────────────────────────

// FeedOptions configures a community template feed pull.
type FeedOptions struct {
	// URL is the feed endpoint URL.
	// Expected to return a newline-delimited list of YAML template URLs,
	// or a JSON array of template objects.
	URL string

	// MaxTemplates limits the number of templates pulled. 0 = unlimited.
	MaxTemplates int

	// Timeout overrides the default feed pull timeout.
	Timeout time.Duration

	// ParseOpts is passed to the parser for each template.
	ParseOpts ParseOptions

	// Tags filters which templates to pull by tag.
	Tags []string
}

// PullFeed fetches templates from a community feed URL and registers them.
// Returns the number of successfully loaded templates.
// BLACKHORN extension — Nuclei has no equivalent programmatic feed pull.
func (r *Registry) PullFeed(ctx context.Context, opts FeedOptions) (int, error) {
	if opts.URL == "" {
		return 0, fmt.Errorf("template: feed URL is required")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.URL, nil)
	if err != nil {
		return 0, fmt.Errorf("template: feed request: %w", err)
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "blackhorn-template-engine/1.0")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("template: feed fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("template: feed returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10 MiB limit
	if err != nil {
		return 0, fmt.Errorf("template: feed read: %w", err)
	}

	// Parse the feed body as a newline-delimited list of template YAML blobs
	// or as a single JSON array.
	templates, parseErr := parseFeedBody(body, opts)
	if parseErr != nil {
		return 0, parseErr
	}

	loaded := 0
	for _, t := range templates {
		if opts.MaxTemplates > 0 && loaded >= opts.MaxTemplates {
			break
		}
		// Tag filter.
		if len(opts.Tags) > 0 && !t.Info.Tags.MatchesAny(opts.Tags) {
			continue
		}
		t.Info.Metadata.Source = "community"
		r.AddOrReplace(t)
		loaded++
	}

	r.logger.Info("feed pulled",
		"url", opts.URL,
		"loaded", loaded,
		"total_in_feed", len(templates),
	)
	return loaded, nil
}

// parseFeedBody tries to parse templates from a feed response body.
// Supports: YAML document stream (---), JSON array, or single template.
func parseFeedBody(body []byte, opts FeedOptions) ([]*Template, error) {
	s := strings.TrimSpace(string(body))

	// JSON array of template objects.
	if strings.HasPrefix(s, "[") {
		return parseFeedJSON(body, opts.ParseOpts)
	}

	// YAML document stream (multiple documents separated by ---).
	if strings.Contains(s, "\n---") || strings.HasPrefix(s, "---") {
		return parseFeedYAMLStream(body, opts.ParseOpts)
	}

	// Single template.
	t, err := ParseBytes(body, opts.ParseOpts)
	if err != nil {
		return nil, err
	}
	return []*Template{t}, nil
}

func parseFeedJSON(data []byte, opts ParseOptions) ([]*Template, error) {
	// Parse as a JSON array of raw template bytes.
	// Each element is either a full template object or a URL string.
	// For MVP: treat as a JSON array of YAML strings (base64 or raw).
	t, err := ParseJSON(data, opts)
	if err != nil {
		return nil, fmt.Errorf("template: feed json parse: %w", err)
	}
	return []*Template{t}, nil
}

func parseFeedYAMLStream(data []byte, opts ParseOptions) ([]*Template, error) {
	parts := strings.Split(string(data), "\n---")
	var templates []*Template
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "---" {
			continue
		}
		t, err := ParseYAML([]byte(part), opts)
		if err != nil {
			continue // skip malformed templates in stream
		}
		templates = append(templates, t)
	}
	return templates, nil
}

// ─── Signing utilities (Componente 4 — signed bundles) ───────────────────────

// GenerateKeyPair generates a new ed25519 key pair for template signing.
// Returns (hexPublicKey, hexPrivateKey, error).
// BLACKHORN extension.
func GenerateKeyPair() (pubHex, privHex string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("template: generate key pair: %w", err)
	}
	return hex.EncodeToString(pub), hex.EncodeToString(priv), nil
}

// SignTemplate signs a template's YAML content with the given private key.
// Populates the template's Signature field.
// BLACKHORN extension.
func SignTemplate(t *Template, privKeyHex string, signerID string) error {
	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return fmt.Errorf("template: decode private key: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("template: private key must be %d bytes", ed25519.PrivateKeySize)
	}

	// Serialize the template to YAML (without the signature field) for signing.
	// We sign the canonical content: id + info + requests.
	content := canonicalContent(t)

	sig := ed25519.Sign(ed25519.PrivateKey(privBytes), []byte(content))
	pubKey := ed25519.PrivateKey(privBytes).Public().(ed25519.PublicKey)

	t.Signature = &SignedBundle{
		PublicKey: hex.EncodeToString(pubKey),
		Signature: base64.StdEncoding.EncodeToString(sig),
		SignedAt:  time.Now().UTC(),
		SignerID:  signerID,
	}
	return nil
}

// AddTrustedKey registers a trusted signer public key (hex-encoded).
func (r *Registry) AddTrustedKey(hexPubKey string) error {
	pubBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return fmt.Errorf("template: decode public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("template: public key must be %d bytes", ed25519.PublicKeySize)
	}
	r.mu.Lock()
	r.trustedKeys = append(r.trustedKeys, ed25519.PublicKey(pubBytes))
	r.mu.Unlock()
	return nil
}

// canonicalContent returns the deterministic string content of a template for signing.
// Uses the ID + engine + severity + first request path as a stable representation.
// Production implementation would use full YAML serialization.
func canonicalContent(t *Template) string {
	var sb strings.Builder
	sb.WriteString("id:")
	sb.WriteString(t.ID)
	sb.WriteString("\nengine:")
	sb.WriteString(t.Engine)
	sb.WriteString("\nseverity:")
	sb.WriteString(string(t.Info.Severity))
	sb.WriteString("\nname:")
	sb.WriteString(t.Info.Name)
	for i, req := range t.HTTP {
		sb.WriteString(fmt.Sprintf("\nhttp[%d].method:%s", i, req.Method))
		for _, p := range req.Path {
			sb.WriteString("\npath:")
			sb.WriteString(p)
		}
	}
	return sb.String()
}

// ─── Utility ──────────────────────────────────────────────────────────────────

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 5,
		},
	}
}
