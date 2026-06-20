// Package registry provides a central catalog of all available blackhorn-modules.
//
// The registry answers three questions that the Blackhorn orchestrator needs:
//  1. Which modules exist?
//  2. What does each module require to run (env vars, options, gates)?
//  3. How do I get an instance of a specific module?
//
// Design principles (guia-go §2, dicas.md §11-12):
//   - Zero dependency on the module implementations themselves — the registry
//     stores metadata only; module construction happens via registered factories.
//   - Metadata is queryable: filter by category, by required key, by gate.
//   - Thread-safe: Register and Lookup can be called from multiple goroutines.
//   - Fail-fast on duplicate registration (programming error, not runtime error).
package registry

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// Gate describes an authorization requirement that must be satisfied before
// the module runs. Missing gates cause the orchestrator to prompt the user.
type Gate string

const (
	GateLGPD       Gate = "lgpd_consent" // requires Options["lgpd_consent"]="true"
	GateAuthorized Gate = "authorized"   // requires Options["authorized"]="true"
)

// EnvVar describes an environment variable consumed by a module.
type EnvVar struct {
	Name     string // e.g. "HIBP_API_KEY"
	Required bool   // false = optional (module degrades gracefully without it)
	Hint     string // human-readable description for the Settings UI
}

// Option describes a configurable option accepted by a module via Input.Options.
type Option struct {
	Key     string // options key, e.g. "sources", "timeout", "threads"
	Default string // default value (empty = no default)
	Hint    string // human-readable description for the UI
}

// Category groups modules by function for the UI.
type Category string

const (
	CategoryOSINTBrasil   Category = "osint-brasil"
	CategoryOSINTEmail    Category = "osint-email"
	CategoryOSINTUsername Category = "osint-username"
	CategoryRecon         Category = "recon"
	CategoryWebVuln       Category = "web-vuln"
	CategoryInjection     Category = "injection"
	CategoryNetworkScan   Category = "network-scan"
	CategoryTLS           Category = "tls"
	CategoryCloud         Category = "cloud"
	CategoryThreatIntel   Category = "threat-intel"
	CategorySecrets       Category = "secrets"
	CategoryFingerprint   Category = "fingerprint"
	CategoryHTTPAudit     Category = "http-audit"
	CategoryAuth          Category = "auth"
	CategoryWireless      Category = "wireless"
	CategoryUtil          Category = "util"
)

// Meta holds static metadata about a module.
// Populated once at init time; immutable after registration.
type Meta struct {
	// Name is the canonical module identifier — must match Module.Name().
	Name string

	// Category groups the module in the UI.
	Category Category

	// Description is a one-sentence summary shown in the UI.
	Description string

	// Gates lists required authorization options. Empty = no gate.
	Gates []Gate

	// EnvVars lists environment variables the module reads.
	EnvVars []EnvVar

	// Options lists configurable input options.
	Options []Option

	// InputTypes describes what kinds of Target the module accepts.
	// e.g. ["domain", "url", "ip", "email", "phone", "username", "cpf", "cnpj", "cep"]
	InputTypes []string

	// OutputTypes describes Finding.Type values this module emits.
	// e.g. ["open_port", "scan_summary", "shodan_host"]
	OutputTypes []string

	// Factory constructs a ready-to-use module instance.
	// The factory is called each time the orchestrator needs a fresh instance.
	Factory func() module.Module
}

// Registry is the central catalog.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*Meta
}

// global is the package-level default registry.
var global = &Registry{entries: make(map[string]*Meta)}

// NewRegistry creates an empty, isolated Registry.
// Use for tests or when you need multiple independent catalogs.
func NewRegistry() *Registry {
	return &Registry{entries: make(map[string]*Meta)}
}

// Register adds a module to the global registry.
// Panics if a module with the same name is already registered (programming error).
func Register(m *Meta) {
	global.Register(m)
}

// Lookup returns the Meta for a module by name, or nil if not found.
func Lookup(name string) *Meta {
	return global.Lookup(name)
}

// All returns all registered Metas sorted by name.
func All() []*Meta {
	return global.All()
}

// ByCategory returns all Metas in the given category, sorted by name.
func ByCategory(cat Category) []*Meta {
	return global.ByCategory(cat)
}

// New instantiates a module by name.
// Returns (nil, error) if the name is unknown.
func New(name string) (module.Module, error) {
	return global.New(name)
}

// MustNew instantiates a module by name.
// Panics if the name is unknown — use only in tests or init code.
func MustNew(name string) module.Module {
	m, err := global.New(name)
	if err != nil {
		panic(err)
	}
	return m
}

// Run is a convenience: looks up, instantiates, and runs a module in one call.
func Run(ctx context.Context, name string, input module.Input) ([]module.Finding, error) {
	return global.Run(ctx, name, input)
}

// ─── Registry methods ─────────────────────────────────────────────────────────

// Register adds a Meta to the registry. Panics on duplicate name.
func (r *Registry) Register(m *Meta) {
	if m == nil || m.Name == "" {
		panic("registry: cannot register nil meta or meta with empty name")
	}
	if m.Factory == nil {
		panic(fmt.Sprintf("registry: module %q has no Factory", m.Name))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[m.Name]; exists {
		panic(fmt.Sprintf("registry: module %q already registered", m.Name))
	}
	r.entries[m.Name] = m
}

// Lookup returns the Meta for a name, or nil.
func (r *Registry) Lookup(name string) *Meta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.entries[name]
}

// All returns all Metas sorted by name.
func (r *Registry) All() []*Meta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Meta, 0, len(r.entries))
	for _, m := range r.entries {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ByCategory returns Metas filtered by category, sorted by name.
func (r *Registry) ByCategory(cat Category) []*Meta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Meta
	for _, m := range r.entries {
		if m.Category == cat {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// New instantiates a module by name using its registered Factory.
func (r *Registry) New(name string) (module.Module, error) {
	r.mu.RLock()
	meta, ok := r.entries[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("registry: module %q not found", name)
	}
	return meta.Factory(), nil
}

// Run looks up, instantiates, and runs a module.
func (r *Registry) Run(ctx context.Context, name string, input module.Input) ([]module.Finding, error) {
	mod, err := r.New(name)
	if err != nil {
		return nil, err
	}
	return mod.Run(ctx, input)
}

// ─── Query helpers ────────────────────────────────────────────────────────────

// WithGate returns all modules that require the given gate.
func WithGate(gate Gate) []*Meta {
	return global.WithGate(gate)
}

func (r *Registry) WithGate(gate Gate) []*Meta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Meta
	for _, m := range r.entries {
		for _, g := range m.Gates {
			if g == gate {
				out = append(out, m)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ForInput returns all modules that accept the given input type.
func ForInput(inputType string) []*Meta {
	return global.ForInput(inputType)
}

func (r *Registry) ForInput(inputType string) []*Meta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Meta
	for _, m := range r.entries {
		for _, t := range m.InputTypes {
			if t == inputType {
				out = append(out, m)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Names returns the sorted list of all registered module names.
func Names() []string {
	return global.Names()
}

func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.entries))
	for name := range r.entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Count returns the number of registered modules.
func Count() int {
	return global.Count()
}

func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}
