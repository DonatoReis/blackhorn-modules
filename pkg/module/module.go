// Package module defines the core interface that every blackhorn-modules
// implementation must satisfy. The interface is intentionally minimal so
// that modules stay self-contained and future integration with orbit-core
// requires no changes on the module side.
package module

import "context"

// Severity levels for findings, aligned with CVSS qualitative scale.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Input carries everything a module needs to run.
// Target is the primary scope (domain, URL, IP).
// URLs is an optional pre-seeded list (e.g. from a previous stage).
// Options holds module-specific flags as key/value strings.
// RawContent is an optional pre-fetched content string (used by truffler and similar
// modules that can scan content directly without making HTTP requests).
type Input struct {
	Target     string
	URLs       []string
	Options    map[string]string
	RawContent string
}

// Finding is a single result emitted by a module.
// Modules must not write to disk or stdout — all output comes through
// the []Finding slice returned by Run.
type Finding struct {
	Type     string            // e.g. "historical_reference", "cors_misconfiguration", "reflected_xss"
	URL      string            // affected URL
	Detail   string            // human-readable description
	Severity Severity          // info | low | medium | high | critical
	Extra    map[string]string // optional structured metadata
}

// Module is the interface every internal module must implement.
// Run must respect ctx cancellation and return promptly when ctx is done.
// Run must be safe to call concurrently from multiple goroutines.
type Module interface {
	// Name returns the canonical module identifier (e.g. "wayback", "corsaudit").
	Name() string

	// Run executes the module logic against input and returns all findings.
	// It must not produce side effects outside the returned slice.
	Run(ctx context.Context, input Input) ([]Finding, error)
}
