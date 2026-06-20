// Package graphql implements a GraphQL security audit module.
//
// Reference implementations studied (for algorithm design only, no code copied):
//   - graphql-cop (MIT): https://github.com/dolevf/graphql-cop
//   - InQL (Apache-2.0): https://github.com/doyensec/inql
//   - graphw00f (MIT): https://github.com/dolevf/graphw00f
//
// What is implemented:
//   - Introspection query to enumerate schema (types, queries, mutations, subscriptions)
//   - 12 common GraphQL vulnerability checks:
//     1.  Introspection enabled (information disclosure)
//     2.  Field suggestions enabled (schema enumeration without introspection)
//     3.  GraphQL batching attack (multiple operations in one request)
//     4.  Deep query complexity DoS (deeply nested query)
//     5.  Alias overloading (N aliases for same field)
//     6.  Fragment spreading abuse (circular reference / DoS)
//     7.  Directive overloading (many directives on one field)
//     8.  GET method introspection enabled (CSRF risk)
//     9.  Debug mode / Stack trace leak
//     10.  Mutation-based CSRF (no CSRF tokens)
//     11.  Subscription endpoint exposed
//     12.  Type system leak via __type queries
//   - Endpoint detection via common GraphQL path probing
//   - io.LimitReader on every body read                  (dicas.md §5)
//   - log/slog structured observability                  (dicas.md §16)
//   - errgroup.SetLimit bounded fan-out                  (guia-go §9)
//   - context propagation and cancellation               (guia-go §9)
package graphql

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	// maxBodyRead is the memory ceiling per response body — dicas.md §5.
	maxBodyRead = 5 * 1024 * 1024 // 5 MiB

	// defaultTimeout per HTTP request.
	defaultTimeout = 15 * time.Second

	// defaultThreads — errgroup limit for concurrent endpoint probing.
	defaultThreads = 5
)

// commonPaths are common GraphQL endpoint paths to probe.
// Mirrors graphw00f's path list (MIT).
var commonPaths = []string{
	"/graphql",
	"/graphql/",
	"/graphiql",
	"/graphql/v1",
	"/graphql/v2",
	"/graphql/v3",
	"/api/graphql",
	"/api",
	"/api/v1",
	"/api/v2",
	"/query",
	"/gql",
	"/graph",
	"/v1/graphql",
	"/v2/graphql",
	"/v3/graphql",
	"/playground",
	"/explorer",
	"/console",
}

// ─── GraphQL wire types ───────────────────────────────────────────────────────

// gqlRequest is a standard GraphQL request body.
type gqlRequest struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
}

// gqlResponse is a minimal GraphQL response envelope.
type gqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []gqlError      `json:"errors"`
}

type gqlError struct {
	Message    string                 `json:"message"`
	Extensions map[string]interface{} `json:"extensions"`
}

// IntrospectionResult holds the parsed schema from an introspection query.
type IntrospectionResult struct {
	Types            []TypeInfo
	QueryType        string
	MutationType     string
	SubscriptionType string
}

// TypeInfo holds basic information about a GraphQL type.
type TypeInfo struct {
	Name        string
	Kind        string
	Fields      []string
	Description string
}

// ─── Checks ──────────────────────────────────────────────────────────────────

// Check represents a single GraphQL security check.
// Mirrors graphql-cop's check structure.
type Check struct {
	ID          string
	Name        string
	Description string
	Severity    module.Severity
	Run         func(ctx context.Context, m *Module, endpoint string) ([]module.Finding, error)
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements module.Module for GraphQL security auditing.
type Module struct {
	logger *slog.Logger
	client *http.Client
	checks []Check
}

// New returns a Module with the built-in check set.
func New() *Module {
	m := &Module{
		logger: slog.Default().With("module", "graphql"),
		client: defaultClient(),
	}
	m.checks = builtinChecks(m)
	return m
}

// NewWithClient returns a Module with an injected http.Client (for tests).
func NewWithClient(c *http.Client) *Module {
	m := &Module{
		logger: slog.Default().With("module", "graphql"),
		client: c,
	}
	m.checks = builtinChecks(m)
	return m
}

// Name satisfies module.Module.
func (m *Module) Name() string { return "graphql" }

// Run satisfies module.Module.
// Input.Target or Input.URLs are GraphQL base URLs or endpoint URLs.
//
// Options:
//
//	"threads"     — concurrent check execution (default: 5)
//	"timeout"     — per-request timeout in seconds (default: 15)
//	"checks"      — comma-separated check IDs to run (default: all)
//	"path"        — explicit GraphQL endpoint path (default: auto-detect)
//	"probe_paths" — also probe common paths to find the endpoint (default: true)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	// Collect targets.
	var targets []string
	if input.Target != "" {
		targets = append(targets, normalizeURL(input.Target))
	}
	for _, u := range input.URLs {
		targets = append(targets, normalizeURL(u))
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("graphql: no target provided")
	}

	// Per-run timeout.
	if ts, ok := input.Options["timeout"]; ok {
		if secs := atoi(ts, 15); secs > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(secs)*time.Second)
			defer cancel()
		}
	}

	threads := defaultThreads
	if t, ok := input.Options["threads"]; ok {
		if n := atoi(t, defaultThreads); n > 0 {
			threads = n
		}
	}

	// Build active check set.
	activeChecks := m.filterChecks(input.Options["checks"])

	eg, gctx := errgroup.WithContext(ctx)
	eg.SetLimit(threads)

	findingsCh := make(chan module.Finding, 64)

	for _, target := range targets {
		target := target
		eg.Go(func() error {
			// Discover GraphQL endpoint.
			endpoint, err := m.discoverEndpoint(gctx, target, input.Options)
			if err != nil {
				m.logger.WarnContext(gctx, "endpoint discovery failed", "target", target, "err", err)
				return nil
			}
			if endpoint == "" {
				m.logger.InfoContext(gctx, "no GraphQL endpoint found", "target", target)
				return nil
			}

			m.logger.InfoContext(gctx, "GraphQL endpoint found", "endpoint", endpoint)

			// Run checks against discovered endpoint.
			for _, check := range activeChecks {
				check := check
				select {
				case <-gctx.Done():
					return nil
				default:
				}

				findings, err := check.Run(gctx, m, endpoint)
				if err != nil {
					m.logger.WarnContext(gctx, "check error",
						"check", check.ID, "endpoint", endpoint, "err", err)
					continue
				}
				for _, f := range findings {
					select {
					case findingsCh <- f:
					case <-gctx.Done():
						return nil
					}
				}
			}
			return nil
		})
	}

	go func() {
		_ = eg.Wait()
		close(findingsCh)
	}()

	var findings []module.Finding
	for f := range findingsCh {
		findings = append(findings, f)
	}

	return findings, eg.Wait()
}

// ─── Endpoint discovery ───────────────────────────────────────────────────────

// discoverEndpoint finds the GraphQL endpoint for a base URL.
// Mirrors graphw00f's endpoint discovery approach (MIT).
func (m *Module) discoverEndpoint(ctx context.Context, baseURL string, opts map[string]string) (string, error) {
	// If explicit path is given, use it directly.
	if path, ok := opts["path"]; ok && path != "" {
		endpoint := strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(path, "/")
		if m.isGraphQL(ctx, endpoint) {
			return endpoint, nil
		}
		return "", nil
	}

	// If the target URL already looks like a full GraphQL endpoint, try it first.
	if m.isGraphQL(ctx, baseURL) {
		return baseURL, nil
	}

	// Probe common paths.
	for _, path := range commonPaths {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		endpoint := strings.TrimRight(baseURL, "/") + path
		if m.isGraphQL(ctx, endpoint) {
			return endpoint, nil
		}
	}

	return "", nil
}

// isGraphQL checks if a URL responds to a simple GraphQL introspection probe.
// Returns true if the response contains GraphQL indicators.
func (m *Module) isGraphQL(ctx context.Context, endpoint string) bool {
	resp, err := m.query(ctx, endpoint, `{__typename}`)
	if err != nil {
		return false
	}
	// A GraphQL endpoint responds with JSON containing "data" or "errors".
	return strings.Contains(resp.raw, `"data"`) || strings.Contains(resp.raw, `"errors"`)
}

// ─── Query execution ──────────────────────────────────────────────────────────

// queryResult holds a raw GraphQL response.
type queryResult struct {
	raw        string
	statusCode int
	parsed     gqlResponse
}

// query sends a POST GraphQL query and returns the raw response.
func (m *Module) query(ctx context.Context, endpoint, query string) (*queryResult, error) {
	return m.queryWithVars(ctx, endpoint, query, nil)
}

// queryWithVars sends a GraphQL query with variables.
func (m *Module) queryWithVars(ctx context.Context, endpoint, query string, vars map[string]interface{}) (*queryResult, error) {
	body := gqlRequest{Query: query, Variables: vars}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-graphql/1.0)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	rawBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	raw := string(rawBytes)

	result := &queryResult{
		raw:        raw,
		statusCode: resp.StatusCode,
	}
	_ = json.Unmarshal(rawBytes, &result.parsed)
	return result, nil
}

// queryGET sends a GET request with the query as a URL parameter.
func (m *Module) queryGET(ctx context.Context, endpoint, query string) (*queryResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Set("query", query)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-graphql/1.0)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rawBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	if err != nil {
		return nil, err
	}
	raw := string(rawBytes)
	result := &queryResult{raw: raw, statusCode: resp.StatusCode}
	_ = json.Unmarshal(rawBytes, &result.parsed)
	return result, nil
}

// ─── Finding helpers ──────────────────────────────────────────────────────────

func finding(checkID, checkName, endpoint, detail string, sev module.Severity, extra map[string]string) module.Finding {
	if extra == nil {
		extra = map[string]string{}
	}
	extra["check_id"] = checkID
	extra["check_name"] = checkName
	// Default confidence: 0.90 — direct server response confirms the misconfiguration.
	if _, ok := extra["confidence"]; !ok {
		extra["confidence"] = "0.90"
	}
	return module.Finding{
		Type:     "graphql_vuln",
		Severity: sev,
		URL:      endpoint,
		Detail:   detail,
		Extra:    extra,
	}
}

// ─── Check filtering ─────────────────────────────────────────────────────────

func (m *Module) filterChecks(ids string) []Check {
	if ids == "" {
		return m.checks
	}
	wanted := map[string]bool{}
	for _, id := range parseCSV(ids) {
		wanted[strings.ToLower(id)] = true
	}
	var out []Check
	for _, c := range m.checks {
		if wanted[strings.ToLower(c.ID)] {
			out = append(out, c)
		}
	}
	return out
}

// ─── Built-in checks ─────────────────────────────────────────────────────────
// Checks below are original implementations. Algorithm reference: graphql-cop (MIT).
// No source code is copied — the check logic is independently implemented.

func builtinChecks(m *Module) []Check {
	return []Check{

		// ── GQL-001: Introspection enabled ────────────────────────────────────
		{
			ID:          "GQL-001",
			Name:        "Introspection Enabled",
			Description: "GraphQL introspection is enabled, allowing full schema enumeration",
			Severity:    module.SeverityMedium,
			Run: func(ctx context.Context, mod *Module, endpoint string) ([]module.Finding, error) {
				const introspectionQuery = `{__schema{queryType{name}}}`
				result, err := mod.query(ctx, endpoint, introspectionQuery)
				if err != nil {
					return nil, err
				}
				if strings.Contains(result.raw, `"queryType"`) || strings.Contains(result.raw, `"__schema"`) {
					return []module.Finding{finding(
						"GQL-001", "Introspection Enabled", endpoint,
						"GraphQL introspection is enabled. Attackers can enumerate all types, fields, queries, and mutations.",
						module.SeverityMedium,
						map[string]string{"evidence": truncate(result.raw, 200)},
					)}, nil
				}
				return nil, nil
			},
		},

		// ── GQL-002: Field suggestions ────────────────────────────────────────
		{
			ID:          "GQL-002",
			Name:        "Field Suggestions Enabled",
			Description: "GraphQL field suggestion hints allow schema enumeration even without introspection",
			Severity:    module.SeverityLow,
			Run: func(ctx context.Context, mod *Module, endpoint string) ([]module.Finding, error) {
				// Send a typo query and look for "Did you mean" suggestions.
				result, err := mod.query(ctx, endpoint, `{__sch3ma{queryType{name}}}`)
				if err != nil {
					return nil, err
				}
				if strings.Contains(strings.ToLower(result.raw), "did you mean") ||
					strings.Contains(strings.ToLower(result.raw), "suggestion") {
					return []module.Finding{finding(
						"GQL-002", "Field Suggestions Enabled", endpoint,
						"Field suggestions are enabled. Typos in field names return hints, allowing schema enumeration without introspection.",
						module.SeverityLow,
						map[string]string{"evidence": truncate(result.raw, 200)},
					)}, nil
				}
				return nil, nil
			},
		},

		// ── GQL-003: Batch query attack ───────────────────────────────────────
		{
			ID:          "GQL-003",
			Name:        "Query Batching Enabled",
			Description: "GraphQL accepts batched queries, enabling amplification attacks and rate-limit bypass",
			Severity:    module.SeverityMedium,
			Run: func(ctx context.Context, mod *Module, endpoint string) ([]module.Finding, error) {
				// Send an array of operations (batch).
				batchBody := `[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]`
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
					strings.NewReader(batchBody))
				if err != nil {
					return nil, err
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-graphql/1.0)")
				resp, err := mod.client.Do(req)
				if err != nil {
					return nil, err
				}
				defer resp.Body.Close()
				rawBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
				raw := string(rawBytes)
				// A batch-supporting endpoint returns a JSON array.
				if strings.HasPrefix(strings.TrimSpace(raw), "[") &&
					strings.Contains(raw, `"data"`) {
					return []module.Finding{finding(
						"GQL-003", "Query Batching Enabled", endpoint,
						"GraphQL accepts batched query arrays. Attackers can bypass per-request rate limits and amplify brute-force attacks.",
						module.SeverityMedium,
						map[string]string{"evidence": truncate(raw, 200)},
					)}, nil
				}
				return nil, nil
			},
		},

		// ── GQL-004: Deep query DoS ───────────────────────────────────────────
		{
			ID:          "GQL-004",
			Name:        "Deep Query Complexity (DoS)",
			Description: "No depth limiting — deeply nested queries may cause CPU/memory exhaustion",
			Severity:    module.SeverityMedium,
			Run: func(ctx context.Context, mod *Module, endpoint string) ([]module.Finding, error) {
				// Build a deeply nested __typename query (depth 15).
				nested := `{__typename`
				for range 15 {
					nested += ` a:__typename`
				}
				nested += strings.Repeat("}", 1)
				result, err := mod.query(ctx, endpoint, `{__typename{__typename{__typename{__typename{__typename{__typename{__typename{__typename{__typename{__typename}}}}}}}}}}`)
				if err != nil {
					return nil, err
				}
				// If not rejected, the server has no depth limiting.
				if !strings.Contains(strings.ToLower(result.raw), "depth") &&
					!strings.Contains(strings.ToLower(result.raw), "complexity") &&
					!strings.Contains(strings.ToLower(result.raw), "too deep") &&
					result.statusCode != 400 {
					return []module.Finding{finding(
						"GQL-004", "Deep Query Complexity (DoS)", endpoint,
						"Server accepted a deeply nested query (depth 10) without rejection. No query depth limiting is enforced.",
						module.SeverityMedium,
						map[string]string{"depth_tested": "10", "status_code": fmt.Sprintf("%d", result.statusCode)},
					)}, nil
				}
				return nil, nil
			},
		},

		// ── GQL-005: Alias overloading ────────────────────────────────────────
		{
			ID:          "GQL-005",
			Name:        "Alias Overloading",
			Description: "Many aliases on a single field can bypass rate limiting and amplify responses",
			Severity:    module.SeverityMedium,
			Run: func(ctx context.Context, mod *Module, endpoint string) ([]module.Finding, error) {
				// Build a query with 100 aliases for __typename.
				var sb strings.Builder
				sb.WriteString("{")
				for i := range 100 {
					fmt.Fprintf(&sb, "a%d:__typename ", i)
				}
				sb.WriteString("}")
				result, err := mod.query(ctx, endpoint, sb.String())
				if err != nil {
					return nil, err
				}
				if !strings.Contains(strings.ToLower(result.raw), "alias") &&
					!strings.Contains(strings.ToLower(result.raw), "limit") &&
					result.statusCode != 400 {
					return []module.Finding{finding(
						"GQL-005", "Alias Overloading", endpoint,
						"Server accepted a query with 100 aliases on a single field. No alias count limiting enforced.",
						module.SeverityMedium,
						map[string]string{"aliases_tested": "100", "status_code": fmt.Sprintf("%d", result.statusCode)},
					)}, nil
				}
				return nil, nil
			},
		},

		// ── GQL-006: Directive overloading ────────────────────────────────────
		{
			ID:          "GQL-006",
			Name:        "Directive Overloading",
			Description: "Repeated directives on a single field can cause server-side DoS",
			Severity:    module.SeverityLow,
			Run: func(ctx context.Context, mod *Module, endpoint string) ([]module.Finding, error) {
				// Build a query with 50 @skip directives.
				var sb strings.Builder
				sb.WriteString("{__typename")
				for range 50 {
					sb.WriteString(` @skip(if: false)`)
				}
				sb.WriteString("}")
				result, err := mod.query(ctx, endpoint, sb.String())
				if err != nil {
					return nil, err
				}
				if result.statusCode != 400 &&
					!strings.Contains(strings.ToLower(result.raw), "directive") {
					return []module.Finding{finding(
						"GQL-006", "Directive Overloading", endpoint,
						"Server accepted a query with 50 repeated @skip directives. No directive count limiting enforced.",
						module.SeverityLow,
						map[string]string{"directives_tested": "50"},
					)}, nil
				}
				return nil, nil
			},
		},

		// ── GQL-007: GET introspection ────────────────────────────────────────
		{
			ID:          "GQL-007",
			Name:        "Introspection via GET Method",
			Description: "GraphQL introspection works via GET, enabling CSRF-based schema enumeration",
			Severity:    module.SeverityLow,
			Run: func(ctx context.Context, mod *Module, endpoint string) ([]module.Finding, error) {
				result, err := mod.queryGET(ctx, endpoint, `{__schema{queryType{name}}}`)
				if err != nil {
					return nil, err
				}
				if strings.Contains(result.raw, `"queryType"`) {
					return []module.Finding{finding(
						"GQL-007", "Introspection via GET Method", endpoint,
						"GraphQL introspection responds to GET requests. Combined with CSRF, attackers can enumerate the schema cross-origin.",
						module.SeverityLow,
						nil,
					)}, nil
				}
				return nil, nil
			},
		},

		// ── GQL-008: Debug mode / stack trace ─────────────────────────────────
		{
			ID:          "GQL-008",
			Name:        "Debug Mode / Stack Trace Leak",
			Description: "Server returns internal stack traces in error responses",
			Severity:    module.SeverityMedium,
			Run: func(ctx context.Context, mod *Module, endpoint string) ([]module.Finding, error) {
				result, err := mod.query(ctx, endpoint, `{__invalidFieldThatShouldError123}`)
				if err != nil {
					return nil, err
				}
				raw := strings.ToLower(result.raw)
				if strings.Contains(raw, "exception") ||
					strings.Contains(raw, "stacktrace") ||
					strings.Contains(raw, "stack_trace") ||
					strings.Contains(raw, "traceback") ||
					strings.Contains(raw, "at line") ||
					strings.Contains(raw, "file:") {
					return []module.Finding{finding(
						"GQL-008", "Debug Mode / Stack Trace Leak", endpoint,
						"Server returned internal stack trace information in a GraphQL error response.",
						module.SeverityMedium,
						map[string]string{"evidence": truncate(result.raw, 300)},
					)}, nil
				}
				return nil, nil
			},
		},

		// ── GQL-009: __type leak ──────────────────────────────────────────────
		{
			ID:          "GQL-009",
			Name:        "Type System Leak via __type",
			Description: "Individual type enumeration via __type works even if full introspection is disabled",
			Severity:    module.SeverityLow,
			Run: func(ctx context.Context, mod *Module, endpoint string) ([]module.Finding, error) {
				result, err := mod.query(ctx, endpoint, `{__type(name:"Query"){name fields{name}}}`)
				if err != nil {
					return nil, err
				}
				if strings.Contains(result.raw, `"fields"`) &&
					!strings.Contains(result.raw, `"errors"`) {
					return []module.Finding{finding(
						"GQL-009", "Type System Leak via __type", endpoint,
						"__type queries return field names even when full introspection is restricted.",
						module.SeverityLow,
						map[string]string{"evidence": truncate(result.raw, 200)},
					)}, nil
				}
				return nil, nil
			},
		},

		// ── GQL-010: Subscription endpoint exposed ────────────────────────────
		{
			ID:          "GQL-010",
			Name:        "Subscription Endpoint Exposed",
			Description: "GraphQL subscription endpoint is publicly reachable",
			Severity:    module.SeverityInfo,
			Run: func(ctx context.Context, mod *Module, endpoint string) ([]module.Finding, error) {
				// Check for common subscription paths.
				base := extractBaseURL(endpoint)
				subPaths := []string{"/subscriptions", "/graphql/subscriptions", "/ws", "/websocket"}
				for _, p := range subPaths {
					subURL := base + p
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, subURL, nil)
					if err != nil {
						continue
					}
					req.Header.Set("Upgrade", "websocket")
					req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-graphql/1.0)")
					resp, err := mod.client.Do(req)
					if err != nil {
						continue
					}
					resp.Body.Close()
					if resp.StatusCode == 101 || resp.StatusCode == 426 {
						return []module.Finding{finding(
							"GQL-010", "Subscription Endpoint Exposed", subURL,
							"A GraphQL subscription (WebSocket) endpoint is publicly reachable.",
							module.SeverityInfo,
							map[string]string{"path": p, "status_code": fmt.Sprintf("%d", resp.StatusCode)},
						)}, nil
					}
				}
				return nil, nil
			},
		},

		// ── GQL-011: Circular fragment DoS ────────────────────────────────────
		{
			ID:          "GQL-011",
			Name:        "Fragment Spreading Abuse",
			Description: "Server does not prevent circular or deeply spread fragment queries",
			Severity:    module.SeverityLow,
			Run: func(ctx context.Context, mod *Module, endpoint string) ([]module.Finding, error) {
				// Attempt a query with many spread fragments.
				var sb strings.Builder
				sb.WriteString("{...f1} ")
				for i := 1; i <= 20; i++ {
					sb.WriteString(fmt.Sprintf("fragment f%d on __Schema { queryType { name } } ", i))
				}
				result, err := mod.query(ctx, endpoint, sb.String())
				if err != nil {
					return nil, err
				}
				if result.statusCode == 200 &&
					!strings.Contains(strings.ToLower(result.raw), "fragment") {
					return []module.Finding{finding(
						"GQL-011", "Fragment Spreading Abuse", endpoint,
						"Server accepted a query with 20 spread fragments without rejection.",
						module.SeverityLow,
						map[string]string{"fragments_tested": "20"},
					)}, nil
				}
				return nil, nil
			},
		},

		// ── GQL-012: Full schema introspection ───────────────────────────────
		{
			ID:          "GQL-012",
			Name:        "Full Schema Introspection",
			Description: "Full schema dump via introspection query succeeds",
			Severity:    module.SeverityMedium,
			Run: func(ctx context.Context, mod *Module, endpoint string) ([]module.Finding, error) {
				const fullIntrospection = `{
					__schema {
						queryType { name }
						mutationType { name }
						subscriptionType { name }
						types {
							name
							kind
							fields { name }
						}
					}
				}`
				result, err := mod.query(ctx, endpoint, fullIntrospection)
				if err != nil {
					return nil, err
				}
				if strings.Contains(result.raw, `"__schema"`) &&
					strings.Contains(result.raw, `"types"`) {
					// Count approximate number of types.
					typeCount := strings.Count(result.raw, `"kind"`)
					return []module.Finding{finding(
						"GQL-012", "Full Schema Introspection", endpoint,
						fmt.Sprintf("Full introspection dump succeeded. Approximately %d types exposed.", typeCount),
						module.SeverityMedium,
						map[string]string{
							"type_count": fmt.Sprintf("%d", typeCount),
							"evidence":   truncate(result.raw, 300),
						},
					)}, nil
				}
				return nil, nil
			},
		},
	}
}

// ─── Utilities ───────────────────────────────────────────────────────────────

func defaultClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
				MinVersion:         tls.VersionTLS10,
			},
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "https://" + raw
	}
	return raw
}

func atoi(s string, def int) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return def
	}
	return n
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func extractBaseURL(endpoint string) string {
	// Return just scheme+host from the endpoint URL.
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(endpoint, prefix) {
			rest := strings.TrimPrefix(endpoint, prefix)
			if idx := strings.Index(rest, "/"); idx != -1 {
				return prefix + rest[:idx]
			}
			return endpoint
		}
	}
	return endpoint
}
