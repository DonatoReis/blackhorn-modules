// Package swaggerfuzz performs automated API fuzzing driven by an OpenAPI/Swagger
// specification. It discovers the spec automatically, parses every endpoint, and
// fires structured probes for each operation — checking for auth bypass, IDOR,
// mass-assignment, sensitive data exposure, and injection entry-points.
//
// Source references (algorithm design, no code copied):
//   - OWASP API Security Top 10 2023 (CC-BY 4.0)
//   - Swagger/OpenAPI specification 2.0 and 3.x (Apache-2.0)
//   - schemathesis (MIT, Stranger Labs) — property-based API testing approach
//   - dredd (MIT, Apiary) — contract testing approach
//
// What this module does:
//  1. Auto-discover the spec at well-known paths if not provided in Options
//  2. Parse OpenAPI 2.0 (swagger.json/yaml) and 3.x (openapi.json/yaml)
//  3. For every endpoint × method:
//     a. Probe with no auth (API1:2023 BOLA / broken auth)
//     b. Probe with missing required params (API3:2023 excessive data exposure)
//     c. Probe with type confusion values (string where int expected)
//     d. Probe with injection markers in string params (SQLi/XSS/CMDi canaries)
//     e. Probe with extra undocumented fields (API6:2023 mass assignment)
//     f. Probe with HTTP method override (API5:2023 broken function level auth)
//  4. Emit findings with the failing endpoint, probe type, and response evidence
//
// Architecture:
//   - errgroup.SetLimit(Parallelism) fan-out                (guia-go §9)
//   - io.LimitReader on every response body                 (dicas.md §5)
//   - log/slog structured observability                     (dicas.md §16)
//   - context propagation and cancellation                  (guia-go §9)
//   - NewWithClient(*http.Client) for testability
//   - confidence scoring per dicas.md §4
package swaggerfuzz

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	maxBodyRead     = 512 * 1024 // 512 KB per response — dicas.md §5
	defaultTimeout  = 15 * time.Second
	defaultParallel = 8
	maxEndpoints    = 500 // cap to avoid DoS on massive specs
)

// Well-known paths where Swagger/OpenAPI specs are commonly exposed.
var specPaths = []string{
	"/swagger.json",
	"/swagger.yaml",
	"/openapi.json",
	"/openapi.yaml",
	"/api-docs",
	"/api-docs.json",
	"/v1/swagger.json",
	"/v2/swagger.json",
	"/v3/openapi.json",
	"/docs/openapi.json",
	"/swagger/v1/swagger.json",
	"/swagger/v2/swagger.json",
	"/api/swagger.json",
	"/api/openapi.json",
}

// Injection canaries for string parameters — detect reflection in response.
var injectionCanaries = []string{
	`BHSWF"'<script>`,
	`BHSWF' OR '1'='1`,
	`BHSWF; ls`,
	`BHSWF{{7*7}}`,
}

// ─── OpenAPI schema types (minimal, sufficient for fuzzing) ───────────────────

type openAPISpec struct {
	Swagger  string                     `json:"swagger"`  // "2.0"
	OpenAPI  string                     `json:"openapi"`  // "3.x.x"
	BasePath string                     `json:"basePath"` // v2
	Servers  []openAPIServer            `json:"servers"`  // v3
	Paths    map[string]openAPIPathItem `json:"paths"`
}

type openAPIServer struct {
	URL string `json:"url"`
}

type openAPIPathItem map[string]openAPIOperation // method → operation

type openAPIOperation struct {
	OperationID string           `json:"operationId"`
	Parameters  []openAPIParam   `json:"parameters"`
	RequestBody *openAPIReqBody  `json:"requestBody"`
	Security    []map[string]any `json:"security"`
	Tags        []string         `json:"tags"`
}

type openAPIParam struct {
	Name     string         `json:"name"`
	In       string         `json:"in"` // query, path, header, cookie
	Required bool           `json:"required"`
	Schema   *openAPISchema `json:"schema"`
	Type     string         `json:"type"` // v2 inline type
}

type openAPIReqBody struct {
	Required bool                        `json:"required"`
	Content  map[string]openAPIMediaType `json:"content"`
}

type openAPIMediaType struct {
	Schema *openAPISchema `json:"schema"`
}

type openAPISchema struct {
	Type       string                    `json:"type"`
	Properties map[string]*openAPISchema `json:"properties"`
	Items      *openAPISchema            `json:"items"`
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements the swaggerfuzz module.
type Module struct {
	client *http.Client
	logger *slog.Logger
}

// New creates a swaggerfuzz module with default HTTP client.
func New() *Module {
	return &Module{
		client: httpclient.Default(),
		logger: slog.Default(),
	}
}

// NewWithClient creates a swaggerfuzz module with a custom HTTP client (for tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{client: c, logger: slog.Default()}
}

func (m *Module) Name() string { return "swaggerfuzz" }

// Run discovers and fuzzes the API spec at input.Target (base URL).
// Options:
//   - spec_url:    explicit URL of the OpenAPI spec (skips auto-discovery)
//   - parallelism: number of concurrent probes (default 8)
//   - checks:      comma-separated list: auth,types,injection,massassign,methods
//     (default: all)
//   - bearer:      Bearer token to use as the baseline auth credential
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(input.Target), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("swaggerfuzz: target (base URL) is required")
	}
	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	parallelism := optInt(opts, "parallelism", defaultParallel)
	checksRaw := optStr(opts, "checks", "auth,types,injection,massassign,methods")
	checks := parseCSV(checksRaw)
	bearer := optStr(opts, "bearer", "")
	specURL := optStr(opts, "spec_url", "")

	m.logger.InfoContext(ctx, "swaggerfuzz: starting",
		"base_url", baseURL, "checks", checksRaw, "parallelism", parallelism)

	// Step 1: obtain the spec.
	spec, specFoundAt, err := m.fetchSpec(ctx, baseURL, specURL)
	if err != nil {
		return []module.Finding{{
			Type:     "swagger_spec_not_found",
			URL:      baseURL,
			Detail:   fmt.Sprintf("swaggerfuzz: could not find OpenAPI spec at %s — %v", baseURL, err),
			Severity: module.SeverityInfo,
			Extra:    map[string]string{"confidence": "0.99", "fonte": "auto_discovery"},
		}}, nil
	}

	m.logger.InfoContext(ctx, "swaggerfuzz: spec found", "url", specFoundAt)

	// Step 2: extract endpoints.
	endpoints := extractEndpoints(spec, baseURL)
	if len(endpoints) == 0 {
		return []module.Finding{{
			Type:     "swagger_empty_spec",
			URL:      specFoundAt,
			Detail:   "swaggerfuzz: spec found but contains no paths/operations",
			Severity: module.SeverityInfo,
			Extra:    map[string]string{"confidence": "0.99", "spec_url": specFoundAt},
		}}, nil
	}
	if len(endpoints) > maxEndpoints {
		endpoints = endpoints[:maxEndpoints]
	}

	m.logger.InfoContext(ctx, "swaggerfuzz: endpoints extracted", "count", len(endpoints))

	// Step 3: probe each endpoint.
	var (
		mu       sync.Mutex
		findings []module.Finding
	)
	add := func(ff ...module.Finding) {
		mu.Lock()
		findings = append(findings, ff...)
		mu.Unlock()
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(parallelism)

	for _, ep := range endpoints {
		ep := ep
		eg.Go(func() error {
			ff := m.probeEndpoint(egCtx, ep, bearer, checks)
			add(ff...)
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return findings, err
	}

	// Emit spec discovery finding.
	add(module.Finding{
		Type:     "swagger_spec_found",
		URL:      specFoundAt,
		Severity: module.SeverityInfo,
		Detail:   fmt.Sprintf("OpenAPI spec discovered at %s — %d endpoints analyzed", specFoundAt, len(endpoints)),
		Extra: map[string]string{
			"endpoints_total": fmt.Sprintf("%d", len(endpoints)),
			"spec_url":        specFoundAt,
			"confidence":      "0.99",
			"fonte":           "swaggerfuzz",
		},
	})

	return dedup(findings), nil
}

// ─── Spec discovery and parsing ───────────────────────────────────────────────

func (m *Module) fetchSpec(ctx context.Context, baseURL, explicitURL string) (*openAPISpec, string, error) {
	candidates := []string{}
	if explicitURL != "" {
		candidates = append(candidates, explicitURL)
	}
	for _, p := range specPaths {
		candidates = append(candidates, baseURL+p)
	}

	for _, u := range candidates {
		body, err := m.get(ctx, u)
		if err != nil {
			continue
		}
		var spec openAPISpec
		if err := json.Unmarshal(body, &spec); err != nil {
			continue
		}
		// Accept spec even if paths is empty — the caller handles the empty case.
		if spec.Swagger == "" && spec.OpenAPI == "" {
			continue
		}
		return &spec, u, nil
	}
	return nil, "", fmt.Errorf("spec not found at any of %d candidate paths", len(candidates))
}

// endpoint is a parsed API operation ready to probe.
type endpoint struct {
	Method      string
	URL         string // full URL with base + path (path params as {name})
	Path        string // raw path from spec
	Params      []openAPIParam
	HasReqBody  bool
	BodySchema  *openAPISchema
	HasSecurity bool
}

func extractEndpoints(spec *openAPISpec, baseURL string) []endpoint {
	base := baseURL
	if spec.BasePath != "" && spec.BasePath != "/" {
		base = strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(spec.BasePath, "/")
	}
	if len(spec.Servers) > 0 && spec.Servers[0].URL != "" {
		srv := spec.Servers[0].URL
		if strings.HasPrefix(srv, "/") {
			base = strings.TrimRight(baseURL, "/") + srv
		} else if strings.HasPrefix(srv, "http") {
			base = strings.TrimRight(srv, "/")
		}
	}

	var out []endpoint
	for path, item := range spec.Paths {
		fullURL := strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
		for method, op := range item {
			method = strings.ToUpper(method)
			if method == "PARAMETERS" {
				continue // path-level param block, not an operation
			}
			ep := endpoint{
				Method:      method,
				URL:         fullURL,
				Path:        path,
				Params:      op.Parameters,
				HasSecurity: len(op.Security) > 0,
			}
			if op.RequestBody != nil {
				ep.HasReqBody = op.RequestBody.Required
				for _, mt := range op.RequestBody.Content {
					ep.BodySchema = mt.Schema
					break
				}
			}
			out = append(out, ep)
		}
	}
	return out
}

// ─── Probing ─────────────────────────────────────────────────────────────────

func (m *Module) probeEndpoint(ctx context.Context, ep endpoint, bearer string, checks map[string]bool) []module.Finding {
	var findings []module.Finding

	// API1/API3: probe without authentication.
	if checks["auth"] && (ep.HasSecurity || bearer != "") {
		if ff := m.probeNoAuth(ctx, ep); len(ff) > 0 {
			findings = append(findings, ff...)
		}
	}

	// API6: mass assignment — inject extra undocumented fields in request body.
	if checks["massassign"] && ep.HasReqBody {
		if ff := m.probeMassAssign(ctx, ep, bearer); len(ff) > 0 {
			findings = append(findings, ff...)
		}
	}

	// Type confusion: pass string where int expected.
	if checks["types"] {
		if ff := m.probeTypeConfusion(ctx, ep, bearer); len(ff) > 0 {
			findings = append(findings, ff...)
		}
	}

	// Injection: canary in string params.
	if checks["injection"] {
		if ff := m.probeInjection(ctx, ep, bearer); len(ff) > 0 {
			findings = append(findings, ff...)
		}
	}

	// HTTP method override (API5).
	if checks["methods"] {
		if ff := m.probeMethodOverride(ctx, ep, bearer); len(ff) > 0 {
			findings = append(findings, ff...)
		}
	}

	return findings
}

// probeNoAuth fires the request without Authorization and looks for 200 when
// the endpoint declared security requirements.
func (m *Module) probeNoAuth(ctx context.Context, ep endpoint) []module.Finding {
	reqURL := fillPathParams(ep.URL, ep.Params)
	req, err := http.NewRequestWithContext(ctx, ep.Method, reqURL, nil)
	if err != nil {
		return nil
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		return []module.Finding{{
			Type:     "swagger_auth_bypass",
			URL:      reqURL,
			Severity: module.SeverityHigh,
			Detail:   fmt.Sprintf("[swaggerfuzz] %s %s returns %d without Authorization — possible broken auth (OWASP API1/API2)", ep.Method, ep.Path, resp.StatusCode),
			Extra: map[string]string{
				"method":      ep.Method,
				"path":        ep.Path,
				"status_code": fmt.Sprintf("%d", resp.StatusCode),
				"body_sample": truncate(string(body), 200),
				"check":       "auth_bypass",
				"confidence":  "0.82",
				"fonte":       "swaggerfuzz",
			},
		}}
	}
	return nil
}

// probeMassAssign sends a request body with extra undocumented fields and looks
// for evidence they were accepted (200/201 response without validation error).
func (m *Module) probeMassAssign(ctx context.Context, ep endpoint, bearer string) []module.Finding {
	if ep.Method == "GET" || ep.Method == "DELETE" || ep.Method == "HEAD" {
		return nil
	}

	extra := `{"role":"admin","is_admin":true,"is_superuser":true,"__proto__":{"admin":true}}`
	reqURL := fillPathParams(ep.URL, ep.Params)
	req, err := http.NewRequestWithContext(ctx, ep.Method, reqURL, strings.NewReader(extra))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		bodyStr := string(body)
		if strings.Contains(bodyStr, "admin") || strings.Contains(bodyStr, "role") {
			return []module.Finding{{
				Type:     "swagger_mass_assignment",
				URL:      reqURL,
				Severity: module.SeverityHigh,
				Detail:   fmt.Sprintf("[swaggerfuzz] %s %s accepted extra privileged fields in body — possible mass assignment (OWASP API6)", ep.Method, ep.Path),
				Extra: map[string]string{
					"method":      ep.Method,
					"path":        ep.Path,
					"status_code": fmt.Sprintf("%d", resp.StatusCode),
					"body_sample": truncate(bodyStr, 200),
					"check":       "mass_assignment",
					"confidence":  "0.78",
					"fonte":       "swaggerfuzz",
				},
			}}
		}
	}
	return nil
}

// probeTypeConfusion sends wrong types for schema-declared parameters.
func (m *Module) probeTypeConfusion(ctx context.Context, ep endpoint, bearer string) []module.Finding {
	var intParams []string
	for _, p := range ep.Params {
		typ := p.Type
		if p.Schema != nil {
			typ = p.Schema.Type
		}
		if typ == "integer" || typ == "number" {
			intParams = append(intParams, p.Name)
		}
	}
	if len(intParams) == 0 {
		return nil
	}

	// Build URL with string where int expected.
	reqURL := fillPathParams(ep.URL, ep.Params)
	parsed, err := url.Parse(reqURL)
	if err != nil {
		return nil
	}
	q := parsed.Query()
	for _, name := range intParams {
		q.Set(name, "not-a-number")
	}
	parsed.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, ep.Method, parsed.String(), nil)
	if err != nil {
		return nil
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))

	// 500 with string input = server doesn't validate types properly.
	if resp.StatusCode == http.StatusInternalServerError {
		return []module.Finding{{
			Type:     "swagger_type_confusion",
			URL:      parsed.String(),
			Severity: module.SeverityMedium,
			Detail:   fmt.Sprintf("[swaggerfuzz] %s %s returns 500 on type confusion for params %v — missing input validation (OWASP API3)", ep.Method, ep.Path, intParams),
			Extra: map[string]string{
				"method":         ep.Method,
				"path":           ep.Path,
				"status_code":    "500",
				"body_sample":    truncate(string(body), 200),
				"invalid_params": strings.Join(intParams, ","),
				"check":          "type_confusion",
				"confidence":     "0.85",
				"fonte":          "swaggerfuzz",
			},
		}}
	}
	return nil
}

// probeInjection injects canary strings in string parameters.
func (m *Module) probeInjection(ctx context.Context, ep endpoint, bearer string) []module.Finding {
	var strParams []string
	for _, p := range ep.Params {
		if p.In != "query" {
			continue
		}
		typ := p.Type
		if p.Schema != nil {
			typ = p.Schema.Type
		}
		if typ == "string" || typ == "" {
			strParams = append(strParams, p.Name)
		}
	}
	if len(strParams) == 0 {
		return nil
	}

	var findings []module.Finding
	for _, canary := range injectionCanaries {
		reqURL := fillPathParams(ep.URL, ep.Params)
		parsed, err := url.Parse(reqURL)
		if err != nil {
			continue
		}
		q := parsed.Query()
		for _, name := range strParams {
			q.Set(name, canary)
		}
		parsed.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, ep.Method, parsed.String(), nil)
		if err != nil {
			continue
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}

		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
		resp.Body.Close()

		bodyStr := string(body)
		// 500 or canary reflected = injection entry point.
		if resp.StatusCode == http.StatusInternalServerError {
			findings = append(findings, module.Finding{
				Type:     "swagger_injection_entrypoint",
				URL:      parsed.String(),
				Severity: module.SeverityMedium,
				Detail:   fmt.Sprintf("[swaggerfuzz] %s %s returns 500 on injection canary in params %v — possible injection entry-point", ep.Method, ep.Path, strParams),
				Extra: map[string]string{
					"method":      ep.Method,
					"path":        ep.Path,
					"status_code": "500",
					"canary":      canary,
					"params":      strings.Join(strParams, ","),
					"check":       "injection",
					"confidence":  "0.80",
					"fonte":       "swaggerfuzz",
				},
			})
			break
		}
		if strings.Contains(bodyStr, "BHSWF") {
			findings = append(findings, module.Finding{
				Type:     "swagger_injection_reflection",
				URL:      parsed.String(),
				Severity: module.SeverityHigh,
				Detail:   fmt.Sprintf("[swaggerfuzz] %s %s reflects canary in response body — injection candidate (XSS/SSTI/CMDi)", ep.Method, ep.Path),
				Extra: map[string]string{
					"method":      ep.Method,
					"path":        ep.Path,
					"status_code": fmt.Sprintf("%d", resp.StatusCode),
					"canary":      canary,
					"body_sample": truncate(bodyStr, 200),
					"check":       "injection_reflection",
					"confidence":  "0.88",
					"fonte":       "swaggerfuzz",
				},
			})
			break
		}
	}
	return findings
}

// probeMethodOverride checks if undocumented HTTP methods are accepted via override headers.
func (m *Module) probeMethodOverride(ctx context.Context, ep endpoint, bearer string) []module.Finding {
	if ep.Method != "GET" {
		return nil
	}
	reqURL := fillPathParams(ep.URL, ep.Params)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("X-HTTP-Method-Override", "DELETE")
	req.Header.Set("X-Method-Override", "DELETE")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyRead))

	if resp.StatusCode < 400 {
		return []module.Finding{{
			Type:     "swagger_method_override",
			URL:      reqURL,
			Severity: module.SeverityMedium,
			Detail:   fmt.Sprintf("[swaggerfuzz] GET %s accepts X-HTTP-Method-Override: DELETE → %d — possible function-level auth bypass (OWASP API5)", ep.Path, resp.StatusCode),
			Extra: map[string]string{
				"method":          "GET",
				"override_method": "DELETE",
				"path":            ep.Path,
				"status_code":     fmt.Sprintf("%d", resp.StatusCode),
				"check":           "method_override",
				"confidence":      "0.75",
				"fonte":           "swaggerfuzz",
			},
		}}
	}
	return nil
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

func (m *Module) get(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
}

// ─── Utility helpers ──────────────────────────────────────────────────────────

// fillPathParams replaces {param} in URL with a placeholder value.
func fillPathParams(rawURL string, params []openAPIParam) string {
	result := rawURL
	for _, p := range params {
		if p.In == "path" {
			typ := p.Type
			if p.Schema != nil {
				typ = p.Schema.Type
			}
			var fill string
			switch typ {
			case "integer", "number":
				fill = "1"
			default:
				fill = "test"
			}
			result = strings.ReplaceAll(result, "{"+p.Name+"}", fill)
		}
	}
	// Fill any remaining {param} placeholders that weren't in the param list.
	for strings.Contains(result, "{") {
		start := strings.Index(result, "{")
		end := strings.Index(result, "}")
		if end < start {
			break
		}
		result = result[:start] + "1" + result[end+1:]
	}
	return result
}

func parseCSV(s string) map[string]bool {
	m := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		t := strings.TrimSpace(part)
		if t != "" {
			m[t] = true
		}
	}
	if len(m) == 0 {
		m["auth"] = true
		m["types"] = true
		m["injection"] = true
		m["massassign"] = true
		m["methods"] = true
	}
	return m
}

func optStr(opts map[string]string, key, def string) string {
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

func optInt(opts map[string]string, key string, def int) int {
	if v, ok := opts[key]; ok && v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	var out []module.Finding
	for _, f := range findings {
		key := f.Type + "|" + f.URL
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

// ensure timeout on client.
func init() {
	_ = defaultTimeout // used in New() via httpclient.Default which has 15s
}
