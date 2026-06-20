// Package deserial implements Insecure Deserialization detection.
//
// Source reference: ysoserial (Apache-2.0) Java gadget chain signatures,
// phpggc PHP gadget chain signatures (MIT), and DeserializationScanner
// nuclei-templates (MIT). Detection logic reimplemented from scratch.
//
// Detection strategies:
//   - Java:  send serialized Java objects with magic bytes (0xACED 0x0005)
//     and gadget chain payloads; detect DNS-based OOB or error patterns
//   - PHP:   inject PHP serialize() patterns (O:, a:, s:, i:) in parameters;
//     detect PHP error strings or object injection evidence
//   - Python: inject pickle/marshal serialized bytes; detect execution evidence
//   - .NET:  inject BinaryFormatter or JSON.NET TypeNameHandling payloads
//
// Magic byte detection:
//   - Java serialized object: 0xACED 0x0005 (or base64: "rO0AB")
//   - PHP serialized: "O:<n>:", "a:<n>:", "s:<n>:", "i:<n>:"
//   - Python pickle: 0x80 0x02 (protocol 2), 0x80 0x03 (protocol 3)
//
// The module primarily looks for:
//  1. Gadget chain error messages in responses (server-side exception)
//  2. HTTP 500 responses to serialized input (server crashed on deserialization)
//  3. Timing differences (time-based gadget chains — future)
//  4. Magic bytes reflected in response (server echoes input without sanitizing)
//
// Architecture:
//   - Probe struct: payload bytes + format + detection function
//   - errgroup.SetLimit(Parallelism) fan-out across url × param × probe
//   - io.LimitReader on all response reads
//   - log/slog observability
//   - sync.Mutex protecting findings slice
//   - NewWithClient(*http.Client) for testability
//   - Probes sent as both query param values and POST body
package deserial

import (
	"bytes"
	"context"
	"encoding/base64"
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
	DefaultTimeout     = 10 * time.Second
	DefaultParallelism = 10
	maxBodyRead        = 512 * 1024 // 512 KB
)

// ─── Format constants ─────────────────────────────────────────────────────────

const (
	FormatJava   = "java"
	FormatPHP    = "php"
	FormatPython = "python"
	FormatDotNet = "dotnet"
)

// ─── Probe ───────────────────────────────────────────────────────────────────

// Probe defines a single deserialization detection test.
type Probe struct {
	// ID is a unique identifier.
	ID string
	// Format: java, php, python, dotnet.
	Format string
	// Payload is the serialized object bytes or string to send.
	Payload string
	// ContentType is the HTTP Content-Type for POST probes.
	ContentType string
	// Detect inspects the response.
	Detect func(body string, status int) bool
	// Severity of a confirmed finding.
	Severity module.Severity
	// Tags are metadata tags.
	Tags []string
}

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements Insecure Deserialization detection.
type Module struct {
	client      *http.Client
	probes      []Probe
	parallelism int
	logger      *slog.Logger
}

// New returns a Module with all built-in probes.
func New() *Module {
	return &Module{
		client:      httpclient.New(httpclient.Options{Timeout: DefaultTimeout}),
		probes:      builtinProbes(),
		parallelism: DefaultParallelism,
		logger:      slog.Default(),
	}
}

// NewWithClient returns a Module using the supplied HTTP client (testability).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// NewWithProbes returns a Module with custom probes (testability).
func NewWithProbes(probes []Probe) *Module {
	m := New()
	m.probes = probes
	return m
}

// Name returns the module name.
func (m *Module) Name() string { return "deserial" }

// Run executes deserialization probes against all target URLs.
//
// Options:
//   - "parallelism" — max concurrent probes (default: 10)
//   - "format"      — comma-separated format filter: java,php,python,dotnet
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

	formatFilter := parseCSV(input.Options["format"])
	probes := m.selectProbes(formatFilter)

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

		for _, probe := range probes {
			probe := probe
			// Test as both GET param injection and POST body.
			for _, param := range params {
				param := param
				eg.Go(func() error {
					f, ok := m.probeGET(egCtx, target, param, probe)
					if ok {
						addFinding(f)
					}
					return nil
				})
			}
			// POST body probe.
			eg.Go(func() error {
				f, ok := m.probePOST(egCtx, target, probe)
				if ok {
					addFinding(f)
				}
				return nil
			})
		}
	}

	_ = eg.Wait()
	return findings, nil
}

func (m *Module) probeGET(ctx context.Context, rawURL, param string, p Probe) (module.Finding, bool) {
	injected := injectParam(rawURL, param, p.Payload)
	body, status, err := m.doGET(ctx, injected)
	if err != nil {
		return module.Finding{}, false
	}
	if p.Detect(body, status) {
		return m.buildFinding(rawURL, param, p, "GET:param"), true
	}
	return module.Finding{}, false
}

func (m *Module) probePOST(ctx context.Context, rawURL string, p Probe) (module.Finding, bool) {
	ct := p.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", rawURL,
		bytes.NewReader([]byte(p.Payload)))
	if err != nil {
		return module.Finding{}, false
	}
	req.Header.Set("Content-Type", ct)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-deserial/1.0)")

	resp, err := m.client.Do(req)
	if err != nil {
		return module.Finding{}, false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	body := string(b)

	if p.Detect(body, resp.StatusCode) {
		return m.buildFinding(rawURL, "POST_body", p, "POST:body"), true
	}
	return module.Finding{}, false
}

func (m *Module) buildFinding(rawURL, param string, p Probe, vector string) module.Finding {
	m.logger.InfoContext(context.Background(), "deserial: vulnerability found",
		"url", rawURL, "param", param, "probe", p.ID, "format", p.Format)
	return module.Finding{
		Type:     "deserial",
		Severity: p.Severity,
		URL:      rawURL,
		Detail:   fmt.Sprintf("[Deserial/%s/%s] param=%q vector=%s: deserialization indicator detected", p.ID, p.Format, param, vector),
		Extra: map[string]string{
			"param":      param,
			"probe_id":   p.ID,
			"format":     p.Format,
			"vector":     vector,
			"tags":       strings.Join(p.Tags, ","),
			"confidence": "0.80", // deserialization indicator in response — possible but not definitive
		},
	}
}

func (m *Module) doGET(ctx context.Context, rawURL string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-deserial/1.0)")
	resp, err := m.client.Do(req)
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

func (m *Module) selectProbes(formatFilter []string) []Probe {
	if len(formatFilter) == 0 {
		return m.probes
	}
	filterSet := make(map[string]struct{})
	for _, f := range formatFilter {
		filterSet[f] = struct{}{}
	}
	var out []Probe
	for _, p := range m.probes {
		if _, ok := filterSet[p.Format]; ok {
			out = append(out, p)
		}
	}
	return out
}

// ─── Error pattern detectors ──────────────────────────────────────────────────

func javaErrors() []string {
	return []string{
		"java.io.streamcorruptedexception",
		"java.lang.classcastexception",
		"java.io.objectstreamexception",
		"invalid stream header",
		"not a serialization stream",
		"com.sun.org.apache.xerces",
		"objectinputstream",
		"objectoutputstream",
		"serializable",
		"noclassdeffounderror",
		"classnotfoundexception",
		"aced0005", // hex dump of magic bytes
	}
}

func phpErrors() []string {
	return []string{
		"unserialize(): error",
		"unserialize() [function.unserialize]",
		"__wakeup()",
		"__destruct()",
		"__toString()",
		"illegal offset type",
		"php warning: unserialize",
		"php fatal error",
		"class `",
		"cannot deserialize",
		"error in object member",
	}
}

func pythonErrors() []string {
	return []string{
		"pickle.loadstring",
		"pickle.loads",
		"unpicklingerror",
		"_pickle.unpackingobjectstack",
		"modulenotfounderror",
		"importerror",
		"attributeerror",
		"memoryerror",
		"marshal.loads",
	}
}

func dotNetErrors() []string {
	return []string{
		"serializationexception",
		"binaryformatter",
		"system.runtime.serialization",
		"newtonsoft.json.jsonserializationexception",
		"typenamhandling",
		"could not load type",
		"system.io.endofstreamexception",
		"invalid data format",
	}
}

func errDetect(patterns []string) func(string, int) bool {
	return func(body string, status int) bool {
		lower := strings.ToLower(body)
		for _, p := range patterns {
			if strings.Contains(lower, strings.ToLower(p)) {
				return true
			}
		}
		// A 500 response to a deserialization payload is also a strong indicator.
		return status == 500
	}
}

// ─── Built-in probes ─────────────────────────────────────────────────────────

// builtinProbes returns the default deserialization detection probe set.
// Java magic bytes: 0xACED 0x0005 → base64: "rO0AB"
// PHP serialize format: O:<n>:<classname>:<n>:{<properties>}
// Python pickle protocol 2 prefix: \x80\x02
// .NET BinaryFormatter magic: 0x00 0x01 0x00 0x00
func builtinProbes() []Probe {

	// Java serialized object magic bytes (minimal object: java.util.HashSet).
	// base64("rO0ABXN...") = Java serialized stream.
	javaBase64 := "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AgAAeHB3DAAAABA/QAAAAAAAAHhw"
	javaPayload, _ := base64.StdEncoding.DecodeString(javaBase64)

	// PHP serialize patterns — we inject a PHP serialized object.
	// O:8:"stdClass":0:{} — minimal PHP object.
	phpPayload := `O:8:"stdClass":0:{}`
	phpMagicExplode := `O:40:"phpggc\Chain\EvalCode":1:{s:4:"code";s:10:"phpinfo();"}`

	// Python pickle minimal exec (prints nothing, just tests if deserialized).
	// Protocol 0: just a STOP opcode = "."
	pythonPickle := "."

	// .NET BinaryFormatter magic bytes (empty object).
	dotNetPayload := "\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00"

	return []Probe{

		// ── Java ──────────────────────────────────────────────────────────────

		{
			ID: "java-magic-bytes-get", Format: FormatJava,
			Payload:     string(javaPayload),
			ContentType: "application/octet-stream",
			Detect:      errDetect(javaErrors()),
			Severity:    module.SeverityCritical,
			Tags:        []string{"deserial", "java", "magic-bytes"},
		},
		{
			ID: "java-base64-stream", Format: FormatJava,
			Payload:     javaBase64, // base64 encoded — for JSON/URL params
			ContentType: "application/json",
			Detect:      errDetect(javaErrors()),
			Severity:    module.SeverityCritical,
			Tags:        []string{"deserial", "java", "base64"},
		},
		{
			ID: "java-ros-prefix", Format: FormatJava,
			Payload:     "rO0AB", // Just the magic bytes prefix — triggers StreamCorruptedException
			ContentType: "application/octet-stream",
			Detect: func(body string, status int) bool {
				lower := strings.ToLower(body)
				return strings.Contains(lower, "streamcorruptedexception") ||
					strings.Contains(lower, "invalid stream header") ||
					strings.Contains(lower, "objectstreamexception") ||
					status == 500
			},
			Severity: module.SeverityHigh,
			Tags:     []string{"deserial", "java", "error-based"},
		},

		// ── PHP ───────────────────────────────────────────────────────────────

		{
			ID: "php-stdclass", Format: FormatPHP,
			Payload:     phpPayload,
			ContentType: "application/x-www-form-urlencoded",
			Detect:      errDetect(phpErrors()),
			Severity:    module.SeverityHigh,
			Tags:        []string{"deserial", "php", "stdclass"},
		},
		{
			ID: "php-phpggc-eval", Format: FormatPHP,
			Payload:     phpMagicExplode,
			ContentType: "application/x-www-form-urlencoded",
			Detect: func(body string, status int) bool {
				lower := strings.ToLower(body)
				return strings.Contains(lower, "phpinfo") ||
					strings.Contains(lower, "php version") ||
					errDetect(phpErrors())(body, status)
			},
			Severity: module.SeverityCritical,
			Tags:     []string{"deserial", "php", "phpggc", "rce"},
		},
		{
			ID: "php-array-inject", Format: FormatPHP,
			Payload:     `a:1:{i:0;O:8:"Exploit":0:{}}`,
			ContentType: "application/x-www-form-urlencoded",
			Detect:      errDetect(phpErrors()),
			Severity:    module.SeverityHigh,
			Tags:        []string{"deserial", "php", "array"},
		},
		{
			ID: "php-magic-string", Format: FormatPHP,
			Payload:     `s:6:"inject";`,
			ContentType: "application/x-www-form-urlencoded",
			Detect: func(body string, status int) bool {
				return strings.Contains(strings.ToLower(body), "unserialize") &&
					status == 500
			},
			Severity: module.SeverityMedium,
			Tags:     []string{"deserial", "php"},
		},

		// ── Python ────────────────────────────────────────────────────────────

		{
			ID: "python-pickle-stop", Format: FormatPython,
			Payload:     pythonPickle,
			ContentType: "application/octet-stream",
			Detect:      errDetect(pythonErrors()),
			Severity:    module.SeverityHigh,
			Tags:        []string{"deserial", "python", "pickle"},
		},
		{
			ID: "python-pickle-proto2", Format: FormatPython,
			Payload:     "\x80\x02.", // Protocol 2 STOP
			ContentType: "application/octet-stream",
			Detect:      errDetect(pythonErrors()),
			Severity:    module.SeverityHigh,
			Tags:        []string{"deserial", "python", "pickle"},
		},

		// ── .NET ──────────────────────────────────────────────────────────────

		{
			ID: "dotnet-binaryformatter", Format: FormatDotNet,
			Payload:     dotNetPayload,
			ContentType: "application/octet-stream",
			Detect:      errDetect(dotNetErrors()),
			Severity:    module.SeverityCritical,
			Tags:        []string{"deserial", "dotnet", "binaryformatter"},
		},
		{
			ID: "dotnet-json-typename", Format: FormatDotNet,
			Payload:     `{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start"}`,
			ContentType: "application/json",
			Detect:      errDetect(dotNetErrors()),
			Severity:    module.SeverityCritical,
			Tags:        []string{"deserial", "dotnet", "json.net", "rce"},
		},
	}
}
