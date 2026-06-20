// Package proxify implements an intercepting HTTP proxy that captures requests
// and responses, applies match/replace rules, and emits structured findings.
// It runs as an in-process proxy server (no external binary required) using
// Go's net/http reverse-proxy facilities.
//
// Reference: projectdiscovery/proxify (MIT) — API shape and rule model only;
// no source code copied. License: MIT (blackhorn-modules).
package proxify

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	defaultListenAddr  = "127.0.0.1:8080"
	maxBodyBytes       = 2 * 1024 * 1024 // 2 MiB
	defaultReadTimeout = 30 * time.Second
)

// ─── match/replace rules ──────────────────────────────────────────────────────

// RuleTarget identifies where a rule applies.
type RuleTarget string

const (
	TargetRequestHeader  RuleTarget = "request-header"
	TargetRequestBody    RuleTarget = "request-body"
	TargetResponseHeader RuleTarget = "response-header"
	TargetResponseBody   RuleTarget = "response-body"
	TargetURL            RuleTarget = "url"
)

// Rule is a match/replace or match/log rule applied to proxied traffic.
type Rule struct {
	// Name is a human-readable identifier for the rule.
	Name string
	// Target controls where the rule is applied.
	Target RuleTarget
	// Match is a regular expression. If empty, the rule matches everything.
	Match string
	// Replace is the replacement string (supports $1 backreferences).
	// If empty, the rule only logs matches (no modification).
	Replace string
	// Severity of findings emitted when this rule matches.
	Severity module.Severity
	// FindingType is emitted as Finding.Type when the rule matches.
	FindingType string

	compiled *regexp.Regexp // compiled once on first use
}

func (r *Rule) compile() error {
	if r.Match == "" {
		return nil
	}
	if r.compiled != nil {
		return nil
	}
	re, err := regexp.Compile(r.Match)
	if err != nil {
		return fmt.Errorf("rule %q: invalid regex %q: %w", r.Name, r.Match, err)
	}
	r.compiled = re
	return nil
}

func (r *Rule) matches(s string) bool {
	if r.compiled == nil {
		return true // empty pattern matches everything
	}
	return r.compiled.MatchString(s)
}

func (r *Rule) apply(s string) string {
	if r.Replace == "" || r.compiled == nil {
		return s
	}
	return r.compiled.ReplaceAllString(s, r.Replace)
}

// ─── module ──────────────────────────────────────────────────────────────────

// Module implements an in-process HTTP intercepting proxy.
// Call Listen() to start the proxy server, then Run() to collect findings.
type Module struct {
	// ListenAddr is the address to bind the proxy server (default: 127.0.0.1:8080).
	ListenAddr string
	// Rules is the ordered list of match/replace/log rules.
	Rules []Rule
	// UpstreamProxy optionally routes all traffic through another proxy.
	UpstreamProxy string
	// PassthroughTLS skips TLS certificate verification for upstream targets.
	PassthroughTLS bool

	mu       sync.Mutex
	findings []module.Finding
	listener net.Listener
	server   *http.Server
}

// New returns a Module with default settings.
func New() *Module {
	return &Module{
		ListenAddr: defaultListenAddr,
	}
}

// NewWithAddr creates a Module bound to a specific address.
func NewWithAddr(addr string) *Module {
	return &Module{
		ListenAddr: addr,
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "proxify" }

// Run implements module.Module.
//
// For the proxify module, Run processes a batch of HTTP transactions provided
// in Input.RawContent (newline-delimited "METHOD URL" pairs) and applies
// rules to them — this is the testable/offline mode.
//
// For live interception, use Listen()+Stop() to control the proxy server
// and collect findings as they accumulate via Findings().
//
// Input.Options:
//   - "mode": "batch" (default) or "intercept"
//   - "upstream": override UpstreamProxy
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	if err := m.compileRules(); err != nil {
		return nil, err
	}

	mode := "batch"
	if input.Options != nil {
		if v := input.Options["mode"]; v != "" {
			mode = v
		}
		if v := input.Options["upstream"]; v != "" {
			m.UpstreamProxy = v
		}
	}

	switch mode {
	case "intercept":
		return m.runIntercept(ctx, input)
	default:
		return m.runBatch(ctx, input)
	}
}

// runBatch processes HTTP transactions from Input (offline rule evaluation).
func (m *Module) runBatch(ctx context.Context, input module.Input) ([]module.Finding, error) {
	txs := parseTransactions(input)
	if len(txs) == 0 {
		return nil, fmt.Errorf("proxify: no transactions to process")
	}

	var findings []module.Finding
	for _, tx := range txs {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		ff := m.applyRules(tx)
		findings = append(findings, ff...)
	}
	return findings, nil
}

// runIntercept starts the proxy listener, waits for ctx cancellation, returns findings.
func (m *Module) runIntercept(ctx context.Context, _ module.Input) ([]module.Finding, error) {
	if err := m.Listen(); err != nil {
		return nil, err
	}
	<-ctx.Done()
	m.Stop()
	return m.Findings(), nil
}

// ─── live proxy server ────────────────────────────────────────────────────────

// Listen starts the intercepting proxy on m.ListenAddr.
func (m *Module) Listen() error {
	if err := m.compileRules(); err != nil {
		return err
	}

	l, err := net.Listen("tcp", m.ListenAddr)
	if err != nil {
		return fmt.Errorf("proxify: listen %s: %w", m.ListenAddr, err)
	}
	m.listener = l

	transport := m.buildTransport()
	handler := m.buildHandler(transport)

	m.server = &http.Server{
		Handler:     handler,
		ReadTimeout: defaultReadTimeout,
	}

	slog.Info("proxify: listening", "addr", l.Addr().String())
	go func() {
		if err := m.server.Serve(l); err != nil && err != http.ErrServerClosed {
			slog.Error("proxify: server error", "err", err)
		}
	}()
	return nil
}

// Addr returns the actual bound address (useful when ListenAddr uses :0).
func (m *Module) Addr() string {
	if m.listener == nil {
		return m.ListenAddr
	}
	return m.listener.Addr().String()
}

// Stop gracefully shuts down the proxy server.
func (m *Module) Stop() {
	if m.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.server.Shutdown(ctx)
	}
}

// Findings returns all findings collected during live interception.
func (m *Module) Findings() []module.Finding {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]module.Finding, len(m.findings))
	copy(out, m.findings)
	return out
}

// ─── transport & handler ──────────────────────────────────────────────────────

func (m *Module) buildTransport() *http.Transport {
	t := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: m.PassthroughTLS}, //nolint:gosec
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	if m.UpstreamProxy != "" {
		if u, err := url.Parse(m.UpstreamProxy); err == nil {
			t.Proxy = http.ProxyURL(u)
		}
	}
	return t
}

func (m *Module) buildHandler(transport http.RoundTripper) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CONNECT tunnel (HTTPS MITM) — for simplicity, just tunnel through.
		if r.Method == http.MethodConnect {
			m.handleCONNECT(w, r)
			return
		}
		m.handleHTTP(w, r, transport)
	})
}

// handleCONNECT opens a raw TCP tunnel to the target for HTTPS traffic.
func (m *Module) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	dest, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "proxy: cannot connect to "+r.Host, http.StatusBadGateway)
		return
	}
	defer dest.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy: hijack not supported", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(dest, conn) }() //nolint:errcheck
	go func() { defer wg.Done(); io.Copy(conn, dest) }() //nolint:errcheck
	wg.Wait()
}

// handleHTTP proxies a plain HTTP request through the rules engine.
func (m *Module) handleHTTP(w http.ResponseWriter, r *http.Request, transport http.RoundTripper) {
	// Read and buffer request body for rule application.
	reqBody, _ := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	r.Body = io.NopCloser(bytes.NewReader(reqBody))

	tx := transaction{
		method:         r.Method,
		rawURL:         r.URL.String(),
		requestHeaders: headerMap(r.Header),
		requestBody:    string(reqBody),
	}

	// Apply request rules before forwarding.
	tx = m.applyRequestRules(tx, r)

	// Forward request.
	rp := &httputil.ReverseProxy{
		Transport: transport,
		Director: func(req *http.Request) {
			// Apply any URL modifications from rules.
			if tx.rawURL != r.URL.String() {
				if u, err := url.Parse(tx.rawURL); err == nil {
					req.URL = u
				}
			}
			// Apply modified request headers.
			for k, v := range tx.requestHeaders {
				req.Header.Set(k, v)
			}
			// Apply modified body.
			req.Body = io.NopCloser(strings.NewReader(tx.requestBody))
			req.ContentLength = int64(len(tx.requestBody))
		},
		ModifyResponse: func(resp *http.Response) error {
			// Read and buffer response body.
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
			tx.responseCode = resp.StatusCode
			tx.responseHeaders = headerMap(resp.Header)
			tx.responseBody = string(respBody)

			// Apply response rules.
			tx = m.applyResponseRules(tx, resp)

			resp.Body = io.NopCloser(strings.NewReader(tx.responseBody))
			resp.ContentLength = int64(len(tx.responseBody))

			// Collect findings.
			ff := m.applyRules(tx)
			if len(ff) > 0 {
				m.mu.Lock()
				m.findings = append(m.findings, ff...)
				m.mu.Unlock()
			}
			return nil
		},
	}
	rp.ServeHTTP(w, r)
}

// ─── transaction model ────────────────────────────────────────────────────────

// transaction holds one captured HTTP request+response pair.
type transaction struct {
	method          string
	rawURL          string
	requestHeaders  map[string]string
	requestBody     string
	responseCode    int
	responseHeaders map[string]string
	responseBody    string
}

// parseTransactions converts Input into a slice of transactions (batch mode).
func parseTransactions(input module.Input) []transaction {
	var txs []transaction
	addLine := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}
		parts := strings.SplitN(line, " ", 2)
		method := "GET"
		rawURL := line
		if len(parts) == 2 {
			method = strings.ToUpper(parts[0])
			rawURL = parts[1]
		}
		txs = append(txs, transaction{
			method: method,
			rawURL: rawURL,
		})
	}
	if input.RawContent != "" {
		for _, line := range strings.Split(input.RawContent, "\n") {
			addLine(line)
		}
	}
	for _, u := range input.URLs {
		addLine(u)
	}
	if input.Target != "" {
		addLine(input.Target)
	}
	return txs
}

// ─── rule engine ─────────────────────────────────────────────────────────────

func (m *Module) compileRules() error {
	for i := range m.Rules {
		if err := m.Rules[i].compile(); err != nil {
			return err
		}
	}
	return nil
}

// applyRequestRules applies request-side rules and returns a modified transaction.
func (m *Module) applyRequestRules(tx transaction, r *http.Request) transaction {
	for _, rule := range m.Rules {
		switch rule.Target {
		case TargetURL:
			if rule.matches(tx.rawURL) {
				tx.rawURL = rule.apply(tx.rawURL)
			}
		case TargetRequestHeader:
			for k, v := range tx.requestHeaders {
				if rule.matches(k + ": " + v) {
					newV := rule.apply(v)
					if newV != v {
						tx.requestHeaders[k] = newV
						if r != nil {
							r.Header.Set(k, newV)
						}
					}
				}
			}
		case TargetRequestBody:
			if rule.matches(tx.requestBody) {
				tx.requestBody = rule.apply(tx.requestBody)
			}
		}
	}
	return tx
}

// applyResponseRules applies response-side rules and returns a modified transaction.
func (m *Module) applyResponseRules(tx transaction, resp *http.Response) transaction {
	for _, rule := range m.Rules {
		switch rule.Target {
		case TargetResponseHeader:
			for k, v := range tx.responseHeaders {
				if rule.matches(k + ": " + v) {
					newV := rule.apply(v)
					if newV != v {
						tx.responseHeaders[k] = newV
						if resp != nil {
							resp.Header.Set(k, newV)
						}
					}
				}
			}
		case TargetResponseBody:
			if rule.matches(tx.responseBody) {
				tx.responseBody = rule.apply(tx.responseBody)
			}
		}
	}
	return tx
}

// applyRules evaluates all rules against a completed transaction and emits findings.
func (m *Module) applyRules(tx transaction) []module.Finding {
	var findings []module.Finding
	for _, rule := range m.Rules {
		if rule.FindingType == "" {
			continue // rule is modify-only, no finding emitted
		}
		var target string
		switch rule.Target {
		case TargetURL:
			target = tx.rawURL
		case TargetRequestHeader:
			target = headersString(tx.requestHeaders)
		case TargetRequestBody:
			target = tx.requestBody
		case TargetResponseHeader:
			target = headersString(tx.responseHeaders)
		case TargetResponseBody:
			target = tx.responseBody
		}
		if rule.matches(target) {
			sev := rule.Severity
			if sev == "" {
				sev = module.SeverityInfo
			}
			findings = append(findings, module.Finding{
				Type:     rule.FindingType,
				URL:      tx.rawURL,
				Severity: sev,
				Detail:   fmt.Sprintf("Rule %q matched on %s", rule.Name, rule.Target),
				Extra: map[string]string{
					"rule":       rule.Name,
					"target":     string(rule.Target),
					"method":     tx.method,
					"confidence": "0.85",
				},
			})
		}
	}
	return findings
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func headerMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, vv := range h {
		m[k] = strings.Join(vv, ", ")
	}
	return m
}

func headersString(h map[string]string) string {
	var sb strings.Builder
	for k, v := range h {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\n")
	}
	return sb.String()
}
