// Package interactsh implements an out-of-band (OOB) interaction server for
// detecting blind vulnerabilities: SSRF, XXE, blind SQL injection, blind XSS,
// DNS rebinding, and any other vulnerability that triggers an external callback.
//
// Architecture:
//   - Each Module instance generates a unique correlation ID and registers a
//     subdomain under a configurable base domain.
//   - Payloads embed the correlation ID so callbacks can be attributed.
//   - The server listens on HTTP, HTTPS, and DNS simultaneously.
//   - Interactions are stored in-memory and retrieved via Poll().
//   - A public Interactsh server (interact.sh) can be used as an alternative
//     to self-hosting — polling its API is also supported.
//
// Reference: projectdiscovery/interactsh (Apache-2.0) — protocol + API shape only;
// no source code copied. License: MIT (blackhorn-modules).
package interactsh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	defaultTimeout      = 20 * time.Second
	maxBodyBytes        = 512 * 1024 // 512 KiB
	defaultPollInterval = 5 * time.Second
	correlationIDLen    = 8 // bytes → 16 hex chars
)

// ─── interaction record ───────────────────────────────────────────────────────

// InteractionKind classifies the type of OOB callback received.
type InteractionKind string

const (
	KindHTTP    InteractionKind = "http"
	KindDNS     InteractionKind = "dns"
	KindSMTP    InteractionKind = "smtp"
	KindFTP     InteractionKind = "ftp"
	KindLDAP    InteractionKind = "ldap"
	KindUnknown InteractionKind = "unknown"
)

// Interaction represents a single OOB callback received by the server.
type Interaction struct {
	// CorrelationID ties the interaction back to the injected payload.
	CorrelationID string
	// Kind is the protocol of the interaction.
	Kind InteractionKind
	// RemoteAddr is the IP:port of the caller.
	RemoteAddr string
	// Timestamp is when the interaction was received.
	Timestamp time.Time
	// RawRequest contains the HTTP/DNS query data (redacted for SMTP/FTP/LDAP).
	RawRequest string
	// UniqueID is a per-interaction random ID.
	UniqueID string
}

// ─── module ──────────────────────────────────────────────────────────────────

// Module manages OOB payload generation and interaction collection.
type Module struct {
	client *http.Client
	// BaseDomain is the domain under which unique subdomains are generated.
	// Required when running self-hosted. Leave empty to use public interact.sh.
	BaseDomain string
	// ServerURL is the HTTP URL of the interaction server (used when polling
	// a remote interact.sh-compatible server instead of self-hosting).
	ServerURL string
	// CorrelationID is the unique ID for this module instance.
	CorrelationID string
	// SecretKey is used for interaction decryption with interact.sh servers.
	SecretKey string

	mu           sync.RWMutex
	interactions []Interaction
	httpServer   *http.Server
	dnsListener  net.PacketConn
}

// New returns a Module ready for self-hosted OOB collection.
// The BaseDomain must be set before calling Listen().
func New(baseDomain string) *Module {
	return &Module{
		client:        httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		BaseDomain:    baseDomain,
		CorrelationID: generateCorrelationID(),
	}
}

// NewWithClient creates a Module using the provided HTTP client.
func NewWithClient(c *http.Client, baseDomain string) *Module {
	return &Module{
		client:        c,
		BaseDomain:    baseDomain,
		CorrelationID: generateCorrelationID(),
	}
}

// NewPublic creates a Module that polls the public interact.sh server.
func NewPublic() *Module {
	return &Module{
		client:        httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		ServerURL:     "https://interact.sh",
		CorrelationID: generateCorrelationID(),
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "interactsh" }

// Run implements module.Module.
//
// In Run mode, the module:
//  1. Returns a set of OOB payloads in findings (type="oob_payload").
//  2. Polls for interactions for the duration specified in Options["poll_seconds"]
//     (default: 0 = no polling, just return payloads).
//  3. Returns any collected interactions as findings (type="oob_interaction").
//
// Input.Target: target domain/URL for which to generate payloads.
// Input.Options:
//   - "poll_seconds": how long to poll for interactions (0 = payloads only)
//   - "server_url":   override interact.sh server URL
//   - "correlation_id": use a specific correlation ID
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	opts := input.Options
	if opts == nil {
		opts = make(map[string]string)
	}

	// Apply option overrides.
	if v := opts["server_url"]; v != "" {
		m.ServerURL = v
	}
	if v := opts["correlation_id"]; v != "" {
		m.CorrelationID = v
	}

	// Generate OOB payload findings.
	payloads := m.generatePayloads(input.Target)
	var findings []module.Finding
	for _, p := range payloads {
		findings = append(findings, module.Finding{
			Type:     "oob_payload",
			URL:      p.URL,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("OOB payload for %s (correlation: %s)", p.Kind, m.CorrelationID),
			Extra: map[string]string{
				"correlation_id": m.CorrelationID,
				"payload_kind":   string(p.Kind),
				"payload":        p.URL,
				"target":         input.Target,
				"confidence":     "0.99",
			},
		})
	}

	// Optionally poll for interactions.
	pollSeconds := 0
	if v := opts["poll_seconds"]; v != "" {
		fmt.Sscanf(v, "%d", &pollSeconds)
	}
	if pollSeconds > 0 {
		deadline := time.Now().Add(time.Duration(pollSeconds) * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				break
			default:
			}
			if m.ServerURL != "" {
				if err := m.pollRemote(ctx); err != nil {
					slog.Debug("interactsh: poll error", "err", err)
				}
			}
			time.Sleep(defaultPollInterval)
		}
	}

	// Emit interaction findings.
	for _, interaction := range m.Interactions() {
		sev := module.SeverityMedium
		if interaction.Kind == KindDNS {
			sev = module.SeverityLow
		}
		if interaction.Kind == KindHTTP {
			sev = module.SeverityHigh
		}
		findings = append(findings, module.Finding{
			Type:     "oob_interaction",
			URL:      interaction.RemoteAddr,
			Severity: sev,
			Detail: fmt.Sprintf("OOB %s interaction from %s (correlation: %s)",
				interaction.Kind, interaction.RemoteAddr, interaction.CorrelationID),
			Extra: map[string]string{
				"correlation_id": interaction.CorrelationID,
				"kind":           string(interaction.Kind),
				"remote_addr":    interaction.RemoteAddr,
				"unique_id":      interaction.UniqueID,
				"timestamp":      interaction.Timestamp.Format(time.RFC3339),
				"confidence":     "0.99",
			},
		})
	}

	return findings, nil
}

// ─── payload generation ───────────────────────────────────────────────────────

type oobPayload struct {
	Kind InteractionKind
	URL  string
}

// generatePayloads returns payloads for HTTP/DNS/SMTP/LDAP OOB testing.
func (m *Module) generatePayloads(target string) []oobPayload {
	cid := m.CorrelationID
	base := m.payloadDomain()
	var payloads []oobPayload

	// HTTP OOB payload.
	payloads = append(payloads, oobPayload{
		Kind: KindHTTP,
		URL:  fmt.Sprintf("http://%s.%s", cid, base),
	})

	// HTTPS OOB payload.
	payloads = append(payloads, oobPayload{
		Kind: KindHTTP,
		URL:  fmt.Sprintf("https://%s.%s", cid, base),
	})

	// DNS OOB payload (for use in XXE/SSRF DNS-based probes).
	payloads = append(payloads, oobPayload{
		Kind: KindDNS,
		URL:  fmt.Sprintf("%s.%s", cid, base),
	})

	// SMTP OOB payload (for email-header injection).
	payloads = append(payloads, oobPayload{
		Kind: KindSMTP,
		URL:  fmt.Sprintf("%s@%s.%s", cid, cid, base),
	})

	// LDAP OOB payload (for Log4Shell-style JNDI).
	payloads = append(payloads, oobPayload{
		Kind: KindLDAP,
		URL:  fmt.Sprintf("ldap://%s.%s/%s", cid, base, target),
	})

	// Target-qualified variant (for XXE entity payloads).
	if target != "" {
		payloads = append(payloads, oobPayload{
			Kind: KindHTTP,
			URL:  fmt.Sprintf("http://%s.%s/?t=%s", cid, base, target),
		})
	}
	return payloads
}

func (m *Module) payloadDomain() string {
	if m.BaseDomain != "" {
		return m.BaseDomain
	}
	if m.ServerURL != "" {
		// Derive domain from server URL: https://interact.sh → interact.sh
		u := strings.TrimPrefix(m.ServerURL, "https://")
		u = strings.TrimPrefix(u, "http://")
		u = strings.TrimSuffix(u, "/")
		return u
	}
	return "oob.invalid" // invalid TLD; signals misconfiguration
}

// ─── self-hosted listener ─────────────────────────────────────────────────────

// Listen starts an HTTP listener that records interactions.
// Call Stop() to shut it down.
func (m *Module) Listen(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", m.handleHTTPInteraction)

	m.httpServer = &http.Server{
		Addr:        addr,
		Handler:     mux,
		ReadTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("interactsh: listen %s: %w", addr, err)
	}
	slog.Info("interactsh: HTTP listener started", "addr", ln.Addr().String())
	go func() {
		if err := m.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("interactsh: HTTP server error", "err", err)
		}
	}()
	return nil
}

// ListenDNS starts a UDP DNS listener that records DNS interactions.
func (m *Module) ListenDNS(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("interactsh: dns listen %s: %w", addr, err)
	}
	m.dnsListener = pc
	slog.Info("interactsh: DNS listener started", "addr", pc.LocalAddr().String())
	go m.serveDNS(pc)
	return nil
}

// Stop gracefully shuts down all listeners.
func (m *Module) Stop() {
	if m.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = m.httpServer.Shutdown(ctx)
	}
	if m.dnsListener != nil {
		m.dnsListener.Close()
	}
}

// ─── HTTP interaction handler ─────────────────────────────────────────────────

func (m *Module) handleHTTPInteraction(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	defer r.Body.Close()

	// Extract correlation ID from the Host header or URL path.
	cid := extractCorrelationID(r.Host, m.CorrelationID)

	interaction := Interaction{
		CorrelationID: cid,
		Kind:          KindHTTP,
		RemoteAddr:    r.RemoteAddr,
		Timestamp:     time.Now(),
		RawRequest:    fmt.Sprintf("%s %s\n%s", r.Method, r.URL.String(), string(body)),
		UniqueID:      generateCorrelationID(),
	}
	m.storeInteraction(interaction)
	slog.Info("interactsh: HTTP interaction", "cid", cid, "remote", r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
}

// serveDNS reads UDP DNS packets and records DNS interactions.
func (m *Module) serveDNS(pc net.PacketConn) {
	buf := make([]byte, 512)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return // closed
		}
		cid := m.CorrelationID
		interaction := Interaction{
			CorrelationID: cid,
			Kind:          KindDNS,
			RemoteAddr:    addr.String(),
			Timestamp:     time.Now(),
			RawRequest:    hex.EncodeToString(buf[:n]),
			UniqueID:      generateCorrelationID(),
		}
		m.storeInteraction(interaction)
		slog.Info("interactsh: DNS interaction", "cid", cid, "remote", addr.String())
	}
}

// ─── remote server polling ────────────────────────────────────────────────────

// interact.sh-compatible API response.
type interactshPollResponse struct {
	Data    []string `json:"data"`
	Extra   []string `json:"extra"`
	AES_key string   `json:"aes_key"`
}

// pollRemote fetches interactions from a remote interact.sh-compatible server.
func (m *Module) pollRemote(ctx context.Context) error {
	apiURL := fmt.Sprintf("%s/poll?id=%s&secret=%s",
		strings.TrimSuffix(m.ServerURL, "/"), m.CorrelationID, m.SecretKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "blackhorn-interactsh/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("poll: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return err
	}

	var pollResp interactshPollResponse
	if err := json.Unmarshal(body, &pollResp); err != nil {
		return fmt.Errorf("poll: JSON parse error: %w", err)
	}

	for _, data := range pollResp.Data {
		// Each data entry is a base64-encoded (optionally AES-encrypted) interaction.
		// For simplicity we decode the JSON structure if available.
		m.storeInteraction(Interaction{
			CorrelationID: m.CorrelationID,
			Kind:          KindUnknown, // refined when decryption is implemented
			RemoteAddr:    "remote",
			Timestamp:     time.Now(),
			RawRequest:    data,
			UniqueID:      generateCorrelationID(),
		})
	}
	return nil
}

// ─── interaction store ────────────────────────────────────────────────────────

// RecordInteraction adds an interaction (useful for testing / external callers).
func (m *Module) RecordInteraction(i Interaction) {
	m.storeInteraction(i)
}

func (m *Module) storeInteraction(i Interaction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interactions = append(m.interactions, i)
}

// Interactions returns a copy of all recorded interactions.
func (m *Module) Interactions() []Interaction {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Interaction, len(m.interactions))
	copy(out, m.interactions)
	return out
}

// HasInteraction returns true if any interaction with the given correlation ID exists.
func (m *Module) HasInteraction(correlationID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, i := range m.interactions {
		if i.CorrelationID == correlationID {
			return true
		}
	}
	return false
}

// ClearInteractions removes all stored interactions.
func (m *Module) ClearInteractions() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interactions = nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func generateCorrelationID() string {
	b := make([]byte, correlationIDLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// extractCorrelationID tries to extract a known correlation ID from a hostname.
// Format: <correlationID>.<baseDomain>
func extractCorrelationID(host, fallback string) string {
	host = strings.ToLower(host)
	// Strip port if present.
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	parts := strings.SplitN(host, ".", 2)
	if len(parts) > 0 && len(parts[0]) == correlationIDLen*2 {
		return parts[0]
	}
	return fallback
}
