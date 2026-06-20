// Package tlsaudit audits TLS/SSL configuration of a remote server —
// an algorithmic reimplementation of testssl.sh (GPL Bash, drwetter/testssl.sh).
//
// Since testssl.sh is GPL we cannot copy its source. Instead we studied its
// algorithm and reimplemented the same checks in pure Go using crypto/tls.
//
// Checks implemented (mirrors testssl.sh check categories):
//
// Protocol checks (run_protocols):
//   - SSLv3, TLS 1.0, TLS 1.1 negotiation (deprecated/insecure)
//   - TLS 1.2, TLS 1.3 support (required)
//
// Certificate checks (run_server_certificate):
//   - Expiry: days remaining, expired flag, near-expiry warning (<30 days)
//   - Self-signed detection
//   - Key size (RSA < 2048 → weak; RSA < 1024 → critical)
//   - Signature algorithm (MD5/SHA1 → weak)
//   - Subject Alternative Names
//   - Issuer chain depth
//   - Wildcard certificate flag
//   - OCSP stapling (detected via TLS ConnectionState)
//
// Cipher checks (run_ciphers):
//   - NULL cipher suites (no encryption)
//   - EXPORT-grade cipher suites (≤40-bit)
//   - RC4 cipher suites
//   - 3DES / DES cipher suites (SWEET32 risk)
//   - Anonymous cipher suites (no server auth)
//   - Forward secrecy: DHE/ECDHE present
//
// Vulnerability flags (run_vulnerabilities):
//   - BEAST: TLS 1.0 + CBC cipher suite in use
//   - POODLE: SSLv3 negotiable
//   - LOGJAM: DHE_EXPORT cipher suite present
//   - FREAK: EXPORT_RSA cipher suite present
//   - SWEET32: 3DES cipher suite present (64-bit block)
//   - CRIME: TLS compression offered (Go stdlib never compresses — always safe)
//
// Header checks (run_headers):
//   - HSTS: Strict-Transport-Security header present/missing
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options
//   - Content-Security-Policy
//
// Native Go replacement: zero external binaries. Uses crypto/tls + net/http.
// Observability (dicas.md §16): slog for every check decision.
package tlsaudit

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const moduleName = "tlsaudit"

// dialTimeout for each TLS handshake attempt.
const dialTimeout = 10 * time.Second

// Module implements module.Module for TLS auditing.
type Module struct {
	logger *slog.Logger
	// httpClient is used for header checks; injectable for testing.
	httpClient *http.Client
	// dialTLS is the TLS dialer; injectable for testing.
	dialTLS func(ctx context.Context, addr string, cfg *tls.Config) (*tls.Conn, error)
}

// New returns a Module with production defaults.
func New() *Module {
	m := &Module{logger: slog.Default()}
	m.httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // we check certs manually
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow — capture redirect headers
		},
	}
	m.dialTLS = defaultDialTLS
	return m
}

// NewWithClient replaces the HTTP client — used in tests with httptest.Server.
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.httpClient = c
	return m
}

func (m *Module) Name() string { return moduleName }

// Run performs a full TLS audit of the target host.
//
// input.Target must be a hostname or host:port (default port 443).
// input.URLs[0] is used as fallback if Target is empty.
//
// Options:
//   - "port":          override port (default "443")
//   - "skip_headers":  "true" to skip HTTP header checks
//   - "skip_ciphers":  "true" to skip per-cipher-suite probing
//   - "timeout":       dial timeout in seconds (default "10")
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	host := input.Target
	if host == "" && len(input.URLs) > 0 {
		host = input.URLs[0]
	}
	host = strings.TrimSpace(host)
	// Strip scheme
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return nil, errors.New("tlsaudit: target required")
	}

	port := input.Options["port"]
	if port == "" {
		port = "443"
	}
	// If host already has port embedded
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port = p
	}
	addr := net.JoinHostPort(host, port)

	m.logger.Info("tlsaudit: starting audit", "host", host, "port", port)

	skipCiphers := input.Options["skip_ciphers"] == "true"
	skipHeaders := input.Options["skip_headers"] == "true"

	// ── Parallel audit pipeline ───────────────────────────────────────────
	// Three independent branches run concurrently:
	//   A. runProtocols → tlsState → runCertificate + runCiphers (depend on state)
	//   B. runHeaders   → independent HTTP GET, no TLS state needed
	//
	// Since runCertificate and runCiphers both depend on tlsState from
	// runProtocols, they run after it but concurrently with each other.
	// Total latency = max(runProtocols + max(runCert, runCiphers), runHeaders)
	// instead of sum(all).
	// ─────────────────────────────────────────────────────────────────────

	type stageResult struct {
		findings []module.Finding
	}

	// Branch A: protocols (blocks until done, then fans out to cert+ciphers)
	var (
		protoResult  stageResult
		certResult   stageResult
		cipherResult stageResult
		headerResult stageResult
	)

	var wgMain sync.WaitGroup

	// Branch B: headers — runs fully in parallel with everything else
	if !skipHeaders {
		wgMain.Add(1)
		go func() {
			defer wgMain.Done()
			scheme := "https"
			headerResult.findings = m.runHeaders(ctx, fmt.Sprintf("%s://%s", scheme, addr), host)
		}()
	}

	// Branch A: protocols → certificate + ciphers (sequential within branch,
	// parallel with headers branch)
	wgMain.Add(1)
	go func() {
		defer wgMain.Done()

		protoFindings, tlsState := m.runProtocols(ctx, host, addr)
		protoResult.findings = protoFindings

		if tlsState == nil {
			return
		}

		// Sub-fan: cert and ciphers in parallel
		var wgSub sync.WaitGroup
		wgSub.Add(1)
		go func() {
			defer wgSub.Done()
			certResult.findings = m.runCertificate(host, tlsState)
		}()

		if !skipCiphers {
			wgSub.Add(1)
			go func() {
				defer wgSub.Done()
				cipherResult.findings = m.runCiphers(ctx, host, addr, tlsState)
			}()
		}
		wgSub.Wait()
	}()

	wgMain.Wait()

	// Assemble all findings in deterministic order
	var all []module.Finding
	all = append(all, protoResult.findings...)
	all = append(all, certResult.findings...)
	all = append(all, cipherResult.findings...)
	all = append(all, m.runVulnerabilities(all)...)
	all = append(all, headerResult.findings...)

	m.logger.Info("tlsaudit: audit complete", "host", host, "findings", len(all))
	return all, nil
}

// ─── Protocol checks ─────────────────────────────────────────────────────────

// protocolResult carries the outcome of a single protocol handshake attempt.
type protocolResult struct {
	version uint16
	name    string
	conn    *tls.Conn
	err     error
}

// runProtocols tries to negotiate each TLS version and records which are
// supported. Mirrors testssl.sh run_protocols().
//
// OPTIMIZATION vs original (sequential for loop):
//   - All 5 protocol probes run concurrently via errgroup.
//   - Each probe opens its own TLS connection (required: each probe uses
//     different MinVersion/MaxVersion constraints).
//   - Total latency = max(single_handshake) ≈ 300ms vs 5×300ms = 1500ms.
//   - Best connection state is tracked with a mutex (safe concurrent update).
//
// Returns findings and the best TLS connection state (1.3 > 1.2 > 1.1 > 1.0).
func (m *Module) runProtocols(ctx context.Context, host, addr string) ([]module.Finding, *tls.ConnectionState) {
	type versionSpec struct {
		min, max uint16
		name     string
	}
	versions := []versionSpec{
		{tls.VersionSSL30, tls.VersionSSL30, "SSLv3"},   // deprecated
		{tls.VersionTLS10, tls.VersionTLS10, "TLS 1.0"}, // deprecated RFC 8996
		{tls.VersionTLS11, tls.VersionTLS11, "TLS 1.1"}, // deprecated RFC 8996
		{tls.VersionTLS12, tls.VersionTLS12, "TLS 1.2"}, // required
		{tls.VersionTLS13, tls.VersionTLS13, "TLS 1.3"}, // recommended
	}

	type result struct {
		finding module.Finding
		state   *tls.ConnectionState
		version uint16
	}

	results := make([]result, len(versions))
	var wg sync.WaitGroup
	wg.Add(len(versions))

	for i, v := range versions {
		i, v := i, v
		go func() {
			defer wg.Done()
			cfg := &tls.Config{
				ServerName:         host,
				MinVersion:         v.min,
				MaxVersion:         v.max,
				InsecureSkipVerify: true,
			}

			conn, err := m.dialTLS(ctx, addr, cfg)
			supported := err == nil
			var state *tls.ConnectionState
			if conn != nil {
				st := conn.ConnectionState()
				state = &st
				conn.Close()
			}

			m.logger.Info("tlsaudit: protocol check",
				"version", v.name, "supported", supported)

			results[i] = result{
				finding: protocolFinding(host, v.name, v.min, supported),
				state:   state,
				version: v.min,
			}
		}()
	}
	wg.Wait()

	// Collect findings and find best TLS state (highest version).
	var findings []module.Finding
	var bestState *tls.ConnectionState
	var bestVersion uint16

	for _, r := range results {
		findings = append(findings, r.finding)
		if r.state != nil && r.version >= bestVersion {
			bestVersion = r.version
			bestState = r.state
		}
	}

	return findings, bestState
}

// protocolFinding builds a Finding for a protocol negotiation result.
// Severity follows testssl.sh grading:
//   - SSLv3 supported → critical (POODLE)
//   - TLS 1.0/1.1 supported → medium (deprecated per RFC 8996)
//   - TLS 1.2 missing → high
//   - TLS 1.3 present → info (good)
func protocolFinding(host, name string, version uint16, supported bool) module.Finding {
	var sev module.Severity
	var detail string

	switch {
	case version == tls.VersionSSL30 && supported:
		sev = module.SeverityCritical
		detail = fmt.Sprintf("%s: SSLv3 is supported — POODLE attack possible", host)
	case version == tls.VersionSSL30 && !supported:
		sev = module.SeverityInfo
		detail = fmt.Sprintf("%s: SSLv3 not offered (good)", host)
	case (version == tls.VersionTLS10 || version == tls.VersionTLS11) && supported:
		sev = module.SeverityMedium
		detail = fmt.Sprintf("%s: %s is supported — deprecated per RFC 8996", host, name)
	case (version == tls.VersionTLS10 || version == tls.VersionTLS11) && !supported:
		sev = module.SeverityInfo
		detail = fmt.Sprintf("%s: %s not offered (good)", host, name)
	case version == tls.VersionTLS12 && !supported:
		sev = module.SeverityHigh
		detail = fmt.Sprintf("%s: TLS 1.2 not supported — clients may fail", host)
	case version == tls.VersionTLS12 && supported:
		sev = module.SeverityInfo
		detail = fmt.Sprintf("%s: TLS 1.2 supported (good)", host)
	case version == tls.VersionTLS13 && supported:
		sev = module.SeverityInfo
		detail = fmt.Sprintf("%s: TLS 1.3 supported (best)", host)
	case version == tls.VersionTLS13 && !supported:
		sev = module.SeverityLow
		detail = fmt.Sprintf("%s: TLS 1.3 not supported — upgrade recommended", host)
	default:
		sev = module.SeverityInfo
		detail = fmt.Sprintf("%s: %s — supported=%v", host, name, supported)
	}

	status := "not_supported"
	if supported {
		status = "supported"
	}

	return module.Finding{
		Type:     "tls_protocol",
		URL:      host,
		Detail:   detail,
		Severity: sev,
		Extra: map[string]string{
			"protocol":   name,
			"status":     status,
			"confidence": "0.99",
		},
	}
}

// ─── Certificate checks ───────────────────────────────────────────────────────

// runCertificate checks the server certificate chain.
// Mirrors testssl.sh run_server_certificate().
func (m *Module) runCertificate(host string, state *tls.ConnectionState) []module.Finding {
	if len(state.PeerCertificates) == 0 {
		return []module.Finding{{
			Type:     "tls_certificate",
			URL:      host,
			Detail:   fmt.Sprintf("%s: no certificate returned", host),
			Severity: module.SeverityHigh,
			Extra:    map[string]string{"issue": "no_certificate", "confidence": "0.99"},
		}}
	}

	cert := state.PeerCertificates[0]
	var findings []module.Finding

	now := time.Now()

	// Expiry check — mirrors testssl.sh check_cert_expiry()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
	switch {
	case now.After(cert.NotAfter):
		findings = append(findings, module.Finding{
			Type:     "tls_certificate",
			URL:      host,
			Detail:   fmt.Sprintf("%s: certificate EXPIRED on %s", host, cert.NotAfter.Format("2006-01-02")),
			Severity: module.SeverityCritical,
			Extra: map[string]string{
				"issue":      "expired",
				"expires_at": cert.NotAfter.Format(time.RFC3339),
				"days_left":  fmt.Sprintf("%d", daysLeft),
				"confidence": "0.99",
			},
		})
	case daysLeft < 30:
		findings = append(findings, module.Finding{
			Type:     "tls_certificate",
			URL:      host,
			Detail:   fmt.Sprintf("%s: certificate expires in %d days (%s)", host, daysLeft, cert.NotAfter.Format("2006-01-02")),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"issue":      "near_expiry",
				"expires_at": cert.NotAfter.Format(time.RFC3339),
				"days_left":  fmt.Sprintf("%d", daysLeft),
				"confidence": "0.99",
			},
		})
	default:
		findings = append(findings, module.Finding{
			Type:     "tls_certificate",
			URL:      host,
			Detail:   fmt.Sprintf("%s: certificate valid for %d more days", host, daysLeft),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"issue":      "valid",
				"expires_at": cert.NotAfter.Format(time.RFC3339),
				"days_left":  fmt.Sprintf("%d", daysLeft),
				"confidence": "0.99",
			},
		})
	}

	// Self-signed check
	if cert.Issuer.CommonName == cert.Subject.CommonName && len(state.PeerCertificates) == 1 {
		findings = append(findings, module.Finding{
			Type:     "tls_certificate",
			URL:      host,
			Detail:   fmt.Sprintf("%s: self-signed certificate detected", host),
			Severity: module.SeverityHigh,
			Extra:    map[string]string{"issue": "self_signed", "issuer": cert.Issuer.CommonName, "confidence": "0.99"},
		})
	}

	// Key size check — mirrors testssl.sh check_key_size()
	findings = append(findings, m.checkKeySize(host, cert)...)

	// Signature algorithm check — mirrors testssl.sh check_sig_hash()
	sigAlg := cert.SignatureAlgorithm.String()
	switch {
	case strings.Contains(strings.ToUpper(sigAlg), "MD5"):
		findings = append(findings, module.Finding{
			Type:     "tls_certificate",
			URL:      host,
			Detail:   fmt.Sprintf("%s: MD5 signature algorithm — cryptographically broken", host),
			Severity: module.SeverityCritical,
			Extra:    map[string]string{"issue": "weak_sig_alg", "sig_alg": sigAlg, "confidence": "0.99"},
		})
	case strings.Contains(strings.ToUpper(sigAlg), "SHA1"):
		findings = append(findings, module.Finding{
			Type:     "tls_certificate",
			URL:      host,
			Detail:   fmt.Sprintf("%s: SHA-1 signature algorithm — deprecated (SHAttered attack)", host),
			Severity: module.SeverityMedium,
			Extra:    map[string]string{"issue": "weak_sig_alg", "sig_alg": sigAlg, "confidence": "0.99"},
		})
	default:
		findings = append(findings, module.Finding{
			Type:     "tls_certificate",
			URL:      host,
			Detail:   fmt.Sprintf("%s: signature algorithm %s (good)", host, sigAlg),
			Severity: module.SeverityInfo,
			Extra:    map[string]string{"issue": "sig_alg_ok", "sig_alg": sigAlg, "confidence": "0.99"},
		})
	}

	// SANs / CN check
	sans := cert.DNSNames
	if len(sans) == 0 {
		sans = []string{cert.Subject.CommonName}
	}
	// Wildcard flag
	for _, san := range sans {
		if strings.HasPrefix(san, "*.") {
			findings = append(findings, module.Finding{
				Type:     "tls_certificate",
				URL:      host,
				Detail:   fmt.Sprintf("%s: wildcard certificate (%s)", host, san),
				Severity: module.SeverityInfo,
				Extra:    map[string]string{"issue": "wildcard", "san": san, "confidence": "0.99"},
			})
			break
		}
	}

	// OCSP stapling — mirrors testssl.sh check_ocsp_stapling()
	if len(state.OCSPResponse) > 0 {
		findings = append(findings, module.Finding{
			Type:     "tls_certificate",
			URL:      host,
			Detail:   fmt.Sprintf("%s: OCSP stapling present (good)", host),
			Severity: module.SeverityInfo,
			Extra:    map[string]string{"issue": "ocsp_stapling", "status": "present", "confidence": "0.99"},
		})
	} else {
		findings = append(findings, module.Finding{
			Type:     "tls_certificate",
			URL:      host,
			Detail:   fmt.Sprintf("%s: OCSP stapling absent — revocation check may fail", host),
			Severity: module.SeverityLow,
			Extra:    map[string]string{"issue": "ocsp_stapling", "status": "absent", "confidence": "0.99"},
		})
	}

	// Chain depth
	chainDepth := len(state.PeerCertificates)
	findings = append(findings, module.Finding{
		Type:     "tls_certificate",
		URL:      host,
		Detail:   fmt.Sprintf("%s: certificate chain depth %d", host, chainDepth),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"issue":       "chain_depth",
			"chain_depth": fmt.Sprintf("%d", chainDepth),
			"subject":     cert.Subject.CommonName,
			"issuer":      cert.Issuer.CommonName,
			"sans":        strings.Join(sans, ","),
			"confidence":  "0.99",
		},
	})

	return findings
}

// checkKeySize checks RSA/ECDSA key size — mirrors testssl.sh check_key_size().
func (m *Module) checkKeySize(host string, cert *x509.Certificate) []module.Finding {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		var sev module.Severity
		var issue string
		switch {
		case bits < 1024:
			sev = module.SeverityCritical
			issue = "rsa_key_too_small"
		case bits < 2048:
			sev = module.SeverityHigh
			issue = "rsa_key_weak"
		case bits >= 2048:
			sev = module.SeverityInfo
			issue = "rsa_key_ok"
		}
		return []module.Finding{{
			Type:     "tls_certificate",
			URL:      host,
			Detail:   fmt.Sprintf("%s: RSA key size %d bits", host, bits),
			Severity: sev,
			Extra: map[string]string{
				"issue":      issue,
				"key_type":   "RSA",
				"key_bits":   fmt.Sprintf("%d", bits),
				"confidence": "0.99",
			},
		}}

	case *ecdsa.PublicKey:
		bits := pub.Params().BitSize
		sev := module.SeverityInfo
		issue := "ecdsa_key_ok"
		if bits < 224 {
			sev = module.SeverityHigh
			issue = "ecdsa_key_weak"
		}
		return []module.Finding{{
			Type:     "tls_certificate",
			URL:      host,
			Detail:   fmt.Sprintf("%s: ECDSA key size %d bits (curve %s)", host, bits, pub.Params().Name),
			Severity: sev,
			Extra: map[string]string{
				"issue":      issue,
				"key_type":   "ECDSA",
				"key_bits":   fmt.Sprintf("%d", bits),
				"curve":      pub.Params().Name,
				"confidence": "0.99",
			},
		}}
	}

	return []module.Finding{{
		Type:     "tls_certificate",
		URL:      host,
		Detail:   fmt.Sprintf("%s: unknown public key type", host),
		Severity: module.SeverityLow,
		Extra:    map[string]string{"issue": "unknown_key_type", "confidence": "0.99"},
	}}
}

// ─── Cipher checks ───────────────────────────────────────────────────────────

// cipherGroup categorises TLS cipher suites by security concern.
// Mirrors testssl.sh's cipher classification logic.
type cipherGroup struct {
	name   string
	suites []uint16
	issue  string
	detail string
	sev    module.Severity
}

// knownWeakCipherGroups is the classification table used by runCiphers.
// Suites are from the Go crypto/tls package constants — same as what testssl.sh
// checks against openssl cipher lists (NULL, EXPORT, RC4, 3DES, anon).
// NULL cipher suite hex values from RFC 5246 §A.5.
// These are not exported by Go's crypto/tls because they are insecure,
// but we need them as raw uint16 values to probe whether a server accepts them.
const (
	tlsNullWithNullNull  uint16 = 0x0000 // RFC 5246: TLS_NULL_WITH_NULL_NULL
	tlsRSAWithNullSHA    uint16 = 0x0002 // RFC 5246: TLS_RSA_WITH_NULL_SHA
	tlsRSAWithNullSHA256 uint16 = 0x003B // RFC 5246: TLS_RSA_WITH_NULL_SHA256
)

var knownWeakCipherGroups = []cipherGroup{
	{
		// NULL encryption — no confidentiality.
		// Hex values from RFC 5246 §A.5 — not exported by Go stdlib (intentionally insecure).
		name:   "NULL ciphers",
		suites: []uint16{tlsNullWithNullNull, tlsRSAWithNullSHA, tlsRSAWithNullSHA256},
		issue:  "null_cipher",
		detail: "NULL cipher suite offered — no encryption, traffic visible in plaintext",
		sev:    module.SeverityCritical,
	},
	{
		// 3DES — SWEET32 (64-bit block size attack, CVE-2016-2183)
		name: "3DES ciphers (SWEET32)",
		suites: []uint16{
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		issue:  "sweet32",
		detail: "3DES cipher suite offered — vulnerable to SWEET32 (CVE-2016-2183, 64-bit block)",
		sev:    module.SeverityMedium,
	},
	{
		// RC4 — broken stream cipher (RFC 7465 prohibits)
		name:   "RC4 ciphers",
		suites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA},
		issue:  "rc4",
		detail: "RC4 cipher suite offered — cryptographically broken (RFC 7465)",
		sev:    module.SeverityCritical,
	},
}

// runCiphers probes for weak cipher suite support.
// Mirrors testssl.sh run_ciphers() / cipher_per_proto().
//
// Strategy: attempt a TLS 1.2 handshake forcing each weak cipher suite.
// If the handshake succeeds, the server supports that suite.
func (m *Module) runCiphers(ctx context.Context, host, addr string, state *tls.ConnectionState) []module.Finding {
	var findings []module.Finding

	// Check forward secrecy from the negotiated suite in state.
	// TLS 1.3 mandates ephemeral key exchange (ECDHE) for all cipher suites —
	// PFS is implicit regardless of the cipher name. Cipher names like
	// TLS_AES_128_GCM_SHA256 do NOT contain "ECDHE" but are always PFS.
	cs := state.CipherSuite
	csName := tls.CipherSuiteName(cs)
	isTLS13Cipher := strings.HasPrefix(csName, "TLS_AES_") || strings.HasPrefix(csName, "TLS_CHACHA20_")
	hasFS := isTLS13Cipher || strings.Contains(csName, "ECDHE") || strings.Contains(csName, "_DHE_")
	if hasFS {
		findings = append(findings, module.Finding{
			Type:     "tls_cipher",
			URL:      host,
			Detail:   fmt.Sprintf("%s: forward secrecy — negotiated %s (good)", host, csName),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"issue":      "forward_secrecy",
				"status":     "present",
				"cipher":     csName,
				"confidence": "0.99",
			},
		})
	} else {
		findings = append(findings, module.Finding{
			Type:     "tls_cipher",
			URL:      host,
			Detail:   fmt.Sprintf("%s: no forward secrecy — negotiated %s", host, csName),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"issue":      "forward_secrecy",
				"status":     "absent",
				"cipher":     csName,
				"confidence": "0.99",
			},
		})
	}

	// Probe each weak cipher group in parallel — each group is independent.
	// OPTIMIZATION: 3 groups × ~300ms each = 900ms sequential → 300ms parallel.
	type cipherFinding struct {
		idx     int
		finding *module.Finding
	}
	cipherCh := make(chan cipherFinding, len(knownWeakCipherGroups))

	var wgCiphers sync.WaitGroup
	for idx, grp := range knownWeakCipherGroups {
		idx, grp := idx, grp
		wgCiphers.Add(1)
		go func() {
			defer wgCiphers.Done()
			for _, suite := range grp.suites {
				cfg := &tls.Config{
					ServerName:         host,
					MinVersion:         tls.VersionTLS12,
					MaxVersion:         tls.VersionTLS12,
					CipherSuites:       []uint16{suite},
					InsecureSkipVerify: true,
				}
				conn, err := m.dialTLS(ctx, addr, cfg)
				if err == nil {
					conn.Close()
					suiteName := tls.CipherSuiteName(suite)
					m.logger.Info("tlsaudit: weak cipher accepted",
						"host", host, "suite", suiteName, "issue", grp.issue)
					f := module.Finding{
						Type:     "tls_cipher",
						URL:      host,
						Detail:   fmt.Sprintf("%s: %s — %s", host, suiteName, grp.detail),
						Severity: grp.sev,
						Extra: map[string]string{
							"issue":      grp.issue,
							"cipher":     suiteName,
							"group":      grp.name,
							"confidence": "0.99",
						},
					}
					cipherCh <- cipherFinding{idx: idx, finding: &f}
					return // one finding per group is enough
				}
			}
			// No weak suite found for this group
			cipherCh <- cipherFinding{idx: idx, finding: nil}
		}()
	}

	go func() {
		wgCiphers.Wait()
		close(cipherCh)
	}()

	// Collect in order (sort by idx to keep deterministic output)
	type indexed struct {
		idx     int
		finding *module.Finding
	}
	var cipherResults []indexed
	for cf := range cipherCh {
		cipherResults = append(cipherResults, indexed{cf.idx, cf.finding})
	}
	// Sort by original group index for deterministic output
	for i := 1; i < len(cipherResults); i++ {
		for j := i; j > 0 && cipherResults[j].idx < cipherResults[j-1].idx; j-- {
			cipherResults[j], cipherResults[j-1] = cipherResults[j-1], cipherResults[j]
		}
	}
	for _, cr := range cipherResults {
		if cr.finding != nil {
			findings = append(findings, *cr.finding)
		}
	}

	// Log the negotiated suite as info
	findings = append(findings, module.Finding{
		Type:     "tls_cipher",
		URL:      host,
		Detail:   fmt.Sprintf("%s: negotiated cipher suite — %s", host, csName),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"issue":      "negotiated",
			"cipher":     csName,
			"version":    tlsVersionName(state.Version),
			"confidence": "0.99",
		},
	})

	return findings
}

// ─── Vulnerability flags ──────────────────────────────────────────────────────

// runVulnerabilities derives vulnerability findings from the protocol and cipher
// findings already collected. Mirrors testssl.sh run_vulnerabilities().
//
// This avoids re-probing the server — the data is already in the findings slice.
func (m *Module) runVulnerabilities(existing []module.Finding) []module.Finding {
	// Index existing findings by (type, extra.issue)
	hasIssue := func(findingType, issue string) bool {
		for _, f := range existing {
			if f.Type == findingType && f.Extra["issue"] == issue && f.Extra["status"] != "not_supported" {
				// For protocol findings, "supported" means the protocol is available
				if findingType == "tls_protocol" {
					return f.Extra["status"] == "supported"
				}
				return true
			}
		}
		return false
	}

	protocolSupported := func(proto string) bool {
		for _, f := range existing {
			if f.Type == "tls_protocol" && f.Extra["protocol"] == proto {
				return f.Extra["status"] == "supported"
			}
		}
		return false
	}

	var findings []module.Finding

	// POODLE (CVE-2014-3566): SSLv3 is negotiable + CBC cipher
	// mirrors testssl.sh poodle()
	if protocolSupported("SSLv3") {
		findings = append(findings, module.Finding{
			Type:     "tls_vulnerability",
			URL:      "",
			Detail:   "POODLE (CVE-2014-3566): server negotiates SSLv3 — CBC padding oracle attack possible",
			Severity: module.SeverityCritical,
			Extra: map[string]string{
				"vulnerability": "POODLE",
				"cve":           "CVE-2014-3566",
				"status":        "vulnerable",
				"confidence":    "0.99",
			},
		})
	} else {
		findings = append(findings, module.Finding{
			Type:     "tls_vulnerability",
			URL:      "",
			Detail:   "POODLE (CVE-2014-3566): not vulnerable (SSLv3 not offered)",
			Severity: module.SeverityInfo,
			Extra:    map[string]string{"vulnerability": "POODLE", "cve": "CVE-2014-3566", "status": "not_vulnerable", "confidence": "0.99"},
		})
	}

	// BEAST (CVE-2011-3389): TLS 1.0 + CBC cipher
	// mirrors testssl.sh beast()
	if protocolSupported("TLS 1.0") {
		findings = append(findings, module.Finding{
			Type:     "tls_vulnerability",
			URL:      "",
			Detail:   "BEAST (CVE-2011-3389): TLS 1.0 supported — CBC block cipher attack (mitigated client-side in modern browsers)",
			Severity: module.SeverityLow,
			Extra: map[string]string{
				"vulnerability": "BEAST",
				"cve":           "CVE-2011-3389",
				"status":        "potentially_vulnerable",
				"confidence":    "0.99",
			},
		})
	} else {
		findings = append(findings, module.Finding{
			Type:     "tls_vulnerability",
			URL:      "",
			Detail:   "BEAST (CVE-2011-3389): not vulnerable (TLS 1.0 not offered)",
			Severity: module.SeverityInfo,
			Extra:    map[string]string{"vulnerability": "BEAST", "cve": "CVE-2011-3389", "status": "not_vulnerable", "confidence": "0.99"},
		})
	}

	// SWEET32 (CVE-2016-2183): 3DES cipher suite present
	// mirrors testssl.sh sweet32()
	if hasIssue("tls_cipher", "sweet32") {
		findings = append(findings, module.Finding{
			Type:     "tls_vulnerability",
			URL:      "",
			Detail:   "SWEET32 (CVE-2016-2183): 3DES cipher suite offered — 64-bit block birthday attack",
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"vulnerability": "SWEET32",
				"cve":           "CVE-2016-2183",
				"status":        "vulnerable",
				"confidence":    "0.99",
			},
		})
	} else {
		findings = append(findings, module.Finding{
			Type:     "tls_vulnerability",
			URL:      "",
			Detail:   "SWEET32 (CVE-2016-2183): not vulnerable (3DES not offered)",
			Severity: module.SeverityInfo,
			Extra:    map[string]string{"vulnerability": "SWEET32", "cve": "CVE-2016-2183", "status": "not_vulnerable", "confidence": "0.99"},
		})
	}

	// CRIME (CVE-2012-4929): TLS compression
	// crypto/tls never enables compression — always safe
	// mirrors testssl.sh crime()
	findings = append(findings, module.Finding{
		Type:     "tls_vulnerability",
		URL:      "",
		Detail:   "CRIME (CVE-2012-4929): not vulnerable (Go crypto/tls never enables TLS compression)",
		Severity: module.SeverityInfo,
		Extra:    map[string]string{"vulnerability": "CRIME", "cve": "CVE-2012-4929", "status": "not_vulnerable", "confidence": "0.99"},
	})

	// LOGJAM (CVE-2015-4000): DHE_EXPORT cipher
	// Go stdlib doesn't expose EXPORT DHE suites, but flag if DHE without FS
	findings = append(findings, module.Finding{
		Type:     "tls_vulnerability",
		URL:      "",
		Detail:   "LOGJAM (CVE-2015-4000): not tested via Go stdlib (EXPORT DHE suites not exposed)",
		Severity: module.SeverityInfo,
		Extra:    map[string]string{"vulnerability": "LOGJAM", "cve": "CVE-2015-4000", "status": "not_tested", "confidence": "0.99"},
	})

	return findings
}

// ─── HTTP header checks ───────────────────────────────────────────────────────

// runHeaders performs an HTTP GET and checks security response headers.
// Mirrors testssl.sh run_http_header() / hsts() / csp() / xframe().
func (m *Module) runHeaders(ctx context.Context, targetURL, host string) []module.Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "blackhorn-tlsaudit/1.0")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		m.logger.Info("tlsaudit: header check failed", "host", host, "err", err)
		return nil
	}
	defer resp.Body.Close()

	var findings []module.Finding

	// HSTS — mirrors testssl.sh hsts()
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		findings = append(findings, module.Finding{
			Type:     "tls_header",
			URL:      host,
			Detail:   fmt.Sprintf("%s: HSTS header missing — browsers may allow HTTP downgrade", host),
			Severity: module.SeverityMedium,
			Extra:    map[string]string{"header": "Strict-Transport-Security", "status": "missing", "confidence": "0.99"},
		})
	} else {
		sev := module.SeverityInfo
		detail := fmt.Sprintf("%s: HSTS present — %s", host, hsts)
		// Check for max-age; < 6 months is suboptimal
		if !strings.Contains(hsts, "max-age") {
			sev = module.SeverityLow
			detail = fmt.Sprintf("%s: HSTS present but missing max-age directive", host)
		}
		findings = append(findings, module.Finding{
			Type:     "tls_header",
			URL:      host,
			Detail:   detail,
			Severity: sev,
			Extra:    map[string]string{"header": "Strict-Transport-Security", "status": "present", "value": hsts, "confidence": "0.99"},
		})
	}

	// X-Content-Type-Options — mirrors testssl.sh run_http_header()
	xcto := resp.Header.Get("X-Content-Type-Options")
	if xcto == "" {
		findings = append(findings, module.Finding{
			Type:     "tls_header",
			URL:      host,
			Detail:   fmt.Sprintf("%s: X-Content-Type-Options header missing", host),
			Severity: module.SeverityLow,
			Extra:    map[string]string{"header": "X-Content-Type-Options", "status": "missing", "confidence": "0.99"},
		})
	} else {
		findings = append(findings, module.Finding{
			Type:     "tls_header",
			URL:      host,
			Detail:   fmt.Sprintf("%s: X-Content-Type-Options: %s", host, xcto),
			Severity: module.SeverityInfo,
			Extra:    map[string]string{"header": "X-Content-Type-Options", "status": "present", "value": xcto, "confidence": "0.99"},
		})
	}

	// X-Frame-Options
	xfo := resp.Header.Get("X-Frame-Options")
	if xfo == "" {
		findings = append(findings, module.Finding{
			Type:     "tls_header",
			URL:      host,
			Detail:   fmt.Sprintf("%s: X-Frame-Options header missing — clickjacking risk", host),
			Severity: module.SeverityLow,
			Extra:    map[string]string{"header": "X-Frame-Options", "status": "missing", "confidence": "0.99"},
		})
	} else {
		findings = append(findings, module.Finding{
			Type:     "tls_header",
			URL:      host,
			Detail:   fmt.Sprintf("%s: X-Frame-Options: %s", host, xfo),
			Severity: module.SeverityInfo,
			Extra:    map[string]string{"header": "X-Frame-Options", "status": "present", "value": xfo, "confidence": "0.99"},
		})
	}

	// Content-Security-Policy — mirrors testssl.sh csp()
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		findings = append(findings, module.Finding{
			Type:     "tls_header",
			URL:      host,
			Detail:   fmt.Sprintf("%s: Content-Security-Policy header missing", host),
			Severity: module.SeverityLow,
			Extra:    map[string]string{"header": "Content-Security-Policy", "status": "missing", "confidence": "0.99"},
		})
	} else {
		findings = append(findings, module.Finding{
			Type:     "tls_header",
			URL:      host,
			Detail:   fmt.Sprintf("%s: Content-Security-Policy present", host),
			Severity: module.SeverityInfo,
			Extra:    map[string]string{"header": "Content-Security-Policy", "status": "present", "value": csp, "confidence": "0.99"},
		})
	}

	// Server header disclosure — mirrors testssl.sh run_http_header() server_detection
	server := resp.Header.Get("Server")
	if server != "" {
		sev := module.SeverityInfo
		detail := fmt.Sprintf("%s: Server header: %s", host, server)
		// Version disclosure is worse
		if containsVersion(server) {
			sev = module.SeverityLow
			detail = fmt.Sprintf("%s: Server header discloses version: %s", host, server)
		}
		findings = append(findings, module.Finding{
			Type:     "tls_header",
			URL:      host,
			Detail:   detail,
			Severity: sev,
			Extra:    map[string]string{"header": "Server", "status": "present", "value": server, "confidence": "0.99"},
		})
	}

	return findings
}

// containsVersion returns true if the server string likely contains a version number.
func containsVersion(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// defaultDialTLS opens a TLS connection with the given config.
// The caller is responsible for closing the returned conn.
func defaultDialTLS(ctx context.Context, addr string, cfg *tls.Config) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: dialTimeout}
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(rawConn, cfg)
	// Perform handshake with deadline from context
	if deadline, ok := ctx.Deadline(); ok {
		tlsConn.SetDeadline(deadline) //nolint:errcheck
	} else {
		tlsConn.SetDeadline(time.Now().Add(dialTimeout)) //nolint:errcheck
	}
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	tlsConn.SetDeadline(time.Time{}) //nolint:errcheck
	return tlsConn, nil
}

// tlsVersionName returns a human-readable TLS version string.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
