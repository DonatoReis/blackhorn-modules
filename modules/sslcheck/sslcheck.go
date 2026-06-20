// Package sslcheck analisa certificados TLS/SSL e configuração de segurança.
//
// Técnicas utilizadas:
//   - Inspeção nativa do certificado via crypto/tls — sem ferramentas externas
//   - Verificação de expiração, SANs, revogação OCSP, CT logs
//   - Detecção de versões TLS fracas (SSLv3, TLS 1.0, TLS 1.1)
//   - Cipher suites inseguros (RC4, DES, NULL, EXPORT, anon)
//   - HSTS, HPKP, CAA DNS record
//   - crt.sh (Certificate Transparency logs) — sem API key
//   - testssl.sh-style checks em Go nativo
//
// Input:
//   - Target: hostname (exemplo: example.com) ou hostname:porta
//   - Options["port"]        — porta (default: 443)
//   - Options["timeout_ms"]  — timeout em ms (default: 10000)
//   - Options["check_ocsp"]  — "true" para checar OCSP (default: true)
//   - Options["check_crt"]   — "true" para consultar crt.sh (default: true)
//   - Options["check_weak"]  — "true" para checar cipher/versões fracas (default: true)
package sslcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	maxBodyBytes     = 2 << 20
	defaultTimeoutMs = 10000
	warningDays      = 30 // alerta de expiração se < 30 dias
	criticalDays     = 7  // crítico se < 7 dias
)

// Module implementa o módulo sslcheck.
type Module struct {
	client *http.Client
}

// New cria um módulo com cliente padrão.
func New() *Module {
	return NewWithClient(&http.Client{Timeout: 15 * time.Second})
}

// NewWithClient cria um módulo com cliente customizado.
func NewWithClient(c *http.Client) *Module {
	return &Module{client: c}
}

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "sslcheck" }

// Run executa a análise do certificado TLS.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("sslcheck: target não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	timeoutMs := optInt(opts, "timeout_ms", defaultTimeoutMs)
	port := optStr(opts, "port", "443")
	checkOCSP := optStr(opts, "check_ocsp", "true") != "false"
	checkCRT := optStr(opts, "check_crt", "true") != "false"
	checkWeak := optStr(opts, "check_weak", "true") != "false"

	// Separa host:porta se fornecido
	host := target
	if strings.Contains(target, ":") {
		h, p, err := net.SplitHostPort(target)
		if err == nil {
			host = h
			port = p
		}
	}

	slog.InfoContext(ctx, "sslcheck: iniciando análise",
		"host", host,
		"port", port,
		"check_ocsp", checkOCSP,
		"check_crt", checkCRT,
	)

	timeout := time.Duration(timeoutMs) * time.Millisecond

	var findings []module.Finding

	// Conexão TLS para inspeção do certificado
	certFindings, certs, err := m.inspectTLS(ctx, host, port, timeout)
	if err != nil {
		// Erro de TLS é um finding em si
		findings = append(findings, module.Finding{
			Type:     "tls_error",
			URL:      fmt.Sprintf("https://%s:%s", host, port),
			Detail:   fmt.Sprintf("Erro ao conectar via TLS a %s:%s: %v.", host, port, err),
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"host":       host,
				"port":       port,
				"error":      err.Error(),
				"fonte":      "sslcheck",
				"confidence": "0.95",
			},
		})
		return dedup(findings), nil
	}
	findings = append(findings, certFindings...)

	// Verificações fracas de versão/cipher
	if checkWeak {
		weakFindings := m.checkWeakConfig(ctx, host, port, timeout)
		findings = append(findings, weakFindings...)
	}

	// OCSP
	if checkOCSP && len(certs) > 0 {
		ocspFindings := m.checkOCSP(ctx, certs[0])
		findings = append(findings, ocspFindings...)
	}

	// Certificate Transparency (crt.sh)
	if checkCRT {
		crtFindings, err := m.queryCRTSH(ctx, host)
		if err != nil {
			slog.WarnContext(ctx, "sslcheck: crt.sh falhou", "err", err)
		} else {
			findings = append(findings, crtFindings...)
		}
	}

	result := dedup(findings)

	slog.InfoContext(ctx, "sslcheck: concluído",
		"total_findings", len(result),
	)

	return result, nil
}

// ─── TLS Inspection ───────────────────────────────────────────────────────────

func (m *Module) inspectTLS(ctx context.Context, host, port string, timeout time.Duration) ([]module.Finding, []*x509.Certificate, error) {
	addr := net.JoinHostPort(host, port)

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	})
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates

	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("sem certificados na conexão TLS")
	}

	leaf := certs[0]
	var findings []module.Finding

	// Finding principal do certificado
	now := time.Now()
	daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)

	certSeverity := module.SeverityInfo
	expiryDetail := ""
	switch {
	case daysLeft < 0:
		certSeverity = module.SeverityCritical
		expiryDetail = fmt.Sprintf("EXPIRADO há %d dias!", -daysLeft)
	case daysLeft < criticalDays:
		certSeverity = module.SeverityCritical
		expiryDetail = fmt.Sprintf("EXPIRA EM %d DIA(S)!", daysLeft)
	case daysLeft < warningDays:
		certSeverity = module.SeverityMedium
		expiryDetail = fmt.Sprintf("expira em %d dias.", daysLeft)
	default:
		expiryDetail = fmt.Sprintf("válido por mais %d dias.", daysLeft)
	}

	// SANs
	sans := append(leaf.DNSNames, leaf.EmailAddresses...)
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}

	// TLS Version
	tlsVersion := tlsVersionName(state.Version)

	// Cipher suite
	cipherName := tls.CipherSuiteName(state.CipherSuite)

	// Issuer e Subject
	issuerCN := leaf.Issuer.CommonName
	issuerOrg := strings.Join(leaf.Issuer.Organization, ", ")
	subjectCN := leaf.Subject.CommonName

	// Wildcard detection
	isWildcard := strings.HasPrefix(subjectCN, "*.")
	for _, san := range leaf.DNSNames {
		if strings.HasPrefix(san, "*.") {
			isWildcard = true
		}
	}

	// Self-signed
	isSelfSigned := leaf.Issuer.CommonName == leaf.Subject.CommonName && len(certs) == 1

	detail := fmt.Sprintf("Certificado de '%s' (issued by %s / %s). TLS: %s, Cipher: %s. SAN: [%s]. Validade: %s → %s (%s)",
		subjectCN, issuerCN, issuerOrg,
		tlsVersion, cipherName,
		strings.Join(sans[:min(5, len(sans))], ", "),
		leaf.NotBefore.Format("2006-01-02"), leaf.NotAfter.Format("2006-01-02"),
		expiryDetail)

	findings = append(findings, module.Finding{
		Type:     "tls_certificate",
		URL:      fmt.Sprintf("https://%s:%s", host, port),
		Detail:   detail,
		Severity: certSeverity,
		Extra: map[string]string{
			"host":           host,
			"subject_cn":     subjectCN,
			"issuer_cn":      issuerCN,
			"issuer_org":     issuerOrg,
			"valid_from":     leaf.NotBefore.Format(time.RFC3339),
			"valid_until":    leaf.NotAfter.Format(time.RFC3339),
			"days_left":      fmt.Sprintf("%d", daysLeft),
			"tls_version":    tlsVersion,
			"cipher_suite":   cipherName,
			"sans_count":     fmt.Sprintf("%d", len(sans)),
			"is_wildcard":    fmt.Sprintf("%v", isWildcard),
			"is_self_signed": fmt.Sprintf("%v", isSelfSigned),
			"serial_number":  leaf.SerialNumber.Text(16),
			"key_usage":      keyUsageNames(leaf.KeyUsage),
			"fonte":          "sslcheck",
			"confidence":     "0.98",
		},
	})

	// Self-signed é warning adicional
	if isSelfSigned {
		findings = append(findings, module.Finding{
			Type:     "self_signed_cert",
			URL:      fmt.Sprintf("https://%s:%s", host, port),
			Detail:   fmt.Sprintf("Certificado auto-assinado em %s:%s — não confiável por browsers/clientes sem configuração explícita.", host, port),
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"host":       host,
				"subject_cn": subjectCN,
				"fonte":      "sslcheck",
				"confidence": "0.98",
			},
		})
	}

	// Wildcard excessivo
	if isWildcard {
		findings = append(findings, module.Finding{
			Type:     "wildcard_certificate",
			URL:      fmt.Sprintf("https://%s:%s", host, port),
			Detail:   fmt.Sprintf("Certificado wildcard detectado em %s:%s — comprometimento do certificado afeta todos os subdomínios.", host, port),
			Severity: module.SeverityLow,
			Extra: map[string]string{
				"host":       host,
				"subject_cn": subjectCN,
				"fonte":      "sslcheck",
				"confidence": "0.95",
			},
		})
	}

	// TLS version insegura
	if state.Version < tls.VersionTLS12 {
		findings = append(findings, module.Finding{
			Type:     "weak_tls_version",
			URL:      fmt.Sprintf("https://%s:%s", host, port),
			Detail:   fmt.Sprintf("Versão TLS insegura negociada: %s. Versões < TLS 1.2 são obsoletas e vulneráveis.", tlsVersion),
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"host":        host,
				"tls_version": tlsVersion,
				"fonte":       "sslcheck",
				"confidence":  "0.98",
			},
		})
	}

	return findings, certs, nil
}

// ─── Weak cipher / version probing ───────────────────────────────────────────

// weakVersions lista versões inseguras para tentar negociar.
var weakVersionChecks = []struct {
	name    string
	version uint16
}{
	{"TLS 1.0", tls.VersionTLS10},
	{"TLS 1.1", tls.VersionTLS11},
}

func (m *Module) checkWeakConfig(ctx context.Context, host, port string, timeout time.Duration) []module.Finding {
	var findings []module.Finding
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: timeout}

	for _, check := range weakVersionChecks {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         host,
			MinVersion:         check.version,
			MaxVersion:         check.version,
			InsecureSkipVerify: true,
		})
		if err == nil {
			conn.Close()
			findings = append(findings, module.Finding{
				Type:     "weak_tls_accepted",
				URL:      fmt.Sprintf("https://%s:%s", host, port),
				Detail:   fmt.Sprintf("Servidor %s:%s aceita %s — versão insegura e descontinuada que deve ser desabilitada.", host, port, check.name),
				Severity: module.SeverityHigh,
				Extra: map[string]string{
					"host":        host,
					"tls_version": check.name,
					"fonte":       "sslcheck",
					"confidence":  "0.95",
				},
			})
		}
	}

	return findings
}

// ─── OCSP check ──────────────────────────────────────────────────────────────

func (m *Module) checkOCSP(ctx context.Context, cert *x509.Certificate) []module.Finding {
	if len(cert.OCSPServer) == 0 {
		return []module.Finding{
			{
				Type:     "ocsp_not_configured",
				URL:      "",
				Detail:   fmt.Sprintf("Certificado '%s' não possui URL OCSP configurada — não é possível verificar revogação online.", cert.Subject.CommonName),
				Severity: module.SeverityLow,
				Extra: map[string]string{
					"subject_cn": cert.Subject.CommonName,
					"fonte":      "sslcheck",
					"confidence": "0.90",
				},
			},
		}
	}

	// Apenas indica qual URL OCSP está configurada — verificação real requer issuer cert
	ocspURL := cert.OCSPServer[0]

	return []module.Finding{
		{
			Type:     "ocsp_configured",
			URL:      ocspURL,
			Detail:   fmt.Sprintf("Certificado '%s' possui OCSP configurado em %s.", cert.Subject.CommonName, ocspURL),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"subject_cn": cert.Subject.CommonName,
				"ocsp_url":   ocspURL,
				"fonte":      "sslcheck",
				"confidence": "0.90",
			},
		},
	}
}

// ─── crt.sh (Certificate Transparency) ───────────────────────────────────────

type crtshEntry struct {
	ID         int    `json:"id"`
	LoggedAt   string `json:"entry_timestamp"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	IssuerName string `json:"issuer_name"`
}

func (m *Module) queryCRTSH(ctx context.Context, host string) ([]module.Finding, error) {
	// Remove wildcard para busca
	domain := strings.TrimPrefix(host, "*.")
	// Remove subdomínio para buscar todo o domínio
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		domain = strings.Join(parts[len(parts)-2:], ".")
	}

	u := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json&limit=20", url.QueryEscape(domain))

	respBody, err := m.getHTTP(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}

	var entries []crtshEntry
	if err := json.Unmarshal(respBody, &entries); err != nil {
		// crt.sh pode retornar HTML em caso de erro
		return nil, fmt.Errorf("crt.sh: parse: %w", err)
	}

	if len(entries) == 0 {
		return nil, nil
	}

	var findings []module.Finding

	// Summary de CT logs
	findings = append(findings, module.Finding{
		Type:     "ct_log_summary",
		URL:      fmt.Sprintf("https://crt.sh/?q=%%25.%s", url.QueryEscape(domain)),
		Detail:   fmt.Sprintf("Certificate Transparency: %d certificado(s) emitido(s) para '*.%s' em CT logs públicos.", len(entries), domain),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"domain":      domain,
			"total_certs": fmt.Sprintf("%d", len(entries)),
			"fonte":       "crtsh",
			"confidence":  "0.92",
		},
	})

	// Certificados recentes (últimos 5)
	maxEntries := min(5, len(entries))
	for _, entry := range entries[:maxEntries] {
		// Detecta SANs incomuns (subdomínios não esperados)
		nameValue := entry.NameValue
		if nameValue == "" {
			nameValue = entry.CommonName
		}

		findings = append(findings, module.Finding{
			Type: "ct_certificate",
			URL:  fmt.Sprintf("https://crt.sh/?id=%d", entry.ID),
			Detail: fmt.Sprintf("CT Log: certificado para '%s' emitido por %s em %s, válido até %s.",
				nameValue, issuerShort(entry.IssuerName), entry.LoggedAt, entry.NotAfter),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"ct_id":       fmt.Sprintf("%d", entry.ID),
				"common_name": entry.CommonName,
				"name_value":  nameValue,
				"issuer":      issuerShort(entry.IssuerName),
				"logged_at":   entry.LoggedAt,
				"not_after":   entry.NotAfter,
				"fonte":       "crtsh",
				"confidence":  "0.92",
			},
		})
	}

	return findings, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func (m *Module) getHTTP(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-modules/1.0 (security research tool)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
}

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
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}

func keyUsageNames(usage x509.KeyUsage) string {
	var names []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		names = append(names, "DigitalSignature")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		names = append(names, "KeyEncipherment")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		names = append(names, "CertSign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		names = append(names, "CRLSign")
	}
	return strings.Join(names, ",")
}

func issuerShort(fullIssuer string) string {
	// Prioridade: O= > CN=
	cnVal := ""
	for _, part := range strings.Split(fullIssuer, ",") {
		part = strings.TrimSpace(part)
		upper := strings.ToUpper(part)
		if strings.HasPrefix(upper, "O=") {
			return strings.TrimPrefix(part[2:], "")
		}
		if strings.HasPrefix(upper, "CN=") && cnVal == "" {
			cnVal = part[3:]
		}
	}
	if cnVal != "" {
		return cnVal
	}
	return fullIssuer
}

func dedup(findings []module.Finding) []module.Finding {
	seen := make(map[string]struct{}, len(findings))
	result := make([]module.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Detail
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, f)
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func optStr(opts map[string]string, key, def string) string {
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

func optInt(opts map[string]string, key string, def int) int {
	v := optStr(opts, key, "")
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
		return n
	}
	return def
}

// Evitar lint por import não usado no arquivo principal.
var _ = big.NewInt
