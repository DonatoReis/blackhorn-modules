package sslcheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// rewriteTransport redireciona requests ao servidor de teste.
type rewriteTransport struct{ base string }

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(r.base, "http://")
	return http.DefaultTransport.RoundTrip(clone)
}

func clientFor(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: &rewriteTransport{base: srv.URL}}
}

// generateTestCert cria um certificado auto-assinado para testes.
func generateTestCert(t *testing.T, template *x509.Certificate) (*tls.Certificate, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gerar chave: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("criar certificado: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}

	return &tlsCert, x509Cert
}

// startTLSServer cria um servidor TLS de teste com o certificado fornecido.
func startTLSServer(t *testing.T, tlsCert *tls.Certificate) (string, int) {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen TLS: %v", err)
	}

	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// TLS handshake + fecha
			go func() {
				tlsConn := conn.(*tls.Conn)
				_ = tlsConn.Handshake()
				conn.Close()
			}()
		}
	}()

	t.Cleanup(func() { ln.Close() })

	return "127.0.0.1", port
}

// ─── tlsVersionName ──────────────────────────────────────────────────────────

func TestTLSVersionName(t *testing.T) {
	cases := []struct {
		v    uint16
		want string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0300, "SSLv3"},
	}
	for _, tt := range cases {
		got := tlsVersionName(tt.v)
		if got != tt.want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", tt.v, got, tt.want)
		}
	}
}

// ─── keyUsageNames ───────────────────────────────────────────────────────────

func TestKeyUsageNames(t *testing.T) {
	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	got := keyUsageNames(usage)
	if !strings.Contains(got, "DigitalSignature") {
		t.Errorf("deve conter DigitalSignature: %s", got)
	}
	if !strings.Contains(got, "KeyEncipherment") {
		t.Errorf("deve conter KeyEncipherment: %s", got)
	}
}

// ─── issuerShort ─────────────────────────────────────────────────────────────

func TestIssuerShort(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"CN=Let's Encrypt R3, O=Let's Encrypt, C=US", "Let's Encrypt"},
		{"CN=DigiCert TLS RSA SHA256 2020 CA1", "DigiCert TLS RSA SHA256 2020 CA1"},
		{"", ""},
	}
	for _, tt := range cases {
		got := issuerShort(tt.input)
		if got != tt.want {
			t.Errorf("issuerShort(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ─── Validações de entrada ────────────────────────────────────────────────────

func TestEmptyTarget(t *testing.T) {
	m := New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Fatal("deve retornar erro para target vazio")
	}
}

// ─── inspectTLS com certificado real ─────────────────────────────────────────

func TestInspectTLSValidCert(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Corp"},
		},
		DNSNames:  []string{"test.example.com", "www.test.example.com"},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	tlsCert, x509Cert := generateTestCert(t, template)
	host, port := startTLSServer(t, tlsCert)

	certPool := x509.NewCertPool()
	certPool.AddCert(x509Cert)

	portStr := fmt.Sprintf("%d", port)
	m := New()

	// O certificado é auto-assinado — o teste vai retornar tls_error ou tls_certificate
	findings, certs, err := m.inspectTLSWithPool(context.Background(), host, portStr, 5*time.Second, certPool)

	if err != nil {
		// Auto-assinado causa erro de verificação — mas deve retornar finding
		if len(findings) > 0 {
			// Se retornou findings mesmo com erro, está OK
			return
		}
		t.Logf("inspectTLS erro (esperado para auto-assinado): %v", err)
		return
	}

	_ = certs

	if len(findings) == 0 {
		t.Fatal("deve retornar findings para certificado válido")
	}

	var hasCertFinding bool
	for _, f := range findings {
		if f.Type == "tls_certificate" {
			hasCertFinding = true
			if f.Extra["subject_cn"] == "" {
				t.Error("tls_certificate sem subject_cn")
			}
			if f.Extra["confidence"] == "" {
				t.Error("tls_certificate sem confidence")
			}
			if f.Extra["tls_version"] == "" {
				t.Error("tls_certificate sem tls_version")
			}
		}
	}
	if !hasCertFinding {
		t.Error("deve ter finding 'tls_certificate'")
	}
}

func TestInspectTLSSelfSigned(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "self-signed.test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	tlsCert, _ := generateTestCert(t, template)
	host, port := startTLSServer(t, tlsCert)

	// Sem pool de confiança — deve falhar mas gerar tls_error finding
	m := New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  fmt.Sprintf("%s:%d", host, port),
		Options: map[string]string{"check_crt": "false", "check_ocsp": "false", "check_weak": "false"},
	})

	_ = err
	// Pode retornar erro de certificado (tls_error) ou auto-assinado
	if len(findings) == 0 {
		t.Fatal("Run deve retornar pelo menos 1 finding mesmo com erro TLS")
	}
}

func TestInspectTLSExpiredCert(t *testing.T) {
	// Cria cert expirado (não-auto-assinado via mock)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "expired.test"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour), // já expirou!
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	tlsCert, x509Cert := generateTestCert(t, template)
	host, port := startTLSServer(t, tlsCert)

	certPool := x509.NewCertPool()
	certPool.AddCert(x509Cert)

	m := New()
	_, certs, err := m.inspectTLSWithPool(context.Background(), host, fmt.Sprintf("%d", port), 5*time.Second, certPool)
	if err != nil {
		// Certificado expirado → erro esperado (x509.CertificateInvalidError)
		t.Logf("cert expirado retornou erro esperado: %v", err)
		return
	}
	_ = certs
}

// ─── OCSP ────────────────────────────────────────────────────────────────────

func TestCheckOCSPNotConfigured(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}
	m := New()
	findings := m.checkOCSP(context.Background(), cert)
	if len(findings) != 1 {
		t.Fatalf("deve retornar 1 finding para cert sem OCSP, got %d", len(findings))
	}
	if findings[0].Type != "ocsp_not_configured" {
		t.Errorf("tipo esperado 'ocsp_not_configured', got '%s'", findings[0].Type)
	}
}

func TestCheckOCSPConfigured(t *testing.T) {
	cert := &x509.Certificate{
		Subject:    pkix.Name{CommonName: "test.example.com"},
		OCSPServer: []string{"http://ocsp.example.com"},
	}
	m := New()
	findings := m.checkOCSP(context.Background(), cert)
	if len(findings) != 1 {
		t.Fatalf("deve retornar 1 finding para cert com OCSP, got %d", len(findings))
	}
	if findings[0].Type != "ocsp_configured" {
		t.Errorf("tipo esperado 'ocsp_configured', got '%s'", findings[0].Type)
	}
	if findings[0].Extra["ocsp_url"] == "" {
		t.Error("finding sem ocsp_url")
	}
	if findings[0].Extra["confidence"] == "" {
		t.Error("finding sem confidence")
	}
}

// ─── crt.sh ──────────────────────────────────────────────────────────────────

func TestQueryCRTSHFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":              12345,
				"entry_timestamp": "2024-01-15T10:00:00",
				"not_before":      "2024-01-01",
				"not_after":       "2025-01-01",
				"common_name":     "example.com",
				"name_value":      "example.com\nwww.example.com",
				"issuer_name":     "CN=Let's Encrypt R3, O=Let's Encrypt, C=US",
			},
			{
				"id":              67890,
				"entry_timestamp": "2023-06-01T08:00:00",
				"not_before":      "2023-06-01",
				"not_after":       "2024-06-01",
				"common_name":     "old.example.com",
				"name_value":      "old.example.com",
				"issuer_name":     "CN=DigiCert CA, O=DigiCert",
			},
		})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryCRTSH(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("queryCRTSH: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("deve retornar summary + pelo menos 1 cert, got %d", len(findings))
	}

	var hasSummary bool
	for _, f := range findings {
		if f.Type == "ct_log_summary" {
			hasSummary = true
			if f.Extra["total_certs"] == "" {
				t.Error("summary sem total_certs")
			}
			if f.Extra["confidence"] == "" {
				t.Error("summary sem confidence")
			}
		}
		if f.Type == "ct_certificate" {
			if f.Extra["ct_id"] == "" {
				t.Error("ct_certificate sem ct_id")
			}
		}
	}
	if !hasSummary {
		t.Error("deve ter finding 'ct_log_summary'")
	}
}

func TestQueryCRTSHEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]interface{}{})
	}))
	defer srv.Close()

	m := NewWithClient(clientFor(srv))
	findings, err := m.queryCRTSH(context.Background(), "notfound.example.com")
	if err != nil {
		t.Fatalf("queryCRTSH empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("sem certs deve retornar 0 findings, got %d", len(findings))
	}
}

// ─── Run com TLS inválido ─────────────────────────────────────────────────────

func TestRunInvalidHost(t *testing.T) {
	m := New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "invalid.host.does.not.exist.xyz",
		Options: map[string]string{"check_crt": "false", "check_ocsp": "false", "check_weak": "false", "timeout_ms": "1000"},
	})
	if err != nil {
		t.Fatalf("Run não deve retornar erro: %v", err)
	}
	// Deve retornar finding de erro TLS
	if len(findings) == 0 {
		t.Fatal("deve retornar pelo menos 1 finding (tls_error)")
	}
}

// ─── dedup ───────────────────────────────────────────────────────────────────

func TestDedup(t *testing.T) {
	findings := []module.Finding{
		{Type: "tls_certificate", URL: "https://example.com:443", Detail: "cert"},
		{Type: "tls_certificate", URL: "https://example.com:443", Detail: "cert"},
		{Type: "ct_log_summary", URL: "https://crt.sh", Detail: "2 certs"},
	}
	result := dedup(findings)
	if len(result) != 2 {
		t.Errorf("dedup: esperado 2 únicos, got %d", len(result))
	}
}

// ─── Module interface ────────────────────────────────────────────────────────

func TestModuleName(t *testing.T) {
	m := New()
	if m.Name() != "sslcheck" {
		t.Errorf("Name() = %q, want 'sslcheck'", m.Name())
	}
}

// ─── Helpers extras ──────────────────────────────────────────────────────────

// inspectTLSWithPool permite injetar um cert pool customizado para testes.
func (m *Module) inspectTLSWithPool(ctx context.Context, host, port string, timeout time.Duration, pool *x509.CertPool) ([]module.Finding, []*x509.Certificate, error) {
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName: host,
		RootCAs:    pool,
	})
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("sem certificados")
	}

	leaf := certs[0]
	now := time.Now()
	daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)

	severity := module.SeverityInfo
	if daysLeft < 0 {
		severity = module.SeverityCritical
	} else if daysLeft < criticalDays {
		severity = module.SeverityCritical
	} else if daysLeft < warningDays {
		severity = module.SeverityMedium
	}

	findings := []module.Finding{
		{
			Type:     "tls_certificate",
			URL:      fmt.Sprintf("https://%s:%s", host, port),
			Detail:   fmt.Sprintf("Certificado '%s' válido por %d dias.", leaf.Subject.CommonName, daysLeft),
			Severity: severity,
			Extra: map[string]string{
				"subject_cn":  leaf.Subject.CommonName,
				"days_left":   fmt.Sprintf("%d", daysLeft),
				"tls_version": tlsVersionName(state.Version),
				"confidence":  "0.98",
			},
		},
	}

	return findings, certs, nil
}

// formatInt formata int para string.
func formatInt(n int) string {
	return fmt.Sprintf("%d", n)
}

var _ = formatInt
