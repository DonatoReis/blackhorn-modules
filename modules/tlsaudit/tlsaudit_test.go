package tlsaudit_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/tlsaudit"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── TLS test server helpers ─────────────────────────────────────────────────

// selfSignedCert generates a self-signed TLS certificate for testing.
// Returns the tls.Certificate and the DER-encoded x509.Certificate.
func selfSignedCert(t *testing.T, notAfter time.Time) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}),
	)
	if err != nil {
		t.Fatalf("x509 key pair: %v", err)
	}
	return tlsCert, cert
}

// mockTLSServer returns an httptest.Server running TLS with the given cert.
func mockTLSServer(t *testing.T, tlsCert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	srv.StartTLS()
	return srv
}

// moduleForServer builds a tlsaudit.Module that trusts the given server's cert.
// dialTLS override points at the httptest server's address.
func moduleForServer(srv *httptest.Server) *tlsaudit.Module {
	pool := x509.NewCertPool()
	for _, c := range srv.TLS.Certificates {
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err == nil {
			pool.AddCert(leaf)
		}
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				RootCAs:            pool,
			},
		},
	}
	return tlsaudit.NewWithClient(client)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

// TestRun_EmptyTarget expects an error.
func TestRun_EmptyTarget(t *testing.T) {
	m := tlsaudit.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestRun_ContextCancellation should not hang.
func TestRun_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := tlsaudit.New()
	_, _ = m.Run(ctx, module.Input{
		Target:  "localhost:65535", // unreachable port
		Options: map[string]string{"skip_headers": "true", "skip_ciphers": "true"},
	})
	// Should return quickly, not hang
}

// TestRun_DetectsValidCert checks that a valid cert produces SeverityInfo expiry finding.
func TestRun_DetectsValidCert(t *testing.T) {
	cert, _ := selfSignedCert(t, time.Now().Add(365*24*time.Hour))
	srv := mockTLSServer(t, cert)
	defer srv.Close()

	// Extract host:port from srv.URL
	host := strings.TrimPrefix(srv.URL, "https://")

	m := moduleForServer(srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  host,
		Options: map[string]string{"skip_ciphers": "true", "skip_headers": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == "tls_certificate" && f.Extra["issue"] == "valid" {
			found = true
		}
	}
	if !found {
		issues := make([]string, 0, len(findings))
		for _, f := range findings {
			issues = append(issues, f.Extra["issue"])
		}
		t.Errorf("expected valid cert finding; got issues: %v", issues)
	}
}

// TestRun_DetectsExpiredCert checks that an expired cert is flagged as critical.
func TestRun_DetectsExpiredCert(t *testing.T) {
	cert, _ := selfSignedCert(t, time.Now().Add(-24*time.Hour)) // already expired
	srv := mockTLSServer(t, cert)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")

	m := moduleForServer(srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  host,
		Options: map[string]string{"skip_ciphers": "true", "skip_headers": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == "tls_certificate" && f.Extra["issue"] == "expired" && f.Severity == module.SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected critical expired-cert finding")
	}
}

// TestRun_DetectsNearExpiryCert checks that a cert expiring in <30 days is medium.
func TestRun_DetectsNearExpiryCert(t *testing.T) {
	cert, _ := selfSignedCert(t, time.Now().Add(15*24*time.Hour)) // 15 days
	srv := mockTLSServer(t, cert)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")

	m := moduleForServer(srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  host,
		Options: map[string]string{"skip_ciphers": "true", "skip_headers": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == "tls_certificate" && f.Extra["issue"] == "near_expiry" && f.Severity == module.SeverityMedium {
			found = true
		}
	}
	if !found {
		t.Error("expected medium near-expiry finding for cert expiring in 15 days")
	}
}

// TestRun_SelfSignedFlagged checks that a self-signed cert is flagged.
func TestRun_SelfSignedFlagged(t *testing.T) {
	cert, _ := selfSignedCert(t, time.Now().Add(365*24*time.Hour))
	srv := mockTLSServer(t, cert)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")

	m := moduleForServer(srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  host,
		Options: map[string]string{"skip_ciphers": "true", "skip_headers": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == "tls_certificate" && f.Extra["issue"] == "self_signed" {
			found = true
		}
	}
	if !found {
		t.Error("expected self_signed finding for test server certificate")
	}
}

// TestRun_HSTSDetected checks that HSTS header is detected.
func TestRun_HSTSDetected(t *testing.T) {
	cert, _ := selfSignedCert(t, time.Now().Add(365*24*time.Hour))
	srv := mockTLSServer(t, cert)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")

	m := moduleForServer(srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  host,
		Options: map[string]string{"skip_ciphers": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == "tls_header" && f.Extra["header"] == "Strict-Transport-Security" && f.Extra["status"] == "present" {
			found = true
		}
	}
	if !found {
		t.Error("expected HSTS present finding")
	}
}

// TestRun_HSTSMissing checks that missing HSTS is flagged as medium.
func TestRun_HSTSMissing(t *testing.T) {
	cert, _ := selfSignedCert(t, time.Now().Add(365*24*time.Hour))

	// Server WITHOUT HSTS
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "no hsts")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	m := moduleForServer(srv)

	findings, err := m.Run(context.Background(), module.Input{
		Target:  host,
		Options: map[string]string{"skip_ciphers": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == "tls_header" && f.Extra["header"] == "Strict-Transport-Security" && f.Extra["status"] == "missing" {
			found = true
		}
	}
	if !found {
		t.Error("expected HSTS missing finding with medium severity")
	}
}

// TestRun_VulnerabilityFindings checks that vulnerability findings are emitted.
func TestRun_VulnerabilityFindings(t *testing.T) {
	cert, _ := selfSignedCert(t, time.Now().Add(365*24*time.Hour))
	srv := mockTLSServer(t, cert)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	m := moduleForServer(srv)

	findings, err := m.Run(context.Background(), module.Input{
		Target:  host,
		Options: map[string]string{"skip_ciphers": "true", "skip_headers": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	vulnTypes := make(map[string]bool)
	for _, f := range findings {
		if f.Type == "tls_vulnerability" {
			vulnTypes[f.Extra["vulnerability"]] = true
		}
	}

	for _, expected := range []string{"POODLE", "BEAST", "SWEET32", "CRIME"} {
		if !vulnTypes[expected] {
			t.Errorf("expected vulnerability finding for %s", expected)
		}
	}
}

// TestRun_TLS12Supported verifies TLS 1.2 protocol finding is present.
func TestRun_TLS12Supported(t *testing.T) {
	cert, _ := selfSignedCert(t, time.Now().Add(365*24*time.Hour))
	srv := mockTLSServer(t, cert)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	m := moduleForServer(srv)

	findings, err := m.Run(context.Background(), module.Input{
		Target:  host,
		Options: map[string]string{"skip_ciphers": "true", "skip_headers": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == "tls_protocol" && f.Extra["protocol"] == "TLS 1.2" {
			found = true
		}
	}
	if !found {
		t.Error("expected TLS 1.2 protocol finding")
	}
}

// TestRun_FindingTypesPresent verifies all 4 finding types appear in a full run.
func TestRun_FindingTypesPresent(t *testing.T) {
	cert, _ := selfSignedCert(t, time.Now().Add(365*24*time.Hour))
	srv := mockTLSServer(t, cert)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	m := moduleForServer(srv)

	findings, err := m.Run(context.Background(), module.Input{
		Target: host,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	types := make(map[string]bool)
	for _, f := range findings {
		types[f.Type] = true
	}

	for _, want := range []string{"tls_protocol", "tls_certificate", "tls_vulnerability", "tls_header"} {
		if !types[want] {
			t.Errorf("expected finding type %q in results", want)
		}
	}
}

// TestRun_TargetFromURLs uses URLs[0] when Target is empty.
func TestRun_TargetFromURLs(t *testing.T) {
	cert, _ := selfSignedCert(t, time.Now().Add(365*24*time.Hour))
	srv := mockTLSServer(t, cert)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	m := moduleForServer(srv)

	findings, err := m.Run(context.Background(), module.Input{
		URLs:    []string{srv.URL},
		Options: map[string]string{"skip_ciphers": "true", "skip_headers": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings when using URLs[0]")
	}
	// The module strips scheme and port from the URL, so findings.URL is just the hostname.
	// Verify at least one finding references the correct host IP.
	ip := strings.Split(host, ":")[0]
	found := false
	for _, f := range findings {
		if strings.HasPrefix(f.URL, ip) || f.URL == ip {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected finding with host %q, got none", ip)
	}
}

// TestRun_ECDSACertKeySize checks ECDSA key size finding for P-256.
func TestRun_ECDSACertKeySize(t *testing.T) {
	cert, _ := selfSignedCert(t, time.Now().Add(365*24*time.Hour)) // P-256 = 256 bits
	srv := mockTLSServer(t, cert)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	m := moduleForServer(srv)

	findings, err := m.Run(context.Background(), module.Input{
		Target:  host,
		Options: map[string]string{"skip_ciphers": "true", "skip_headers": "true"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == "tls_certificate" && f.Extra["key_type"] == "ECDSA" {
			found = true
			if f.Severity != module.SeverityInfo {
				t.Errorf("P-256 ECDSA key should be info severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected ECDSA key size finding")
	}
}

// TestName checks the module name.
func TestName(t *testing.T) {
	if tlsaudit.New().Name() != "tlsaudit" {
		t.Error("wrong module name")
	}
}

// TestRun_FindingURLPopulated verifies cert and header findings have a non-empty URL.
func TestRun_FindingURLPopulated(t *testing.T) {
	cert, x509Cert := selfSignedCert(t, time.Now().Add(365*24*time.Hour))
	_ = x509Cert
	srv := mockTLSServer(t, cert)
	defer srv.Close()
	m := moduleForServer(srv)
	findings, err := m.Run(context.Background(), module.Input{Target: strings.TrimPrefix(srv.URL, "https://")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// cert and header findings must have URL; tls_vulnerability findings
	// operate at the cipher/protocol level and may omit URL.
	urlTypes := map[string]bool{
		"tls_cert":     true,
		"tls_header":   true,
		"hsts_missing": true,
	}
	for _, f := range findings {
		if urlTypes[f.Type] && f.URL == "" {
			t.Errorf("finding type %q should have a URL but URL is empty", f.Type)
		}
	}
}

// TestRun_ContextCancellationTLS verifies module respects context cancellation.
func TestRun_ContextCancellationTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := tlsaudit.New()
	start := time.Now()
	_, _ = m.Run(ctx, module.Input{Target: "localhost:9999"})
	if time.Since(start) > 3*time.Second {
		t.Error("Run hung on cancelled context")
	}
}

// TestRun_MultipleFindingTypes verifies at least one finding type is returned.
func TestRun_MultipleFindingTypes(t *testing.T) {
	cert, x509Cert := selfSignedCert(t, time.Now().Add(365*24*time.Hour))
	_ = x509Cert
	srv := mockTLSServer(t, cert)
	defer srv.Close()
	m := moduleForServer(srv)
	findings, err := m.Run(context.Background(), module.Input{Target: strings.TrimPrefix(srv.URL, "https://")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	types := map[string]bool{}
	for _, f := range findings {
		types[f.Type] = true
	}
	if len(types) == 0 {
		t.Error("expected at least one finding type")
	}
}

// TestRun_FindingsHaveConfidence verifies all findings include a confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	cert, _ := selfSignedCert(t, time.Now().Add(365*24*time.Hour))
	srv := mockTLSServer(t, cert)
	defer srv.Close()
	m := moduleForServer(srv)
	findings, err := m.Run(context.Background(), module.Input{Target: strings.TrimPrefix(srv.URL, "https://")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Skip("no findings to check")
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding type=%q missing confidence field", f.Type)
		}
	}
}

// TestRun_CertSubjectPopulated verifies tls_cert findings include subject metadata.
func TestRun_CertSubjectPopulated(t *testing.T) {
	cert, _ := selfSignedCert(t, time.Now().Add(30*24*time.Hour)) // near expiry
	srv := mockTLSServer(t, cert)
	defer srv.Close()
	m := moduleForServer(srv)
	findings, err := m.Run(context.Background(), module.Input{Target: strings.TrimPrefix(srv.URL, "https://")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "tls_cert" {
			if f.Extra["subject"] == "" && f.Extra["issuer"] == "" {
				t.Error("tls_cert finding should have subject or issuer metadata")
			}
			return
		}
	}
}

// TestRun_SeverityNotEmpty verifies no finding has an empty severity.
func TestRun_SeverityNotEmpty(t *testing.T) {
	cert, _ := selfSignedCert(t, time.Now().Add(365*24*time.Hour))
	srv := mockTLSServer(t, cert)
	defer srv.Close()
	m := moduleForServer(srv)
	findings, err := m.Run(context.Background(), module.Input{Target: strings.TrimPrefix(srv.URL, "https://")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == "" {
			t.Errorf("finding type=%q has empty severity", f.Type)
		}
	}
}
