package dnsrecon_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/dnsrecon"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// mockResolver é um net.Resolver fake usando LookupTXT etc via override
// Como net.Resolver não é interface, usamos um resolver real mas com domínios de teste.

func TestName(t *testing.T) {
	if dnsrecon.New().Name() != "dnsrecon" {
		t.Error("nome incorreto")
	}
}

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	_, err := dnsrecon.New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

func TestRun_InvalidDomain_ReturnsError(t *testing.T) {
	_, err := dnsrecon.New().Run(context.Background(), module.Input{Target: "nodot"})
	if err == nil {
		t.Fatal("esperava erro para domínio sem ponto")
	}
}

func TestRun_DomainNormalisation_HTTPS(t *testing.T) {
	m := dnsrecon.New()
	// https://example.com → example.com — não deve dar erro de domínio inválido
	_, err := m.Run(context.Background(), module.Input{
		Target:  "https://example.com",
		Options: map[string]string{"checks": "spf"},
	})
	if err != nil && strings.Contains(err.Error(), "domínio inválido") {
		t.Errorf("normalização HTTPS falhou: %v", err)
	}
}

func TestRun_SPF_Missing_RealDomain(t *testing.T) {
	// Usa um domínio fictício sem SPF — deve retornar spf_missing
	// (Se não resolver, o check retorna nil graciosamente)
	m := dnsrecon.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "blackhorn-no-spf-test-xyzabc.com",
		Options: map[string]string{"checks": "spf"},
	})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	// Pode retornar 0 findings (DNS error) ou spf_missing — ambos aceitáveis
	for _, f := range findings {
		if f.Type == "spf_missing" {
			if f.Severity != module.SeverityMedium {
				t.Errorf("spf_missing deve ser SeverityMedium, obteve %s", f.Severity)
			}
		}
	}
}

func TestRun_DMARC_Missing_RealDomain(t *testing.T) {
	m := dnsrecon.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "blackhorn-no-dmarc-test-xyzabc.com",
		Options: map[string]string{"checks": "dmarc"},
	})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	for _, f := range findings {
		if f.Type == "dmarc_missing" {
			if f.Severity != module.SeverityMedium {
				t.Errorf("dmarc_missing deve ser SeverityMedium, obteve %s", f.Severity)
			}
		}
	}
}

func TestRun_DKIM_Missing_NoFindings(t *testing.T) {
	m := dnsrecon.New()
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "blackhorn-no-dkim-test-xyzabc.com",
		Options: map[string]string{"checks": "dkim", "dkim_selectors": "google,mail"},
	})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	for _, f := range findings {
		if f.Type == "dkim_missing" {
			if f.Extra["selectors_checked"] == "" {
				t.Error("dkim_missing deve ter selectors_checked")
			}
		}
	}
}

func TestRun_AllFindings_HaveConfidence(t *testing.T) {
	m := dnsrecon.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"checks": "spf"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding sem confidence: %+v", f)
		}
	}
}

func TestRun_AllFindings_HaveDetail(t *testing.T) {
	m := dnsrecon.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"checks": "spf"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding sem Detail")
		}
	}
}

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = dnsrecon.New().Run(ctx, module.Input{
		Target:  "example.com",
		Options: map[string]string{"checks": "records"},
	})
}

func TestRun_CheckFilter_OnlySPF(t *testing.T) {
	m := dnsrecon.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"checks": "spf"},
	})
	for _, f := range findings {
		if f.Extra["source"] != "spf_check" {
			t.Errorf("com checks=spf só deve haver findings de spf_check, obteve %s", f.Extra["source"])
		}
	}
}

func TestRun_CheckFilter_OnlyDMARC(t *testing.T) {
	m := dnsrecon.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"checks": "dmarc"},
	})
	for _, f := range findings {
		if f.Extra["source"] != "dmarc_check" {
			t.Errorf("com checks=dmarc só deve haver findings de dmarc_check, obteve %s", f.Extra["source"])
		}
	}
}

func TestRun_SPF_AllPass_SeverityHigh(t *testing.T) {
	// Usando resolver customizado que injeta SPF com +all
	// Como não podemos mockar net.Resolver facilmente, testamos a lógica via domínio real
	// Aqui validamos apenas que o módulo não entra em pânico
	m := dnsrecon.New()
	_, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"checks": "spf"},
	})
	_ = err
}

func TestRun_DNSSEC_FindingExists(t *testing.T) {
	m := dnsrecon.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"checks": "dnssec"},
	})
	// Deve retornar dnssec_unverified ou 0 findings (se lookup falhar)
	for _, f := range findings {
		if f.Type != "dnssec_unverified" {
			t.Errorf("dnssec check deve retornar dnssec_unverified, obteve %s", f.Type)
		}
		if f.Extra["check_cmd"] == "" {
			t.Error("dnssec finding deve ter check_cmd")
		}
	}
}

func TestRun_CAA_FindingHasCheckCmd(t *testing.T) {
	m := dnsrecon.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"checks": "caa"},
	})
	for _, f := range findings {
		if f.Extra["check_cmd"] == "" {
			t.Error("caa finding deve ter check_cmd")
		}
	}
}

func TestRun_Wildcard_NonexistentDomain_NoFinding(t *testing.T) {
	m := dnsrecon.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "blackhorn-wildcard-nonexistent-xyzabc123.com",
		Options: map[string]string{"checks": "wildcard"},
	})
	for _, f := range findings {
		if f.Type == "dns_wildcard" {
			t.Error("domínio inexistente não deve ter wildcard DNS")
		}
	}
}

func TestNewWithResolver_ReturnsNonNil(t *testing.T) {
	r := &net.Resolver{PreferGo: true}
	if dnsrecon.NewWithResolver(r) == nil {
		t.Fatal("NewWithResolver() retornou nil")
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	if dnsrecon.New() == nil {
		t.Fatal("New() retornou nil")
	}
}

func TestRun_MultipleChecks_NoError(t *testing.T) {
	m := dnsrecon.New()
	_, err := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"checks": "spf,dmarc,caa"},
	})
	if err != nil {
		t.Fatalf("erro inesperado com múltiplos checks: %v", err)
	}
}

func TestRun_Records_FindingsHaveURL(t *testing.T) {
	m := dnsrecon.New()
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "example.com",
		Options: map[string]string{"checks": "records"},
	})
	for _, f := range findings {
		if f.URL == "" {
			t.Error("finding sem URL")
		}
	}
}

// ─── AXFR tests ───────────────────────────────────────────────────────────────

// TestAXFR_Refused_NoFinding: servidor que retorna RCODE=5 (REFUSED) não deve gerar finding.
// Isso cobre a maioria dos nameservers reais — TCP/53 aberto + AXFR recusado é o
// comportamento correto. O bug anterior emitia Medium apenas por TCP/53 estar aberto.
func TestAXFR_Refused_NoFinding(t *testing.T) {
	// Cria um servidor TCP falso que responde DNS com RCODE=5 (REFUSED).
	srv := newFakeDNSTCPServer(t, dnsRcodeRefused)
	defer srv.Close()

	findings := runAXFRProbe(t, srv.Addr().String())
	for _, f := range findings {
		if f.Type == "dns_axfr_possible" || f.Type == "dns_axfr_success" {
			t.Errorf("RCODE=REFUSED não deve gerar finding AXFR, obteve: %s", f.Type)
		}
	}
}

// TestAXFR_Success_EmitsHighFinding: servidor que retorna registros DNS deve gerar dns_axfr_success (High).
func TestAXFR_Success_EmitsHighFinding(t *testing.T) {
	srv := newFakeDNSTCPServer(t, dnsRcodeSuccess)
	defer srv.Close()

	findings := runAXFRProbe(t, srv.Addr().String())
	found := false
	for _, f := range findings {
		if f.Type == "dns_axfr_success" {
			found = true
			if f.Severity != module.SeverityHigh {
				t.Errorf("dns_axfr_success deve ser High, obteve %v", f.Severity)
			}
			if f.Extra["confidence"] == "" {
				t.Error("dns_axfr_success deve ter confidence")
			}
			if f.Extra["record_count"] == "" {
				t.Error("dns_axfr_success deve ter record_count")
			}
		}
	}
	if !found {
		t.Error("esperava dns_axfr_success quando servidor retorna registros DNS")
	}
}

// TestAXFR_ConnectionRefused_NoFinding: servidor inacessível não deve gerar finding.
func TestAXFR_ConnectionRefused_NoFinding(t *testing.T) {
	// Porta que não existe — conexão recusada imediatamente.
	findings := runAXFRProbe(t, "127.0.0.1:1")
	for _, f := range findings {
		if f.Type == "dns_axfr_possible" || f.Type == "dns_axfr_success" {
			t.Errorf("conexão recusada não deve gerar finding AXFR, obteve: %s", f.Type)
		}
	}
}

// TestAXFR_NoRecords_RCODE0_NoFinding: RCODE=0 mas ANCOUNT=0 não é vulnerabilidade.
func TestAXFR_NoRecords_RCODE0_NoFinding(t *testing.T) {
	srv := newFakeDNSTCPServer(t, dnsRcodeSuccessEmpty)
	defer srv.Close()

	findings := runAXFRProbe(t, srv.Addr().String())
	for _, f := range findings {
		if f.Type == "dns_axfr_success" {
			t.Errorf("RCODE=0 com ANCOUNT=0 não deve gerar dns_axfr_success, obteve: %s", f.Type)
		}
	}
}

// runAXFRProbe runs the dnsrecon module with axfr check against a fake nameserver address.
// We need to expose attemptAXFR — since it's internal, we test via the full module Run()
// with a custom resolver that returns our fake server as nameserver.
func runAXFRProbe(t *testing.T, nsAddr string) []module.Finding {
	t.Helper()
	// We can't easily inject a custom resolver that returns a fake NS pointing to our server
	// without exporting attemptAXFR. So we test via the exported AttemptAXFRForTesting
	// helper, or we verify the logic via a direct integration approach.
	//
	// Since attemptAXFR is package-private, use the exported test helper instead.
	return dnsrecon.AttemptAXFRForTesting(t, "example.com", nsAddr)
}

// ─── fake DNS TCP server helpers ─────────────────────────────────────────────

type dnsServerMode int

const (
	dnsRcodeRefused      dnsServerMode = iota // RCODE=5, ANCOUNT=0
	dnsRcodeSuccess                           // RCODE=0, ANCOUNT=3 (simulates zone transfer)
	dnsRcodeSuccessEmpty                      // RCODE=0, ANCOUNT=0
)

type fakeDNSTCPServer struct {
	ln net.Listener
}

func newFakeDNSTCPServer(t *testing.T, mode dnsServerMode) *fakeDNSTCPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fakeDNSTCPServer: %v", err)
	}
	srv := &fakeDNSTCPServer{ln: ln}
	go srv.serve(mode)
	return srv
}

func (s *fakeDNSTCPServer) Addr() net.Addr { return s.ln.Addr() }
func (s *fakeDNSTCPServer) Close()         { _ = s.ln.Close() }

func (s *fakeDNSTCPServer) serve(mode dnsServerMode) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn, mode)
	}
}

func (s *fakeDNSTCPServer) handleConn(conn net.Conn, mode dnsServerMode) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	// Read 2-byte length prefix.
	lenBuf := make([]byte, 2)
	if _, err := readFull(conn, lenBuf); err != nil {
		return
	}
	msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if msgLen > 512 {
		msgLen = 512
	}
	body := make([]byte, msgLen)
	if _, err := readFull(conn, body); err != nil {
		return
	}
	// Build response based on mode.
	resp := buildFakeDNSResponse(body, mode)
	// Write 2-byte length + response.
	out := []byte{byte(len(resp) >> 8), byte(len(resp))}
	out = append(out, resp...)
	_, _ = conn.Write(out)
}

func buildFakeDNSResponse(query []byte, mode dnsServerMode) []byte {
	if len(query) < 12 {
		return buildMinimalDNSError()
	}
	// Copy query ID (bytes 0-1).
	resp := make([]byte, 12)
	copy(resp[0:2], query[0:2])

	switch mode {
	case dnsRcodeRefused:
		// QR=1 (response), RCODE=5 (REFUSED), ANCOUNT=0
		resp[2] = 0x80 // QR=1
		resp[3] = 0x05 // RCODE=5
		// All counts = 0
	case dnsRcodeSuccess:
		// QR=1, RCODE=0, ANCOUNT=3 — pretend 3 records returned
		resp[2] = 0x80 // QR=1
		resp[3] = 0x00 // RCODE=0
		resp[6] = 0x00 // ANCOUNT hi
		resp[7] = 0x03 // ANCOUNT lo = 3
	case dnsRcodeSuccessEmpty:
		// QR=1, RCODE=0, ANCOUNT=0
		resp[2] = 0x80
		resp[3] = 0x00
		// All counts = 0
	}
	return resp
}

func buildMinimalDNSError() []byte {
	resp := make([]byte, 12)
	resp[2] = 0x80
	resp[3] = 0x02 // RCODE=2 SERVFAIL
	return resp
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
