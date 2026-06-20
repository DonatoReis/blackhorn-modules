package osintbr_test

import (
	"context"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/osintbr"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── stub runner ─────────────────────────────────────────────────────────────

type stubRunner struct {
	name     string
	findings []module.Finding
	err      error
}

func (s *stubRunner) Name() string { return s.name }
func (s *stubRunner) Run(_ context.Context, _ module.Input) ([]module.Finding, error) {
	return s.findings, s.err
}

func stubFinding(typ, detail string, sev module.Severity) module.Finding {
	return module.Finding{
		Type:     typ,
		URL:      "",
		Detail:   detail,
		Severity: sev,
		Extra:    map[string]string{"confidence": "0.90"},
	}
}

// ─── detectTargetType (via Run behavior) ─────────────────────────────────────

func TestDetectCPF(t *testing.T) {
	runners := map[string]osintbr.Runner{
		"cpflookup": &stubRunner{name: "cpflookup", findings: []module.Finding{
			stubFinding("cpf_data", "CPF encontrado", module.SeverityInfo),
		}},
	}
	m := osintbr.NewWithRunners(runners)

	ff, err := m.Run(context.Background(), module.Input{
		Target:  "123.456.789-09",
		Options: map[string]string{"lgpd_consent": "true"},
	})

	if err != nil {
		t.Fatalf("esperava nil err, obteve: %v", err)
	}
	if len(ff) == 0 {
		t.Fatal("esperava ao menos 1 finding (summary)")
	}

	// Primeiro finding deve ser summary
	if ff[0].Type != "osintbr_summary" {
		t.Errorf("primeiro finding deveria ser osintbr_summary, obteve: %s", ff[0].Type)
	}

	// Extra deve ter target_type = cpf
	if ff[0].Extra["target_type"] != "cpf" {
		t.Errorf("expected target_type=cpf, got: %s", ff[0].Extra["target_type"])
	}
}

func TestDetectCNPJ(t *testing.T) {
	runners := map[string]osintbr.Runner{
		"registroempresas": &stubRunner{name: "registroempresas", findings: []module.Finding{
			stubFinding("cnpj_data", "Empresa encontrada", module.SeverityLow),
		}},
	}
	m := osintbr.NewWithRunners(runners)

	ff, err := m.Run(context.Background(), module.Input{
		Target:  "11.222.333/0001-81",
		Options: map[string]string{},
	})

	if err != nil {
		t.Fatalf("esperava nil err: %v", err)
	}
	if len(ff) == 0 {
		t.Fatal("esperava findings")
	}
	if ff[0].Extra["target_type"] != "cnpj" {
		t.Errorf("expected target_type=cnpj, got: %s", ff[0].Extra["target_type"])
	}
}

func TestDetectCEP(t *testing.T) {
	runners := map[string]osintbr.Runner{
		"addresssearch": &stubRunner{name: "addresssearch", findings: []module.Finding{
			stubFinding("address", "Endereço encontrado", module.SeverityInfo),
		}},
	}
	m := osintbr.NewWithRunners(runners)

	ff, err := m.Run(context.Background(), module.Input{
		Target:  "01310-100",
		Options: map[string]string{},
	})

	if err != nil {
		t.Fatalf("esperava nil err: %v", err)
	}
	if ff[0].Extra["target_type"] != "cep" {
		t.Errorf("expected target_type=cep, got: %s", ff[0].Extra["target_type"])
	}
}

func TestDetectTelefone(t *testing.T) {
	runners := map[string]osintbr.Runner{
		"anatel": &stubRunner{name: "anatel", findings: []module.Finding{
			stubFinding("phone_data", "DDD: 11, operadora: Vivo", module.SeverityInfo),
		}},
	}
	m := osintbr.NewWithRunners(runners)

	ff, err := m.Run(context.Background(), module.Input{
		Target:  "(11) 98765-4321",
		Options: map[string]string{},
	})

	if err != nil {
		t.Fatalf("esperava nil err: %v", err)
	}
	if ff[0].Extra["target_type"] != "telefone" {
		t.Errorf("expected target_type=telefone, got: %s", ff[0].Extra["target_type"])
	}
}

func TestDetectNome(t *testing.T) {
	runners := map[string]osintbr.Runner{
		"namesearch": &stubRunner{name: "namesearch", findings: []module.Finding{
			stubFinding("name_data", "Nome localizado em IBGE", module.SeverityInfo),
		}},
	}
	m := osintbr.NewWithRunners(runners)

	ff, err := m.Run(context.Background(), module.Input{
		Target:  "João da Silva",
		Options: map[string]string{},
	})

	if err != nil {
		t.Fatalf("esperava nil err: %v", err)
	}
	if ff[0].Extra["target_type"] != "nome" {
		t.Errorf("expected target_type=nome, got: %s", ff[0].Extra["target_type"])
	}
}

// ─── LGPD gate ────────────────────────────────────────────────────────────────

func TestCPFSemLGPD(t *testing.T) {
	m := osintbr.New()

	_, err := m.Run(context.Background(), module.Input{
		Target:  "12345678909",
		Options: map[string]string{}, // sem lgpd_consent
	})

	if err == nil {
		t.Fatal("esperava erro de LGPD")
	}
}

func TestCPFComLGPD(t *testing.T) {
	runners := map[string]osintbr.Runner{
		"cpflookup": &stubRunner{name: "cpflookup", findings: nil},
	}
	m := osintbr.NewWithRunners(runners)

	_, err := m.Run(context.Background(), module.Input{
		Target:  "12345678909",
		Options: map[string]string{"lgpd_consent": "true"},
	})

	if err != nil {
		t.Fatalf("esperava nil err com LGPD, obteve: %v", err)
	}
}

// ─── empty target ─────────────────────────────────────────────────────────────

func TestEmptyTarget(t *testing.T) {
	m := osintbr.New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Fatal("esperava erro para target vazio")
	}
}

// ─── Seleção de módulos ───────────────────────────────────────────────────────

func TestModulesFilter(t *testing.T) {
	calledAnatel := false
	calledWhatsapp := false

	runners := map[string]osintbr.Runner{
		"anatel": &stubRunnerFn{
			name: "anatel",
			fn: func() {
				calledAnatel = true
			},
		},
		"whatsapp": &stubRunnerFn{
			name: "whatsapp",
			fn: func() {
				calledWhatsapp = true
			},
		},
	}
	m := osintbr.NewWithRunners(runners)

	// Apenas anatel habilitado
	_, err := m.Run(context.Background(), module.Input{
		Target:  "(11) 98765-4321",
		Options: map[string]string{"modules": "anatel"},
	})
	if err != nil {
		t.Fatalf("err inesperado: %v", err)
	}

	if !calledAnatel {
		t.Error("anatel deveria ter sido chamado")
	}
	if calledWhatsapp {
		t.Error("whatsapp não deveria ter sido chamado (filtrado)")
	}
}

// stubRunnerFn permite inspecionar se o Run foi chamado
type stubRunnerFn struct {
	name string
	fn   func()
}

func (s *stubRunnerFn) Name() string { return s.name }
func (s *stubRunnerFn) Run(_ context.Context, _ module.Input) ([]module.Finding, error) {
	if s.fn != nil {
		s.fn()
	}
	return nil, nil
}

// ─── Dedup ────────────────────────────────────────────────────────────────────

func TestDedup(t *testing.T) {
	dupFinding := stubFinding("duplicate", "mesmo detail", module.SeverityInfo)

	runners := map[string]osintbr.Runner{
		"registroempresas": &stubRunner{name: "registroempresas", findings: []module.Finding{dupFinding}},
		"govbr":            &stubRunner{name: "govbr", findings: []module.Finding{dupFinding}},
		"tribunais":        &stubRunner{name: "tribunais", findings: []module.Finding{dupFinding}},
	}
	m := osintbr.NewWithRunners(runners)

	ff, err := m.Run(context.Background(), module.Input{
		Target:  "11222333000181",
		Options: map[string]string{},
	})
	if err != nil {
		t.Fatalf("err inesperado: %v", err)
	}

	// Deve ter: 1 summary + 1 finding deduplicado (não 3)
	if len(ff) != 2 {
		t.Errorf("esperava 2 findings (summary+1), obteve %d", len(ff))
	}
}

// ─── Summary finding ─────────────────────────────────────────────────────────

func TestSummaryFinding(t *testing.T) {
	runners := map[string]osintbr.Runner{
		"registroempresas": &stubRunner{name: "registroempresas", findings: []module.Finding{
			stubFinding("cnpj_info", "CNPJ ativo", module.SeverityHigh),
		}},
	}
	m := osintbr.NewWithRunners(runners)

	ff, err := m.Run(context.Background(), module.Input{
		Target:  "11222333000181",
		Options: map[string]string{},
	})
	if err != nil {
		t.Fatalf("err inesperado: %v", err)
	}

	summary := ff[0]
	if summary.Type != "osintbr_summary" {
		t.Errorf("esperava osintbr_summary, obteve: %s", summary.Type)
	}
	if summary.Severity != module.SeverityHigh {
		t.Errorf("severity do summary deveria refletir o maior severity dos filhos: %v", summary.Severity)
	}
	if summary.Extra["confidence"] != "1.00" {
		t.Errorf("confidence esperada 1.00, obteve: %s", summary.Extra["confidence"])
	}
	if summary.Extra["fonte"] != "osintbr" {
		t.Errorf("fonte esperada osintbr, obteve: %s", summary.Extra["fonte"])
	}
}

// ─── Sem sub-módulos ─────────────────────────────────────────────────────────

func TestNoRunners(t *testing.T) {
	m := osintbr.New() // sem runners

	ff, err := m.Run(context.Background(), module.Input{
		Target:  "11.222.333/0001-81",
		Options: map[string]string{},
	})
	if err != nil {
		t.Fatalf("err inesperado: %v", err)
	}
	// Sem runners, sem findings (e sem summary)
	if len(ff) != 0 {
		t.Errorf("esperava 0 findings sem runners, obteve: %d", len(ff))
	}
}

// ─── Sub-módulo falha ─────────────────────────────────────────────────────────

func TestRunnerError(t *testing.T) {
	runners := map[string]osintbr.Runner{
		"registroempresas": &stubRunner{
			name:     "registroempresas",
			findings: nil,
			err:      errSimulado,
		},
	}
	m := osintbr.NewWithRunners(runners)

	// Erro de sub-módulo não deve propagar — é apenas logado
	ff, err := m.Run(context.Background(), module.Input{
		Target:  "11222333000181",
		Options: map[string]string{},
	})
	if err != nil {
		t.Fatalf("erro de sub-módulo não deveria propagar, obteve: %v", err)
	}
	// Sem findings válidos, sem summary
	if len(ff) != 0 {
		t.Errorf("esperava 0 findings, obteve: %d", len(ff))
	}
}

var errSimulado = &testError{msg: "falha simulada de sub-módulo"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

// ─── Name() ──────────────────────────────────────────────────────────────────

func TestModuleName(t *testing.T) {
	m := osintbr.New()
	if m.Name() != "osintbr" {
		t.Errorf("Name() esperado 'osintbr', obteve '%s'", m.Name())
	}
}

// ─── Módulos all (default) ────────────────────────────────────────────────────

func TestModulesAll(t *testing.T) {
	calledAnatel := false
	calledWhatsapp := false

	runners := map[string]osintbr.Runner{
		"anatel": &stubRunnerFn{
			name: "anatel",
			fn:   func() { calledAnatel = true },
		},
		"whatsapp": &stubRunnerFn{
			name: "whatsapp",
			fn:   func() { calledWhatsapp = true },
		},
	}
	m := osintbr.NewWithRunners(runners)

	_, err := m.Run(context.Background(), module.Input{
		Target:  "(11) 98765-4321",
		Options: map[string]string{"modules": "all"}, // explicitamente all
	})
	if err != nil {
		t.Fatalf("err inesperado: %v", err)
	}

	if !calledAnatel || !calledWhatsapp {
		t.Errorf("ambos deveriam ter sido chamados com modules=all (anatel=%v, whatsapp=%v)",
			calledAnatel, calledWhatsapp)
	}
}

// ─── osintbr_source tag ───────────────────────────────────────────────────────

func TestOsintbrSourceTag(t *testing.T) {
	runners := map[string]osintbr.Runner{
		"registroempresas": &stubRunner{name: "registroempresas", findings: []module.Finding{
			stubFinding("cnpj_info", "empresa X", module.SeverityInfo),
		}},
	}
	m := osintbr.NewWithRunners(runners)

	ff, _ := m.Run(context.Background(), module.Input{
		Target:  "11222333000181",
		Options: map[string]string{},
	})

	// ff[0] = summary; ff[1] = o finding com source tag
	if len(ff) < 2 {
		t.Fatalf("esperava pelo menos 2 findings")
	}
	if ff[1].Extra["osintbr_source"] != "registroempresas" {
		t.Errorf("esperava osintbr_source=registroempresas, obteve: %s",
			ff[1].Extra["osintbr_source"])
	}
}

// ─── CEP sem hífen ────────────────────────────────────────────────────────────

func TestCEPSemHifen(t *testing.T) {
	runners := map[string]osintbr.Runner{
		"addresssearch": &stubRunner{name: "addresssearch", findings: []module.Finding{
			stubFinding("address", "CEP: 01310100", module.SeverityInfo),
		}},
	}
	m := osintbr.NewWithRunners(runners)

	ff, err := m.Run(context.Background(), module.Input{
		Target:  "01310100",
		Options: map[string]string{},
	})
	if err != nil {
		t.Fatalf("err inesperado: %v", err)
	}
	if ff[0].Extra["target_type"] != "cep" {
		t.Errorf("target_type esperado cep, obteve: %s", ff[0].Extra["target_type"])
	}
}

// ─── Telefone com DDI +55 ─────────────────────────────────────────────────────

func TestTelefoneComDDI(t *testing.T) {
	runners := map[string]osintbr.Runner{
		"anatel": &stubRunner{name: "anatel", findings: []module.Finding{
			stubFinding("phone_data", "DDD: 11", module.SeverityInfo),
		}},
	}
	m := osintbr.NewWithRunners(runners)

	ff, err := m.Run(context.Background(), module.Input{
		Target:  "+55 11 98765-4321",
		Options: map[string]string{},
	})
	if err != nil {
		t.Fatalf("err inesperado: %v", err)
	}
	if ff[0].Extra["target_type"] != "telefone" {
		t.Errorf("target_type esperado telefone, obteve: %s", ff[0].Extra["target_type"])
	}
}

// ─── CNPJ formatado ──────────────────────────────────────────────────────────

func TestCNPJFormatado(t *testing.T) {
	runners := map[string]osintbr.Runner{
		"registroempresas": &stubRunner{name: "registroempresas", findings: nil},
	}
	m := osintbr.NewWithRunners(runners)

	_, err := m.Run(context.Background(), module.Input{
		Target:  "11.222.333/0001-81",
		Options: map[string]string{},
	})
	if err != nil {
		t.Fatalf("CNPJ formatado deveria ser aceito: %v", err)
	}
}

// ─── Contexto cancelado ───────────────────────────────────────────────────────

func TestContextCancelado(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // já cancelado

	runners := map[string]osintbr.Runner{
		"registroempresas": &stubRunner{name: "registroempresas", findings: nil},
	}
	m := osintbr.NewWithRunners(runners)

	// Não deve panicar; pode retornar vazio ou erro não-fatal
	_, err := m.Run(ctx, module.Input{
		Target:  "11222333000181",
		Options: map[string]string{},
	})
	_ = err // comportamento tolerante esperado
}
