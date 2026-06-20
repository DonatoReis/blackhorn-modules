// Package osintbr é o módulo integrador de OSINT brasileiro.
//
// Centraliza chamadas aos módulos especializados brasileiros:
//   - cpflookup    — CPF → dados cadastrais
//   - registroempresas — CNPJ → sócios, Simples, MEI
//   - anatel       — telefone BR → DDD, operadora
//   - addresssearch — CEP/logradouro → endereço
//   - govbr        — feriados, câmbio, bancos, Transparência
//   - namesearch   — pessoa por nome → IBGE, Transparência, OpenSanctions
//   - tribunais    — processos judiciais (DataJud)
//
// Auto-detecção do tipo de target:
//   - CPF (11 dígitos)   → cpflookup + namesearch
//   - CNPJ (14 dígitos)  → registroempresas + tribunais + govbr
//   - CEP (8 dígitos)    → addresssearch + govbr
//   - Telefone BR (DDD)  → anatel + whatsapp
//   - Nome               → namesearch + tribunais
//
// Input:
//   - Target: CPF, CNPJ, CEP, telefone ou nome
//   - Options[*]: mesmos da options dos módulos individuais
//   - Options["lgpd_consent"]   — "true" para CPF e dados pessoais
//   - Options["datajud_key"]    — para processos judiciais
//   - Options["modules"]        — módulos a usar (default: all)
//
// Privacidade / LGPD:
//
//	CPF requer lgpd_consent=true. Dados pessoais são mascarados nos findings.
package osintbr

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// TargetType classifica o tipo de target brasileiro.
type TargetType string

const (
	TargetCPF      TargetType = "cpf"
	TargetCNPJ     TargetType = "cnpj"
	TargetCEP      TargetType = "cep"
	TargetTelefone TargetType = "telefone"
	TargetNome     TargetType = "nome"
)

var (
	reCPF    = regexp.MustCompile(`^\d{11}$`)
	reCNPJ   = regexp.MustCompile(`^\d{14}$`)
	reCEP    = regexp.MustCompile(`^\d{5}-?\d{3}$`)
	reTel    = regexp.MustCompile(`^(\+?55)?0?\d{2,3}\d{8,9}$`)
	reDigits = regexp.MustCompile(`\D`)
)

// Runner é a interface mínima necessária para sub-módulos.
type Runner interface {
	Name() string
	Run(ctx context.Context, input module.Input) ([]module.Finding, error)
}

// Module implementa o módulo osintbr.
type Module struct {
	cpflookup        Runner
	registroempresas Runner
	anatel           Runner
	addresssearch    Runner
	govbr            Runner
	namesearch       Runner
	tribunais        Runner
	whatsapp         Runner
}

// New cria um módulo osintbr com todos os sub-módulos.
// Para uso real, os sub-módulos serão carregados dinamicamente via registry.
// Para testes, use NewWithRunners.
func New() *Module {
	return &Module{}
}

// NewWithRunners cria um módulo osintbr com sub-módulos injetados.
func NewWithRunners(runners map[string]Runner) *Module {
	m := &Module{}
	if r, ok := runners["cpflookup"]; ok {
		m.cpflookup = r
	}
	if r, ok := runners["registroempresas"]; ok {
		m.registroempresas = r
	}
	if r, ok := runners["anatel"]; ok {
		m.anatel = r
	}
	if r, ok := runners["addresssearch"]; ok {
		m.addresssearch = r
	}
	if r, ok := runners["govbr"]; ok {
		m.govbr = r
	}
	if r, ok := runners["namesearch"]; ok {
		m.namesearch = r
	}
	if r, ok := runners["tribunais"]; ok {
		m.tribunais = r
	}
	if r, ok := runners["whatsapp"]; ok {
		m.whatsapp = r
	}
	return m
}

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "osintbr" }

// Run executa o OSINT brasileiro integrado.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("osintbr: target não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	lgpdConsent := optStr(opts, "lgpd_consent", "") == "true"
	enabledModules := parseModules(optStr(opts, "modules", "all"))

	// Auto-detect tipo de target
	targetType, cleanTarget := detectTargetType(target)

	if (targetType == TargetCPF) && !lgpdConsent {
		return nil, fmt.Errorf("osintbr: consulta por CPF requer lgpd_consent=true")
	}

	slog.InfoContext(ctx, "osintbr: iniciando",
		"target_type", string(targetType),
		"clean_target", maskTarget(cleanTarget, targetType),
		"lgpd_consent", lgpdConsent,
	)

	var (
		mu       sync.Mutex
		findings []module.Finding
	)
	add := func(source string, ff []module.Finding) {
		// Child modules may reuse findings or Extra maps. Clone before adding
		// orchestration metadata so concurrent runners never mutate shared data.
		cloned := make([]module.Finding, len(ff))
		for i, finding := range ff {
			cloned[i] = finding
			cloned[i].Extra = make(map[string]string, len(finding.Extra)+1)
			for key, value := range finding.Extra {
				cloned[i].Extra[key] = value
			}
			cloned[i].Extra["osintbr_source"] = source
		}
		mu.Lock()
		findings = append(findings, cloned...)
		mu.Unlock()
	}

	eg, ctx2 := errgroup.WithContext(ctx)
	eg.SetLimit(5)

	switch targetType {
	case TargetCPF:
		if m.cpflookup != nil && moduleEnabled(enabledModules, "cpflookup") {
			eg.Go(func() error {
				ff, err := m.cpflookup.Run(ctx2, module.Input{
					Target:  cleanTarget,
					Options: opts,
				})
				if err != nil {
					slog.WarnContext(ctx2, "osintbr: cpflookup falhou", "err", err)
					return nil
				}
				add("cpflookup", ff)
				return nil
			})
		}
		if m.namesearch != nil && moduleEnabled(enabledModules, "namesearch") {
			// Tenta extrair nome do CPF via BrasilAPI (se disponível no resultado)
			eg.Go(func() error {
				ff, err := m.namesearch.Run(ctx2, module.Input{
					Target:  cleanTarget, // CPF como hint para namesearch
					Options: opts,
				})
				if err != nil {
					slog.WarnContext(ctx2, "osintbr: namesearch/cpf falhou", "err", err)
					return nil
				}
				add("namesearch", ff)
				return nil
			})
		}
		if m.tribunais != nil && moduleEnabled(enabledModules, "tribunais") {
			eg.Go(func() error {
				ff, err := m.tribunais.Run(ctx2, module.Input{
					Target:  cleanTarget,
					Options: opts,
				})
				if err != nil {
					slog.WarnContext(ctx2, "osintbr: tribunais/cpf falhou", "err", err)
					return nil
				}
				add("tribunais", ff)
				return nil
			})
		}

	case TargetCNPJ:
		if m.registroempresas != nil && moduleEnabled(enabledModules, "registroempresas") {
			eg.Go(func() error {
				ff, err := m.registroempresas.Run(ctx2, module.Input{
					Target:  cleanTarget,
					Options: opts,
				})
				if err != nil {
					slog.WarnContext(ctx2, "osintbr: registroempresas falhou", "err", err)
					return nil
				}
				add("registroempresas", ff)
				return nil
			})
		}
		if m.govbr != nil && moduleEnabled(enabledModules, "govbr") {
			eg.Go(func() error {
				ff, err := m.govbr.Run(ctx2, module.Input{
					Target:  cleanTarget,
					Options: opts,
				})
				if err != nil {
					slog.WarnContext(ctx2, "osintbr: govbr/cnpj falhou", "err", err)
					return nil
				}
				add("govbr", ff)
				return nil
			})
		}
		if m.tribunais != nil && moduleEnabled(enabledModules, "tribunais") {
			eg.Go(func() error {
				ff, err := m.tribunais.Run(ctx2, module.Input{
					Target:  cleanTarget,
					Options: opts,
				})
				if err != nil {
					slog.WarnContext(ctx2, "osintbr: tribunais/cnpj falhou", "err", err)
					return nil
				}
				add("tribunais", ff)
				return nil
			})
		}

	case TargetCEP:
		if m.addresssearch != nil && moduleEnabled(enabledModules, "addresssearch") {
			eg.Go(func() error {
				ff, err := m.addresssearch.Run(ctx2, module.Input{
					Target:  cleanTarget,
					Options: opts,
				})
				if err != nil {
					slog.WarnContext(ctx2, "osintbr: addresssearch falhou", "err", err)
					return nil
				}
				add("addresssearch", ff)
				return nil
			})
		}
		if m.govbr != nil && moduleEnabled(enabledModules, "govbr") {
			eg.Go(func() error {
				ff, err := m.govbr.Run(ctx2, module.Input{
					Target:  cleanTarget,
					Options: opts,
				})
				if err != nil {
					slog.WarnContext(ctx2, "osintbr: govbr/cep falhou", "err", err)
					return nil
				}
				add("govbr", ff)
				return nil
			})
		}

	case TargetTelefone:
		if m.anatel != nil && moduleEnabled(enabledModules, "anatel") {
			eg.Go(func() error {
				ff, err := m.anatel.Run(ctx2, module.Input{
					Target:  target, // número original (anatel faz próprio parse)
					Options: opts,
				})
				if err != nil {
					slog.WarnContext(ctx2, "osintbr: anatel falhou", "err", err)
					return nil
				}
				add("anatel", ff)
				return nil
			})
		}
		if m.whatsapp != nil && moduleEnabled(enabledModules, "whatsapp") {
			eg.Go(func() error {
				ff, err := m.whatsapp.Run(ctx2, module.Input{
					Target:  target,
					Options: opts,
				})
				if err != nil {
					slog.WarnContext(ctx2, "osintbr: whatsapp falhou", "err", err)
					return nil
				}
				add("whatsapp", ff)
				return nil
			})
		}

	case TargetNome:
		if m.namesearch != nil && moduleEnabled(enabledModules, "namesearch") {
			eg.Go(func() error {
				ff, err := m.namesearch.Run(ctx2, module.Input{
					Target:  target,
					Options: opts,
				})
				if err != nil {
					slog.WarnContext(ctx2, "osintbr: namesearch falhou", "err", err)
					return nil
				}
				add("namesearch", ff)
				return nil
			})
		}
		if m.tribunais != nil && moduleEnabled(enabledModules, "tribunais") {
			eg.Go(func() error {
				ff, err := m.tribunais.Run(ctx2, module.Input{
					Target:  target,
					Options: opts,
				})
				if err != nil {
					slog.WarnContext(ctx2, "osintbr: tribunais/nome falhou", "err", err)
					return nil
				}
				add("tribunais", ff)
				return nil
			})
		}
	}

	_ = eg.Wait()

	// Adiciona finding de sumário
	result := dedup(findings)

	if len(result) > 0 {
		summary := buildSummary(target, targetType, result)
		result = append([]module.Finding{summary}, result...)
	}

	slog.InfoContext(ctx, "osintbr: concluído",
		"target_type", string(targetType),
		"total_findings", len(result),
	)

	return result, nil
}

// ─── detectTargetType ────────────────────────────────────────────────────────

// rePhoneFormat detecta formatos explícitos de telefone: (11) ..., +55..., 0800...
var rePhoneFormat = regexp.MustCompile(`^\s*(\+55|0800|\(\d{2}\)|\d{2}\s)`)

func detectTargetType(target string) (TargetType, string) {
	digits := reDigits.ReplaceAllString(target, "")

	// Telefone: verificar ANTES de CPF/CNPJ.
	// Formatos explícitos têm parênteses, +55 ou 0800 — nunca confundem com CPF/CNPJ.
	if rePhoneFormat.MatchString(target) && isBrazilianPhone(target) {
		return TargetTelefone, digits
	}

	// CEP: 8 dígitos (com ou sem hífen) — padrão NNNNN-NNN
	if reCEP.MatchString(target) {
		return TargetCEP, digits
	}

	// CPF: exatamente 11 dígitos numéricos
	if len(digits) == 11 && reCPF.MatchString(digits) {
		// Pode ainda ser telefone sem formatação (ex: "11987654321") — DDD válido decide
		if hasExplicitPhoneFormatting(target) {
			return TargetTelefone, digits
		}
		return TargetCPF, digits
	}

	// CNPJ: 14 dígitos
	if len(digits) == 14 && reCNPJ.MatchString(digits) {
		return TargetCNPJ, digits
	}

	// Telefone sem formatação mas com 0800
	if isBrazilianPhone(target) {
		return TargetTelefone, digits
	}

	return TargetNome, target
}

// hasExplicitPhoneFormatting verifica se o target usa formatação típica de telefone.
func hasExplicitPhoneFormatting(target string) bool {
	return strings.Contains(target, "(") ||
		strings.Contains(target, "+") ||
		strings.HasPrefix(strings.TrimSpace(target), "0800")
}

func isBrazilianPhone(target string) bool {
	// Remove caracteres de formatação
	digits := reDigits.ReplaceAllString(target, "")

	// 0800 gratuito
	if strings.HasPrefix(digits, "0800") {
		return true
	}

	// Com DDI +55 ou 55: 12-13 dígitos
	if (strings.HasPrefix(digits, "55") || strings.HasPrefix(target, "+55")) &&
		(len(digits) == 12 || len(digits) == 13) {
		return true
	}

	// Sem DDI: 10-11 dígitos (DDD + número)
	if len(digits) >= 10 && len(digits) <= 11 {
		ddd := digits[:2]
		// Verifica DDD válido (11-99)
		if len(ddd) == 2 && ddd[0] >= '1' && ddd[0] <= '9' {
			return true
		}
	}

	return false
}

// ─── maskTarget ──────────────────────────────────────────────────────────────

func maskTarget(target string, targetType TargetType) string {
	switch targetType {
	case TargetCPF:
		if len(target) == 11 {
			return target[:3] + ".***.***-" + target[9:]
		}
		return "***.***.***-**"
	case TargetCNPJ:
		if len(target) == 14 {
			return target[:2] + ".***.***/" + target[10:14]
		}
		return "**.***.***/*****-**"
	default:
		return target
	}
}

// ─── buildSummary ─────────────────────────────────────────────────────────────

func buildSummary(target string, targetType TargetType, findings []module.Finding) module.Finding {
	sources := make(map[string]bool)
	maxSeverity := module.SeverityInfo

	for _, f := range findings {
		if src, ok := f.Extra["osintbr_source"]; ok {
			sources[src] = true
		}
		if severityLevel(f.Severity) > severityLevel(maxSeverity) {
			maxSeverity = f.Severity
		}
	}

	sourceList := make([]string, 0, len(sources))
	for s := range sources {
		sourceList = append(sourceList, s)
	}

	displayTarget := maskTarget(target, targetType)

	return module.Finding{
		Type: "osintbr_summary",
		URL:  "",
		Detail: fmt.Sprintf("OSINT BR de '%s' (tipo: %s): %d finding(s) de %d fonte(s) [%s].",
			displayTarget, string(targetType), len(findings), len(sources), strings.Join(sourceList, ", ")),
		Severity: maxSeverity,
		Extra: map[string]string{
			"target_type":    string(targetType),
			"total_findings": fmt.Sprintf("%d", len(findings)),
			"sources":        strings.Join(sourceList, ","),
			"fonte":          "osintbr",
			"confidence":     "1.00",
		},
	}
}

func severityLevel(s module.Severity) int {
	switch s {
	case module.SeverityInfo:
		return 0
	case module.SeverityLow:
		return 1
	case module.SeverityMedium:
		return 2
	case module.SeverityHigh:
		return 3
	case module.SeverityCritical:
		return 4
	default:
		return 0
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func parseModules(s string) map[string]bool {
	if s == "all" || s == "" {
		return nil
	}
	m := map[string]bool{}
	for _, mod := range strings.Split(s, ",") {
		mod = strings.TrimSpace(strings.ToLower(mod))
		if mod != "" {
			m[mod] = true
		}
	}
	return m
}

func moduleEnabled(enabled map[string]bool, mod string) bool {
	if enabled == nil {
		return true
	}
	return enabled[mod]
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

func optStr(opts map[string]string, key, def string) string {
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

// Suppress lint unused.
var _ = time.Second
