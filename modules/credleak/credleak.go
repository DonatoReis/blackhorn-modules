// Package credleak realiza análise combinada de credenciais vazadas.
//
// Combina dados de múltiplas fontes de breach com análise local de padrões
// de senha para identificar riscos de reutilização de credenciais.
//
// PRIVACIDADE:
//   - Senhas NUNCA são enviadas para APIs externas
//   - Análise de padrões é 100% local
//   - Apenas hashes parciais (k-anonymity) são usados para verificação externa
//   - Emails são mascarados nos findings
//
// Fontes suportadas:
//   - hibp_breaches    : HaveIBeenPwned — breaches por email (requer API key)
//   - hibp_passwords   : HaveIBeenPwned — k-anonymity para senhas (sem key)
//   - leakcheck        : LeakCheck.io — verificação de email (requer API key)
//   - pattern_analysis : Análise local de padrões de senha (sem chamadas externas)
//
// Tipos de target detectados automaticamente:
//   - email            : verifica email em bases de breach
//   - email:senha      : verifica par credencial (email + senha juntos)
//   - :senha           : verifica apenas padrão de senha
//
// Options:
//
//	sources         : lista separada por vírgula (padrão: hibp_breaches,hibp_passwords,pattern_analysis)
//	hibp_key        : API key HaveIBeenPwned (ou env HIBP_API_KEY)
//	leakcheck_key   : API key LeakCheck.io (ou env LEAKCHECK_API_KEY)
//	min_score       : score mínimo de risco para incluir findings (0.0–1.0, padrão: 0.0)
package credleak

import (
	"context"
	"crypto/sha1" //nolint:gosec // SHA-1 obrigatório para k-anonymity HIBP
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	maxBodyBytes   = 512 * 1024
	defaultTimeout = 20 * time.Second

	baseURLHIBPBreaches  = "https://haveibeenpwned.com/api/v3"
	baseURLHIBPPasswords = "https://api.pwnedpasswords.com"
	baseURLLeakCheck     = "https://leakcheck.io/api/public"
)

var (
	reEmail    = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	reCredPair = regexp.MustCompile(`^([^:]+):(.+)$`)
)

// Module implementa module.Module para análise de credenciais vazadas.
type Module struct {
	client *http.Client
}

// New cria um Module com cliente HTTP padrão.
func New() *Module { return &Module{client: &http.Client{Timeout: defaultTimeout}} }

// NewWithClient cria um Module com cliente HTTP injetado (útil em testes).
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "credleak" }

// Run executa a análise de credenciais vazadas.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	if strings.TrimSpace(input.Target) == "" {
		return nil, fmt.Errorf("credleak: target não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	// Parse do target: pode ser "email", "email:senha" ou ":senha"
	email, password := parseTarget(input.Target)

	// Se o target (sem o prefixo de senha ":") contém @ mas não é email válido, é malformado
	rawTarget := input.Target
	if strings.HasPrefix(rawTarget, ":") {
		rawTarget = rawTarget[1:]
	}
	if email == "" && password == "" {
		return nil, fmt.Errorf("credleak: target deve ser email, email:senha ou :senha")
	}
	if email == "" && !strings.HasPrefix(input.Target, ":") && strings.Contains(rawTarget, "@") && !reEmail.MatchString(rawTarget) {
		return nil, fmt.Errorf("credleak: '%s' não é um email válido", rawTarget)
	}
	if email != "" && !reEmail.MatchString(email) {
		return nil, fmt.Errorf("credleak: '%s' não é um email válido", email)
	}

	sources := parseSources(optStr(opts, "sources", "hibp_breaches,hibp_passwords,pattern_analysis"))
	hibpKey := firstNonEmpty(opts["hibp_key"], os.Getenv("HIBP_API_KEY"))
	leakCheckKey := firstNonEmpty(opts["leakcheck_key"], os.Getenv("LEAKCHECK_API_KEY"))
	minScore := optFloat(opts, "min_score", 0.0)

	slog.InfoContext(ctx, "credleak: iniciando análise",
		"has_email", email != "",
		"has_password", password != "",
		"sources", sources,
	)

	type result struct {
		findings []module.Finding
	}

	ch := make(chan result, len(sources)+2)
	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(4)

	for _, src := range sources {
		src := src
		eg.Go(func() error {
			var ff []module.Finding
			var err error

			switch src {
			case "hibp_breaches":
				if email == "" {
					return nil
				}
				if hibpKey == "" {
					slog.WarnContext(egCtx, "credleak: hibp_breaches ignorado — HIBP_API_KEY não configurada")
					return nil
				}
				ff, err = m.checkHIBPBreaches(egCtx, email, hibpKey)

			case "hibp_passwords":
				if password == "" {
					return nil
				}
				ff, err = m.checkHIBPPassword(egCtx, password)

			case "leakcheck":
				if email == "" || leakCheckKey == "" {
					if leakCheckKey == "" && email != "" {
						slog.WarnContext(egCtx, "credleak: leakcheck ignorado — LEAKCHECK_API_KEY não configurada")
					}
					return nil
				}
				ff, err = m.checkLeakCheck(egCtx, email, leakCheckKey)

			case "pattern_analysis":
				if password == "" {
					return nil
				}
				ff = analyzePasswordPattern(password, email)
			}

			if err != nil {
				slog.WarnContext(egCtx, "credleak: fonte falhou",
					"source", src, "error", err.Error())
				return nil
			}
			if len(ff) > 0 {
				ch <- result{findings: ff}
			}
			return nil
		})
	}

	// Se temos par de credenciais, adiciona análise de reutilização
	if email != "" && password != "" {
		eg.Go(func() error {
			ff := analyzeCredentialPair(email, password)
			if len(ff) > 0 {
				ch <- result{findings: ff}
			}
			return nil
		})
	}

	go func() {
		_ = eg.Wait()
		close(ch)
	}()

	var all []module.Finding
	for r := range ch {
		all = append(all, r.findings...)
	}

	// Filtra por score mínimo
	if minScore > 0 {
		var filtered []module.Finding
		for _, f := range all {
			if score, err := strconv.ParseFloat(f.Extra["confidence"], 64); err == nil {
				if score >= minScore {
					filtered = append(filtered, f)
				}
			}
		}
		all = filtered
	}

	return dedup(all), nil
}

// ─── HIBP Breaches ────────────────────────────────────────────────────────────

func (m *Module) checkHIBPBreaches(ctx context.Context, email, apiKey string) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("%s/breachedaccount/%s?truncateResponse=false", baseURLHIBPBreaches, email)

	body, status, err := m.get(ctx, apiURL, map[string]string{
		"hibp-api-key": apiKey,
	})
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return []module.Finding{{
			Type:     "email_not_in_breach",
			Detail:   fmt.Sprintf("Email %s não encontrado em breaches conhecidos via HIBP", maskEmail(email)),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":     "hibp_breaches",
				"confidence": "0.95",
				"email":      maskEmail(email),
				"breached":   "false",
			},
		}}, nil
	}
	if status == http.StatusUnauthorized {
		return nil, fmt.Errorf("hibp: API key inválida")
	}
	if status == http.StatusTooManyRequests {
		return nil, fmt.Errorf("hibp: rate limit")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("hibp breaches HTTP %d", status)
	}

	var breaches []struct {
		Name        string   `json:"Name"`
		Domain      string   `json:"Domain"`
		BreachDate  string   `json:"BreachDate"`
		PwnCount    int      `json:"PwnCount"`
		DataClasses []string `json:"DataClasses"`
		IsVerified  bool     `json:"IsVerified"`
		IsSensitive bool     `json:"IsSensitive"`
	}
	if err := json.Unmarshal(body, &breaches); err != nil {
		return nil, fmt.Errorf("hibp JSON: %w", err)
	}

	var findings []module.Finding
	hasPasswordBreach := false
	for _, b := range breaches {
		hasPwd := containsIgnoreCase(b.DataClasses, "passwords")
		if hasPwd {
			hasPasswordBreach = true
		}

		sev := module.SeverityMedium
		if hasPwd || b.IsSensitive {
			sev = module.SeverityCritical
		}

		conf := 0.90
		if b.IsVerified {
			conf = 0.95
		}

		f := module.Finding{
			Type:     "credential_in_breach",
			URL:      fmt.Sprintf("https://haveibeenpwned.com/account/%s", email),
			Detail:   fmt.Sprintf("Email %s exposto no breach '%s' (%s) — %d contas — dados: %s", maskEmail(email), b.Name, b.BreachDate, b.PwnCount, strings.Join(b.DataClasses, ", ")),
			Severity: sev,
			Extra: map[string]string{
				"source":        "hibp_breaches",
				"confidence":    strconv.FormatFloat(conf, 'f', 2, 64),
				"email":         maskEmail(email),
				"breach_name":   b.Name,
				"breach_domain": b.Domain,
				"breach_date":   b.BreachDate,
				"pwn_count":     strconv.Itoa(b.PwnCount),
				"data_classes":  strings.Join(b.DataClasses, ", "),
				"has_passwords": strconv.FormatBool(hasPwd),
				"is_verified":   strconv.FormatBool(b.IsVerified),
			},
		}
		findings = append(findings, f)
	}

	// Finding consolidado de risco
	if hasPasswordBreach {
		findings = append(findings, module.Finding{
			Type:     "credential_risk_high",
			Detail:   fmt.Sprintf("Email %s encontrado em breaches com SENHAS expostas — risco de credential stuffing", maskEmail(email)),
			Severity: module.SeverityCritical,
			Extra: map[string]string{
				"source":         "hibp_breaches",
				"confidence":     "0.95",
				"email":          maskEmail(email),
				"risk":           "credential_stuffing",
				"recommendation": "trocar_senha_em_todos_servicos",
			},
		})
	}

	return findings, nil
}

// ─── HIBP Pwned Passwords (k-anonymity) ──────────────────────────────────────

func (m *Module) checkHIBPPassword(ctx context.Context, password string) ([]module.Finding, error) {
	//nolint:gosec // SHA-1 obrigatório para k-anonymity
	h := sha1.New()
	h.Write([]byte(password))
	hash := strings.ToUpper(fmt.Sprintf("%x", h.Sum(nil)))
	prefix := hash[:5]
	suffix := hash[5:]

	apiURL := fmt.Sprintf("%s/range/%s", baseURLHIBPPasswords, prefix)
	body, status, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("hibp passwords HTTP %d", status)
	}

	var pwnCount int
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), suffix) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				pwnCount, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
			break
		}
	}

	if pwnCount == 0 {
		return []module.Finding{{
			Type:     "password_not_exposed",
			Detail:   "Senha não encontrada em bases de breach conhecidas (verificação k-anonymity — senha nunca saiu do dispositivo)",
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":     "hibp_passwords",
				"confidence": "0.99",
				"pwn_count":  "0",
				"method":     "k-anonymity",
			},
		}}, nil
	}

	sev := module.SeverityHigh
	if pwnCount >= 10_000 {
		sev = module.SeverityCritical
	}

	return []module.Finding{{
		Type:     "password_exposed",
		Detail:   fmt.Sprintf("Senha encontrada em %d bases de breach (k-anonymity — senha não enviada) — troque imediatamente", pwnCount),
		Severity: sev,
		Extra: map[string]string{
			"source":         "hibp_passwords",
			"confidence":     "0.99",
			"pwn_count":      strconv.Itoa(pwnCount),
			"method":         "k-anonymity",
			"recommendation": "trocar_senha_imediatamente",
		},
	}}, nil
}

// ─── LeakCheck.io ─────────────────────────────────────────────────────────────

func (m *Module) checkLeakCheck(ctx context.Context, email, apiKey string) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("%s?key=%s&check=%s", baseURLLeakCheck, apiKey, email)

	body, status, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, fmt.Errorf("leakcheck: API key inválida")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("leakcheck HTTP %d", status)
	}

	var resp struct {
		Success bool     `json:"success"`
		Found   int      `json:"found"`
		Fields  []string `json:"fields"`
		Sources []struct {
			Name      string `json:"name"`
			Date      string `json:"date"`
			UnencHash bool   `json:"unencrypted_hash"`
		} `json:"sources"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("leakcheck JSON: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("leakcheck: %s", resp.Error)
	}
	if resp.Found == 0 {
		return []module.Finding{{
			Type:     "email_not_in_breach",
			Detail:   fmt.Sprintf("Email %s não encontrado em LeakCheck.io", maskEmail(email)),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":     "leakcheck",
				"confidence": "0.88",
				"email":      maskEmail(email),
				"breached":   "false",
			},
		}}, nil
	}

	var sourceNames []string
	hasUnencrypted := false
	for _, s := range resp.Sources {
		sourceNames = append(sourceNames, s.Name)
		if s.UnencHash {
			hasUnencrypted = true
		}
	}

	sev := module.SeverityHigh
	if hasUnencrypted {
		sev = module.SeverityCritical
	}

	f := module.Finding{
		Type:     "credential_in_breach",
		URL:      "https://leakcheck.io",
		Detail:   fmt.Sprintf("Email %s encontrado em %d fontes via LeakCheck — campos: %s — fontes: %s", maskEmail(email), resp.Found, strings.Join(resp.Fields, ", "), strings.Join(sourceNames, ", ")),
		Severity: sev,
		Extra: map[string]string{
			"source":          "leakcheck",
			"confidence":      "0.88",
			"email":           maskEmail(email),
			"found_count":     strconv.Itoa(resp.Found),
			"fields":          strings.Join(resp.Fields, ", "),
			"sources":         strings.Join(sourceNames, ", "),
			"has_unencrypted": strconv.FormatBool(hasUnencrypted),
		},
	}
	return []module.Finding{f}, nil
}

// ─── Pattern Analysis (100% local) ───────────────────────────────────────────

// analyzePasswordPattern analisa padrões de senha localmente sem chamadas externas.
func analyzePasswordPattern(password, email string) []module.Finding {
	score, issues := scorePassword(password)

	// Penalidade por senha igual ao email local
	if email != "" {
		local := strings.ToLower(strings.SplitN(email, "@", 2)[0])
		if strings.ToLower(password) == local || strings.Contains(strings.ToLower(password), local) {
			issues = append(issues, "senha contém/é igual à parte local do email")
			score = math.Max(0, score-0.3)
		}
	}

	sev := severityFromPasswordScore(score)
	riskLabel := passwordRiskLabel(score)

	var findings []module.Finding

	// Finding de análise de padrão
	findings = append(findings, module.Finding{
		Type:     "password_pattern_analysis",
		Detail:   fmt.Sprintf("Análise local de padrão de senha — score: %.0f/100 — risco: %s — problemas: %s", score*100, riskLabel, strings.Join(issues, "; ")),
		Severity: sev,
		Extra: map[string]string{
			"source":       "pattern_analysis",
			"confidence":   "0.85",
			"score":        strconv.FormatFloat(score, 'f', 2, 64),
			"risk_label":   riskLabel,
			"issues":       strings.Join(issues, "; "),
			"length":       strconv.Itoa(len(password)),
			"has_upper":    strconv.FormatBool(hasUppercase(password)),
			"has_lower":    strconv.FormatBool(hasLowercase(password)),
			"has_digit":    strconv.FormatBool(hasDigit(password)),
			"has_special":  strconv.FormatBool(hasSpecial(password)),
			"entropy_bits": strconv.FormatFloat(entropyBits(password), 'f', 1, 64),
		},
	})

	// Findings específicos para padrões muito perigosos
	if isCommonPassword(password) {
		findings = append(findings, module.Finding{
			Type:     "common_password_detected",
			Detail:   "Senha identificada como extremamente comum — presente em todas as wordlists de ataque",
			Severity: module.SeverityCritical,
			Extra: map[string]string{
				"source":         "pattern_analysis",
				"confidence":     "0.99",
				"risk":           "trivially_crackable",
				"recommendation": "troque_senha_imediatamente",
			},
		})
	}

	return findings
}

// scorePassword calcula score 0.0–1.0 de força da senha com lista de problemas.
func scorePassword(pwd string) (float64, []string) {
	var issues []string
	score := 1.0

	// Comprimento
	l := len(pwd)
	switch {
	case l < 6:
		issues = append(issues, fmt.Sprintf("muito curta (%d chars)", l))
		score -= 0.5
	case l < 8:
		issues = append(issues, fmt.Sprintf("curta (%d chars)", l))
		score -= 0.3
	case l < 12:
		score -= 0.1
	}

	// Diversidade de caracteres
	if !hasUppercase(pwd) {
		issues = append(issues, "sem maiúsculas")
		score -= 0.1
	}
	if !hasLowercase(pwd) {
		issues = append(issues, "sem minúsculas")
		score -= 0.1
	}
	if !hasDigit(pwd) {
		issues = append(issues, "sem dígitos")
		score -= 0.1
	}
	if !hasSpecial(pwd) {
		issues = append(issues, "sem caracteres especiais")
		score -= 0.1
	}

	// Padrões sequenciais
	if hasSequential(pwd) {
		issues = append(issues, "contém sequência (123, abc)")
		score -= 0.2
	}

	// Repetição excessiva
	if hasRepetition(pwd) {
		issues = append(issues, "contém repetição excessiva")
		score -= 0.15
	}

	// Só dígitos
	if allDigits(pwd) {
		issues = append(issues, "apenas dígitos — facilmente quebrada por brute-force")
		score -= 0.3
	}

	// Entropia muito baixa
	entropy := entropyBits(pwd)
	if entropy < 28 {
		issues = append(issues, fmt.Sprintf("entropia muito baixa (%.1f bits)", entropy))
		score -= 0.2
	} else if entropy < 40 {
		issues = append(issues, fmt.Sprintf("entropia baixa (%.1f bits)", entropy))
		score -= 0.1
	}

	return math.Max(0, math.Min(1, score)), issues
}

// analyzeCredentialPair analisa correlações entre email e senha.
func analyzeCredentialPair(email, password string) []module.Finding {
	var findings []module.Finding
	local := strings.ToLower(strings.SplitN(email, "@", 2)[0])
	domain := ""
	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 {
		domain = strings.ToLower(strings.SplitN(parts[1], ".", 2)[0])
	}

	pwdLower := strings.ToLower(password)

	// Senha = parte local do email
	if pwdLower == local {
		findings = append(findings, module.Finding{
			Type:     "credential_pattern_risk",
			Detail:   fmt.Sprintf("Senha idêntica à parte local do email (%s) — trivialmente adivinável", maskEmail(email)),
			Severity: module.SeverityCritical,
			Extra: map[string]string{
				"source":     "pattern_analysis",
				"confidence": "0.99",
				"risk":       "password_equals_email_local",
			},
		})
	}

	// Senha contém domínio do email
	if domain != "" && strings.Contains(pwdLower, domain) && len(domain) > 3 {
		findings = append(findings, module.Finding{
			Type:     "credential_pattern_risk",
			Detail:   fmt.Sprintf("Senha contém nome do domínio do email — padrão previsível facilmente quebrado"),
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"source":     "pattern_analysis",
				"confidence": "0.92",
				"risk":       "password_contains_domain",
			},
		})
	}

	// Senha é variação simples do email local (com números no final)
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(local) + `\d{1,4}[!@#$%^&*]?$`)
	if re.MatchString(pwdLower) {
		findings = append(findings, module.Finding{
			Type:     "credential_pattern_risk",
			Detail:   "Senha é variação trivial do email local com números — padrão comum e inseguro",
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"source":     "pattern_analysis",
				"confidence": "0.90",
				"risk":       "password_is_email_variation",
			},
		})
	}

	return findings
}

// ─── Password helpers ─────────────────────────────────────────────────────────

func hasUppercase(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func hasLowercase(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func hasDigit(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func hasSpecial(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func allDigits(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func hasSequential(s string) bool {
	if len(s) < 3 {
		return false
	}
	sLower := strings.ToLower(s)
	seqs := []string{"0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"}
	for _, seq := range seqs {
		for i := 0; i+2 < len(seq); i++ {
			if strings.Contains(sLower, seq[i:i+3]) {
				return true
			}
		}
	}
	return false
}

func hasRepetition(s string) bool {
	if len(s) < 4 {
		return false
	}
	for i := 0; i+3 < len(s); i++ {
		if s[i] == s[i+1] && s[i] == s[i+2] && s[i] == s[i+3] {
			return true
		}
	}
	return false
}

// entropyBits calcula entropia de Shannon da senha em bits.
func entropyBits(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := map[rune]int{}
	for _, r := range s {
		freq[r]++
	}
	entropy := 0.0
	n := float64(len(s))
	for _, count := range freq {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy * n
}

// isCommonPassword verifica se a senha está na lista de senhas mais comuns.
func isCommonPassword(pwd string) bool {
	common := []string{
		"123456", "password", "12345678", "qwerty", "abc123", "monkey", "1234567",
		"letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
		"ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
		"qazwsx", "michael", "football", "senha", "123mudar", "mudar123", "admin",
		"root", "toor", "pass", "test", "guest", "1234", "12345", "1234567890",
		"0987654321", "password1", "password123", "admin123", "admin1234",
	}
	pwdLower := strings.ToLower(pwd)
	for _, c := range common {
		if pwdLower == c {
			return true
		}
	}
	return false
}

func severityFromPasswordScore(score float64) module.Severity {
	switch {
	case score >= 0.8:
		return module.SeverityInfo
	case score >= 0.6:
		return module.SeverityLow
	case score >= 0.4:
		return module.SeverityMedium
	case score >= 0.2:
		return module.SeverityHigh
	default:
		return module.SeverityCritical
	}
}

func passwordRiskLabel(score float64) string {
	switch {
	case score >= 0.8:
		return "forte"
	case score >= 0.6:
		return "moderada"
	case score >= 0.4:
		return "fraca"
	case score >= 0.2:
		return "muito_fraca"
	default:
		return "crítica"
	}
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func (m *Module) get(ctx context.Context, apiURL string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "blackhorn-modules/1.0")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return body, resp.StatusCode, err
}

// ─── Target parsing ───────────────────────────────────────────────────────────

// parseTarget extrai email e senha do target.
// Formatos: "email", "email:senha", ":senha"
func parseTarget(target string) (email, password string) {
	// Formato ":senha" — começa com dois pontos
	if strings.HasPrefix(target, ":") {
		return "", target[1:]
	}
	// Formato "email:senha" ou "email"
	if strings.Contains(target, ":") {
		parts := strings.SplitN(target, ":", 2)
		possibleEmail := strings.TrimSpace(parts[0])
		possiblePwd := parts[1]
		if reEmail.MatchString(possibleEmail) {
			return possibleEmail, possiblePwd
		}
		// Parte do email não é email válido — trata tudo como senha
		return "", target
	}
	// Sem dois pontos: pode ser email simples ou senha
	if reEmail.MatchString(target) {
		return target, ""
	}
	return "", target
}

// ─── Misc helpers ─────────────────────────────────────────────────────────────

func maskEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return "***@***"
	}
	local := parts[0]
	if len(local) <= 2 {
		return "**@" + parts[1]
	}
	return string(local[0]) + strings.Repeat("*", len(local)-2) + string(local[len(local)-1]) + "@" + parts[1]
}

func containsIgnoreCase(slice []string, s string) bool {
	sLower := strings.ToLower(s)
	for _, v := range slice {
		if strings.ToLower(v) == sLower {
			return true
		}
	}
	return false
}

func parseSources(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func optStr(opts map[string]string, key, def string) string {
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

func optFloat(opts map[string]string, key string, def float64) float64 {
	if v, ok := opts[key]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	var out []module.Finding
	for _, f := range findings {
		key := f.Type + "|" + f.Extra["source"] + "|" + f.Extra["breach_name"] + "|" + f.Extra["risk"]
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}
