// Package hibp realiza consultas ao HaveIBeenPwned (HIBP) com suporte a
// verificação de senhas via k-anonymity (SHA-1 prefix).
//
// Funcionalidades:
//   - Verificação de email em breaches conhecidos (API v3)
//   - Verificação de email em pastes (pastebin, etc.)
//   - Verificação de senha via k-anonymity — APENAS os 5 primeiros chars do hash
//     SHA-1 são enviados ao servidor, nunca a senha completa
//   - Consulta de detalhes de breaches específicos
//   - Listagem de todos os breaches públicos
//
// PRIVACIDADE: A verificação de senha usa k-anonymity — somente o prefixo
// SHA-1 (5 chars) é enviado. O sufixo é comparado localmente. A senha
// NUNCA sai do dispositivo.
//
// Options:
//
//	hibp_key         : API key HIBP (ou env HIBP_API_KEY) — obrigatória para email/paste
//	mode             : email | password | breach | paste (padrão: email)
//	include_unverified: incluir breaches não verificados (padrão: false)
//	truncate_response: retornar apenas nomes dos breaches, sem detalhes (padrão: false)
package hibp

import (
	"context"
	"crypto/sha1" //nolint:gosec // SHA-1 é obrigatório para compatibilidade com HIBP k-anonymity
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	maxBodyBytes   = 512 * 1024
	defaultTimeout = 20 * time.Second

	baseURLHIBP  = "https://haveibeenpwned.com/api/v3"
	baseURLPwned = "https://api.pwnedpasswords.com"
)

var reEmail = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// Module implementa module.Module para consultas HIBP.
type Module struct {
	client *http.Client
}

// New cria um Module com cliente HTTP padrão.
func New() *Module { return &Module{client: &http.Client{Timeout: defaultTimeout}} }

// NewWithClient cria um Module com cliente HTTP injetado (útil em testes).
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "hibp" }

// Run executa as consultas HIBP e retorna os findings.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	if strings.TrimSpace(input.Target) == "" {
		return nil, fmt.Errorf("hibp: target não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	mode := optStr(opts, "mode", autoDetectMode(input.Target))
	hibpKey := firstNonEmpty(opts["hibp_key"], os.Getenv("HIBP_API_KEY"))

	slog.InfoContext(ctx, "hibp: iniciando consulta",
		"mode", mode,
		"target_preview", previewTarget(input.Target, mode),
	)

	switch mode {
	case "email":
		if hibpKey == "" {
			return nil, fmt.Errorf("hibp: HIBP_API_KEY é obrigatória para consulta de email")
		}
		return m.checkEmail(ctx, input.Target, hibpKey, opts)
	case "paste":
		if hibpKey == "" {
			return nil, fmt.Errorf("hibp: HIBP_API_KEY é obrigatória para consulta de pastes")
		}
		return m.checkPaste(ctx, input.Target, hibpKey)
	case "password":
		// k-anonymity — sem API key necessária
		slog.InfoContext(ctx, "hibp: verificando senha via k-anonymity (senha não sai do dispositivo)")
		return m.checkPassword(ctx, input.Target)
	case "breach":
		return m.getBreach(ctx, input.Target, hibpKey)
	default:
		return nil, fmt.Errorf("hibp: modo '%s' inválido (use: email, password, breach, paste)", mode)
	}
}

// ─── checkEmail: verifica email em breaches ───────────────────────────────────

func (m *Module) checkEmail(ctx context.Context, email, apiKey string, opts map[string]string) ([]module.Finding, error) {
	if !reEmail.MatchString(email) {
		return nil, fmt.Errorf("hibp: '%s' não parece um email válido", email)
	}

	includeUnverified := optStr(opts, "include_unverified", "false") == "true"
	truncate := optStr(opts, "truncate_response", "false") == "true"

	apiURL := fmt.Sprintf("%s/breachedaccount/%s?includeUnverified=%v&truncateResponse=%v",
		baseURLHIBP, email, includeUnverified, truncate)

	body, status, err := m.get(ctx, apiURL, map[string]string{
		"hibp-api-key": apiKey,
	})
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		// Email não encontrado em nenhum breach — isso é bom
		slog.InfoContext(ctx, "hibp: email não encontrado em nenhum breach conhecido",
			"email_domain", emailDomain(email))
		return []module.Finding{{
			Type:     "hibp_no_breach",
			Detail:   fmt.Sprintf("Email %s não encontrado em nenhum breach conhecido no HIBP", maskEmail(email)),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":     "hibp",
				"confidence": "0.95",
				"email":      maskEmail(email),
				"breached":   "false",
			},
		}}, nil
	}
	if status == http.StatusUnauthorized {
		return nil, fmt.Errorf("hibp: API key inválida ou sem permissão")
	}
	if status == http.StatusTooManyRequests {
		return nil, fmt.Errorf("hibp: rate limit atingido")
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("hibp breachedaccount HTTP %d", status)
	}

	var breaches []struct {
		Name         string   `json:"Name"`
		Domain       string   `json:"Domain"`
		BreachDate   string   `json:"BreachDate"`
		AddedDate    string   `json:"AddedDate"`
		PwnCount     int      `json:"PwnCount"`
		Description  string   `json:"Description"`
		DataClasses  []string `json:"DataClasses"`
		IsVerified   bool     `json:"IsVerified"`
		IsFabricated bool     `json:"IsFabricated"`
		IsSensitive  bool     `json:"IsSensitive"`
		IsRetired    bool     `json:"IsRetired"`
		IsSpamList   bool     `json:"IsSpamList"`
		LogoPath     string   `json:"LogoPath"`
	}
	if err := json.Unmarshal(body, &breaches); err != nil {
		return nil, fmt.Errorf("hibp breaches JSON: %w", err)
	}

	slog.WarnContext(ctx, "hibp: email encontrado em breaches",
		"email_domain", emailDomain(email),
		"breach_count", len(breaches),
	)

	var findings []module.Finding
	for _, b := range breaches {
		sev := severityFromBreachClasses(b.DataClasses, b.IsSensitive)
		hasPwd := containsIgnoreCase(b.DataClasses, "passwords")

		f := module.Finding{
			Type:     "email_in_breach",
			URL:      fmt.Sprintf("https://haveibeenpwned.com/account/%s", email),
			Detail:   fmt.Sprintf("Email encontrado no breach '%s' (%s) — %d contas expostas — dados: %s", b.Name, b.BreachDate, b.PwnCount, strings.Join(b.DataClasses, ", ")),
			Severity: sev,
			Extra: map[string]string{
				"source":        "hibp",
				"confidence":    "0.95",
				"email":         maskEmail(email),
				"breach_name":   b.Name,
				"breach_domain": b.Domain,
				"breach_date":   b.BreachDate,
				"pwn_count":     strconv.Itoa(b.PwnCount),
				"data_classes":  strings.Join(b.DataClasses, ", "),
				"has_passwords": strconv.FormatBool(hasPwd),
				"is_verified":   strconv.FormatBool(b.IsVerified),
				"is_sensitive":  strconv.FormatBool(b.IsSensitive),
			},
		}
		findings = append(findings, f)
	}
	return dedup(findings), nil
}

// ─── checkPaste: verifica email em pastes ─────────────────────────────────────

func (m *Module) checkPaste(ctx context.Context, email, apiKey string) ([]module.Finding, error) {
	if !reEmail.MatchString(email) {
		return nil, fmt.Errorf("hibp pastes: '%s' não é um email válido", email)
	}

	apiURL := fmt.Sprintf("%s/pasteaccount/%s", baseURLHIBP, email)

	body, status, err := m.get(ctx, apiURL, map[string]string{
		"hibp-api-key": apiKey,
	})
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return []module.Finding{{
			Type:     "hibp_no_paste",
			Detail:   fmt.Sprintf("Email %s não encontrado em nenhum paste conhecido no HIBP", maskEmail(email)),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":     "hibp",
				"confidence": "0.93",
				"email":      maskEmail(email),
				"in_paste":   "false",
			},
		}}, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("hibp pastes HTTP %d", status)
	}

	var pastes []struct {
		Source     string `json:"Source"`
		ID         string `json:"Id"`
		Title      string `json:"Title"`
		Date       string `json:"Date"`
		EmailCount int    `json:"EmailCount"`
	}
	if err := json.Unmarshal(body, &pastes); err != nil {
		return nil, fmt.Errorf("hibp pastes JSON: %w", err)
	}

	var findings []module.Finding
	for _, p := range pastes {
		f := module.Finding{
			Type:     "email_in_paste",
			URL:      pasteURL(p.Source, p.ID),
			Detail:   fmt.Sprintf("Email encontrado em paste '%s' (%s) — fonte: %s — %d emails expostos", p.Title, p.Date, p.Source, p.EmailCount),
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"source":       "hibp",
				"confidence":   "0.90",
				"email":        maskEmail(email),
				"paste_id":     p.ID,
				"paste_source": p.Source,
				"paste_title":  p.Title,
				"paste_date":   p.Date,
				"email_count":  strconv.Itoa(p.EmailCount),
			},
		}
		findings = append(findings, f)
	}
	return dedup(findings), nil
}

// ─── checkPassword: k-anonymity SHA-1 prefix ─────────────────────────────────

func (m *Module) checkPassword(ctx context.Context, password string) ([]module.Finding, error) {
	// Calcula SHA-1 da senha
	//nolint:gosec // SHA-1 obrigatório para HIBP k-anonymity
	h := sha1.New()
	h.Write([]byte(password))
	hash := strings.ToUpper(fmt.Sprintf("%x", h.Sum(nil)))

	prefix := hash[:5]
	suffix := hash[5:]

	slog.DebugContext(ctx, "hibp: k-anonymity request",
		"prefix_length", len(prefix),
		"never_sends_full_hash", true,
	)

	apiURL := fmt.Sprintf("%s/range/%s", baseURLPwned, prefix)
	body, status, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("hibp pwned passwords HTTP %d", status)
	}

	// Resposta: linhas no formato "SUFFIX:COUNT"
	lines := strings.Split(string(body), "\n")
	var pwnCount int
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), suffix) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				pwnCount, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
			break
		}
	}

	slog.InfoContext(ctx, "hibp: resultado k-anonymity",
		"pwn_count", pwnCount,
		"password_exposed", pwnCount > 0,
	)

	if pwnCount == 0 {
		return []module.Finding{{
			Type:     "password_not_pwned",
			Detail:   "Senha não encontrada em nenhum breach conhecido (verificação via k-anonymity, senha nunca saiu do dispositivo)",
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":     "hibp_pwned_passwords",
				"confidence": "0.99",
				"pwn_count":  "0",
				"method":     "k-anonymity",
			},
		}}, nil
	}

	sev := module.SeverityHigh
	if pwnCount >= 10000 {
		sev = module.SeverityCritical
	} else if pwnCount >= 100 {
		sev = module.SeverityHigh
	} else if pwnCount >= 10 {
		sev = module.SeverityMedium
	}

	return []module.Finding{{
		Type:     "password_pwned",
		Detail:   fmt.Sprintf("Senha encontrada em %d breaches conhecidos — troque imediatamente! (verificação segura via k-anonymity)", pwnCount),
		Severity: sev,
		Extra: map[string]string{
			"source":     "hibp_pwned_passwords",
			"confidence": "0.99",
			"pwn_count":  strconv.Itoa(pwnCount),
			"method":     "k-anonymity",
			"action":     "troque_senha_imediatamente",
		},
	}}, nil
}

// ─── getBreach: detalhes de um breach específico ─────────────────────────────

func (m *Module) getBreach(ctx context.Context, breachName, apiKey string) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("%s/breach/%s", baseURLHIBP, breachName)

	headers := map[string]string{}
	if apiKey != "" {
		headers["hibp-api-key"] = apiKey
	}

	body, status, err := m.get(ctx, apiURL, headers)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, fmt.Errorf("hibp: breach '%s' não encontrado", breachName)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("hibp breach HTTP %d", status)
	}

	var b struct {
		Name        string   `json:"Name"`
		Title       string   `json:"Title"`
		Domain      string   `json:"Domain"`
		BreachDate  string   `json:"BreachDate"`
		AddedDate   string   `json:"AddedDate"`
		PwnCount    int      `json:"PwnCount"`
		Description string   `json:"Description"`
		DataClasses []string `json:"DataClasses"`
		IsVerified  bool     `json:"IsVerified"`
		IsSensitive bool     `json:"IsSensitive"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, fmt.Errorf("hibp breach JSON: %w", err)
	}

	f := module.Finding{
		Type:     "breach_details",
		URL:      fmt.Sprintf("https://haveibeenpwned.com/PwnedWebsites#%s", b.Name),
		Detail:   fmt.Sprintf("Breach '%s' (%s) — %d contas — dados: %s", b.Title, b.BreachDate, b.PwnCount, strings.Join(b.DataClasses, ", ")),
		Severity: severityFromBreachClasses(b.DataClasses, b.IsSensitive),
		Extra: map[string]string{
			"source":       "hibp",
			"confidence":   "0.99",
			"breach_name":  b.Name,
			"breach_title": b.Title,
			"domain":       b.Domain,
			"breach_date":  b.BreachDate,
			"added_date":   b.AddedDate,
			"pwn_count":    strconv.Itoa(b.PwnCount),
			"data_classes": strings.Join(b.DataClasses, ", "),
			"is_verified":  strconv.FormatBool(b.IsVerified),
			"is_sensitive": strconv.FormatBool(b.IsSensitive),
		},
	}
	return []module.Finding{f}, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

func autoDetectMode(target string) string {
	if reEmail.MatchString(target) {
		return "email"
	}
	// Heurística: se parece nome de breach (alfanumérico simples), usa breach
	if regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(target) && len(target) > 3 && len(target) < 50 {
		return "breach"
	}
	return "password"
}

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

func emailDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func previewTarget(target, mode string) string {
	switch mode {
	case "email":
		return maskEmail(target)
	case "password":
		return "[senha ocultada]"
	default:
		if len(target) > 30 {
			return target[:30] + "..."
		}
		return target
	}
}

func pasteURL(source, id string) string {
	switch strings.ToLower(source) {
	case "pastebin":
		return "https://pastebin.com/" + id
	case "pastie":
		return "http://pastie.org/" + id
	default:
		return fmt.Sprintf("https://haveibeenpwned.com/paste/%s/%s", source, id)
	}
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

func severityFromBreachClasses(classes []string, sensitive bool) module.Severity {
	criticalClasses := []string{"passwords", "credit cards", "bank account numbers", "social security numbers", "passport numbers"}
	highClasses := []string{"email addresses", "phone numbers", "physical addresses", "dates of birth", "government issued ids"}

	for _, c := range classes {
		if containsIgnoreCase(criticalClasses, c) {
			return module.SeverityCritical
		}
	}
	for _, c := range classes {
		if containsIgnoreCase(highClasses, c) {
			if sensitive {
				return module.SeverityCritical
			}
			return module.SeverityHigh
		}
	}
	return module.SeverityMedium
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

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	var out []module.Finding
	for _, f := range findings {
		key := f.Type + "|" + f.Extra["source"] + "|" + f.Extra["breach_name"] + "|" + f.Extra["paste_id"]
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}
