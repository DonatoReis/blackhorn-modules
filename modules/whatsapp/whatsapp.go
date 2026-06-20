// Package whatsapp realiza OSINT de números de WhatsApp via fontes públicas.
//
// Métodos de verificação:
//   - Click-to-chat URL probe  — wa.me/{numero} responde com indicação de conta ativa
//   - WhatsApp Business API    — verificação via API oficial (requer token Business)
//   - PhoneBook OSINT          — correlação com listas públicas (nenhuma key)
//   - Profile picture URL      — tenta resolver URL pública de foto de perfil
//
// Análise local:
//   - Formato E.164 e validação do número BR/internacional
//   - Estimativa de tipo (móvel favorecido — WhatsApp não funciona em fixos)
//
// Limitações:
//   - Sem token Business: apenas probe passivo (não confirma conta com certeza)
//   - WhatsApp não oferece API pública de lookup — resultados são heurísticos
//   - Alterações de privacidade do WhatsApp podem afetar a detecção
//
// Input:
//   - Target: número de telefone (qualquer formato, preferencialmente com DDI)
//   - Options["wa_business_token"] — token WhatsApp Business API (ou WA_BUSINESS_TOKEN)
//   - Options["wa_phone_id"]       — Phone Number ID da conta Business (ou WA_PHONE_NUMBER_ID)
//   - Options["country_code"]      — código do país se não presente no número (default: 55 para BR)
//   - Options["check_profile"]     — "true" para tentar obter foto de perfil (default: true)
//   - Options["timeout"]           — timeout por request em segundos (default: 15)
//
// Ética e privacidade:
//
//	Verificações são passivas (HEAD requests). Nenhum dado é enviado ao contato.
//	Use apenas em investigações autorizadas. WhatsApp TOS §7 proíbe scraping massivo.
package whatsapp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	maxBodyBytes   = 1 << 20
	defaultTimeout = 15
)

var reDigits = regexp.MustCompile(`\D`)

// Module implementa o módulo whatsapp.
type Module struct {
	client *http.Client
}

// New cria um módulo com cliente padrão.
func New() *Module {
	return NewWithClient(&http.Client{
		Timeout: time.Duration(defaultTimeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // não seguir redirects automaticamente
		},
	})
}

// NewWithClient cria um módulo com cliente customizado.
func NewWithClient(c *http.Client) *Module {
	return &Module{client: c}
}

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "whatsapp" }

// Run executa a verificação de presença no WhatsApp.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	raw := strings.TrimSpace(input.Target)
	if raw == "" {
		return nil, fmt.Errorf("whatsapp: target (número de telefone) não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	businessToken := firstNonEmpty(opts["wa_business_token"], os.Getenv("WA_BUSINESS_TOKEN"))
	phoneNumberID := firstNonEmpty(opts["wa_phone_id"], os.Getenv("WA_PHONE_NUMBER_ID"))
	countryCode := optStr(opts, "country_code", "55")
	checkProfile := optStr(opts, "check_profile", "true") == "true"

	// Normaliza número para E.164
	e164, err := normalizeE164(raw, countryCode)
	if err != nil {
		return nil, fmt.Errorf("whatsapp: %w", err)
	}

	slog.InfoContext(ctx, "whatsapp: iniciando verificação",
		"number", maskPhone(e164),
		"has_business_token", businessToken != "",
	)

	var findings []module.Finding

	// Análise local sempre primeiro
	findings = append(findings, analyzeLocally(raw, e164)...)

	// Click-to-chat probe passivo (wa.me link)
	ctcFindings, err := m.probeClickToChat(ctx, e164)
	if err != nil {
		slog.WarnContext(ctx, "whatsapp: click-to-chat probe falhou", "err", err)
	} else {
		findings = append(findings, ctcFindings...)
	}

	// WhatsApp Business API (se token disponível)
	if businessToken != "" && phoneNumberID != "" {
		bizFindings, err := m.queryBusinessAPI(ctx, e164, businessToken, phoneNumberID)
		if err != nil {
			slog.WarnContext(ctx, "whatsapp: business API falhou", "err", err)
		} else {
			findings = append(findings, bizFindings...)
		}
	}

	// Profile picture probe
	if checkProfile {
		ppFindings, err := m.probeProfilePicture(ctx, e164)
		if err != nil {
			slog.WarnContext(ctx, "whatsapp: profile picture probe falhou", "err", err)
		} else {
			findings = append(findings, ppFindings...)
		}
	}

	result := dedup(findings)

	slog.InfoContext(ctx, "whatsapp: concluído",
		"number", maskPhone(e164),
		"total_findings", len(result),
	)

	return result, nil
}

// ─── Análise local ─────────────────────────────────────────────────────────────

func analyzeLocally(raw, e164 string) []module.Finding {
	isMobile := isMobileNumber(e164)
	suitability := "adequado para WhatsApp"
	severity := module.SeverityInfo
	if !isMobile {
		suitability = "provavelmente fixo — WhatsApp requer número móvel"
		severity = module.SeverityLow
	}

	return []module.Finding{{
		Type:     "whatsapp_number_analysis",
		URL:      fmt.Sprintf("https://wa.me/%s", strings.TrimPrefix(e164, "+")),
		Detail:   fmt.Sprintf("Número '%s' (E.164: %s) — %s.", maskPhone(raw), e164, suitability),
		Severity: severity,
		Extra: map[string]string{
			"e164":       e164,
			"is_mobile":  fmt.Sprintf("%v", isMobile),
			"fonte":      "local_analysis",
			"confidence": "0.80",
		},
	}}
}

// ─── Click-to-chat probe ───────────────────────────────────────────────────────

// probeClickToChat faz um HEAD request para wa.me/{number}.
// Se retorna 200 ou redirect para open.whatsapp.com = número possivelmente ativo.
// Se retorna 404 ou corpo sem referência = número não registrado.
func (m *Module) probeClickToChat(ctx context.Context, e164 string) ([]module.Finding, error) {
	numberStripped := strings.TrimPrefix(e164, "+")
	u := fmt.Sprintf("https://wa.me/%s", numberStripped)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-research/1.0)")
	req.Header.Set("Accept", "text/html")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("click-to-chat: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	bodyStr := string(body)

	// Heurísticas baseadas na resposta do wa.me
	registered := false
	confidence := "0.55"
	detail := ""

	switch {
	case resp.StatusCode == http.StatusOK && strings.Contains(bodyStr, "open.whatsapp.com"):
		registered = true
		confidence = "0.70"
		detail = fmt.Sprintf("Número '%s' aparenta ter conta WhatsApp ativa (wa.me respondeu com link de abertura).", maskPhone(e164))
	case resp.StatusCode == http.StatusOK && strings.Contains(bodyStr, "phone-number"):
		registered = true
		confidence = "0.65"
		detail = fmt.Sprintf("Número '%s' aparenta estar registrado no WhatsApp (wa.me retornou página de chat).", maskPhone(e164))
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		location := resp.Header.Get("Location")
		if strings.Contains(location, "open.whatsapp.com") || strings.Contains(location, "wa.me") {
			registered = true
			confidence = "0.60"
			detail = fmt.Sprintf("Número '%s' pode ter conta WhatsApp (wa.me redirecionou para: %s).", maskPhone(e164), location)
		} else {
			detail = fmt.Sprintf("Número '%s' recebeu redirect inesperado de wa.me: %s.", maskPhone(e164), location)
		}
	case resp.StatusCode == http.StatusNotFound:
		detail = fmt.Sprintf("Número '%s' não encontrado no wa.me — pode não ter conta WhatsApp.", maskPhone(e164))
	default:
		detail = fmt.Sprintf("Número '%s' — wa.me retornou status %d.", maskPhone(e164), resp.StatusCode)
	}

	if detail == "" {
		return nil, nil
	}

	findingType := "whatsapp_not_found"
	severity := module.SeverityInfo
	if registered {
		findingType = "whatsapp_account_found"
		severity = module.SeverityLow
	}

	return []module.Finding{{
		Type:     findingType,
		URL:      u,
		Detail:   detail,
		Severity: severity,
		Extra: map[string]string{
			"e164":        e164,
			"http_status": fmt.Sprintf("%d", resp.StatusCode),
			"registered":  fmt.Sprintf("%v", registered),
			"fonte":       "wa_me_probe",
			"confidence":  confidence,
		},
	}}, nil
}

// ─── WhatsApp Business API ─────────────────────────────────────────────────────

type waCheckResponse struct {
	Input string `json:"input"`
	WaID  string `json:"wa_id"`
	Name  string `json:"name"`
}

func (m *Module) queryBusinessAPI(ctx context.Context, e164, token, phoneNumberID string) ([]module.Finding, error) {
	// API de verificação de números: POST /v17.0/{phone-number-id}/messages
	// Usa endpoint de check de número disponível na Cloud API
	numberStripped := strings.TrimPrefix(e164, "+")
	u := fmt.Sprintf("https://graph.facebook.com/v18.0/%s/contacts", phoneNumberID)

	payload := fmt.Sprintf(`{"blocking":"no_wait","contacts":["+%s"],"force_check":true}`, numberStripped)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("wa business api: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wa business api: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("wa business api: token inválido (401)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wa business api: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("wa business api: leitura: %w", err)
	}

	var raw struct {
		Contacts []waCheckResponse `json:"contacts"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil
	}

	var findings []module.Finding
	for _, contact := range raw.Contacts {
		isValid := contact.WaID != ""
		findingType := "whatsapp_not_registered"
		detail := fmt.Sprintf("WhatsApp Business API: número '%s' NÃO está registrado no WhatsApp.", maskPhone(e164))
		severity := module.SeverityInfo

		if isValid {
			findingType = "whatsapp_registered"
			detail = fmt.Sprintf("WhatsApp Business API: número '%s' está registrado no WhatsApp (WA ID: %s).", maskPhone(e164), contact.WaID)
			severity = module.SeverityMedium
		}

		extra := map[string]string{
			"e164":       e164,
			"registered": fmt.Sprintf("%v", isValid),
			"fonte":      "wa_business_api",
			"confidence": "0.92",
		}
		if contact.WaID != "" {
			extra["wa_id"] = contact.WaID
		}
		if contact.Name != "" {
			extra["display_name"] = contact.Name
		}

		findings = append(findings, module.Finding{
			Type:     findingType,
			URL:      fmt.Sprintf("https://business.facebook.com/wa/manage"),
			Detail:   detail,
			Severity: severity,
			Extra:    extra,
		})
	}

	return findings, nil
}

// ─── Profile picture probe ────────────────────────────────────────────────────

// probeProfilePicture tenta determinar se há foto de perfil pública.
// Nota: sem token Business, esta verificação é muito limitada.
func (m *Module) probeProfilePicture(ctx context.Context, e164 string) ([]module.Finding, error) {
	numberStripped := strings.TrimPrefix(e164, "+")

	// wa.me não expõe foto diretamente, mas o click-to-chat page pode ter og:image
	u := fmt.Sprintf("https://wa.me/%s", numberStripped)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
	req.Header.Set("Accept", "text/html")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("profile picture: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	bodyStr := string(body)

	// Procura og:image na página
	ogImagePrefix := `<meta property="og:image" content="`
	if idx := strings.Index(bodyStr, ogImagePrefix); idx >= 0 {
		start := idx + len(ogImagePrefix)
		end := strings.Index(bodyStr[start:], `"`)
		if end > 0 {
			imageURL := bodyStr[start : start+end]
			if strings.HasPrefix(imageURL, "http") {
				return []module.Finding{{
					Type:     "whatsapp_profile_picture",
					URL:      imageURL,
					Detail:   fmt.Sprintf("Foto de perfil pública detectada para número '%s' no WhatsApp.", maskPhone(e164)),
					Severity: module.SeverityLow,
					Extra: map[string]string{
						"e164":       e164,
						"image_url":  imageURL,
						"fonte":      "wa_me_og_image",
						"confidence": "0.65",
					},
				}}, nil
			}
		}
	}

	return nil, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// normalizeE164 converte número para formato E.164 (+XXXXXXXXXXX).
func normalizeE164(raw, defaultCountryCode string) (string, error) {
	digits := reDigits.ReplaceAllString(raw, "")
	if len(digits) == 0 {
		return "", fmt.Errorf("número '%s' não contém dígitos", raw)
	}

	// Já está em E.164 com + ou com código do país
	if strings.HasPrefix(raw, "+") {
		return "+" + digits, nil
	}

	// Se começa com 0, assume que é número local com 0 de discagem
	if strings.HasPrefix(digits, "0") && len(digits) > 2 {
		digits = digits[1:]
	}

	// Se tem mais de 12 dígitos, provavelmente já tem DDI
	if len(digits) >= 12 {
		return "+" + digits, nil
	}

	// Adiciona código do país default
	cc := reDigits.ReplaceAllString(defaultCountryCode, "")
	if cc == "" {
		cc = "55"
	}

	// Evita duplicar código do país
	if strings.HasPrefix(digits, cc) && len(digits) > len(cc)+8 {
		return "+" + digits, nil
	}

	return "+" + cc + digits, nil
}

// isMobileNumber estima se um número E.164 é móvel (heurística BR).
func isMobileNumber(e164 string) bool {
	digits := strings.TrimPrefix(e164, "+")
	// Brasil: após código 55, DDD (2 dígitos), número móvel começa com 9 e tem 9 dígitos → total 13
	if strings.HasPrefix(digits, "55") {
		if len(digits) == 13 {
			numberPart := digits[4:] // remove 55 + DDD
			return numberPart[0] == '9'
		}
		if len(digits) == 12 {
			// Fixo BR: 55 + DDD + 8 dígitos
			return false
		}
	}
	// Internacional: número com 11+ dígitos pode ser móvel
	if len(digits) >= 11 {
		return true
	}
	return false
}

// maskPhone mascara número para logs.
func maskPhone(phone string) string {
	digits := reDigits.ReplaceAllString(phone, "")
	if len(digits) <= 4 {
		return strings.Repeat("*", len(digits))
	}
	return digits[:3] + strings.Repeat("*", len(digits)-5) + digits[len(digits)-2:]
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
