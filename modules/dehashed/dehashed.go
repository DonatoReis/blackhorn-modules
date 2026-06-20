// Package dehashed integra a API DeHashed para busca em bancos de dados de credenciais vazadas.
//
// API: https://www.dehashed.com/docs
//
// Tipos de busca suportados:
//   - email           — busca por endereço de email
//   - username        — busca por nome de usuário
//   - ip_address      — busca por endereço IP
//   - password        — busca por senha (hash ou texto)
//   - hashed_password — busca por hash de senha
//   - name            — busca por nome
//   - vin             — VIN (veículo)
//   - address         — endereço físico
//   - phone           — número de telefone
//   - domain          — domínio (retorna todas as contas daquele domínio)
//
// Detecção automática:
//
//	Se o target parecer um email → campo "email"
//	Se parecer IP → campo "ip_address"
//	Se parecer domínio → campo "domain"
//	Caso contrário → usa Options["field"] ou "username" como default
//
// Input:
//   - Target: valor a buscar
//   - Options["dehashed_email"] — email da conta DeHashed (obrigatório)
//   - Options["dehashed_key"]   — API key DeHashed (ou DEHASHED_API_KEY)
//   - Options["field"]          — campo de busca (default: auto-detect)
//   - Options["max_results"]    — máximo de resultados (default: 20, max: 10000)
//   - Options["page"]           — página de resultados (default: 1)
//
// Autenticação: Basic Auth com email:api_key
//
// Privacidade:
//
//	Senhas e hashes são mascarados em logs e findings.
//	Este módulo deve ser usado apenas em contextos autorizados e éticos.
package dehashed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	maxBodyBytes      = 4 << 20 // 4 MB
	defaultTimeout    = 25
	defaultMaxResults = 20
	apiBase           = "https://api.dehashed.com"
)

var (
	reEmail  = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	reDomain = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
	reIP     = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
)

// Module implementa o módulo dehashed.
type Module struct {
	client *http.Client
}

// New cria um módulo com cliente padrão.
func New() *Module {
	return NewWithClient(&http.Client{Timeout: time.Duration(defaultTimeout) * time.Second})
}

// NewWithClient cria um módulo com cliente customizado (útil para testes).
func NewWithClient(c *http.Client) *Module {
	return &Module{client: c}
}

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "dehashed" }

// Run executa a busca no DeHashed.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("dehashed: target não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	accountEmail := firstNonEmpty(opts["dehashed_email"], os.Getenv("DEHASHED_EMAIL"))
	apiKey := firstNonEmpty(opts["dehashed_key"], os.Getenv("DEHASHED_API_KEY"))

	if accountEmail == "" || apiKey == "" {
		return nil, fmt.Errorf("dehashed: credenciais obrigatórias — defina dehashed_email e dehashed_key (ou DEHASHED_EMAIL e DEHASHED_API_KEY)")
	}

	field := optStr(opts, "field", "")
	if field == "" {
		field = detectField(target)
	}

	maxResults := optInt(opts, "max_results", defaultMaxResults)
	page := optInt(opts, "page", 1)

	slog.InfoContext(ctx, "dehashed: iniciando busca",
		"target", maskTarget(target, field),
		"field", field,
		"page", page,
	)

	findings, err := m.search(ctx, target, field, accountEmail, apiKey, maxResults, page)
	if err != nil {
		return nil, err
	}

	result := dedup(findings)

	slog.InfoContext(ctx, "dehashed: concluído",
		"target", maskTarget(target, field),
		"total_findings", len(result),
	)

	return result, nil
}

// ─── Busca principal ──────────────────────────────────────────────────────────

type dehashedResponse struct {
	Balance int             `json:"balance"`
	Entries []dehashedEntry `json:"entries"`
	Success bool            `json:"success"`
	Total   int             `json:"total"`
	Took    float64         `json:"took"`
}

type dehashedEntry struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	IPAddress      string `json:"ip_address"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	HashedPassword string `json:"hashed_password"`
	Name           string `json:"name"`
	VIN            string `json:"vin"`
	Address        string `json:"address"`
	Phone          string `json:"phone"`
	DatabaseName   string `json:"database_name"`
}

func (m *Module) search(ctx context.Context, target, field, accountEmail, apiKey string, maxResults, page int) ([]module.Finding, error) {
	// DeHashed usa query syntax: campo:"valor"
	query := fmt.Sprintf(`%s:"%s"`, field, target)

	u := fmt.Sprintf("%s/search?query=%s&size=%d&page=%d",
		apiBase,
		url.QueryEscape(query),
		clampSize(maxResults),
		page,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("dehashed: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "blackhorn-modules/1.0")
	req.SetBasicAuth(accountEmail, apiKey)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dehashed: request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("dehashed: credenciais inválidas (401)")
	case http.StatusTooManyRequests:
		slog.WarnContext(ctx, "dehashed: rate limit atingido")
		return nil, fmt.Errorf("dehashed: rate limit (429)")
	case http.StatusPaymentRequired:
		return nil, fmt.Errorf("dehashed: créditos insuficientes (402)")
	case http.StatusBadRequest:
		return nil, fmt.Errorf("dehashed: query inválida (400)")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dehashed: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("dehashed: leitura body: %w", err)
	}

	var data dehashedResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("dehashed: parse resposta: %w", err)
	}

	if !data.Success {
		return []module.Finding{{
			Type:     "dehashed_no_results",
			URL:      "https://dehashed.com",
			Detail:   fmt.Sprintf("DeHashed: nenhum resultado encontrado para '%s' no campo '%s'.", maskTarget(target, field), field),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"field":      field,
				"total":      "0",
				"fonte":      "dehashed",
				"confidence": "0.90",
			},
		}}, nil
	}

	if len(data.Entries) == 0 {
		return []module.Finding{{
			Type:     "dehashed_no_results",
			URL:      "https://dehashed.com",
			Detail:   fmt.Sprintf("DeHashed: nenhum resultado para '%s' (campo: %s, total: %d).", maskTarget(target, field), field, data.Total),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"field":      field,
				"total":      fmt.Sprintf("%d", data.Total),
				"fonte":      "dehashed",
				"confidence": "0.90",
			},
		}}, nil
	}

	var findings []module.Finding

	// Finding de sumário — quantos registros existem
	if data.Total > 0 {
		findings = append(findings, module.Finding{
			Type:     "dehashed_summary",
			URL:      "https://dehashed.com",
			Detail:   fmt.Sprintf("DeHashed: encontrados %d registros totais para '%s' no campo '%s'.", data.Total, maskTarget(target, field), field),
			Severity: totalSeverity(data.Total),
			Extra: map[string]string{
				"field":      field,
				"total":      fmt.Sprintf("%d", data.Total),
				"returned":   fmt.Sprintf("%d", len(data.Entries)),
				"balance":    fmt.Sprintf("%d", data.Balance),
				"fonte":      "dehashed",
				"confidence": "0.95",
			},
		})
	}

	// Um finding por entry com dados expostos
	for _, e := range data.Entries {
		extra := map[string]string{
			"id":            e.ID,
			"database_name": e.DatabaseName,
			"fonte":         "dehashed",
			"confidence":    "0.90",
		}

		var exposedFields []string

		// Email: não mascarar completamente para correlação, mas truncar
		if e.Email != "" {
			extra["email"] = maskEmail(e.Email)
			exposedFields = append(exposedFields, "email")
		}
		if e.Username != "" {
			extra["username"] = e.Username
			exposedFields = append(exposedFields, "username")
		}
		if e.Name != "" {
			extra["name"] = e.Name
			exposedFields = append(exposedFields, "name")
		}
		if e.IPAddress != "" {
			extra["ip_address"] = e.IPAddress
			exposedFields = append(exposedFields, "ip_address")
		}
		if e.Phone != "" {
			extra["phone"] = maskPhone(e.Phone)
			exposedFields = append(exposedFields, "phone")
		}
		if e.Address != "" {
			extra["address"] = e.Address
			exposedFields = append(exposedFields, "address")
		}
		if e.VIN != "" {
			extra["vin"] = e.VIN
			exposedFields = append(exposedFields, "vin")
		}

		// Senhas: SEMPRE mascaradas
		if e.Password != "" {
			extra["password_exposed"] = "true"
			extra["password_length"] = fmt.Sprintf("%d", len(e.Password))
			exposedFields = append(exposedFields, "password")
		}
		if e.HashedPassword != "" {
			extra["hashed_password_exposed"] = "true"
			extra["hash_prefix"] = hashPrefix(e.HashedPassword)
			exposedFields = append(exposedFields, "hashed_password")
		}

		severity := module.SeverityMedium
		if e.Password != "" || e.HashedPassword != "" {
			severity = module.SeverityHigh
		}

		detail := fmt.Sprintf("Registro '%s' encontrado no leak '%s'. Campos expostos: %s.",
			maskTarget(target, field), e.DatabaseName, strings.Join(exposedFields, ", "))

		findings = append(findings, module.Finding{
			Type:     "dehashed_record",
			URL:      fmt.Sprintf("https://dehashed.com/search?query=%s:%q", field, target),
			Detail:   detail,
			Severity: severity,
			Extra:    extra,
		})
	}

	return findings, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// detectField determina automaticamente o campo de busca DeHashed.
func detectField(target string) string {
	if reEmail.MatchString(target) {
		return "email"
	}
	if reIP.MatchString(target) {
		return "ip_address"
	}
	// Domínio real: deve ter pelo menos 1 ponto, TLD de 2+ chars,
	// e não conter underscores (usernames podem ter)
	// ex: "example.com" → domain, "john.doe" → username (sem TLD real)
	if reDomain.MatchString(target) && !strings.Contains(target, "_") && looksLikeDomain(target) {
		return "domain"
	}
	return "username"
}

// looksLikeDomain verifica se o target tem aparência de domínio real
// (TLD de palavra comum ou ccTLD conhecido).
func looksLikeDomain(target string) bool {
	parts := strings.Split(target, ".")
	if len(parts) < 2 {
		return false
	}
	tld := strings.ToLower(parts[len(parts)-1])
	// TLDs comuns — lista suficiente para distinguir domínio de nome de pessoa
	knownTLDs := map[string]bool{
		"com": true, "net": true, "org": true, "edu": true, "gov": true,
		"br": true, "uk": true, "us": true, "de": true, "fr": true,
		"io": true, "co": true, "ai": true, "app": true, "dev": true,
		"info": true, "biz": true, "tech": true, "cloud": true,
		// Brasil
		"com.br": true, "net.br": true, "org.br": true, "gov.br": true,
	}
	return knownTLDs[tld]
}

// totalSeverity classifica a severidade pelo número de registros encontrados.
func totalSeverity(total int) module.Severity {
	switch {
	case total >= 10000:
		return module.SeverityCritical
	case total >= 100:
		return module.SeverityHigh
	case total >= 10:
		return module.SeverityMedium
	default:
		return module.SeverityLow
	}
}

// maskTarget mascara o target dependendo do campo.
func maskTarget(target, field string) string {
	switch field {
	case "email":
		return maskEmail(target)
	case "password", "hashed_password":
		return "***REDACTED***"
	case "phone":
		return maskPhone(target)
	default:
		return target
	}
}

// maskEmail mascara um endereço de email para logs.
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

// maskPhone mascara número de telefone.
func maskPhone(phone string) string {
	if len(phone) < 4 {
		return "****"
	}
	return phone[:3] + strings.Repeat("*", len(phone)-6) + phone[len(phone)-3:]
}

// hashPrefix retorna apenas os primeiros 8 chars do hash para identificação de tipo.
func hashPrefix(h string) string {
	if len(h) <= 8 {
		return h
	}
	return h[:8] + "..."
}

// clampSize limita o tamanho da busca ao máximo da API DeHashed (10000).
func clampSize(n int) int {
	if n <= 0 {
		return defaultMaxResults
	}
	if n > 10000 {
		return 10000
	}
	return n
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
