// Package emailosint realiza investigação profunda de endereços de email.
//
// Fontes integradas:
//   - Verificação técnica local   — formato RFC 5321, domínio, MX via DNS, SPF, DMARC
//   - Hunter.io                   — verificação, score de entregabilidade, fontes web
//   - EmailRep.io                 — reputação, categorias, atividade suspeita
//   - Holehe (via API pública)    — presença em 120+ plataformas (password reset probe)
//   - HaveIBeenPwned              — breaches e pastes (requer API key para emails)
//   - LeakCheck                   — breaches adicionais (requer API key)
//   - Gravatar                    — avatar e nome público (hash MD5, sem key)
//   - Clearbit Enrichment         — dados corporativos (requer CLEARBIT_API_KEY)
//
// Input:
//   - Target: endereço de email
//   - Options["sources"]        — fontes separadas por vírgula (default: all)
//   - Options["hunter_key"]     — API key Hunter.io (ou HUNTER_API_KEY)
//   - Options["emailrep_key"]   — API key EmailRep (ou EMAILREP_API_KEY)
//   - Options["hibp_key"]       — API key HIBP (ou HIBP_API_KEY)
//   - Options["leakcheck_key"]  — API key LeakCheck (ou LEAKCHECK_API_KEY)
//   - Options["clearbit_key"]   — API key Clearbit (ou CLEARBIT_API_KEY)
//   - Options["max_results"]    — máximo de resultados por fonte (default: 20)
//   - Options["timeout"]        — timeout por request em segundos (default: 20)
//   - Options["check_dns"]      — "false" para desabilitar DNS local (default: true)
//
// Privacidade:
//
//	Emails são mascarados em logs. Nenhuma senha enviada. Gravatar usa MD5 do email.
package emailosint

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	maxBodyBytes   = 2 << 20 // 2 MB
	defaultTimeout = 20
)

var reEmail = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// Module implementa o módulo emailosint.
type Module struct {
	client   *http.Client
	resolver *net.Resolver
}

// New cria um módulo com cliente padrão.
func New() *Module {
	return NewWithClient(&http.Client{Timeout: time.Duration(defaultTimeout) * time.Second})
}

// NewWithClient cria um módulo com cliente customizado (útil para testes).
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client:   c,
		resolver: net.DefaultResolver,
	}
}

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "emailosint" }

func looksLikeDomain(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if strings.ContainsAny(value, "@/:\\ \t\r\n") || len(value) > 253 {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// Run executa a investigação de email.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	email := strings.TrimSpace(strings.ToLower(input.Target))
	if email == "" {
		return nil, fmt.Errorf("emailosint: target (email) não pode ser vazio")
	}
	if !reEmail.MatchString(email) {
		if looksLikeDomain(email) {
			return nil, nil
		}
		return nil, fmt.Errorf("emailosint: '%s' não é um endereço de email válido", email)
	}

	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("emailosint: email malformado '%s'", email)
	}
	localPart := parts[0]
	domain := parts[1]

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	enabledSources := parseSources(optStr(opts, "sources", "all"))
	maxResults := optInt(opts, "max_results", 20)
	checkDNS := optStr(opts, "check_dns", "true") == "true"

	hunterKey := firstNonEmpty(opts["hunter_key"], os.Getenv("HUNTER_API_KEY"))
	emailRepKey := firstNonEmpty(opts["emailrep_key"], os.Getenv("EMAILREP_API_KEY"))
	hibpKey := firstNonEmpty(opts["hibp_key"], os.Getenv("HIBP_API_KEY"))
	leakcheckKey := firstNonEmpty(opts["leakcheck_key"], os.Getenv("LEAKCHECK_API_KEY"))
	clearbitKey := firstNonEmpty(opts["clearbit_key"], os.Getenv("CLEARBIT_API_KEY"))

	slog.InfoContext(ctx, "emailosint: iniciando investigação",
		"email", maskEmail(email),
		"domain", domain,
		"sources", enabledSources,
	)

	var (
		mu       sync.Mutex
		findings []module.Finding
	)
	add := func(ff []module.Finding) {
		mu.Lock()
		findings = append(findings, ff...)
		mu.Unlock()
	}

	// Análise técnica local — sempre executada
	localFindings := m.analyzeLocally(ctx, email, localPart, domain, checkDNS)
	add(localFindings)

	eg, ctx2 := errgroup.WithContext(ctx)
	eg.SetLimit(5)

	// Gravatar — sem key, usa MD5 do email
	if sourceEnabled(enabledSources, "gravatar") {
		eg.Go(func() error {
			ff, err := m.queryGravatar(ctx2, email)
			if err != nil {
				slog.WarnContext(ctx2, "emailosint: gravatar falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Hunter.io — verificação e entregabilidade
	if sourceEnabled(enabledSources, "hunter") && hunterKey != "" {
		eg.Go(func() error {
			ff, err := m.queryHunter(ctx2, email, hunterKey)
			if err != nil {
				slog.WarnContext(ctx2, "emailosint: hunter falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// EmailRep — reputação e categorias
	if sourceEnabled(enabledSources, "emailrep") {
		eg.Go(func() error {
			ff, err := m.queryEmailRep(ctx2, email, emailRepKey)
			if err != nil {
				slog.WarnContext(ctx2, "emailosint: emailrep falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// HIBP — breaches
	if sourceEnabled(enabledSources, "hibp") && hibpKey != "" {
		eg.Go(func() error {
			ff, err := m.queryHIBP(ctx2, email, hibpKey, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "emailosint: hibp falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// LeakCheck — breaches adicionais
	if sourceEnabled(enabledSources, "leakcheck") && leakcheckKey != "" {
		eg.Go(func() error {
			ff, err := m.queryLeakCheck(ctx2, email, leakcheckKey, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "emailosint: leakcheck falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Clearbit — enriquecimento corporativo
	if sourceEnabled(enabledSources, "clearbit") && clearbitKey != "" {
		eg.Go(func() error {
			ff, err := m.queryClearbit(ctx2, email, clearbitKey)
			if err != nil {
				slog.WarnContext(ctx2, "emailosint: clearbit falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	_ = eg.Wait()

	result := dedup(findings)

	slog.InfoContext(ctx, "emailosint: concluído",
		"email", maskEmail(email),
		"total_findings", len(result),
	)

	return result, nil
}

// ─── Análise local ─────────────────────────────────────────────────────────────

func (m *Module) analyzeLocally(ctx context.Context, email, localPart, domain string, checkDNS bool) []module.Finding {
	var findings []module.Finding

	// Validação de formato
	detail := fmt.Sprintf("Email '%s' possui formato válido (RFC 5321). Parte local: '%s', domínio: '%s'.",
		maskEmail(email), localPart, domain)
	findings = append(findings, module.Finding{
		Type:     "email_format_valid",
		URL:      "",
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"local_part": localPart,
			"domain":     domain,
			"fonte":      "local_analysis",
			"confidence": "0.95",
		},
	})

	// Domínio descartável
	if isDisposable(domain) {
		findings = append(findings, module.Finding{
			Type:     "disposable_email",
			URL:      "",
			Detail:   fmt.Sprintf("O domínio '%s' é reconhecido como serviço de email temporário/descartável.", domain),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"domain":     domain,
				"fonte":      "local_disposable_list",
				"confidence": "0.90",
			},
		})
	}

	// TLD suspeitos
	tld := domainTLD(domain)
	if isSuspiciousTLD(tld) {
		findings = append(findings, module.Finding{
			Type:     "suspicious_tld",
			URL:      "",
			Detail:   fmt.Sprintf("O TLD '.%s' do domínio '%s' é frequentemente associado a atividades suspeitas.", tld, domain),
			Severity: module.SeverityLow,
			Extra: map[string]string{
				"tld":        tld,
				"domain":     domain,
				"fonte":      "local_analysis",
				"confidence": "0.55",
			},
		})
	}

	// Verificações DNS — MX, SPF, DMARC
	if checkDNS {
		// MX lookup
		mxRecords, err := m.resolver.LookupMX(ctx, domain)
		if err != nil {
			findings = append(findings, module.Finding{
				Type:     "email_mx_missing",
				URL:      "",
				Detail:   fmt.Sprintf("Nenhum registro MX encontrado para '%s' — o domínio pode não aceitar emails.", domain),
				Severity: module.SeverityMedium,
				Extra: map[string]string{
					"domain":     domain,
					"error":      err.Error(),
					"fonte":      "dns_lookup",
					"confidence": "0.85",
				},
			})
		} else {
			mxHosts := make([]string, 0, len(mxRecords))
			for _, mx := range mxRecords {
				mxHosts = append(mxHosts, mx.Host)
			}
			provider := detectEmailProvider(mxHosts)
			findings = append(findings, module.Finding{
				Type:     "email_mx_found",
				URL:      "",
				Detail:   fmt.Sprintf("Registro MX encontrado para '%s' (%d servidores). Provedor detectado: %s.", domain, len(mxRecords), provider),
				Severity: module.SeverityInfo,
				Extra: map[string]string{
					"domain":     domain,
					"mx_hosts":   strings.Join(mxHosts, ", "),
					"provider":   provider,
					"fonte":      "dns_lookup",
					"confidence": "0.90",
				},
			})
		}

		// SPF via TXT
		txtRecords, err := m.resolver.LookupTXT(ctx, domain)
		if err == nil {
			for _, txt := range txtRecords {
				if strings.HasPrefix(txt, "v=spf1") {
					spfPolicy := extractSPFPolicy(txt)
					findings = append(findings, module.Finding{
						Type:     "spf_record",
						URL:      "",
						Detail:   fmt.Sprintf("Registro SPF encontrado para '%s'. Política: %s.", domain, spfPolicy),
						Severity: module.SeverityInfo,
						Extra: map[string]string{
							"domain":     domain,
							"spf_record": txt,
							"policy":     spfPolicy,
							"fonte":      "dns_lookup",
							"confidence": "0.90",
						},
					})
					break
				}
			}

			// DMARC via _dmarc.domain
			dmarcDomain := "_dmarc." + domain
			dmarcRecords, dmarcErr := m.resolver.LookupTXT(ctx, dmarcDomain)
			if dmarcErr == nil {
				for _, txt := range dmarcRecords {
					if strings.HasPrefix(txt, "v=DMARC1") {
						dmarcPolicy := extractDMARCPolicy(txt)
						findings = append(findings, module.Finding{
							Type:     "dmarc_record",
							URL:      "",
							Detail:   fmt.Sprintf("Registro DMARC encontrado para '%s'. Política: %s.", domain, dmarcPolicy),
							Severity: module.SeverityInfo,
							Extra: map[string]string{
								"domain":       domain,
								"dmarc_record": txt,
								"policy":       dmarcPolicy,
								"fonte":        "dns_lookup",
								"confidence":   "0.90",
							},
						})
						break
					}
				}
			}
		}
	}

	return findings
}

// ─── Gravatar ─────────────────────────────────────────────────────────────────

type gravatarProfile struct {
	Entry []struct {
		ID          string `json:"id"`
		Hash        string `json:"hash"`
		DisplayName string `json:"displayName"`
		ProfileURL  string `json:"profileUrl"`
		AboutMe     string `json:"aboutMe"`
		Emails      []struct {
			Value   string `json:"value"`
			Primary string `json:"primary"`
		} `json:"emails"`
		Accounts []struct {
			Domain    string `json:"domain"`
			Username  string `json:"username"`
			Verified  bool   `json:"verified"`
			Shortname string `json:"shortname"`
			Display   string `json:"display"`
		} `json:"accounts"`
		Name struct {
			GivenName  string `json:"givenName"`
			FamilyName string `json:"familyName"`
		} `json:"name"`
	} `json:"entry"`
}

func (m *Module) queryGravatar(ctx context.Context, email string) ([]module.Finding, error) {
	// MD5 do email normalizado — nunca expõe email
	hash := fmt.Sprintf("%x", md5.Sum([]byte(strings.ToLower(strings.TrimSpace(email)))))
	u := fmt.Sprintf("https://www.gravatar.com/%s.json", hash)

	resp, err := m.get(ctx, u, nil)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, nil // Sem perfil Gravatar, não é erro
		}
		return nil, fmt.Errorf("gravatar: %w", err)
	}

	var profile gravatarProfile
	if err := json.Unmarshal(resp, &profile); err != nil || len(profile.Entry) == 0 {
		return nil, nil
	}

	entry := profile.Entry[0]
	var findings []module.Finding

	findings = append(findings, module.Finding{
		Type:     "gravatar_profile",
		URL:      entry.ProfileURL,
		Detail:   fmt.Sprintf("Perfil Gravatar público encontrado para o email '%s'. Nome público: '%s'.", maskEmail(email), entry.DisplayName),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"display_name": entry.DisplayName,
			"hash":         hash,
			"profile_url":  entry.ProfileURL,
			"fonte":        "gravatar",
			"confidence":   "0.85",
		},
	})

	// Contas vinculadas
	for _, acc := range entry.Accounts {
		findings = append(findings, module.Finding{
			Type:     "linked_account",
			URL:      fmt.Sprintf("https://%s", acc.Domain),
			Detail:   fmt.Sprintf("Conta vinculada ao Gravatar: %s (@%s).", acc.Display, acc.Username),
			Severity: module.SeverityLow,
			Extra: map[string]string{
				"platform":   acc.Domain,
				"username":   acc.Username,
				"verified":   fmt.Sprintf("%v", acc.Verified),
				"fonte":      "gravatar_accounts",
				"confidence": "0.75",
			},
		})
	}

	return findings, nil
}

// ─── Hunter.io ────────────────────────────────────────────────────────────────

type hunterVerifyResp struct {
	Data struct {
		Result     string `json:"result"`
		Score      int    `json:"score"`
		Email      string `json:"email"`
		Regexp     bool   `json:"regexp"`
		Gibberish  bool   `json:"gibberish"`
		Disposable bool   `json:"disposable"`
		Webmail    bool   `json:"webmail"`
		MXRecords  bool   `json:"mx_records"`
		SMTPServer bool   `json:"smtp_server"`
		SMTPCheck  bool   `json:"smtp_check"`
		AcceptAll  bool   `json:"accept_all"`
		Block      bool   `json:"block"`
		Status     string `json:"status"`
	} `json:"data"`
}

func (m *Module) queryHunter(ctx context.Context, email string, apiKey string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://api.hunter.io/v2/email-verifier?email=%s&api_key=%s",
		email, apiKey)

	resp, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("hunter: %w", err)
	}

	var data hunterVerifyResp
	if err := json.Unmarshal(resp, &data); err != nil {
		return nil, fmt.Errorf("hunter: parse: %w", err)
	}

	severity := module.SeverityInfo
	if data.Data.Result == "risky" {
		severity = module.SeverityMedium
	} else if data.Data.Result == "undeliverable" {
		severity = module.SeverityHigh
	}

	confidence := fmt.Sprintf("%.2f", float64(data.Data.Score)/100.0)

	extra := map[string]string{
		"result":      data.Data.Result,
		"score":       fmt.Sprintf("%d", data.Data.Score),
		"mx_records":  fmt.Sprintf("%v", data.Data.MXRecords),
		"smtp_server": fmt.Sprintf("%v", data.Data.SMTPServer),
		"smtp_check":  fmt.Sprintf("%v", data.Data.SMTPCheck),
		"disposable":  fmt.Sprintf("%v", data.Data.Disposable),
		"webmail":     fmt.Sprintf("%v", data.Data.Webmail),
		"accept_all":  fmt.Sprintf("%v", data.Data.AcceptAll),
		"fonte":       "hunter_io",
		"confidence":  confidence,
	}

	detail := fmt.Sprintf("Hunter.io: email '%s' verificado — resultado '%s', score %d/100. Entregável: %v, Webmail: %v, Descartável: %v.",
		maskEmail(email), data.Data.Result, data.Data.Score, data.Data.SMTPCheck, data.Data.Webmail, data.Data.Disposable)

	return []module.Finding{{
		Type:     "email_deliverability",
		URL:      fmt.Sprintf("https://hunter.io/email-verifier/%s", email),
		Detail:   detail,
		Severity: severity,
		Extra:    extra,
	}}, nil
}

// ─── EmailRep ─────────────────────────────────────────────────────────────────

type emailRepResp struct {
	Email      string `json:"email"`
	Reputation string `json:"reputation"`
	Suspicious bool   `json:"suspicious"`
	References int    `json:"references"`
	Details    struct {
		Blacklisted       bool     `json:"blacklisted"`
		MaliciousActivity bool     `json:"malicious_activity"`
		Credentials       bool     `json:"credentials_leaked"`
		DataBreaches      bool     `json:"data_breach"`
		FirstSeen         string   `json:"first_seen"`
		LastSeen          string   `json:"last_seen"`
		DomainExists      bool     `json:"domain_exists"`
		DomainReputat     string   `json:"domain_reputation"`
		NewDomain         bool     `json:"new_domain"`
		DaysSinceDomain   int      `json:"days_since_domain_creation"`
		SuspActivity      bool     `json:"suspicious_tld"`
		Spam              bool     `json:"spam"`
		FreeMail          bool     `json:"free_provider"`
		Deliverable       bool     `json:"deliverable"`
		AcceptAll         bool     `json:"accept_all"`
		ValidMX           bool     `json:"valid_mx"`
		Categories        []string `json:"profiles"`
	} `json:"details"`
}

func (m *Module) queryEmailRep(ctx context.Context, email string, apiKey string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://emailrep.io/%s", email)
	headers := map[string]string{
		"Accept": "application/json",
	}
	if apiKey != "" {
		headers["Key"] = apiKey
	}

	resp, err := m.get(ctx, u, headers)
	if err != nil {
		return nil, fmt.Errorf("emailrep: %w", err)
	}

	var data emailRepResp
	if err := json.Unmarshal(resp, &data); err != nil {
		return nil, fmt.Errorf("emailrep: parse: %w", err)
	}

	severity := module.SeverityInfo
	switch data.Reputation {
	case "low":
		severity = module.SeverityMedium
	case "none":
		severity = module.SeverityHigh
	}
	if data.Details.Blacklisted || data.Details.MaliciousActivity {
		severity = module.SeverityCritical
	}

	confidence := "0.70"
	if data.References > 5 {
		confidence = "0.85"
	}
	if data.References > 20 {
		confidence = "0.92"
	}

	extra := map[string]string{
		"reputation":         data.Reputation,
		"suspicious":         fmt.Sprintf("%v", data.Suspicious),
		"references":         fmt.Sprintf("%d", data.References),
		"blacklisted":        fmt.Sprintf("%v", data.Details.Blacklisted),
		"malicious_activity": fmt.Sprintf("%v", data.Details.MaliciousActivity),
		"credentials_leaked": fmt.Sprintf("%v", data.Details.Credentials),
		"data_breach":        fmt.Sprintf("%v", data.Details.DataBreaches),
		"spam":               fmt.Sprintf("%v", data.Details.Spam),
		"free_provider":      fmt.Sprintf("%v", data.Details.FreeMail),
		"first_seen":         data.Details.FirstSeen,
		"last_seen":          data.Details.LastSeen,
		"fonte":              "emailrep_io",
		"confidence":         confidence,
	}
	if len(data.Details.Categories) > 0 {
		extra["categories"] = strings.Join(data.Details.Categories, ", ")
	}

	detail := fmt.Sprintf("EmailRep: email '%s' tem reputação '%s', %d referências. Suspeito: %v, Blacklisted: %v, Breaches: %v.",
		maskEmail(email), data.Reputation, data.References, data.Suspicious, data.Details.Blacklisted, data.Details.DataBreaches)

	return []module.Finding{{
		Type:     "email_reputation",
		URL:      u,
		Detail:   detail,
		Severity: severity,
		Extra:    extra,
	}}, nil
}

// ─── HIBP ─────────────────────────────────────────────────────────────────────

type hibpBreach struct {
	Name        string   `json:"Name"`
	Title       string   `json:"Title"`
	Domain      string   `json:"Domain"`
	BreachDate  string   `json:"BreachDate"`
	PwnCount    int      `json:"PwnCount"`
	DataClasses []string `json:"DataClasses"`
	IsVerified  bool     `json:"IsVerified"`
	IsSensitive bool     `json:"IsSensitive"`
}

func (m *Module) queryHIBP(ctx context.Context, email string, apiKey string, max int) ([]module.Finding, error) {
	u := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=false", email)

	headers := map[string]string{
		"hibp-api-key": apiKey,
		"User-Agent":   "blackhorn-modules/emailosint",
	}

	resp, err := m.get(ctx, u, headers)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return []module.Finding{{
				Type:     "hibp_no_breach",
				URL:      "https://haveibeenpwned.com",
				Detail:   fmt.Sprintf("Email '%s' não encontrado em nenhum breach no HIBP.", maskEmail(email)),
				Severity: module.SeverityInfo,
				Extra: map[string]string{
					"fonte":      "hibp",
					"confidence": "0.90",
				},
			}}, nil
		}
		return nil, fmt.Errorf("hibp: %w", err)
	}

	var breaches []hibpBreach
	if err := json.Unmarshal(resp, &breaches); err != nil {
		return nil, fmt.Errorf("hibp: parse: %w", err)
	}

	var findings []module.Finding
	for i, b := range breaches {
		if max > 0 && i >= max {
			break
		}
		severity := module.SeverityMedium
		if b.PwnCount >= 100000 {
			severity = module.SeverityHigh
		}
		if b.PwnCount >= 1000000 {
			severity = module.SeverityCritical
		}
		if b.IsSensitive {
			severity = module.SeverityHigh
		}

		findings = append(findings, module.Finding{
			Type:     "email_in_breach",
			URL:      fmt.Sprintf("https://haveibeenpwned.com/PwnedWebsites#%s", b.Name),
			Detail:   fmt.Sprintf("Email '%s' encontrado no breach '%s' (%s, %d registros expostos). Dados: %s.", maskEmail(email), b.Title, b.BreachDate, b.PwnCount, strings.Join(b.DataClasses, ", ")),
			Severity: severity,
			Extra: map[string]string{
				"breach_name":  b.Name,
				"breach_title": b.Title,
				"breach_date":  b.BreachDate,
				"pwn_count":    fmt.Sprintf("%d", b.PwnCount),
				"data_classes": strings.Join(b.DataClasses, ", "),
				"verified":     fmt.Sprintf("%v", b.IsVerified),
				"sensitive":    fmt.Sprintf("%v", b.IsSensitive),
				"fonte":        "hibp",
				"confidence":   "0.95",
			},
		})
	}

	return findings, nil
}

// ─── LeakCheck ────────────────────────────────────────────────────────────────

type leakCheckResp struct {
	Success bool     `json:"success"`
	Found   int      `json:"found"`
	Fields  []string `json:"fields"`
	Sources []struct {
		Name string `json:"name"`
		Date string `json:"date"`
	} `json:"sources"`
}

func (m *Module) queryLeakCheck(ctx context.Context, email string, apiKey string, max int) ([]module.Finding, error) {
	u := fmt.Sprintf("https://leakcheck.io/api/public?key=%s&check=%s", apiKey, email)

	resp, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("leakcheck: %w", err)
	}

	var data leakCheckResp
	if err := json.Unmarshal(resp, &data); err != nil {
		return nil, fmt.Errorf("leakcheck: parse: %w", err)
	}

	if !data.Success || data.Found == 0 {
		return []module.Finding{{
			Type:     "leakcheck_no_breach",
			URL:      "https://leakcheck.io",
			Detail:   fmt.Sprintf("Email '%s' não encontrado em nenhum leak no LeakCheck.", maskEmail(email)),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"fonte":      "leakcheck",
				"confidence": "0.85",
			},
		}}, nil
	}

	var findings []module.Finding
	for i, src := range data.Sources {
		if max > 0 && i >= max {
			break
		}
		findings = append(findings, module.Finding{
			Type:     "email_in_leak",
			URL:      "https://leakcheck.io",
			Detail:   fmt.Sprintf("Email '%s' encontrado no leak '%s' (%s). Campos expostos: %s.", maskEmail(email), src.Name, src.Date, strings.Join(data.Fields, ", ")),
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"source_name": src.Name,
				"source_date": src.Date,
				"fields":      strings.Join(data.Fields, ", "),
				"total_found": fmt.Sprintf("%d", data.Found),
				"fonte":       "leakcheck",
				"confidence":  "0.88",
			},
		})
	}

	return findings, nil
}

// ─── Clearbit ─────────────────────────────────────────────────────────────────

type clearbitPerson struct {
	ID   string `json:"id"`
	Name struct {
		FullName string `json:"fullName"`
	} `json:"name"`
	Email      string `json:"email"`
	Location   string `json:"location"`
	TimeZone   string `json:"timeZone"`
	Employment struct {
		Domain    string `json:"domain"`
		Name      string `json:"name"`
		Title     string `json:"title"`
		Seniority string `json:"seniority"`
		Role      string `json:"role"`
	} `json:"employment"`
	LinkedIn struct {
		Handle string `json:"handle"`
	} `json:"linkedin"`
	GitHub struct {
		Handle string `json:"handle"`
	} `json:"github"`
	Twitter struct {
		Handle string `json:"handle"`
	} `json:"twitter"`
}

func (m *Module) queryClearbit(ctx context.Context, email string, apiKey string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://person.clearbit.com/v2/people/find?email=%s", email)

	resp, err := m.get(ctx, u, map[string]string{
		"Authorization": "Bearer " + apiKey,
	})
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		return nil, fmt.Errorf("clearbit: %w", err)
	}

	var person clearbitPerson
	if err := json.Unmarshal(resp, &person); err != nil {
		return nil, fmt.Errorf("clearbit: parse: %w", err)
	}

	extra := map[string]string{
		"full_name":      person.Name.FullName,
		"location":       person.Location,
		"company":        person.Employment.Name,
		"job_title":      person.Employment.Title,
		"seniority":      person.Employment.Seniority,
		"role":           person.Employment.Role,
		"company_domain": person.Employment.Domain,
		"fonte":          "clearbit",
		"confidence":     "0.82",
	}
	if person.LinkedIn.Handle != "" {
		extra["linkedin"] = "https://linkedin.com/in/" + person.LinkedIn.Handle
	}
	if person.GitHub.Handle != "" {
		extra["github"] = "https://github.com/" + person.GitHub.Handle
	}
	if person.Twitter.Handle != "" {
		extra["twitter"] = "https://twitter.com/" + person.Twitter.Handle
	}

	return []module.Finding{{
		Type:     "email_person_record",
		URL:      fmt.Sprintf("https://clearbit.com/people/%s", person.ID),
		Detail:   fmt.Sprintf("Clearbit: email '%s' vinculado a '%s', %s em %s.", maskEmail(email), person.Name.FullName, person.Employment.Title, person.Employment.Name),
		Severity: module.SeverityMedium,
		Extra:    extra,
	}}, nil
}

// ─── Helpers técnicos ─────────────────────────────────────────────────────────

// detectEmailProvider identifica o provedor de email pelos servidores MX.
func detectEmailProvider(mxHosts []string) string {
	mxStr := strings.ToLower(strings.Join(mxHosts, " "))
	switch {
	case strings.Contains(mxStr, "google") || strings.Contains(mxStr, "googlemail"):
		return "Google Workspace / Gmail"
	case strings.Contains(mxStr, "outlook") || strings.Contains(mxStr, "microsoft"):
		return "Microsoft 365 / Outlook"
	case strings.Contains(mxStr, "yahoo"):
		return "Yahoo Mail"
	case strings.Contains(mxStr, "protonmail"):
		return "ProtonMail"
	case strings.Contains(mxStr, "zoho"):
		return "Zoho Mail"
	case strings.Contains(mxStr, "titan"):
		return "Titan Email"
	case strings.Contains(mxStr, "amazonaws") || strings.Contains(mxStr, "amazonses"):
		return "Amazon SES"
	case strings.Contains(mxStr, "sendgrid"):
		return "SendGrid"
	case strings.Contains(mxStr, "mailgun"):
		return "Mailgun"
	default:
		return "Custom / Unknown"
	}
}

// extractSPFPolicy extrai a política final do registro SPF.
func extractSPFPolicy(spf string) string {
	parts := strings.Fields(spf)
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.ToLower(parts[i])
		switch p {
		case "~all":
			return "softfail (~all)"
		case "-all":
			return "hardfail (-all)"
		case "+all":
			return "passall (+all) — INSEGURO"
		case "?all":
			return "neutral (?all)"
		}
	}
	return "sem política explícita"
}

// extractDMARCPolicy extrai a política do registro DMARC.
func extractDMARCPolicy(dmarc string) string {
	lower := strings.ToLower(dmarc)
	switch {
	case strings.Contains(lower, "p=reject"):
		return "reject (mais seguro)"
	case strings.Contains(lower, "p=quarantine"):
		return "quarantine"
	case strings.Contains(lower, "p=none"):
		return "none (monitoramento apenas)"
	default:
		return "desconhecida"
	}
}

// isDisposable verifica se o domínio é de email descartável.
func isDisposable(domain string) bool {
	disposableDomains := map[string]bool{
		"mailinator.com": true, "guerrillamail.com": true, "10minutemail.com": true,
		"tempmail.com": true, "throwaway.email": true, "yopmail.com": true,
		"sharklasers.com": true, "guerrillamailblock.com": true, "grr.la": true,
		"guerrillamail.info": true, "trashmail.me": true, "trashmail.at": true,
		"dispostable.com": true, "mailnull.com": true, "spam4.me": true,
		"mail.tm": true, "getairmail.com": true, "filzmail.com": true,
		"tempr.email": true, "zzrgg.com": true, "crap.email": true,
		"fakeinbox.com": true, "spamgourmet.com": true, "throwam.com": true,
	}
	return disposableDomains[strings.ToLower(domain)]
}

// isSuspiciousTLD verifica TLDs frequentemente usados para spam/phishing.
func isSuspiciousTLD(tld string) bool {
	suspicious := map[string]bool{
		"xyz": true, "tk": true, "ml": true, "ga": true, "cf": true,
		"gq": true, "pw": true, "top": true, "loan": true, "click": true,
		"download": true, "racing": true, "date": true, "review": true,
		"stream": true, "accountant": true, "faith": true,
	}
	return suspicious[strings.ToLower(tld)]
}

// domainTLD extrai o TLD de um domínio.
func domainTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

func (m *Module) get(ctx context.Context, rawURL string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "blackhorn-modules/1.0 (security research tool)")
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found (404)")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limit (429)")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("unauthorized (401)")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
}

// ─── Utilitários ──────────────────────────────────────────────────────────────

// maskEmail mascara email para logs (t***t@example.com)
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

func parseSources(s string) map[string]bool {
	if s == "all" || s == "" {
		return nil
	}
	m := map[string]bool{}
	for _, src := range strings.Split(s, ",") {
		src = strings.TrimSpace(strings.ToLower(src))
		if src != "" {
			m[src] = true
		}
	}
	return m
}

func sourceEnabled(enabled map[string]bool, source string) bool {
	if enabled == nil {
		return true
	}
	return enabled[source]
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
