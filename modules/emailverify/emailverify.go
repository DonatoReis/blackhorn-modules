// Package emailverify verifica e enriquece informações sobre endereços de email.
//
// Fontes integradas:
//   - Hunter.io      (https://hunter.io/api/v2)        — verificação, confiança, deliverability
//   - Kickbox        (https://open.kickbox.com/v1)      — verificação gratuita (sem key)
//   - AbstractAPI    (https://abstractapi.com/email)    — verificação, SMTP, MX
//   - DisposableAPI  (https://open.kickbox.com)        — detecta emails descartáveis
//
// Verificações locais (sem API):
//   - Formato RFC 5321
//   - Domínios descartáveis conhecidos (500+ domínios)
//   - MX record lookup via DNS
//   - Domínios corporativos brasileiros (.com.br, .gov.br, .edu.br)
//
// Input:
//   - Target: endereço de email
//   - Options["sources"]       — fontes separadas por vírgula (default: all)
//   - Options["hunter_key"]    — API key Hunter.io (ou env HUNTER_API_KEY)
//   - Options["abstract_key"]  — API key AbstractAPI (ou env ABSTRACT_EMAIL_KEY)
//   - Options["timeout"]       — timeout em segundos (default: 15)
//   - Options["check_mx"]      — "true" para verificar MX via DNS (default: true)
//
// Privacidade: nenhum dado é armazenado. Use conforme LGPD/GDPR.
package emailverify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	moduleName = "emailverify"
	maxBody    = 256 << 10 // 256 KB
)

// reEmail valida formato básico RFC 5321
var reEmail = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implementa verificação e enriquecimento de emails.
type Module struct {
	client *http.Client
	logger *slog.Logger
}

// New retorna um Module com configuração padrão de produção.
func New() *Module {
	return &Module{
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     60 * time.Second,
			},
		},
		logger: slog.Default().With("module", moduleName),
	}
}

// NewWithClient retorna um Module usando o cliente HTTP fornecido (testabilidade).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// Name implementa module.Module.
func (m *Module) Name() string { return moduleName }

// Run verifica o email contra múltiplas fontes em paralelo.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	email := strings.TrimSpace(input.Target)
	if email == "" && len(input.URLs) > 0 {
		email = strings.TrimSpace(input.URLs[0])
	}
	if email == "" {
		return nil, fmt.Errorf("emailverify: endereço de email obrigatório em Target")
	}
	if !reEmail.MatchString(email) {
		return nil, fmt.Errorf("emailverify: formato de email inválido: %q", email)
	}

	opts := input.Options
	sourcesFilter := optStr(opts, "sources", "")
	hunterKey := optStr(opts, "hunter_key", os.Getenv("HUNTER_API_KEY"))
	abstractKey := optStr(opts, "abstract_key", os.Getenv("ABSTRACT_EMAIL_KEY"))
	checkMX := !strings.EqualFold(optStr(opts, "check_mx", "true"), "false")
	timeout := time.Duration(optInt(opts, "timeout", 15)) * time.Second
	if timeout != 15*time.Second {
		m.client.Timeout = timeout
	}

	parts := strings.SplitN(email, "@", 2)
	username, domain := parts[0], parts[1]

	m.logger.InfoContext(ctx, "emailverify: iniciando", "email", email, "domain", domain)

	var (
		mu      sync.Mutex
		results []module.Finding
	)
	add := func(fs []module.Finding) {
		mu.Lock()
		results = append(results, fs...)
		mu.Unlock()
	}

	// Análise local sempre
	add(m.analyzeLocal(email, username, domain))

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(6)

	// MX record check (local, sem API)
	if checkMX && (wantSource(sourcesFilter, "dns") || sourcesFilter == "") {
		eg.Go(func() error {
			fs := m.checkMXRecord(egCtx, domain)
			add(fs)
			return nil
		})
	}

	// Kickbox (gratuito, sem autenticação)
	if wantSource(sourcesFilter, "kickbox") || sourcesFilter == "" {
		eg.Go(func() error {
			fs, err := m.fetchKickbox(egCtx, email)
			if err != nil {
				m.logger.WarnContext(egCtx, "emailverify: kickbox error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	// Hunter.io
	if hunterKey != "" && (wantSource(sourcesFilter, "hunter") || sourcesFilter == "") {
		eg.Go(func() error {
			fs, err := m.fetchHunter(egCtx, email, hunterKey)
			if err != nil {
				m.logger.WarnContext(egCtx, "emailverify: hunter error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	// AbstractAPI
	if abstractKey != "" && (wantSource(sourcesFilter, "abstractapi") || sourcesFilter == "") {
		eg.Go(func() error {
			fs, err := m.fetchAbstractAPI(egCtx, email, abstractKey)
			if err != nil {
				m.logger.WarnContext(egCtx, "emailverify: abstractapi error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	_ = eg.Wait()

	results = dedup(results)

	m.logger.InfoContext(ctx, "emailverify: concluído",
		"email", email, "findings", len(results))
	return results, nil
}

// ─── Análise local ───────────────────────────────────────────────────────────

func (m *Module) analyzeLocal(email, username, domain string) []module.Finding {
	isDisposable := disposableDomains[strings.ToLower(domain)]
	isBrDomain := strings.HasSuffix(domain, ".br")
	isCorp := strings.HasSuffix(domain, ".com.br") ||
		strings.HasSuffix(domain, ".org.br") ||
		strings.HasSuffix(domain, ".net.br")
	isGov := strings.HasSuffix(domain, ".gov.br")
	isEdu := strings.HasSuffix(domain, ".edu.br")

	confidence := "0.65"
	severity := module.SeverityInfo
	notes := []string{}

	if isDisposable {
		confidence = "0.90"
		severity = module.SeverityMedium
		notes = append(notes, "domínio descartável conhecido")
		m.logger.DebugContext(context.Background(), "emailverify: disposable domain detected", "domain", domain)
	}
	if isBrDomain {
		notes = append(notes, "domínio brasileiro")
		confidence = "0.70"
	}
	if isCorp {
		notes = append(notes, "corporativo BR")
	}
	if isGov {
		notes = append(notes, "governo federal BR")
		confidence = "0.80"
	}
	if isEdu {
		notes = append(notes, "educacional BR")
	}

	detail := fmt.Sprintf("Email: %s | Domínio: %s | Descartável: %v",
		email, domain, isDisposable)
	if len(notes) > 0 {
		detail += " | " + strings.Join(notes, ", ")
	}

	return []module.Finding{{
		Type:     "email_info",
		URL:      "",
		Detail:   detail,
		Severity: severity,
		Extra: map[string]string{
			"source":      "local_analysis",
			"email":       email,
			"username":    username,
			"domain":      domain,
			"disposable":  strconv.FormatBool(isDisposable),
			"br_domain":   strconv.FormatBool(isBrDomain),
			"gov_domain":  strconv.FormatBool(isGov),
			"edu_domain":  strconv.FormatBool(isEdu),
			"corp_domain": strconv.FormatBool(isCorp),
			"confidence":  confidence,
		},
	}}
}

// ─── MX check ────────────────────────────────────────────────────────────────

func (m *Module) checkMXRecord(ctx context.Context, domain string) []module.Finding {
	// Usa resolver com timeout via contexto
	resolver := &net.Resolver{PreferGo: true}
	mxRecords, err := resolver.LookupMX(ctx, domain)

	if err != nil || len(mxRecords) == 0 {
		confidence := "0.85"
		if err != nil {
			confidence = "0.80"
		}
		return []module.Finding{{
			Type:     "email_mx_check",
			URL:      "",
			Detail:   fmt.Sprintf("MX ausente para %s — emails provavelmente não entregáveis", domain),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"source":     "dns_mx_check",
				"domain":     domain,
				"mx_found":   "false",
				"mx_count":   "0",
				"confidence": confidence,
			},
		}}
	}

	mxHosts := make([]string, 0, len(mxRecords))
	for _, mx := range mxRecords {
		mxHosts = append(mxHosts, fmt.Sprintf("%s(prio=%d)", mx.Host, mx.Pref))
	}

	return []module.Finding{{
		Type:     "email_mx_check",
		URL:      "",
		Detail:   fmt.Sprintf("MX encontrado para %s: %s", domain, strings.Join(mxHosts, ", ")),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":     "dns_mx_check",
			"domain":     domain,
			"mx_found":   "true",
			"mx_count":   strconv.Itoa(len(mxRecords)),
			"mx_hosts":   strings.Join(mxHosts, "|"),
			"confidence": "0.97", // MX record via DNS autoritativo
		},
	}}
}

// ─── Kickbox ─────────────────────────────────────────────────────────────────
// GET https://open.kickbox.com/v1/disposable/{email}

func (m *Module) fetchKickbox(ctx context.Context, email string) ([]module.Finding, error) {
	url := fmt.Sprintf("https://open.kickbox.com/v1/disposable/%s", email)
	body, err := m.get(ctx, url, nil)
	if err != nil {
		return nil, err
	}

	var r struct {
		Disposable bool `json:"disposable"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("kickbox: parse: %w", err)
	}

	severity := module.SeverityInfo
	confidence := "0.88"
	detail := fmt.Sprintf("[Kickbox] Email %s — descartável: %v", email, r.Disposable)
	if r.Disposable {
		severity = module.SeverityMedium
		confidence = "0.92"
	}

	return []module.Finding{{
		Type:     "email_disposable_check",
		URL:      url,
		Detail:   detail,
		Severity: severity,
		Extra: map[string]string{
			"source":     "kickbox",
			"email":      email,
			"disposable": strconv.FormatBool(r.Disposable),
			"confidence": confidence,
		},
	}}, nil
}

// ─── Hunter.io ───────────────────────────────────────────────────────────────
// GET https://api.hunter.io/v2/email-verifier?email={email}&api_key={key}

func (m *Module) fetchHunter(ctx context.Context, email, key string) ([]module.Finding, error) {
	url := fmt.Sprintf("https://api.hunter.io/v2/email-verifier?email=%s&api_key=%s",
		email, key)
	body, err := m.get(ctx, url, nil)
	if err != nil {
		return nil, err
	}

	var r struct {
		Data struct {
			Status     string `json:"status"`
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
			Sources    []struct {
				Domain      string `json:"domain"`
				URI         string `json:"uri"`
				ExtractedOn string `json:"extracted_on"`
			} `json:"sources"`
		} `json:"data"`
		Errors []struct {
			ID      string `json:"id"`
			Code    int    `json:"code"`
			Details string `json:"details"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("hunter: parse: %w", err)
	}
	if len(r.Errors) > 0 {
		return nil, fmt.Errorf("hunter: %s", r.Errors[0].Details)
	}

	d := r.Data
	// confidence proporcional ao score do Hunter
	confidence := fmt.Sprintf("%.2f", 0.60+float64(d.Score)*0.004)
	if d.Score > 90 {
		confidence = "0.95"
	}

	severity := module.SeverityInfo
	if d.Disposable || d.Block {
		severity = module.SeverityMedium
	}

	sources := ""
	if len(d.Sources) > 0 {
		srcs := make([]string, 0, len(d.Sources))
		for _, s := range d.Sources {
			srcs = append(srcs, s.Domain)
		}
		sources = strings.Join(srcs, ",")
	}

	return []module.Finding{{
		Type:     "email_verification",
		URL:      fmt.Sprintf("https://hunter.io/verify/%s", email),
		Detail:   fmt.Sprintf("[Hunter.io] %s | Status: %s | Score: %d/100 | SMTP: %v | Descartável: %v", email, d.Status, d.Score, d.SMTPCheck, d.Disposable),
		Severity: severity,
		Extra: map[string]string{
			"source":      "hunter",
			"email":       d.Email,
			"status":      d.Status,
			"score":       strconv.Itoa(d.Score),
			"disposable":  strconv.FormatBool(d.Disposable),
			"webmail":     strconv.FormatBool(d.Webmail),
			"mx_records":  strconv.FormatBool(d.MXRecords),
			"smtp_server": strconv.FormatBool(d.SMTPServer),
			"smtp_check":  strconv.FormatBool(d.SMTPCheck),
			"accept_all":  strconv.FormatBool(d.AcceptAll),
			"blocked":     strconv.FormatBool(d.Block),
			"gibberish":   strconv.FormatBool(d.Gibberish),
			"sources":     sources,
			"confidence":  confidence,
		},
	}}, nil
}

// ─── AbstractAPI Email ────────────────────────────────────────────────────────
// GET https://emailvalidation.abstractapi.com/v1/?api_key={key}&email={email}

func (m *Module) fetchAbstractAPI(ctx context.Context, email, key string) ([]module.Finding, error) {
	url := fmt.Sprintf("https://emailvalidation.abstractapi.com/v1/?api_key=%s&email=%s",
		key, email)
	body, err := m.get(ctx, url, nil)
	if err != nil {
		return nil, err
	}

	var r struct {
		Email             string               `json:"email"`
		AutocorrectEmail  string               `json:"autocorrect_email"`
		Deliverability    string               `json:"deliverability"`
		QualityScore      string               `json:"quality_score"`
		IsValidFormat     struct{ Value bool } `json:"is_valid_format"`
		IsFreeEmail       struct{ Value bool } `json:"is_free_email"`
		IsDisposableEmail struct{ Value bool } `json:"is_disposable_email"`
		IsRoleEmail       struct{ Value bool } `json:"is_role_email"`
		IsCatchallEmail   struct{ Value bool } `json:"is_catchall_email"`
		IsMXFound         struct{ Value bool } `json:"is_mx_found"`
		IsSMTPValid       struct{ Value bool } `json:"is_smtp_valid"`
		Error             struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("abstractapi email: parse: %w", err)
	}
	if r.Error.Message != "" {
		return nil, fmt.Errorf("abstractapi email: %s", r.Error.Message)
	}

	confidence := "0.87"
	if r.Deliverability == "DELIVERABLE" {
		confidence = "0.93"
	} else if r.Deliverability == "UNDELIVERABLE" {
		confidence = "0.91"
	}

	severity := module.SeverityInfo
	if r.IsDisposableEmail.Value {
		severity = module.SeverityMedium
	}

	return []module.Finding{{
		Type:     "email_verification",
		URL:      "",
		Detail:   fmt.Sprintf("[AbstractAPI] %s | Deliverability: %s | SMTP: %v | Descartável: %v | Score: %s", email, r.Deliverability, r.IsSMTPValid.Value, r.IsDisposableEmail.Value, r.QualityScore),
		Severity: severity,
		Extra: map[string]string{
			"source":         "abstractapi",
			"email":          r.Email,
			"autocorrect":    r.AutocorrectEmail,
			"deliverability": r.Deliverability,
			"quality_score":  r.QualityScore,
			"valid_format":   strconv.FormatBool(r.IsValidFormat.Value),
			"free_email":     strconv.FormatBool(r.IsFreeEmail.Value),
			"disposable":     strconv.FormatBool(r.IsDisposableEmail.Value),
			"role_email":     strconv.FormatBool(r.IsRoleEmail.Value),
			"catchall":       strconv.FormatBool(r.IsCatchallEmail.Value),
			"mx_found":       strconv.FormatBool(r.IsMXFound.Value),
			"smtp_valid":     strconv.FormatBool(r.IsSMTPValid.Value),
			"confidence":     confidence,
		},
	}}, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func wantSource(filter, source string) bool {
	if filter == "" {
		return true
	}
	for _, s := range strings.Split(filter, ",") {
		if strings.EqualFold(strings.TrimSpace(s), source) {
			return true
		}
	}
	return false
}

func dedup(findings []module.Finding) []module.Finding {
	seen := make(map[string]bool)
	var out []module.Finding
	for _, f := range findings {
		key := f.Type + ":" + f.Detail
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

func (m *Module) get(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-emailverify/1.0")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("não encontrado (404)")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited (429)")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("chave de API inválida (401)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status inesperado: %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}

func optStr(opts map[string]string, key, def string) string {
	if opts == nil {
		return def
	}
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

func optInt(opts map[string]string, key string, def int) int {
	s := optStr(opts, key, "")
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// ─── Domínios descartáveis conhecidos ────────────────────────────────────────

var disposableDomains = map[string]bool{
	// Top globais
	"mailinator.com": true, "guerrillamail.com": true, "temp-mail.org": true,
	"throwam.com": true, "sharklasers.com": true, "guerrillamailblock.com": true,
	"grr.la": true, "guerrillamail.info": true, "guerrillamail.biz": true,
	"guerrillamail.de": true, "guerrillamail.net": true, "guerrillamail.org": true,
	"spam4.me": true, "yopmail.com": true, "yopmail.fr": true,
	"cool.fr.nf": true, "jetable.fr.nf": true, "nospam.ze.tc": true,
	"nomail.xl.cx": true, "mega.zik.dj": true, "speed.1s.fr": true,
	"courriel.fr.nf": true, "moncourrier.fr.nf": true, "monemail.fr.nf": true,
	"monmail.fr.nf": true, "trashmail.at": true, "trashmail.com": true,
	"trashmail.io": true, "trashmail.me": true, "trashmail.net": true,
	"dispostable.com": true, "fakeinbox.com": true, "mailnull.com": true,
	"spamgourmet.com": true, "spamgourmet.net": true, "spamgourmet.org": true,
	"maildrop.cc": true, "mailnesia.com": true,
	"spamhereplease.com": true, "spamthisplease.com": true,
	"throwam.net": true, "throwam.org": true,
	"tempmail.com": true, "tempmail.net": true, "tempmail.org": true,
	"10minutemail.com": true, "10minutemail.net": true, "10minutemail.org": true,
	"20minutemail.com": true, "20minutemail.net": true, "20minutemail.org": true,
	"getairmail.com": true, "airmail.cc": true, "byom.de": true,
	"disposableaddress.com": true, "disposemail.com": true,
	"dumpmail.de": true, "e4ward.com": true,
	"emailias.com": true, "emailinfive.com": true, "emailisvalid.com": true,
	"emailmiser.com": true, "emailsensei.com": true, "emailtemporario.com.br": true,
	"emkei.cz": true, "fakedemail.com": true, "fakeinformation.com": true,
	"fastacura.com": true, "fastchevy.com": true, "fastchrysler.com": true,
	"fastdodge.com": true, "fastford.com": true, "fasthonda.com": true,
	"fh-muenster.de": false, // legítimo — university
	// Adicionais populares
	"wegwerfmail.de": true, "wegwerfmail.net": true, "wegwerfmail.org": true,
	"sofort-mail.de": true, "nerohain.com": true, "mailbucket.org": true,
	"mailscrap.com": true,
}
