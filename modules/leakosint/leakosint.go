// Package leakosint combina múltiplas fontes de OSINT de dados vazados.
//
// Fontes integradas:
//   - Intelligence X (IntelX)  — maior repositório de dados vazados; busca por email/domínio/IP/Bitcoin/etc.
//   - BreachDirectory          — API gratuita de breaches; busca por email/usuário/domínio/senha/hash
//   - HudsonRock               — Cavalier DB; credenciais corporativas de info-stealers
//   - Leak-Lookup (LeakLookup) — agregador de breaches; busca por email/domínio/hash
//
// Tipos de busca suportados:
//   - email     — endereço de e-mail
//   - domain    — domínio (example.com)
//   - username  — nome de usuário
//   - ip        — endereço IP
//   - hash      — hash de senha (MD5/SHA1/SHA256)
//
// Input:
//   - Target: o termo de busca
//   - Options["intelx_key"]        — API key IntelX (obrigatória para IntelX)
//   - Options["breachdirectory_key"] — API key BreachDirectory (obrigatória)
//   - Options["leaklookup_key"]    — API key Leak-Lookup (obrigatória)
//   - Options["sources"]           — fontes separadas por vírgula (default: all)
//   - Options["max_results"]       — máximo de resultados (default: 20)
//   - Options["search_type"]       — tipo de busca: email/domain/username/ip/hash (auto-detect)
//
// Segurança:
//
//	Senhas e hashes nunca aparecem em clear text nos findings.
//	Passwords são truncadas: primeiros 3 chars + "***".
package leakosint

import (
	"bytes"
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
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	maxBodyBytes   = 4 << 20
	defaultTimeout = 30
	defaultMax     = 20
)

var (
	reEmail  = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	reIP     = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	reHash   = regexp.MustCompile(`^[a-fA-F0-9]{32,64}$`)
	reDomain = regexp.MustCompile(`^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$`)
)

// SearchType classifica o tipo de busca.
type SearchType string

const (
	SearchEmail    SearchType = "email"
	SearchDomain   SearchType = "domain"
	SearchUsername SearchType = "username"
	SearchIP       SearchType = "ip"
	SearchHash     SearchType = "hash"
)

// Module implementa o módulo leakosint.
type Module struct {
	client *http.Client
}

// New cria um módulo com cliente padrão.
func New() *Module {
	return NewWithClient(&http.Client{Timeout: time.Duration(defaultTimeout) * time.Second})
}

// NewWithClient cria um módulo com cliente customizado.
func NewWithClient(c *http.Client) *Module {
	return &Module{client: c}
}

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "leakosint" }

// Run executa buscas em múltiplas fontes de dados vazados.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("leakosint: target não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	maxResults := optInt(opts, "max_results", defaultMax)
	enabledSources := parseSources(optStr(opts, "sources", "all"))

	intelxKey := firstNonEmpty(opts["intelx_key"], os.Getenv("INTELX_API_KEY"))
	bdKey := firstNonEmpty(opts["breachdirectory_key"], os.Getenv("BREACHDIRECTORY_API_KEY"))
	llKey := firstNonEmpty(opts["leaklookup_key"], os.Getenv("LEAKLOOKUP_API_KEY"))

	searchType := detectSearchType(target, optStr(opts, "search_type", ""))

	slog.InfoContext(ctx, "leakosint: iniciando busca",
		"search_type", string(searchType),
		"has_intelx", intelxKey != "",
		"has_breachdirectory", bdKey != "",
		"has_leaklookup", llKey != "",
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

	eg, ctx2 := errgroup.WithContext(ctx)
	eg.SetLimit(4)

	// IntelX — melhor para email, domínio, IP
	if intelxKey != "" && sourceEnabled(enabledSources, "intelx") {
		eg.Go(func() error {
			ff, err := m.queryIntelX(ctx2, target, searchType, intelxKey, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "leakosint: intelx falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// BreachDirectory — email/username/domain/hash
	if bdKey != "" && sourceEnabled(enabledSources, "breachdirectory") {
		eg.Go(func() error {
			ff, err := m.queryBreachDirectory(ctx2, target, searchType, bdKey, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "leakosint: breachdirectory falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// HudsonRock (Cavalier DB) — grátis para domínio, email
	if sourceEnabled(enabledSources, "hudsonrock") &&
		(searchType == SearchEmail || searchType == SearchDomain) {
		eg.Go(func() error {
			ff, err := m.queryHudsonRock(ctx2, target, searchType, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "leakosint: hudsonrock falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Leak-Lookup
	if llKey != "" && sourceEnabled(enabledSources, "leaklookup") {
		eg.Go(func() error {
			ff, err := m.queryLeakLookup(ctx2, target, searchType, llKey, maxResults)
			if err != nil {
				slog.WarnContext(ctx2, "leakosint: leaklookup falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	_ = eg.Wait()

	result := dedup(findings)

	slog.InfoContext(ctx, "leakosint: concluído",
		"total_findings", len(result),
	)

	return result, nil
}

// ─── Intelligence X ──────────────────────────────────────────────────────────

func (m *Module) queryIntelX(ctx context.Context, target string, searchType SearchType, apiKey string, max int) ([]module.Finding, error) {
	// Passo 1: iniciar busca e obter ID
	searchPayload := map[string]interface{}{
		"term":        target,
		"buckets":     []interface{}{},
		"timeout":     20,
		"datefrom":    "",
		"dateto":      "",
		"sort":        4,
		"media":       0,
		"terminate":   []interface{}{},
		"maxresults":  clampMax(max, 100),
		"lookuplevel": 0,
	}

	body, err := json.Marshal(searchPayload)
	if err != nil {
		return nil, fmt.Errorf("intelx: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://2.intelx.io/intelligent/search", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("intelx: request: %w", err)
	}
	req.Header.Set("x-key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("intelx: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("intelx: API key inválida")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("intelx: status %d", resp.StatusCode)
	}

	searchBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("intelx: read: %w", err)
	}

	var searchResp struct {
		ID     string `json:"id"`
		Status int    `json:"status"`
	}
	if err := json.Unmarshal(searchBody, &searchResp); err != nil {
		return nil, fmt.Errorf("intelx: parse search: %w", err)
	}

	if searchResp.ID == "" {
		return nil, nil
	}

	// Passo 2: obter resultados
	resultsURL := fmt.Sprintf("https://2.intelx.io/intelligent/search/result?id=%s&limit=%d&offset=0",
		url.QueryEscape(searchResp.ID), clampMax(max, 100))

	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, resultsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("intelx: results request: %w", err)
	}
	req2.Header.Set("x-key", apiKey)

	resp2, err := m.client.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("intelx: results http: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode >= 400 {
		return nil, fmt.Errorf("intelx: results status %d", resp2.StatusCode)
	}

	resultsBody, err := io.ReadAll(io.LimitReader(resp2.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("intelx: results read: %w", err)
	}

	var resultsResp struct {
		Records []struct {
			SystemID string `json:"systemid"`
			Type     int    `json:"type"`
			Media    int    `json:"media"`
			Added    string `json:"added"`
			Date     string `json:"date"`
			Name     string `json:"name"`
			Bucket   string `json:"bucket"`
		} `json:"records"`
		Status int `json:"status"`
	}
	if err := json.Unmarshal(resultsBody, &resultsResp); err != nil {
		return nil, fmt.Errorf("intelx: parse results: %w", err)
	}

	if len(resultsResp.Records) == 0 {
		return nil, nil
	}

	var findings []module.Finding

	findings = append(findings, module.Finding{
		Type:     "intelx_summary",
		URL:      "https://intelx.io/?s=" + url.QueryEscape(target),
		Detail:   fmt.Sprintf("Intelligence X encontrou %d registros para '%s'.", len(resultsResp.Records), maskTarget(target, searchType)),
		Severity: severityByCount(len(resultsResp.Records)),
		Extra: map[string]string{
			"total_records": fmt.Sprintf("%d", len(resultsResp.Records)),
			"search_id":     searchResp.ID,
			"fonte":         "intelx",
			"confidence":    "0.88",
		},
	})

	for _, rec := range resultsResp.Records {
		findings = append(findings, module.Finding{
			Type: "intelx_record",
			URL:  fmt.Sprintf("https://intelx.io/search?selectorid=%s", url.QueryEscape(rec.SystemID)),
			Detail: fmt.Sprintf("IntelX: arquivo '%s' (bucket: %s) indexado em %s contém dados de '%s'.",
				rec.Name, rec.Bucket, rec.Date, maskTarget(target, searchType)),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"system_id":  rec.SystemID,
				"name":       rec.Name,
				"bucket":     rec.Bucket,
				"date":       rec.Date,
				"media_type": fmt.Sprintf("%d", rec.Media),
				"fonte":      "intelx",
				"confidence": "0.85",
			},
		})
	}

	return findings, nil
}

// ─── BreachDirectory ──────────────────────────────────────────────────────────

func (m *Module) queryBreachDirectory(ctx context.Context, target string, searchType SearchType, apiKey string, max int) ([]module.Finding, error) {
	// BreachDirectory suporta: email, username, password, hashedpassword, domain, VIN, phone
	bdType := breachDirType(searchType)

	u := fmt.Sprintf("https://breachdirectory.p.rapidapi.com/?func=auto&term=%s",
		url.QueryEscape(target))

	respBody, err := m.get(ctx, u, map[string]string{
		"x-rapidapi-host": "breachdirectory.p.rapidapi.com",
		"x-rapidapi-key":  apiKey,
	})
	if err != nil {
		return nil, fmt.Errorf("breachdirectory: %w", err)
	}

	var result struct {
		Found  int `json:"found"`
		Result []struct {
			Sources  []string `json:"sources"`
			Password string   `json:"password"`
			SHA1     string   `json:"sha1"`
		} `json:"result"`
		Error  bool   `json:"error"`
		Reason string `json:"reason"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("breachdirectory: parse: %w", err)
	}

	if result.Error {
		if strings.Contains(strings.ToLower(result.Reason), "not found") {
			return nil, nil
		}
		return nil, fmt.Errorf("breachdirectory: %s", result.Reason)
	}

	if result.Found == 0 || len(result.Result) == 0 {
		return nil, nil
	}

	var findings []module.Finding

	findings = append(findings, module.Finding{
		Type:     "breachdirectory_summary",
		URL:      "https://breachdirectory.org",
		Detail:   fmt.Sprintf("BreachDirectory encontrou %d entradas para '%s' (tipo: %s).", result.Found, maskTarget(target, searchType), bdType),
		Severity: severityByCount(result.Found),
		Extra: map[string]string{
			"total_found": fmt.Sprintf("%d", result.Found),
			"search_type": bdType,
			"fonte":       "breachdirectory",
			"confidence":  "0.90",
		},
	})

	shown := 0
	for _, r := range result.Result {
		if shown >= clampMax(max, 50) {
			break
		}

		sourceStr := strings.Join(r.Sources, ", ")
		hasPassword := r.Password != "" || r.SHA1 != ""

		detail := fmt.Sprintf("BreachDirectory: '%s' encontrado em: %s.", maskTarget(target, searchType), sourceStr)
		if hasPassword {
			detail += " Senha comprometida."
		}

		findings = append(findings, module.Finding{
			Type:     "breach_record",
			URL:      "https://breachdirectory.org",
			Detail:   detail,
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"sources":          sourceStr,
				"password_exposed": fmt.Sprintf("%v", hasPassword),
				"has_hash":         fmt.Sprintf("%v", r.SHA1 != ""),
				"hash_prefix":      hashPrefix(r.SHA1),
				"fonte":            "breachdirectory",
				"confidence":       "0.90",
			},
		})
		shown++
	}

	return findings, nil
}

// ─── HudsonRock (Cavalier DB) ────────────────────────────────────────────────

func (m *Module) queryHudsonRock(ctx context.Context, target string, searchType SearchType, max int) ([]module.Finding, error) {
	var u string
	switch searchType {
	case SearchEmail:
		u = fmt.Sprintf("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=%s",
			url.QueryEscape(target))
	case SearchDomain:
		u = fmt.Sprintf("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=%s",
			url.QueryEscape(target))
	default:
		return nil, nil
	}

	respBody, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("hudsonrock: %w", err)
	}

	var result struct {
		Stealers []struct {
			ComputerName    string `json:"computer_name"`
			OperatingSystem string `json:"operating_system"`
			MalwareFamily   string `json:"malware_family"`
			DateCompromised string `json:"date_compromised"`
			Country         string `json:"country"`
			Credentials     []struct {
				Username string `json:"username"`
				Password string `json:"password"`
				URL      string `json:"url"`
			} `json:"credentials"`
		} `json:"stealers"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("hudsonrock: parse: %w", err)
	}

	if len(result.Stealers) == 0 {
		return nil, nil
	}

	var findings []module.Finding

	totalCreds := 0
	for _, s := range result.Stealers {
		totalCreds += len(s.Credentials)
	}

	findings = append(findings, module.Finding{
		Type: "infostealer_summary",
		URL:  "https://cavalier.hudsonrock.com",
		Detail: fmt.Sprintf("HudsonRock: '%s' aparece em %d infecção(ões) de info-stealer com %d credencial(is) comprometida(s).",
			maskTarget(target, searchType), len(result.Stealers), totalCreds),
		Severity: module.SeverityCritical,
		Extra: map[string]string{
			"total_stealers":    fmt.Sprintf("%d", len(result.Stealers)),
			"total_credentials": fmt.Sprintf("%d", totalCreds),
			"fonte":             "hudsonrock",
			"confidence":        "0.92",
		},
	})

	shown := 0
	for _, s := range result.Stealers {
		if shown >= clampMax(max, 50) {
			break
		}

		credURLs := make([]string, 0, len(s.Credentials))
		for _, c := range s.Credentials {
			if c.URL != "" {
				credURLs = append(credURLs, c.URL)
			}
		}

		findings = append(findings, module.Finding{
			Type: "infostealer_record",
			URL:  "https://cavalier.hudsonrock.com",
			Detail: fmt.Sprintf("Info-stealer '%s' comprometeu dispositivo %s (%s/%s) em %s. Credenciais para: %s.",
				s.MalwareFamily, s.ComputerName, s.OperatingSystem, s.Country, s.DateCompromised,
				truncate(strings.Join(credURLs, ", "), 200)),
			Severity: module.SeverityCritical,
			Extra: map[string]string{
				"malware_family":   s.MalwareFamily,
				"computer_name":    s.ComputerName,
				"operating_system": s.OperatingSystem,
				"country":          s.Country,
				"date_compromised": s.DateCompromised,
				"total_creds":      fmt.Sprintf("%d", len(s.Credentials)),
				"fonte":            "hudsonrock",
				"confidence":       "0.92",
			},
		})
		shown++
	}

	return findings, nil
}

// ─── Leak-Lookup ─────────────────────────────────────────────────────────────

func (m *Module) queryLeakLookup(ctx context.Context, target string, searchType SearchType, apiKey string, max int) ([]module.Finding, error) {
	llType := leakLookupType(searchType)
	if llType == "" {
		return nil, nil
	}

	u := fmt.Sprintf("https://leak-lookup.com/api/search?type=%s&query=%s",
		url.QueryEscape(llType), url.QueryEscape(target))

	respBody, err := m.get(ctx, u, map[string]string{
		"X-API-Key": apiKey,
	})
	if err != nil {
		return nil, fmt.Errorf("leaklookup: %w", err)
	}

	var result struct {
		Error   int    `json:"error"`
		Message string `json:"message"`
		Sources map[string][]struct {
			Email    string `json:"email"`
			Username string `json:"username"`
			Password string `json:"password"`
			Hash     string `json:"hash"`
			Name     string `json:"name"`
		} `json:"sources"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("leaklookup: parse: %w", err)
	}

	if result.Error != 0 {
		if strings.Contains(strings.ToLower(result.Message), "no results") ||
			strings.Contains(strings.ToLower(result.Message), "not found") {
			return nil, nil
		}
		return nil, fmt.Errorf("leaklookup: %s", result.Message)
	}

	if len(result.Sources) == 0 {
		return nil, nil
	}

	var findings []module.Finding

	totalRecords := 0
	for _, records := range result.Sources {
		totalRecords += len(records)
	}

	findings = append(findings, module.Finding{
		Type:     "leaklookup_summary",
		URL:      "https://leak-lookup.com",
		Detail:   fmt.Sprintf("Leak-Lookup encontrou '%s' em %d fonte(s) com %d registro(s) total.", maskTarget(target, searchType), len(result.Sources), totalRecords),
		Severity: severityByCount(totalRecords),
		Extra: map[string]string{
			"total_sources": fmt.Sprintf("%d", len(result.Sources)),
			"total_records": fmt.Sprintf("%d", totalRecords),
			"fonte":         "leaklookup",
			"confidence":    "0.87",
		},
	})

	shown := 0
	for source, records := range result.Sources {
		for _, rec := range records {
			if shown >= clampMax(max, 100) {
				break
			}

			hasPassword := rec.Password != "" || rec.Hash != ""
			detail := fmt.Sprintf("Leak-Lookup: '%s' encontrado na fonte '%s'.", maskTarget(target, searchType), source)
			if hasPassword {
				detail += " Senha comprometida."
			}

			findings = append(findings, module.Finding{
				Type:     "leak_record",
				URL:      "https://leak-lookup.com",
				Detail:   detail,
				Severity: module.SeverityHigh,
				Extra: map[string]string{
					"source":           source,
					"password_exposed": fmt.Sprintf("%v", hasPassword),
					"hash_prefix":      hashPrefix(rec.Hash),
					"fonte":            "leaklookup",
					"confidence":       "0.87",
				},
			})
			shown++
		}
	}

	return findings, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func detectSearchType(target, override string) SearchType {
	if override != "" {
		switch strings.ToLower(override) {
		case "email":
			return SearchEmail
		case "domain":
			return SearchDomain
		case "username":
			return SearchUsername
		case "ip":
			return SearchIP
		case "hash":
			return SearchHash
		}
	}

	if reEmail.MatchString(target) {
		return SearchEmail
	}
	if reIP.MatchString(target) {
		return SearchIP
	}
	if reHash.MatchString(target) {
		return SearchHash
	}
	if reDomain.MatchString(target) {
		return SearchDomain
	}
	return SearchUsername
}

func maskTarget(target string, searchType SearchType) string {
	switch searchType {
	case SearchEmail:
		parts := strings.SplitN(target, "@", 2)
		if len(parts) != 2 {
			return target
		}
		local := parts[0]
		if len(local) <= 2 {
			return local + "@" + parts[1]
		}
		return local[:1] + strings.Repeat("*", len(local)-2) + local[len(local)-1:] + "@" + parts[1]
	case SearchIP:
		parts := strings.Split(target, ".")
		if len(parts) != 4 {
			return target
		}
		return parts[0] + "." + parts[1] + ".***." + "***"
	default:
		if len(target) <= 3 {
			return target
		}
		return target[:3] + strings.Repeat("*", len(target)-3)
	}
}

func hashPrefix(h string) string {
	if len(h) < 8 {
		return ""
	}
	return h[:8] + "..."
}

func breachDirType(st SearchType) string {
	switch st {
	case SearchEmail:
		return "email"
	case SearchDomain:
		return "domain"
	case SearchHash:
		return "hash"
	default:
		return "username"
	}
}

func leakLookupType(st SearchType) string {
	switch st {
	case SearchEmail:
		return "email_address"
	case SearchDomain:
		return "domain"
	case SearchHash:
		return "hash"
	case SearchUsername:
		return "username"
	default:
		return ""
	}
}

func severityByCount(count int) module.Severity {
	switch {
	case count >= 100:
		return module.SeverityCritical
	case count >= 10:
		return module.SeverityHigh
	case count >= 1:
		return module.SeverityMedium
	default:
		return module.SeverityInfo
	}
}

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

	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, fmt.Errorf("not found (404)")
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("não autorizado (%d)", resp.StatusCode)
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("rate limit (429)")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
}

func clampMax(val, max int) int {
	if val <= 0 {
		return defaultMax
	}
	if val > max {
		return max
	}
	return val
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
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
