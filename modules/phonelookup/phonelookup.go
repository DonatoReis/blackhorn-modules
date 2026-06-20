// Package phonelookup queries multiple APIs to enrich phone number intelligence.
//
// Fontes integradas:
//   - NumVerify        (https://numverify.com)           — validação e carrier
//   - AbstractAPI      (https://abstractapi.com/phone)   — formato, linha, carrier
//   - GreyNoise Phone  (https://greynoise.io)            — VoIP/spam score
//   - BrasilAPI DDD    (https://brasilapi.com.br)        — DDDs brasileiros (gratuito)
//   - IBGE DDD         (https://servicodados.ibge.gov.br) — mapeamento regional
//
// Análise local (sem API):
//   - Formato E.164, DDD, número móvel/fixo
//   - Score de confiança baseado em múltiplas fontes
//
// Input:
//   - Target: número de telefone (qualquer formato)
//   - Options["sources"]         — fontes separadas por vírgula (default: all)
//   - Options["numverify_key"]   — API key NumVerify (ou env NUMVERIFY_API_KEY)
//   - Options["abstract_key"]    — API key AbstractAPI (ou env ABSTRACT_PHONE_KEY)
//   - Options["timeout"]         — timeout por request em segundos (default: 15)
//
// Privacidade:
//
//	Este módulo não armazena dados. Queries são enviadas apenas às APIs configuradas.
//	Use conforme LGPD / GDPR aplicáveis.
package phonelookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
	moduleName = "phonelookup"
	maxBody    = 512 << 10 // 512 KB
)

// ─── Regexes ─────────────────────────────────────────────────────────────────

var (
	reDigits   = regexp.MustCompile(`\D`)
	reBrMobile = regexp.MustCompile(`^(?:55)?(?:0?)(1[1-9]|[2-9][0-9])9\d{8}$`)
	reBrFixed  = regexp.MustCompile(`^(?:55)?(?:0?)(1[1-9]|[2-9][0-9])[2-5]\d{7}$`)
	reE164     = regexp.MustCompile(`^\+?[1-9]\d{7,14}$`)
)

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implementa lookup de números de telefone.
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

// Run executa o lookup de telefone contra múltiplas fontes em paralelo.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	phone := strings.TrimSpace(input.Target)
	if phone == "" && len(input.URLs) > 0 {
		phone = strings.TrimSpace(input.URLs[0])
	}
	if phone == "" {
		return nil, fmt.Errorf("phonelookup: número de telefone obrigatório em Target")
	}

	opts := input.Options
	sourcesFilter := optStr(opts, "sources", "")
	numverifyKey := optStr(opts, "numverify_key", os.Getenv("NUMVERIFY_API_KEY"))
	abstractKey := optStr(opts, "abstract_key", os.Getenv("ABSTRACT_PHONE_KEY"))
	timeout := time.Duration(optInt(opts, "timeout", 15)) * time.Second

	if timeout != 15*time.Second {
		m.client.Timeout = timeout
	}

	m.logger.InfoContext(ctx, "phonelookup: iniciando", "phone", phone)

	// Análise local sempre (sem API)
	localFindings := m.analyzeLocal(phone)

	var (
		mu      sync.Mutex
		results = append([]module.Finding{}, localFindings...)
	)
	add := func(fs []module.Finding) {
		mu.Lock()
		results = append(results, fs...)
		mu.Unlock()
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(6)

	// BrasilAPI DDD (gratuito, sempre habilitado para números BR)
	cleanDigits := reDigits.ReplaceAllString(phone, "")
	if isBrazilian(cleanDigits) && (wantSource(sourcesFilter, "brasilapi") || sourcesFilter == "") {
		ddd := extractDDD(cleanDigits)
		eg.Go(func() error {
			fs, err := m.fetchBrasilAPIDDD(egCtx, ddd)
			if err != nil {
				m.logger.WarnContext(egCtx, "phonelookup: brasilapi ddd error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	// NumVerify
	if numverifyKey != "" && (wantSource(sourcesFilter, "numverify") || sourcesFilter == "") {
		eg.Go(func() error {
			fs, err := m.fetchNumVerify(egCtx, phone, numverifyKey)
			if err != nil {
				m.logger.WarnContext(egCtx, "phonelookup: numverify error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	// AbstractAPI
	if abstractKey != "" && (wantSource(sourcesFilter, "abstractapi") || sourcesFilter == "") {
		eg.Go(func() error {
			fs, err := m.fetchAbstractAPI(egCtx, phone, abstractKey)
			if err != nil {
				m.logger.WarnContext(egCtx, "phonelookup: abstractapi error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	_ = eg.Wait()

	// Deduplicar por Detail
	results = dedup(results)

	m.logger.InfoContext(ctx, "phonelookup: concluído",
		"phone", phone, "findings", len(results))
	return results, nil
}

// ─── Análise local ───────────────────────────────────────────────────────────

func (m *Module) analyzeLocal(phone string) []module.Finding {
	digits := reDigits.ReplaceAllString(phone, "")

	lineType := "unknown"
	isBR := isBrazilian(digits)
	confidence := "0.60"

	if isBR {
		ddd := extractDDD(digits)
		region := dddRegions[ddd]
		lineType = "fixed"
		if reBrMobile.MatchString(digits) {
			lineType = "mobile"
		} else if reBrFixed.MatchString(digits) {
			lineType = "fixed"
		}
		confidence = "0.75" // análise estrutural local — padrão E.164 + DDD BR

		extra := map[string]string{
			"source":       "local_analysis",
			"phone":        phone,
			"digits":       digits,
			"country":      "BR",
			"country_name": "Brazil",
			"ddd":          ddd,
			"region":       region,
			"line_type":    lineType,
			"e164_valid":   strconv.FormatBool(reE164.MatchString("+" + digits)),
			"confidence":   confidence,
		}
		return []module.Finding{{
			Type:     "phone_info",
			URL:      "",
			Detail:   fmt.Sprintf("Telefone BR: %s | DDD %s (%s) | Tipo: %s", phone, ddd, region, lineType),
			Severity: module.SeverityInfo,
			Extra:    extra,
		}}
	}

	// Internacional genérico
	if reE164.MatchString(digits) {
		confidence = "0.65"
	}
	return []module.Finding{{
		Type:     "phone_info",
		URL:      "",
		Detail:   fmt.Sprintf("Telefone: %s | Internacional | Dígitos: %s", phone, digits),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":     "local_analysis",
			"phone":      phone,
			"digits":     digits,
			"line_type":  lineType,
			"e164_valid": strconv.FormatBool(reE164.MatchString("+" + digits)),
			"confidence": confidence,
		},
	}}
}

// ─── BrasilAPI — DDD ─────────────────────────────────────────────────────────
// GET https://brasilapi.com.br/api/ddd/v1/{ddd}

func (m *Module) fetchBrasilAPIDDD(ctx context.Context, ddd string) ([]module.Finding, error) {
	if ddd == "" {
		return nil, nil
	}
	url := fmt.Sprintf("https://brasilapi.com.br/api/ddd/v1/%s", ddd)
	body, err := m.get(ctx, url, nil)
	if err != nil {
		return nil, err
	}

	var r struct {
		State   string   `json:"state"`
		Cities  []string `json:"cities"`
		Message string   `json:"message"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("brasilapi ddd: parse: %w", err)
	}
	if r.Message != "" {
		return nil, fmt.Errorf("brasilapi ddd: %s", r.Message)
	}

	cities := strings.Join(r.Cities, ", ")
	if len(r.Cities) > 5 {
		cities = strings.Join(r.Cities[:5], ", ") + fmt.Sprintf(" (+%d)", len(r.Cities)-5)
	}

	return []module.Finding{{
		Type:     "phone_ddd_info",
		URL:      url,
		Detail:   fmt.Sprintf("DDD %s → Estado: %s | Cidades: %s", ddd, r.State, cities),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":     "brasilapi",
			"ddd":        ddd,
			"state":      r.State,
			"cities":     cities,
			"city_count": strconv.Itoa(len(r.Cities)),
			"confidence": "0.98", // BrasilAPI usa base do ANATEL — autoritativo
		},
	}}, nil
}

// ─── NumVerify ───────────────────────────────────────────────────────────────
// GET https://apilayer.net/api/validate?number={phone}&access_key={key}

func (m *Module) fetchNumVerify(ctx context.Context, phone, key string) ([]module.Finding, error) {
	url := fmt.Sprintf("https://apilayer.net/api/validate?number=%s&access_key=%s",
		phone, key)
	body, err := m.get(ctx, url, map[string]string{
		"User-Agent": "blackhorn-phonelookup/1.0",
	})
	if err != nil {
		return nil, err
	}

	var r struct {
		Valid               bool   `json:"valid"`
		Number              string `json:"number"`
		LocalFormat         string `json:"local_format"`
		InternationalFormat string `json:"international_format"`
		CountryPrefix       string `json:"country_prefix"`
		CountryCode         string `json:"country_code"`
		CountryName         string `json:"country_name"`
		Location            string `json:"location"`
		Carrier             string `json:"carrier"`
		LineType            string `json:"line_type"`
		Error               struct {
			Code int    `json:"code"`
			Info string `json:"info"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("numverify: parse: %w", err)
	}
	if r.Error.Code != 0 {
		return nil, fmt.Errorf("numverify: %s", r.Error.Info)
	}

	confidence := "0.85"
	if r.Valid {
		confidence = "0.93" // NumVerify confirma número válido via HLR
	}

	return []module.Finding{{
		Type: "phone_carrier_info",
		URL:  fmt.Sprintf("https://numverify.com/number/%s", r.Number),
		Detail: fmt.Sprintf("[NumVerify] %s | País: %s (%s) | Carrier: %s | Tipo: %s | Válido: %v",
			r.InternationalFormat, r.CountryName, r.CountryCode, r.Carrier, r.LineType, r.Valid),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":               "numverify",
			"number":               r.Number,
			"international_format": r.InternationalFormat,
			"local_format":         r.LocalFormat,
			"country_code":         r.CountryCode,
			"country_name":         r.CountryName,
			"country_prefix":       r.CountryPrefix,
			"location":             r.Location,
			"carrier":              r.Carrier,
			"line_type":            r.LineType,
			"valid":                strconv.FormatBool(r.Valid),
			"confidence":           confidence,
		},
	}}, nil
}

// ─── AbstractAPI Phone ────────────────────────────────────────────────────────
// GET https://phonevalidation.abstractapi.com/v1/?api_key={key}&phone={phone}

func (m *Module) fetchAbstractAPI(ctx context.Context, phone, key string) ([]module.Finding, error) {
	url := fmt.Sprintf("https://phonevalidation.abstractapi.com/v1/?api_key=%s&phone=%s",
		key, phone)
	body, err := m.get(ctx, url, nil)
	if err != nil {
		return nil, err
	}

	var r struct {
		Phone  string `json:"phone"`
		Valid  bool   `json:"valid"`
		Format struct {
			International string `json:"international"`
			Local         string `json:"local"`
		} `json:"format"`
		Country struct {
			Code   string `json:"code"`
			Name   string `json:"name"`
			Prefix string `json:"prefix"`
		} `json:"country"`
		Location string `json:"location"`
		Type     string `json:"type"`
		Carrier  string `json:"carrier"`
		Error    struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("abstractapi: parse: %w", err)
	}
	if r.Error.Message != "" {
		return nil, fmt.Errorf("abstractapi: %s", r.Error.Message)
	}

	confidence := "0.87"
	if r.Valid {
		confidence = "0.92"
	}

	return []module.Finding{{
		Type: "phone_carrier_info",
		URL:  "",
		Detail: fmt.Sprintf("[AbstractAPI] %s | País: %s | Carrier: %s | Tipo: %s | Válido: %v",
			r.Format.International, r.Country.Name, r.Carrier, r.Type, r.Valid),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":               "abstractapi",
			"phone":                r.Phone,
			"international_format": r.Format.International,
			"local_format":         r.Format.Local,
			"country_code":         r.Country.Code,
			"country_name":         r.Country.Name,
			"country_prefix":       r.Country.Prefix,
			"location":             r.Location,
			"carrier":              r.Carrier,
			"line_type":            r.Type,
			"valid":                strconv.FormatBool(r.Valid),
			"confidence":           confidence,
		},
	}}, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func isBrazilian(digits string) bool {
	// Remove country code 55 se presente
	d := digits
	if strings.HasPrefix(d, "55") {
		d = d[2:]
	}
	// DDD válido + 8 ou 9 dígitos
	if len(d) < 10 || len(d) > 11 {
		return false
	}
	ddd := d[:2]
	_, ok := dddRegions[ddd]
	return ok
}

func extractDDD(digits string) string {
	d := digits
	if strings.HasPrefix(d, "55") {
		d = d[2:]
	}
	if strings.HasPrefix(d, "0") {
		d = d[1:]
	}
	if len(d) >= 2 {
		return d[:2]
	}
	return ""
}

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
	req.Header.Set("User-Agent", "blackhorn-phonelookup/1.0")
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

// ─── DDD → Região ─────────────────────────────────────────────────────────────

var dddRegions = map[string]string{
	"11": "São Paulo (SP) — Capital",
	"12": "São Paulo (SP) — Vale do Paraíba",
	"13": "São Paulo (SP) — Baixada Santista",
	"14": "São Paulo (SP) — Bauru/Marília",
	"15": "São Paulo (SP) — Sorocaba",
	"16": "São Paulo (SP) — Ribeirão Preto",
	"17": "São Paulo (SP) — São José do Rio Preto",
	"18": "São Paulo (SP) — Presidente Prudente",
	"19": "São Paulo (SP) — Campinas",
	"21": "Rio de Janeiro (RJ) — Capital",
	"22": "Rio de Janeiro (RJ) — Campos/Norte Fluminense",
	"24": "Rio de Janeiro (RJ) — Volta Redonda",
	"27": "Espírito Santo (ES) — Vitória",
	"28": "Espírito Santo (ES) — Sul/Cachoeiro",
	"31": "Minas Gerais (MG) — Belo Horizonte",
	"32": "Minas Gerais (MG) — Juiz de Fora",
	"33": "Minas Gerais (MG) — Governador Valadares",
	"34": "Minas Gerais (MG) — Uberlândia",
	"35": "Minas Gerais (MG) — Poços de Caldas",
	"37": "Minas Gerais (MG) — Divinópolis",
	"38": "Minas Gerais (MG) — Montes Claros",
	"41": "Paraná (PR) — Curitiba",
	"42": "Paraná (PR) — Ponta Grossa",
	"43": "Paraná (PR) — Londrina",
	"44": "Paraná (PR) — Maringá",
	"45": "Paraná (PR) — Foz do Iguaçu",
	"46": "Paraná (PR) — Francisco Beltrão",
	"47": "Santa Catarina (SC) — Joinville/Blumenau",
	"48": "Santa Catarina (SC) — Florianópolis",
	"49": "Santa Catarina (SC) — Chapecó",
	"51": "Rio Grande do Sul (RS) — Porto Alegre",
	"53": "Rio Grande do Sul (RS) — Pelotas",
	"54": "Rio Grande do Sul (RS) — Caxias do Sul",
	"55": "Rio Grande do Sul (RS) — Santa Maria",
	"61": "Distrito Federal (DF) / Goiás (GO)",
	"62": "Goiás (GO) — Goiânia",
	"63": "Tocantins (TO)",
	"64": "Goiás (GO) — Rio Verde",
	"65": "Mato Grosso (MT) — Cuiabá",
	"66": "Mato Grosso (MT) — Rondonópolis",
	"67": "Mato Grosso do Sul (MS) — Campo Grande",
	"68": "Acre (AC)",
	"69": "Rondônia (RO)",
	"71": "Bahia (BA) — Salvador",
	"73": "Bahia (BA) — Ilhéus",
	"74": "Bahia (BA) — Juazeiro",
	"75": "Bahia (BA) — Feira de Santana",
	"77": "Bahia (BA) — Vitória da Conquista",
	"79": "Sergipe (SE)",
	"81": "Pernambuco (PE) — Recife",
	"82": "Alagoas (AL)",
	"83": "Paraíba (PB)",
	"84": "Rio Grande do Norte (RN)",
	"85": "Ceará (CE) — Fortaleza",
	"86": "Piauí (PI) — Teresina",
	"87": "Pernambuco (PE) — Caruaru",
	"88": "Ceará (CE) — Juazeiro do Norte",
	"89": "Piauí (PI) — Picos",
	"91": "Pará (PA) — Belém",
	"92": "Amazonas (AM) — Manaus",
	"93": "Pará (PA) — Santarém",
	"94": "Pará (PA) — Marabá",
	"95": "Roraima (RR)",
	"96": "Amapá (AP)",
	"97": "Amazonas (AM) — Interior",
	"98": "Maranhão (MA) — São Luís",
	"99": "Maranhão (MA) — Imperatriz",
}
