// Package addresssearch realiza busca e enriquecimento de endereços brasileiros.
//
// Fontes suportadas:
//   - brasilapi    : BrasilAPI CEP v2 + FIPE/Endereço
//   - viacep       : ViaCEP.com.br (CEP → endereço completo)
//   - nominatim    : OpenStreetMap Nominatim (endereço → coordenadas GPS)
//   - opencage     : OpenCage Geocoder (endereço → GPS, requer API key)
//   - ibge         : IBGE API – dados do município (código, UF, região, etc.)
//   - correios     : SIGEP-Web Correios (CEP) — fallback via BrasilAPI
//
// Tipos de target detectados automaticamente:
//   - CEP         : 8 dígitos (com ou sem hífen)
//   - Logradouro  : string com rua/av/travessa, cidade, UF
//   - Coordenadas : lat,lon (reverse geocoding)
//
// Options:
//
//	sources          : lista separada por vírgula (padrão: brasilapi,viacep,nominatim,ibge)
//	opencage_key     : API key para OpenCage (ou env OPENCAGE_API_KEY)
//	lang             : idioma para Nominatim/OpenCage (padrão: pt-BR)
package addresssearch

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
	"strconv"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	maxBodyBytes   = 512 * 1024
	defaultTimeout = 20 * time.Second

	baseURLBrasilAPICEP = "https://brasilapi.com.br/api/cep/v2"
	baseURLViaCEP       = "https://viacep.com.br/ws"
	baseURLNominatim    = "https://nominatim.openstreetmap.org"
	baseURLOpenCage     = "https://api.opencagedata.com/geocode/v1"
	baseURLIBGE         = "https://servicodados.ibge.gov.br/api/v1/localidades"
)

var (
	reCEP         = regexp.MustCompile(`^\d{5}-?\d{3}$`)
	reCoordinates = regexp.MustCompile(`^-?\d+(\.\d+)?,-?\d+(\.\d+)?$`)
)

// TargetType classifica o tipo de endereço recebido.
type TargetType string

const (
	TargetCEP         TargetType = "cep"
	TargetLogradouro  TargetType = "logradouro"
	TargetCoordinates TargetType = "coordinates"
	TargetUnknown     TargetType = "unknown"
)

// Module implementa module.Module para busca de endereços.
type Module struct {
	client *http.Client
}

// New cria um Module com cliente HTTP padrão.
func New() *Module { return &Module{client: &http.Client{Timeout: defaultTimeout}} }

// NewWithClient cria um Module com cliente HTTP injetado (útil em testes).
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "addresssearch" }

// Run executa as buscas de endereço e retorna os findings.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	if strings.TrimSpace(input.Target) == "" {
		return nil, fmt.Errorf("addresssearch: target não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	targetType := detectTargetType(input.Target)
	sources := parseSources(optStr(opts, "sources", "brasilapi,viacep,nominatim,ibge"))
	lang := optStr(opts, "lang", "pt-BR")
	opencageKey := firstNonEmpty(opts["opencage_key"], os.Getenv("OPENCAGE_API_KEY"))

	slog.InfoContext(ctx, "addresssearch: iniciando busca",
		"target_type", string(targetType),
		"sources", sources,
		"target_preview", previewTarget(input.Target),
	)

	type result struct {
		findings []module.Finding
	}

	ch := make(chan result, len(sources))
	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(5)

	for _, src := range sources {
		src := src
		eg.Go(func() error {
			var ff []module.Finding
			var err error

			switch src {
			case "brasilapi":
				if targetType == TargetCEP {
					ff, err = m.queryBrasilAPICEP(egCtx, digitsOnly(input.Target))
				}
			case "viacep":
				switch targetType {
				case TargetCEP:
					ff, err = m.queryViaCEPbyCEP(egCtx, digitsOnly(input.Target))
				case TargetLogradouro:
					ff, err = m.queryViaCEPbyAddress(egCtx, input.Target)
				}
			case "nominatim":
				switch targetType {
				case TargetLogradouro:
					ff, err = m.queryNominatimForward(egCtx, input.Target, lang)
				case TargetCoordinates:
					ff, err = m.queryNominatimReverse(egCtx, input.Target, lang)
				case TargetCEP:
					// Nominatim com CEP como query
					ff, err = m.queryNominatimForward(egCtx, input.Target+", Brasil", lang)
				}
			case "opencage":
				if opencageKey == "" {
					slog.WarnContext(egCtx, "addresssearch: opencage ignorado — OPENCAGE_API_KEY não configurada")
					return nil
				}
				ff, err = m.queryOpenCage(egCtx, input.Target, opencageKey, lang)
			case "ibge":
				if targetType == TargetCEP {
					// Primeiro pega o município pelo CEP via BrasilAPI, depois consulta IBGE
					ff, err = m.queryIBGEviaCEP(egCtx, digitsOnly(input.Target))
				}
			}

			if err != nil {
				slog.WarnContext(egCtx, "addresssearch: fonte falhou",
					"source", src, "error", err.Error())
				return nil
			}
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

	return dedup(all), nil
}

// ─── BrasilAPI CEP v2 ────────────────────────────────────────────────────────

func (m *Module) queryBrasilAPICEP(ctx context.Context, cep string) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("%s/%s", baseURLBrasilAPICEP, cep)
	slog.DebugContext(ctx, "addresssearch: BrasilAPI CEP", "url", apiURL)

	body, status, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("brasilapi cep HTTP %d", status)
	}

	var resp struct {
		CEP          string `json:"cep"`
		State        string `json:"state"`
		City         string `json:"city"`
		Neighborhood string `json:"neighborhood"`
		Street       string `json:"street"`
		Service      string `json:"service"`
		Location     struct {
			Type        string `json:"type"`
			Coordinates struct {
				Longitude string `json:"longitude"`
				Latitude  string `json:"latitude"`
			} `json:"coordinates"`
		} `json:"location"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("brasilapi cep JSON: %w", err)
	}

	detail := fmt.Sprintf("CEP %s → %s, %s, %s — %s/%s via BrasilAPI",
		resp.CEP, resp.Street, resp.Neighborhood, resp.City, resp.City, resp.State)

	f := module.Finding{
		Type:     "address_record",
		URL:      apiURL,
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":       "brasilapi",
			"confidence":   "0.98",
			"cep":          resp.CEP,
			"street":       resp.Street,
			"neighborhood": resp.Neighborhood,
			"city":         resp.City,
			"state":        resp.State,
			"latitude":     resp.Location.Coordinates.Latitude,
			"longitude":    resp.Location.Coordinates.Longitude,
		},
	}
	return []module.Finding{f}, nil
}

// ─── ViaCEP por CEP ───────────────────────────────────────────────────────────

func (m *Module) queryViaCEPbyCEP(ctx context.Context, cep string) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("%s/%s/json/", baseURLViaCEP, cep)
	slog.DebugContext(ctx, "addresssearch: ViaCEP CEP", "url", apiURL)

	body, status, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("viacep HTTP %d", status)
	}

	var resp struct {
		CEP         string `json:"cep"`
		Logradouro  string `json:"logradouro"`
		Complemento string `json:"complemento"`
		Bairro      string `json:"bairro"`
		Localidade  string `json:"localidade"`
		UF          string `json:"uf"`
		IBGE        string `json:"ibge"`
		DDD         string `json:"ddd"`
		Erro        bool   `json:"erro"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("viacep JSON: %w", err)
	}
	if resp.Erro {
		return nil, nil
	}

	detail := fmt.Sprintf("CEP %s → %s, %s, %s/%s (IBGE: %s, DDD: %s) via ViaCEP",
		resp.CEP, resp.Logradouro, resp.Bairro, resp.Localidade, resp.UF, resp.IBGE, resp.DDD)

	f := module.Finding{
		Type:     "address_record",
		URL:      apiURL,
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":       "viacep",
			"confidence":   "0.97",
			"cep":          resp.CEP,
			"street":       resp.Logradouro,
			"complement":   resp.Complemento,
			"neighborhood": resp.Bairro,
			"city":         resp.Localidade,
			"state":        resp.UF,
			"ibge_code":    resp.IBGE,
			"ddd":          resp.DDD,
		},
	}
	return []module.Finding{f}, nil
}

// ─── ViaCEP por Endereço ──────────────────────────────────────────────────────

// queryViaCEPbyAddress busca CEP por logradouro no formato "UF/cidade/logradouro".
// Tenta extrair UF e cidade da string de entrada.
func (m *Module) queryViaCEPbyAddress(ctx context.Context, addr string) ([]module.Finding, error) {
	uf, cidade, logradouro := parseAddressComponents(addr)
	if uf == "" || cidade == "" {
		return nil, fmt.Errorf("viacep por endereço: não foi possível extrair UF e cidade de '%s'", addr)
	}

	apiURL := fmt.Sprintf("%s/%s/%s/%s/json/",
		baseURLViaCEP, uf,
		url.PathEscape(cidade),
		url.PathEscape(logradouro))
	slog.DebugContext(ctx, "addresssearch: ViaCEP por endereço", "url", apiURL)

	body, status, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("viacep endereço HTTP %d", status)
	}

	var results []struct {
		CEP        string `json:"cep"`
		Logradouro string `json:"logradouro"`
		Bairro     string `json:"bairro"`
		Localidade string `json:"localidade"`
		UF         string `json:"uf"`
		IBGE       string `json:"ibge"`
	}
	if err := json.Unmarshal(body, &results); err != nil {
		// Pode ser objeto único em vez de array
		var single struct {
			CEP        string `json:"cep"`
			Logradouro string `json:"logradouro"`
			Bairro     string `json:"bairro"`
			Localidade string `json:"localidade"`
			UF         string `json:"uf"`
			IBGE       string `json:"ibge"`
			Erro       bool   `json:"erro"`
		}
		if err2 := json.Unmarshal(body, &single); err2 != nil {
			return nil, fmt.Errorf("viacep endereço JSON: %w", err)
		}
		if single.Erro {
			return nil, nil
		}
		results = append(results, struct {
			CEP        string `json:"cep"`
			Logradouro string `json:"logradouro"`
			Bairro     string `json:"bairro"`
			Localidade string `json:"localidade"`
			UF         string `json:"uf"`
			IBGE       string `json:"ibge"`
		}{
			CEP: single.CEP, Logradouro: single.Logradouro, Bairro: single.Bairro,
			Localidade: single.Localidade, UF: single.UF, IBGE: single.IBGE,
		})
	}

	var findings []module.Finding
	for _, r := range results {
		f := module.Finding{
			Type:     "address_record",
			URL:      apiURL,
			Detail:   fmt.Sprintf("Endereço encontrado: CEP %s — %s, %s, %s/%s via ViaCEP busca", r.CEP, r.Logradouro, r.Bairro, r.Localidade, r.UF),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":       "viacep",
				"confidence":   "0.93",
				"cep":          r.CEP,
				"street":       r.Logradouro,
				"neighborhood": r.Bairro,
				"city":         r.Localidade,
				"state":        r.UF,
				"ibge_code":    r.IBGE,
			},
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ─── Nominatim (OpenStreetMap) ────────────────────────────────────────────────

func (m *Module) queryNominatimForward(ctx context.Context, query, lang string) ([]module.Finding, error) {
	params := url.Values{}
	params.Set("q", query)
	params.Set("format", "json")
	params.Set("addressdetails", "1")
	params.Set("limit", "3")
	params.Set("accept-language", lang)
	params.Set("countrycodes", "br")

	apiURL := fmt.Sprintf("%s/search?%s", baseURLNominatim, params.Encode())
	slog.DebugContext(ctx, "addresssearch: Nominatim forward geocoding")

	body, status, err := m.get(ctx, apiURL, map[string]string{
		"User-Agent": "blackhorn-modules/1.0 (security research tool)",
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("nominatim HTTP %d", status)
	}

	var results []struct {
		PlaceID     int     `json:"place_id"`
		DisplayName string  `json:"display_name"`
		Lat         string  `json:"lat"`
		Lon         string  `json:"lon"`
		Type        string  `json:"type"`
		Importance  float64 `json:"importance"`
		Address     struct {
			Road         string `json:"road"`
			Suburb       string `json:"suburb"`
			City         string `json:"city"`
			Town         string `json:"town"`
			Municipality string `json:"municipality"`
			State        string `json:"state"`
			Postcode     string `json:"postcode"`
			Country      string `json:"country"`
			CountryCode  string `json:"country_code"`
		} `json:"address"`
	}
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("nominatim JSON: %w", err)
	}

	var findings []module.Finding
	for _, r := range results {
		city := firstNonEmpty(r.Address.City, r.Address.Town, r.Address.Municipality)
		f := module.Finding{
			Type:     "geocoding_result",
			URL:      apiURL,
			Detail:   fmt.Sprintf("Nominatim geocoding: %s (lat=%s, lon=%s, importância=%.2f)", r.DisplayName, r.Lat, r.Lon, r.Importance),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":       "nominatim",
				"confidence":   strconv.FormatFloat(r.Importance, 'f', 2, 64),
				"latitude":     r.Lat,
				"longitude":    r.Lon,
				"display_name": r.DisplayName,
				"street":       r.Address.Road,
				"neighborhood": r.Address.Suburb,
				"city":         city,
				"state":        r.Address.State,
				"postcode":     r.Address.Postcode,
				"country_code": r.Address.CountryCode,
			},
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func (m *Module) queryNominatimReverse(ctx context.Context, latlon, lang string) ([]module.Finding, error) {
	parts := strings.SplitN(latlon, ",", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("nominatim reverse: formato lat,lon inválido")
	}

	params := url.Values{}
	params.Set("lat", strings.TrimSpace(parts[0]))
	params.Set("lon", strings.TrimSpace(parts[1]))
	params.Set("format", "json")
	params.Set("addressdetails", "1")
	params.Set("accept-language", lang)

	apiURL := fmt.Sprintf("%s/reverse?%s", baseURLNominatim, params.Encode())
	slog.DebugContext(ctx, "addresssearch: Nominatim reverse geocoding")

	body, status, err := m.get(ctx, apiURL, map[string]string{
		"User-Agent": "blackhorn-modules/1.0 (security research tool)",
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("nominatim reverse HTTP %d", status)
	}

	var resp struct {
		PlaceID     int    `json:"place_id"`
		DisplayName string `json:"display_name"`
		Lat         string `json:"lat"`
		Lon         string `json:"lon"`
		Address     struct {
			Road        string `json:"road"`
			Suburb      string `json:"suburb"`
			City        string `json:"city"`
			Town        string `json:"town"`
			State       string `json:"state"`
			Postcode    string `json:"postcode"`
			CountryCode string `json:"country_code"`
		} `json:"address"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("nominatim reverse JSON: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("nominatim reverse: %s", resp.Error)
	}

	city := firstNonEmpty(resp.Address.City, resp.Address.Town)
	f := module.Finding{
		Type:     "reverse_geocoding",
		URL:      apiURL,
		Detail:   fmt.Sprintf("Reverse geocoding (%.4s,%.4s) → %s", parts[0], parts[1], resp.DisplayName),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":       "nominatim",
			"confidence":   "0.90",
			"latitude":     resp.Lat,
			"longitude":    resp.Lon,
			"display_name": resp.DisplayName,
			"street":       resp.Address.Road,
			"neighborhood": resp.Address.Suburb,
			"city":         city,
			"state":        resp.Address.State,
			"postcode":     resp.Address.Postcode,
			"country_code": resp.Address.CountryCode,
		},
	}
	return []module.Finding{f}, nil
}

// ─── OpenCage Geocoder ────────────────────────────────────────────────────────

func (m *Module) queryOpenCage(ctx context.Context, query, apiKey, lang string) ([]module.Finding, error) {
	params := url.Values{}
	params.Set("q", query)
	params.Set("key", apiKey)
	params.Set("language", lang)
	params.Set("countrycode", "br")
	params.Set("limit", "3")
	params.Set("no_annotations", "0")

	apiURL := fmt.Sprintf("%s/json?%s", baseURLOpenCage, params.Encode())
	slog.DebugContext(ctx, "addresssearch: OpenCage geocoding")

	body, status, err := m.get(ctx, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return nil, fmt.Errorf("opencage: API key inválida (HTTP %d)", status)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("opencage HTTP %d", status)
	}

	var resp struct {
		Results []struct {
			Formatted  string `json:"formatted"`
			Confidence int    `json:"confidence"`
			Geometry   struct {
				Lat float64 `json:"lat"`
				Lng float64 `json:"lng"`
			} `json:"geometry"`
			Components struct {
				Road        string `json:"road"`
				Suburb      string `json:"suburb"`
				City        string `json:"city"`
				Town        string `json:"town"`
				State       string `json:"state"`
				Postcode    string `json:"postcode"`
				CountryCode string `json:"country_code"`
			} `json:"components"`
			Annotations struct {
				OSM struct {
					EditURL string `json:"edit_url"`
				} `json:"OSM"`
			} `json:"annotations"`
		} `json:"results"`
		Status struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("opencage JSON: %w", err)
	}

	var findings []module.Finding
	for _, r := range resp.Results {
		conf := float64(r.Confidence) / 10.0
		city := firstNonEmpty(r.Components.City, r.Components.Town)
		f := module.Finding{
			Type:     "geocoding_result",
			Detail:   fmt.Sprintf("OpenCage geocoding: %s (confiança: %d/10)", r.Formatted, r.Confidence),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":       "opencage",
				"confidence":   strconv.FormatFloat(conf, 'f', 2, 64),
				"latitude":     strconv.FormatFloat(r.Geometry.Lat, 'f', 6, 64),
				"longitude":    strconv.FormatFloat(r.Geometry.Lng, 'f', 6, 64),
				"display_name": r.Formatted,
				"street":       r.Components.Road,
				"neighborhood": r.Components.Suburb,
				"city":         city,
				"state":        r.Components.State,
				"postcode":     r.Components.Postcode,
			},
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ─── IBGE Municípios ──────────────────────────────────────────────────────────

func (m *Module) queryIBGEviaCEP(ctx context.Context, cep string) ([]module.Finding, error) {
	// Primeiro resolve CEP → código IBGE via BrasilAPI
	brasilAPIURL := fmt.Sprintf("%s/%s", baseURLBrasilAPICEP, cep)
	body, status, err := m.get(ctx, brasilAPIURL, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, nil
	}

	var cepResp struct {
		City  string `json:"city"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(body, &cepResp); err != nil {
		return nil, fmt.Errorf("ibge: erro ao parsear CEP: %w", err)
	}
	if cepResp.City == "" {
		return nil, nil
	}

	// Busca município no IBGE por nome e UF
	ibgeURL := fmt.Sprintf("%s/municipios?nome=%s", baseURLIBGE, url.QueryEscape(cepResp.City))
	slog.DebugContext(ctx, "addresssearch: IBGE municipios", "url", ibgeURL)

	body2, status2, err := m.get(ctx, ibgeURL, nil)
	if err != nil {
		return nil, err
	}
	if status2 != http.StatusOK {
		return nil, fmt.Errorf("ibge municipios HTTP %d", status2)
	}

	var municipios []struct {
		ID   int    `json:"id"`
		Nome string `json:"nome"`
		UF   struct {
			ID     int    `json:"id"`
			Sigla  string `json:"sigla"`
			Nome   string `json:"nome"`
			Regiao struct {
				ID    int    `json:"id"`
				Sigla string `json:"sigla"`
				Nome  string `json:"nome"`
			} `json:"regiao"`
		} `json:"microrregiao"`
	}
	_ = json.Unmarshal(body2, &municipios)

	var ibgeMunicipios []struct {
		ID   int    `json:"id"`
		Nome string `json:"nome"`
		UF   struct {
			Sigla  string `json:"sigla"`
			Nome   string `json:"nome"`
			Regiao struct {
				Nome string `json:"nome"`
			} `json:"regiao"`
		} `json:"microrregiao"`
	}

	// Usar estrutura simplificada para o IBGE
	var muniList []struct {
		ID           int    `json:"id"`
		Nome         string `json:"nome"`
		Microrregiao struct {
			Mesorregiao struct {
				UF struct {
					Sigla  string `json:"sigla"`
					Nome   string `json:"nome"`
					Regiao struct {
						Nome string `json:"nome"`
					} `json:"regiao"`
				} `json:"UF"`
			} `json:"mesorregiao"`
		} `json:"microrregiao"`
	}
	if err := json.Unmarshal(body2, &muniList); err != nil {
		return nil, fmt.Errorf("ibge municipios JSON: %w", err)
	}

	_ = ibgeMunicipios

	var findings []module.Finding
	for _, muni := range muniList {
		uf := muni.Microrregiao.Mesorregiao.UF
		if cepResp.State != "" && !strings.EqualFold(uf.Sigla, cepResp.State) {
			continue
		}
		f := module.Finding{
			Type:     "municipality_info",
			URL:      ibgeURL,
			Detail:   fmt.Sprintf("Município IBGE: %s/%s (código IBGE: %d, região: %s)", muni.Nome, uf.Sigla, muni.ID, uf.Regiao.Nome),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":     "ibge",
				"confidence": "0.99",
				"ibge_code":  strconv.Itoa(muni.ID),
				"city":       muni.Nome,
				"state":      uf.Sigla,
				"state_name": uf.Nome,
				"region":     uf.Regiao.Nome,
			},
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func detectTargetType(target string) TargetType {
	t := strings.TrimSpace(target)
	if reCEP.MatchString(digitsOnly(t)) && len(digitsOnly(t)) == 8 {
		return TargetCEP
	}
	if reCoordinates.MatchString(t) {
		return TargetCoordinates
	}
	// Heurística para endereço
	lower := strings.ToLower(t)
	streetKeywords := []string{"rua ", "av ", "avenida ", "alameda ", "travessa ", "praça ", "estrada ", "rod ", "rodovia "}
	for _, kw := range streetKeywords {
		if strings.Contains(lower, kw) {
			return TargetLogradouro
		}
	}
	// Fallback: string com vírgula pode ser endereço
	if strings.Contains(t, ",") {
		return TargetLogradouro
	}
	return TargetUnknown
}

// parseAddressComponents tenta extrair UF, cidade e logradouro de uma string.
// Formato esperado: "Logradouro, Bairro, Cidade - UF" ou "Cidade/UF"
func parseAddressComponents(addr string) (uf, cidade, logradouro string) {
	// Tenta padrão "- UF" no final
	parts := strings.Split(addr, "-")
	if len(parts) >= 2 {
		possibleUF := strings.TrimSpace(parts[len(parts)-1])
		if len(possibleUF) == 2 {
			uf = strings.ToUpper(possibleUF)
			remaining := strings.Join(parts[:len(parts)-1], "-")
			commaParts := strings.Split(remaining, ",")
			if len(commaParts) >= 2 {
				logradouro = strings.TrimSpace(commaParts[0])
				cidade = strings.TrimSpace(commaParts[len(commaParts)-1])
				return
			}
		}
	}

	// Tenta padrão "cidade/UF"
	slashParts := strings.Split(addr, "/")
	if len(slashParts) == 2 {
		cidade = strings.TrimSpace(slashParts[0])
		uf = strings.TrimSpace(strings.ToUpper(slashParts[1]))
		return
	}

	return "", "", addr
}

func previewTarget(target string) string {
	if len(target) > 30 {
		return target[:30] + "..."
	}
	return target
}

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
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
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

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	var out []module.Finding
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Extra["source"] + "|" + f.Extra["cep"] + "|" + f.Extra["latitude"]
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}
