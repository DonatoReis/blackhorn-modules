// Package ipintel agrega inteligência sobre endereços IP de múltiplas fontes OSINT.
//
// Fontes integradas:
//   - AbuseIPDB       (https://www.abuseipdb.com/api/v2)  — score de abuso, reports
//   - IPInfo          (https://ipinfo.io)                  — geolocalização, ASN, org
//   - GreyNoise       (https://api.greynoise.io/v3)        — classificação noise/vuln
//   - Shodan          (https://api.shodan.io)              — portas, banners, vulns
//   - IP-API          (https://ip-api.com)                 — geo gratuito (sem key)
//   - ThreatFox       (https://threatfox-api.abuse.ch)     — IOCs, malware
//
// Análise local (sem API):
//   - Classificação: privado, loopback, link-local, multicast, público
//   - Faixa CGNAT (100.64.0.0/10)
//   - Faixas reservadas do IETF
//
// Input:
//   - Target: endereço IP (IPv4 ou IPv6)
//   - Options["sources"]       — fontes separadas por vírgula (default: all)
//   - Options["abuseipdb_key"] — chave AbuseIPDB (ou env ABUSEIPDB_API_KEY)
//   - Options["ipinfo_key"]    — chave IPInfo (ou env IPINFO_TOKEN)
//   - Options["greynoise_key"] — chave GreyNoise (ou env GREYNOISE_API_KEY)
//   - Options["shodan_key"]    — chave Shodan (ou env SHODAN_API_KEY)
//   - Options["timeout"]       — timeout em segundos (default: 15)
//   - Options["days"]          — janela de lookback AbuseIPDB em dias (default: 90)
package ipintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	moduleName               = "ipintel"
	maxBody                  = 512 << 10 // 512 KB
	defaultMaxRuntimeSeconds = 30
	defaultMaxResults        = 100
)

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implementa agregação de inteligência sobre IPs.
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

// Run executa inteligência de IP contra múltiplas fontes em paralelo.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" && len(input.URLs) > 0 {
		target = strings.TrimSpace(input.URLs[0])
	}
	if target == "" {
		return nil, fmt.Errorf("ipintel: endereço IP obrigatório em Target")
	}

	ip := net.ParseIP(target)
	if ip == nil {
		return nil, fmt.Errorf("ipintel: endereço IP inválido: %q", target)
	}
	target = ip.String()

	opts := input.Options
	sourcesFilter := optStr(opts, "sources", "")
	abuseKey := optStr(opts, "abuseipdb_key", os.Getenv("ABUSEIPDB_API_KEY"))
	ipinfoKey := optStr(opts, "ipinfo_key", os.Getenv("IPINFO_TOKEN"))
	greynoise := optStr(opts, "greynoise_key", os.Getenv("GREYNOISE_API_KEY"))
	shodanKey := optStr(opts, "shodan_key", os.Getenv("SHODAN_API_KEY"))
	days := clampInt(optInt(opts, "days", 90), 1, 365)
	maxRuntimeSeconds := optInt(opts, "max_runtime_seconds", optInt(opts, "timeout", defaultMaxRuntimeSeconds))
	maxRuntime := time.Duration(clampInt(maxRuntimeSeconds, 1, 120)) * time.Second
	maxResults := clampInt(optInt(opts, "max_results", defaultMaxResults), 1, 1000)
	runCtx, cancel := context.WithTimeout(ctx, maxRuntime)
	defer cancel()

	m.logger.InfoContext(runCtx, "ipintel: iniciando", "ip", target)

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
	add(m.analyzeLocal(ip, target))

	eg, egCtx := errgroup.WithContext(runCtx)
	eg.SetLimit(8)

	// IP-API (gratuito, sem autenticação para uso não-comercial)
	if (wantSource(sourcesFilter, "ipapi") || sourcesFilter == "") && ip.IsGlobalUnicast() {
		eg.Go(func() error {
			fs, err := m.fetchIPAPI(egCtx, target)
			if err != nil {
				m.logger.WarnContext(egCtx, "ipintel: ip-api error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	// AbuseIPDB
	if abuseKey != "" && (wantSource(sourcesFilter, "abuseipdb") || sourcesFilter == "") {
		eg.Go(func() error {
			fs, err := m.fetchAbuseIPDB(egCtx, target, abuseKey, days)
			if err != nil {
				m.logger.WarnContext(egCtx, "ipintel: abuseipdb error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	// IPInfo
	if ipinfoKey != "" && (wantSource(sourcesFilter, "ipinfo") || sourcesFilter == "") {
		eg.Go(func() error {
			fs, err := m.fetchIPInfo(egCtx, target, ipinfoKey)
			if err != nil {
				m.logger.WarnContext(egCtx, "ipintel: ipinfo error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	// GreyNoise
	if greynoise != "" && (wantSource(sourcesFilter, "greynoise") || sourcesFilter == "") {
		eg.Go(func() error {
			fs, err := m.fetchGreyNoise(egCtx, target, greynoise)
			if err != nil {
				m.logger.WarnContext(egCtx, "ipintel: greynoise error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	// Shodan
	if shodanKey != "" && (wantSource(sourcesFilter, "shodan") || sourcesFilter == "") {
		eg.Go(func() error {
			fs, err := m.fetchShodan(egCtx, target, shodanKey)
			if err != nil {
				m.logger.WarnContext(egCtx, "ipintel: shodan error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	// ThreatFox
	if wantSource(sourcesFilter, "threatfox") || sourcesFilter == "" {
		eg.Go(func() error {
			fs, err := m.fetchThreatFox(egCtx, target)
			if err != nil {
				m.logger.WarnContext(egCtx, "ipintel: threatfox error", "err", err)
			} else {
				add(fs)
			}
			return nil
		})
	}

	_ = eg.Wait()

	results = decorateFindings(dedup(results))
	sort.Slice(results, func(i, j int) bool {
		if results[i].Type != results[j].Type {
			return results[i].Type < results[j].Type
		}
		if results[i].URL != results[j].URL {
			return results[i].URL < results[j].URL
		}
		return results[i].Detail < results[j].Detail
	})
	if len(results) > maxResults {
		results = results[:maxResults]
	}

	m.logger.InfoContext(runCtx, "ipintel: concluído",
		"ip", target, "findings", len(results))
	return results, nil
}

// ─── Análise local ───────────────────────────────────────────────────────────

var (
	cgnat          = mustParseCIDR("100.64.0.0/10")
	loopback4      = mustParseCIDR("127.0.0.0/8")
	private10      = mustParseCIDR("10.0.0.0/8")
	private172     = mustParseCIDR("172.16.0.0/12")
	private192     = mustParseCIDR("192.168.0.0/16")
	linkLocal      = mustParseCIDR("169.254.0.0/16")
	multicast      = mustParseCIDR("224.0.0.0/4")
	broadcast      = mustParseCIDR("255.255.255.255/32")
	documentation1 = mustParseCIDR("192.0.2.0/24")
	documentation2 = mustParseCIDR("198.51.100.0/24")
	documentation3 = mustParseCIDR("203.0.113.0/24")
)

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func (m *Module) analyzeLocal(ip net.IP, target string) []module.Finding {
	ipType := "public"
	notes := []string{}
	confidence := "0.99" // classificação de faixa IP é determinística

	switch {
	case ip.IsLoopback():
		ipType = "loopback"
		notes = append(notes, "endereço de loopback — não roteável")
	case private10.Contains(ip) || private172.Contains(ip) || private192.Contains(ip):
		ipType = "private"
		notes = append(notes, "endereço privado RFC 1918 — não roteável na internet")
	case cgnat.Contains(ip):
		ipType = "cgnat"
		notes = append(notes, "faixa CGNAT RFC 6598 — compartilhado pelo ISP")
	case linkLocal.Contains(ip):
		ipType = "link_local"
		notes = append(notes, "link-local — escopo de enlace apenas")
	case ip.IsMulticast():
		ipType = "multicast"
		notes = append(notes, "endereço multicast")
	case documentation1.Contains(ip) || documentation2.Contains(ip) || documentation3.Contains(ip):
		ipType = "documentation"
		notes = append(notes, "endereço de documentação — não deve aparecer em tráfego real")
	case ip.IsUnspecified():
		ipType = "unspecified"
		notes = append(notes, "endereço não especificado (0.0.0.0 ou ::)")
	}

	if ip.To4() == nil {
		notes = append(notes, "IPv6")
	}

	detail := fmt.Sprintf("IP: %s | Tipo: %s", target, ipType)
	if len(notes) > 0 {
		detail += " | " + strings.Join(notes, "; ")
	}

	return []module.Finding{{
		Type:     "address_classification",
		URL:      "",
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":     "local_analysis",
			"ip":         target,
			"ip_type":    ipType,
			"is_ipv6":    strconv.FormatBool(ip.To4() == nil),
			"notes":      strings.Join(notes, "|"),
			"confidence": confidence,
		},
	}}
}

// ─── IP-API ──────────────────────────────────────────────────────────────────
// GET https://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query

func (m *Module) fetchIPAPI(ctx context.Context, ip string) ([]module.Finding, error) {
	fields := "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
	url := fmt.Sprintf("https://ip-api.com/json/%s?fields=%s", ip, fields)
	body, err := m.get(ctx, url, nil)
	if err != nil {
		return nil, err
	}

	var r struct {
		Status      string  `json:"status"`
		Message     string  `json:"message"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		Region      string  `json:"region"`
		RegionName  string  `json:"regionName"`
		City        string  `json:"city"`
		Zip         string  `json:"zip"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		Timezone    string  `json:"timezone"`
		ISP         string  `json:"isp"`
		Org         string  `json:"org"`
		AS          string  `json:"as"`
		ASName      string  `json:"asname"`
		Mobile      bool    `json:"mobile"`
		Proxy       bool    `json:"proxy"`
		Hosting     bool    `json:"hosting"`
		Query       string  `json:"query"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("ip-api: parse: %w", err)
	}
	if r.Status == "fail" {
		return nil, fmt.Errorf("ip-api: %s", r.Message)
	}
	if net.ParseIP(r.Query) == nil || net.ParseIP(r.Query).String() != ip {
		return nil, nil
	}

	confidence := "0.80" // IP-API usa base GeoIP2 — boa precisão de país, menor de cidade
	if r.Proxy || r.Hosting {
		confidence = "0.75" // proxy/hosting detection é heurístico
	}

	flags := []string{}
	if r.Proxy {
		flags = append(flags, "PROXY")
	}
	if r.Hosting {
		flags = append(flags, "HOSTING")
	}
	if r.Mobile {
		flags = append(flags, "MOBILE")
	}

	detail := fmt.Sprintf("[IP-API] %s | %s, %s, %s | ISP: %s | %s",
		ip, r.City, r.RegionName, r.Country, r.ISP, r.AS)
	if len(flags) > 0 {
		detail += " | Flags: " + strings.Join(flags, ",")
	}

	return []module.Finding{{
		Type:     "geolocation_reference",
		URL:      fmt.Sprintf("https://ip-api.com/#%s", ip),
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":       "ipapi",
			"ip":           ip,
			"country":      r.Country,
			"country_code": r.CountryCode,
			"region":       r.RegionName,
			"city":         r.City,
			"zip":          r.Zip,
			"lat":          fmt.Sprintf("%.4f", r.Lat),
			"lon":          fmt.Sprintf("%.4f", r.Lon),
			"timezone":     r.Timezone,
			"isp":          r.ISP,
			"org":          r.Org,
			"asn":          r.AS,
			"asname":       r.ASName,
			"is_proxy":     strconv.FormatBool(r.Proxy),
			"is_hosting":   strconv.FormatBool(r.Hosting),
			"is_mobile":    strconv.FormatBool(r.Mobile),
			"confidence":   confidence,
		},
	}}, nil
}

// ─── AbuseIPDB ───────────────────────────────────────────────────────────────
// GET https://api.abuseipdb.com/api/v2/check

func (m *Module) fetchAbuseIPDB(ctx context.Context, ip, key string, days int) ([]module.Finding, error) {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=%d&verbose",
		ip, days)
	body, err := m.get(ctx, url, map[string]string{
		"Key":    key,
		"Accept": "application/json",
	})
	if err != nil {
		return nil, err
	}

	var r struct {
		Data struct {
			IPAddress            string `json:"ipAddress"`
			IsPublic             bool   `json:"isPublic"`
			IPVersion            int    `json:"ipVersion"`
			IsWhitelisted        bool   `json:"isWhitelisted"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			UsageType            string `json:"usageType"`
			ISP                  string `json:"isp"`
			Domain               string `json:"domain"`
			TotalReports         int    `json:"totalReports"`
			NumDistinctUsers     int    `json:"numDistinctUsers"`
			LastReportedAt       string `json:"lastReportedAt"`
			Categories           []int  `json:"categories"`
		} `json:"data"`
		Errors []struct {
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("abuseipdb: parse: %w", err)
	}
	if len(r.Errors) > 0 {
		return nil, fmt.Errorf("abuseipdb: %s", r.Errors[0].Detail)
	}

	d := r.Data
	if net.ParseIP(d.IPAddress) == nil || net.ParseIP(d.IPAddress).String() != ip {
		return nil, nil
	}
	score := d.AbuseConfidenceScore
	severity := module.SeverityInfo
	confidence := "0.90" // score calculado pela comunidade AbuseIPDB
	if score >= 25 {
		severity = module.SeverityLow
	}
	if score >= 75 {
		severity = module.SeverityMedium
		confidence = "0.95"
	}
	if d.IsWhitelisted {
		severity = module.SeverityInfo
	}

	return []module.Finding{{
		Type:     "abuse_reputation_reference",
		URL:      fmt.Sprintf("https://www.abuseipdb.com/check/%s", ip),
		Detail:   fmt.Sprintf("[AbuseIPDB] %s | Score: %d/100 | Reports: %d | Usuários distintos: %d | ISP: %s | Último: %s", ip, score, d.TotalReports, d.NumDistinctUsers, d.ISP, d.LastReportedAt),
		Severity: severity,
		Extra: map[string]string{
			"source":         "abuseipdb",
			"ip":             ip,
			"abuse_score":    strconv.Itoa(score),
			"total_reports":  strconv.Itoa(d.TotalReports),
			"distinct_users": strconv.Itoa(d.NumDistinctUsers),
			"country_code":   d.CountryCode,
			"isp":            d.ISP,
			"domain":         d.Domain,
			"usage_type":     d.UsageType,
			"last_reported":  d.LastReportedAt,
			"whitelisted":    strconv.FormatBool(d.IsWhitelisted),
			"confidence":     confidence,
		},
	}}, nil
}

// ─── IPInfo ──────────────────────────────────────────────────────────────────
// GET https://ipinfo.io/{ip}?token={key}

func (m *Module) fetchIPInfo(ctx context.Context, ip, key string) ([]module.Finding, error) {
	url := fmt.Sprintf("https://ipinfo.io/%s?token=%s", ip, key)
	body, err := m.get(ctx, url, nil)
	if err != nil {
		return nil, err
	}

	var r struct {
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Loc      string `json:"loc"`
		Org      string `json:"org"`
		Postal   string `json:"postal"`
		Timezone string `json:"timezone"`
		Bogon    bool   `json:"bogon"`
		ASN      struct {
			ASN    string `json:"asn"`
			Name   string `json:"name"`
			Domain string `json:"domain"`
			Route  string `json:"route"`
			Type   string `json:"type"`
		} `json:"asn"`
		Company struct {
			Name   string `json:"name"`
			Domain string `json:"domain"`
			Type   string `json:"type"`
		} `json:"company"`
		Privacy struct {
			VPN     bool   `json:"vpn"`
			Proxy   bool   `json:"proxy"`
			Tor     bool   `json:"tor"`
			Relay   bool   `json:"relay"`
			Hosting bool   `json:"hosting"`
			Service string `json:"service"`
		} `json:"privacy"`
		Abuse struct {
			Address string `json:"address"`
			Country string `json:"country"`
			Email   string `json:"email"`
			Name    string `json:"name"`
			Network string `json:"network"`
			Phone   string `json:"phone"`
		} `json:"abuse"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("ipinfo: parse: %w", err)
	}
	if net.ParseIP(r.IP) == nil || net.ParseIP(r.IP).String() != ip {
		return nil, nil
	}

	priv := r.Privacy
	flags := []string{}
	if priv.VPN {
		flags = append(flags, "VPN")
	}
	if priv.Proxy {
		flags = append(flags, "PROXY")
	}
	if priv.Tor {
		flags = append(flags, "TOR")
	}
	if priv.Relay {
		flags = append(flags, "RELAY")
	}
	if priv.Hosting {
		flags = append(flags, "HOSTING")
	}

	confidence := "0.90" // IPInfo usa RIPE/ARIN/LACNIC — alta qualidade ASN

	detail := fmt.Sprintf("[IPInfo] %s | %s, %s, %s | Org: %s | ASN: %s (%s)",
		ip, r.City, r.Region, r.Country, r.Org, r.ASN.ASN, r.ASN.Name)
	if len(flags) > 0 {
		detail += " | " + strings.Join(flags, ",")
	}

	return []module.Finding{{
		Type:     "asn_reference",
		URL:      fmt.Sprintf("https://ipinfo.io/%s", ip),
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":       "ipinfo",
			"ip":           ip,
			"hostname":     r.Hostname,
			"city":         r.City,
			"region":       r.Region,
			"country":      r.Country,
			"org":          r.Org,
			"asn":          r.ASN.ASN,
			"asn_name":     r.ASN.Name,
			"asn_domain":   r.ASN.Domain,
			"asn_type":     r.ASN.Type,
			"company_name": r.Company.Name,
			"company_type": r.Company.Type,
			"is_vpn":       strconv.FormatBool(priv.VPN),
			"is_proxy":     strconv.FormatBool(priv.Proxy),
			"is_tor":       strconv.FormatBool(priv.Tor),
			"is_hosting":   strconv.FormatBool(priv.Hosting),
			"privacy_svc":  priv.Service,
			"abuse_email":  r.Abuse.Email,
			"abuse_phone":  r.Abuse.Phone,
			"confidence":   confidence,
		},
	}}, nil
}

// ─── GreyNoise ───────────────────────────────────────────────────────────────
// GET https://api.greynoise.io/v3/community/{ip}

func (m *Module) fetchGreyNoise(ctx context.Context, ip, key string) ([]module.Finding, error) {
	url := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", ip)
	body, err := m.get(ctx, url, map[string]string{
		"key": key,
	})
	if err != nil {
		return nil, err
	}

	var r struct {
		IP             string `json:"ip"`
		Noise          bool   `json:"noise"`
		Riot           bool   `json:"riot"`
		Classification string `json:"classification"`
		Name           string `json:"name"`
		Link           string `json:"link"`
		LastSeen       string `json:"last_seen"`
		Message        string `json:"message"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("greynoise: parse: %w", err)
	}
	if r.IP != "" && (net.ParseIP(r.IP) == nil || net.ParseIP(r.IP).String() != ip) {
		return nil, nil
	}
	if r.Message == "IP not observed scanning the internet or has not been seen in the past 3 months." {
		// Não é ruído — isso é informação válida
		r.Noise = false
		r.Classification = "unknown"
	}

	severity := module.SeverityInfo
	confidence := "0.88" // GreyNoise usa varredura passiva da própria rede
	if r.Noise && r.Classification == "malicious" {
		severity = module.SeverityMedium
		confidence = "0.92"
	} else if r.Noise && r.Classification == "unknown" {
		severity = module.SeverityLow
	}

	detail := fmt.Sprintf("[GreyNoise] %s | Noise: %v | Classificação: %s | Nome: %s | Visto: %s",
		ip, r.Noise, r.Classification, r.Name, r.LastSeen)

	link := r.Link
	if link == "" {
		link = fmt.Sprintf("https://viz.greynoise.io/ip/%s", ip)
	}

	return []module.Finding{{
		Type:     "noise_reputation_reference",
		URL:      link,
		Detail:   detail,
		Severity: severity,
		Extra: map[string]string{
			"source":         "greynoise",
			"ip":             ip,
			"noise":          strconv.FormatBool(r.Noise),
			"riot":           strconv.FormatBool(r.Riot),
			"classification": r.Classification,
			"name":           r.Name,
			"last_seen":      r.LastSeen,
			"confidence":     confidence,
		},
	}}, nil
}

// ─── Shodan ───────────────────────────────────────────────────────────────────
// GET https://api.shodan.io/shodan/host/{ip}?key={key}

func (m *Module) fetchShodan(ctx context.Context, ip, key string) ([]module.Finding, error) {
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, key)
	body, err := m.get(ctx, url, nil)
	if err != nil {
		return nil, err
	}

	var r struct {
		IP         string   `json:"ip_str"`
		Org        string   `json:"org"`
		ISP        string   `json:"isp"`
		ASN        string   `json:"asn"`
		Country    string   `json:"country_name"`
		City       string   `json:"city"`
		Ports      []int    `json:"ports"`
		Vulns      []string `json:"vulns"`
		Tags       []string `json:"tags"`
		LastUpdate string   `json:"last_update"`
		Hostnames  []string `json:"hostnames"`
		Domains    []string `json:"domains"`
		Data       []struct {
			Port      int      `json:"port"`
			Transport string   `json:"transport"`
			Product   string   `json:"product"`
			Version   string   `json:"version"`
			Banner    string   `json:"banner"`
			CVEs      []string `json:"vulns"`
		} `json:"data"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("shodan: parse: %w", err)
	}
	if r.Error != "" {
		return nil, fmt.Errorf("shodan: %s", r.Error)
	}
	if net.ParseIP(r.IP) == nil || net.ParseIP(r.IP).String() != ip {
		return nil, nil
	}

	var findings []module.Finding

	// Finding principal
	confidence := "0.92" // Shodan tem varredura ativa contínua
	if len(r.Vulns) > 0 {
		confidence = "0.75"
	}

	ports := make([]string, len(r.Ports))
	for i, p := range r.Ports {
		ports[i] = strconv.Itoa(p)
	}

	findings = append(findings, module.Finding{
		Type:     "external_inventory_reference",
		URL:      fmt.Sprintf("https://www.shodan.io/host/%s", ip),
		Detail:   fmt.Sprintf("[Shodan] %s | Org: %s | %s, %s | Portas: %s | CVEs: %d", ip, r.Org, r.City, r.Country, strings.Join(ports, ","), len(r.Vulns)),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":      "shodan",
			"ip":          ip,
			"org":         r.Org,
			"isp":         r.ISP,
			"asn":         r.ASN,
			"country":     r.Country,
			"city":        r.City,
			"ports":       strings.Join(ports, ","),
			"vulns":       strings.Join(r.Vulns, ","),
			"tags":        strings.Join(r.Tags, ","),
			"hostnames":   strings.Join(r.Hostnames, ","),
			"domains":     strings.Join(r.Domains, ","),
			"last_update": r.LastUpdate,
			"port_count":  strconv.Itoa(len(r.Ports)),
			"vuln_count":  strconv.Itoa(len(r.Vulns)),
			"confidence":  confidence,
		},
	})

	// Um finding por CVE crítico
	for _, cve := range r.Vulns {
		findings = append(findings, module.Finding{
			Type:     "external_vulnerability_reference",
			URL:      fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve),
			Detail:   fmt.Sprintf("[Shodan] referência externa associa %s a %s; confirme serviço e versão diretamente", ip, cve),
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"source":     "shodan",
				"ip":         ip,
				"cve":        cve,
				"confidence": "0.60",
			},
		})
	}

	return findings, nil
}

// ─── ThreatFox ───────────────────────────────────────────────────────────────
// POST https://threatfox-api.abuse.ch/api/v1/ (sem autenticação para query básica)

func (m *Module) fetchThreatFox(ctx context.Context, ip string) ([]module.Finding, error) {
	payload := fmt.Sprintf(`{"query":"search_ioc","search_term":"%s"}`, ip)
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://threatfox-api.abuse.ch/api/v1/",
		strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "blackhorn-ipintel/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}

	var r struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			ID             string   `json:"id"`
			IOC            string   `json:"ioc"`
			ThreatType     string   `json:"threat_type"`
			ThreatTypeDesc string   `json:"threat_type_desc"`
			MalwareAlias   string   `json:"malware_alias"`
			Confidence     int      `json:"confidence_level"`
			FirstSeen      string   `json:"first_seen"`
			LastSeen       string   `json:"last_seen"`
			Reporter       string   `json:"reporter"`
			Tags           []string `json:"tags"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("threatfox: parse: %w", err)
	}

	if r.QueryStatus == "no_results" || len(r.Data) == 0 {
		return nil, nil
	}

	var findings []module.Finding
	for _, d := range r.Data {
		if !iocMatchesIP(d.IOC, ip) {
			continue
		}
		severity := module.SeverityLow
		if d.Confidence >= 75 {
			severity = module.SeverityMedium
		}
		confidence := fmt.Sprintf("%.2f", float64(d.Confidence)/100.0)

		findings = append(findings, module.Finding{
			Type:     "threat_ioc_reference",
			URL:      fmt.Sprintf("https://threatfox.abuse.ch/ioc/%s/", d.ID),
			Detail:   fmt.Sprintf("[ThreatFox] %s | Tipo: %s | Malware: %s | Primeira vez: %s", ip, d.ThreatTypeDesc, d.MalwareAlias, d.FirstSeen),
			Severity: severity,
			Extra: map[string]string{
				"source":      "threatfox",
				"ip":          ip,
				"ioc_id":      d.ID,
				"threat_type": d.ThreatType,
				"malware":     d.MalwareAlias,
				"first_seen":  d.FirstSeen,
				"last_seen":   d.LastSeen,
				"reporter":    d.Reporter,
				"tags":        strings.Join(d.Tags, ","),
				"confidence":  confidence,
			},
		})
	}
	return findings, nil
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

func decorateFindings(findings []module.Finding) []module.Finding {
	for i := range findings {
		if findings[i].Extra == nil {
			findings[i].Extra = make(map[string]string)
		}
		findings[i].Extra["promote_to_context"] = "false"
		if findings[i].Extra["source"] == "local_analysis" {
			findings[i].Extra["validated"] = "true"
			findings[i].Extra["validation_state"] = "deterministic_local_classification"
			continue
		}
		findings[i].Extra["validated"] = "false"
		findings[i].Extra["validation_state"] = "third_party_intelligence_reference"
	}
	return findings
}

func iocMatchesIP(ioc, target string) bool {
	ioc = strings.TrimSpace(ioc)
	if parsed := net.ParseIP(ioc); parsed != nil {
		return parsed.String() == target
	}
	if host, _, err := net.SplitHostPort(ioc); err == nil {
		if parsed := net.ParseIP(strings.Trim(host, "[]")); parsed != nil {
			return parsed.String() == target
		}
	}
	return false
}

func (m *Module) get(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-ipintel/1.0")
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

func clampInt(value, minimum, maximum int) int {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}
