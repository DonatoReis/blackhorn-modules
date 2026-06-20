// Package ipgeolocation realiza geolocalização e análise de reputação de endereços IP.
//
// Fontes integradas (algumas gratuitas, outras com API key):
//   - ip-api.com              — geolocalização grátis (60 req/min sem key)
//   - ipinfo.io               — geolocalização + ASN + abuse (free tier: 50k/mês)
//   - AbuseIPDB              — score de reputação de abuso (API key obrigatória)
//   - VirusTotal              — reputação e análises de segurança (API key)
//   - IPQualityScore (IPQS)  — fraude, proxy, VPN, Tor (API key)
//   - Shodan internetdb       — portas abertas e vulns (grátis, sem key)
//
// Input:
//   - Target: endereço IPv4 ou IPv6
//   - Options["abuseipdb_key"]  — API key AbuseIPDB
//   - Options["ipinfo_key"]     — API key ipinfo.io (opcional, aumenta limite)
//   - Options["virustotal_key"] — API key VirusTotal
//   - Options["ipqs_key"]       — API key IPQualityScore
//   - Options["sources"]        — fontes separadas por vírgula (default: all)
//   - Options["days"]           — janela de análise para AbuseIPDB (default: 30)
package ipgeolocation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	maxBodyBytes            = 2 << 20
	defaultTimeout          = 15
	defaultMaxResults       = 100
	defaultMaxRuntimeSecond = 30
)

// Module implementa o módulo ipgeolocation.
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
func (m *Module) Name() string { return "ipgeolocation" }

// Run executa a geolocalização e análise de reputação.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("ipgeolocation: target não pode ser vazio")
	}

	parsedIP := net.ParseIP(target)
	if parsedIP == nil {
		return nil, fmt.Errorf("ipgeolocation: %q não é um endereço IP válido", target)
	}
	ip := parsedIP.String()

	// Rejeita IPs privados/loopback para análise externa
	if isPrivateIP(ip) {
		return []module.Finding{
			{
				Type:     "address_classification",
				URL:      "",
				Detail:   fmt.Sprintf("IP '%s' é privado/loopback — análise externa não aplicável.", ip),
				Severity: module.SeverityInfo,
				Extra: map[string]string{
					"ip":                     ip,
					"is_private":             "true",
					"fonte":                  "ipgeolocation",
					"confidence":             "1.00",
					"validated":              "true",
					"validation_state":       "local_address_classification",
					"promote_to_context":     "false",
					"target_scope_validated": "true",
				},
			},
		}, nil
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	enabledSources := parseSources(optStr(opts, "sources", "all"))
	abuseKey := firstNonEmpty(opts["abuseipdb_key"], os.Getenv("ABUSEIPDB_API_KEY"))
	ipinfoKey := firstNonEmpty(opts["ipinfo_key"], os.Getenv("IPINFO_API_KEY"))
	vtKey := firstNonEmpty(opts["virustotal_key"], os.Getenv("VIRUSTOTAL_API_KEY"))
	ipqsKey := firstNonEmpty(opts["ipqs_key"], os.Getenv("IPQS_API_KEY"))
	days := clampInt(optInt(opts, "days", 30), 1, 365)
	maxResults := clampInt(optInt(opts, "max_results", defaultMaxResults), 1, 1000)
	maxRuntime := clampInt(optInt(opts, "max_runtime_seconds", defaultMaxRuntimeSecond), 1, 300)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntime)*time.Second)
	defer cancel()

	slog.InfoContext(runCtx, "ipgeolocation: iniciando análise",
		"ip", ip,
		"target", target,
		"has_abuseipdb", abuseKey != "",
		"has_virustotal", vtKey != "",
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

	eg, ctx2 := errgroup.WithContext(runCtx)
	eg.SetLimit(5)

	// ip-api.com — geolocalização principal (grátis)
	if sourceEnabled(enabledSources, "ipapi") {
		eg.Go(func() error {
			ff, err := m.queryIPAPI(ctx2, ip)
			if err != nil {
				slog.WarnContext(ctx2, "ipgeolocation: ip-api falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// ipinfo.io — geolocalização + ASN + abuse (grátis)
	if sourceEnabled(enabledSources, "ipinfo") {
		eg.Go(func() error {
			ff, err := m.queryIPInfo(ctx2, ip, ipinfoKey)
			if err != nil {
				slog.WarnContext(ctx2, "ipgeolocation: ipinfo falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// AbuseIPDB
	if abuseKey != "" && sourceEnabled(enabledSources, "abuseipdb") {
		eg.Go(func() error {
			ff, err := m.queryAbuseIPDB(ctx2, ip, abuseKey, days)
			if err != nil {
				slog.WarnContext(ctx2, "ipgeolocation: abuseipdb falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Shodan internetdb — grátis
	if sourceEnabled(enabledSources, "shodan") {
		eg.Go(func() error {
			ff, err := m.queryShodanInternetDB(ctx2, ip)
			if err != nil {
				slog.WarnContext(ctx2, "ipgeolocation: shodan internetdb falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// IPQualityScore
	if ipqsKey != "" && sourceEnabled(enabledSources, "ipqs") {
		eg.Go(func() error {
			ff, err := m.queryIPQS(ctx2, ip, ipqsKey)
			if err != nil {
				slog.WarnContext(ctx2, "ipgeolocation: ipqs falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	_ = eg.Wait()

	// VirusTotal — faz após as outras (usa mais quota)
	if vtKey != "" && sourceEnabled(enabledSources, "virustotal") {
		ff, err := m.queryVirusTotal(runCtx, ip, vtKey)
		if err != nil {
			slog.WarnContext(runCtx, "ipgeolocation: virustotal falhou", "err", err)
		} else {
			findings = append(findings, ff...)
		}
	}

	result := decorateExternalFindings(dedup(findings), ip)
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}
		if result[i].URL != result[j].URL {
			return result[i].URL < result[j].URL
		}
		return result[i].Detail < result[j].Detail
	})
	if len(result) > maxResults {
		result = result[:maxResults]
	}

	slog.InfoContext(runCtx, "ipgeolocation: concluído",
		"total_findings", len(result),
	)

	return result, nil
}

// ─── ip-api.com ───────────────────────────────────────────────────────────────

func (m *Module) queryIPAPI(ctx context.Context, ip string) ([]module.Finding, error) {
	u := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,hosting,proxy,mobile,query",
		url.PathEscape(ip))

	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("ip-api: %w", err)
	}

	var result struct {
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
		Hosting     bool    `json:"hosting"`
		Proxy       bool    `json:"proxy"`
		Mobile      bool    `json:"mobile"`
		Query       string  `json:"query"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("ip-api: parse: %w", err)
	}

	if result.Status == "fail" {
		return nil, fmt.Errorf("ip-api: %s", result.Message)
	}
	if !sameIP(result.Query, ip) {
		return nil, fmt.Errorf("ip-api: resposta para IP inesperado %q", result.Query)
	}

	flags := []string{}
	if result.Proxy {
		flags = append(flags, "PROXY")
	}
	if result.Hosting {
		flags = append(flags, "HOSTING")
	}
	if result.Mobile {
		flags = append(flags, "MOBILE")
	}
	flagsStr := strings.Join(flags, ",")

	detail := fmt.Sprintf("IP %s geolocado em %s/%s (%s). ISP: %s, ASN: %s. Flags: [%s].",
		ip, result.City, result.Country, result.CountryCode, result.ISP, result.AS, flagsStr)

	return []module.Finding{
		{
			Type:     "geolocation_reference",
			URL:      fmt.Sprintf("https://ip-api.com/#%s", ip),
			Detail:   detail,
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"ip":           ip,
				"country":      result.Country,
				"country_code": result.CountryCode,
				"region":       result.RegionName,
				"city":         result.City,
				"lat":          fmt.Sprintf("%.4f", result.Lat),
				"lon":          fmt.Sprintf("%.4f", result.Lon),
				"timezone":     result.Timezone,
				"isp":          result.ISP,
				"org":          result.Org,
				"asn":          result.AS,
				"is_hosting":   fmt.Sprintf("%v", result.Hosting),
				"is_proxy":     fmt.Sprintf("%v", result.Proxy),
				"is_mobile":    fmt.Sprintf("%v", result.Mobile),
				"flags":        flagsStr,
				"fonte":        "ipapi",
				"confidence":   "0.88",
			},
		},
	}, nil
}

// ─── ipinfo.io ────────────────────────────────────────────────────────────────

func (m *Module) queryIPInfo(ctx context.Context, ip, apiKey string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://ipinfo.io/%s/json", url.PathEscape(ip))
	if apiKey != "" {
		u += "?token=" + apiKey
	}

	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("ipinfo: %w", err)
	}

	var result struct {
		IP       string `json:"ip"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Loc      string `json:"loc"`
		Org      string `json:"org"`
		Postal   string `json:"postal"`
		Timezone string `json:"timezone"`
		Bogon    bool   `json:"bogon"`
		Abuse    struct {
			Address string `json:"address"`
			Country string `json:"country"`
			Email   string `json:"email"`
			Name    string `json:"name"`
			Network string `json:"network"`
			Phone   string `json:"phone"`
		} `json:"abuse"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("ipinfo: parse: %w", err)
	}
	if !sameIP(result.IP, ip) {
		return nil, fmt.Errorf("ipinfo: resposta para IP inesperado %q", result.IP)
	}

	var findings []module.Finding

	findings = append(findings, module.Finding{
		Type: "geolocation_reference",
		URL:  fmt.Sprintf("https://ipinfo.io/%s", ip),
		Detail: fmt.Sprintf("IPInfo: %s em %s/%s/%s. Org: %s. TZ: %s.",
			ip, result.City, result.Region, result.Country, result.Org, result.Timezone),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"ip":         ip,
			"city":       result.City,
			"region":     result.Region,
			"country":    result.Country,
			"location":   result.Loc,
			"org":        result.Org,
			"timezone":   result.Timezone,
			"fonte":      "ipinfo",
			"confidence": "0.90",
		},
	})

	// Abuse contact
	if result.Abuse.Email != "" {
		findings = append(findings, module.Finding{
			Type:     "abuse_contact_reference",
			URL:      fmt.Sprintf("https://ipinfo.io/%s", ip),
			Detail:   fmt.Sprintf("Contato de abuso para %s: %s (%s) — %s.", ip, result.Abuse.Name, result.Abuse.Email, result.Abuse.Network),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"ip":            ip,
				"abuse_name":    result.Abuse.Name,
				"abuse_email":   result.Abuse.Email,
				"abuse_network": result.Abuse.Network,
				"abuse_country": result.Abuse.Country,
				"fonte":         "ipinfo",
				"confidence":    "0.90",
			},
		})
	}

	return findings, nil
}

// ─── AbuseIPDB ────────────────────────────────────────────────────────────────

func (m *Module) queryAbuseIPDB(ctx context.Context, ip, apiKey string, days int) ([]module.Finding, error) {
	u := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=%d&verbose",
		url.QueryEscape(ip), days)

	body, err := m.get(ctx, u, map[string]string{
		"Key":    apiKey,
		"Accept": "application/json",
	})
	if err != nil {
		return nil, fmt.Errorf("abuseipdb: %w", err)
	}

	var result struct {
		Data struct {
			IPAddress        string   `json:"ipAddress"`
			IsPublic         bool     `json:"isPublic"`
			IPVersion        int      `json:"ipVersion"`
			IsWhitelisted    bool     `json:"isWhitelisted"`
			AbuseScore       int      `json:"abuseConfidenceScore"`
			CountryCode      string   `json:"countryCode"`
			ISP              string   `json:"isp"`
			Domain           string   `json:"domain"`
			Hostnames        []string `json:"hostnames"`
			TotalReports     int      `json:"totalReports"`
			NumDistinctUsers int      `json:"numDistinctUsers"`
			LastReportedAt   string   `json:"lastReportedAt"`
			Reports          []struct {
				ReportedAt          string `json:"reportedAt"`
				Comment             string `json:"comment"`
				Categories          []int  `json:"categories"`
				ReporterCountryCode string `json:"reporterCountryCode"`
			} `json:"reports"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("abuseipdb: parse: %w", err)
	}

	d := result.Data
	if !sameIP(d.IPAddress, ip) {
		return nil, fmt.Errorf("abuseipdb: resposta para IP inesperado %q", d.IPAddress)
	}
	var findings []module.Finding

	severity := abuseScoreToSeverity(d.AbuseScore)
	if d.IsWhitelisted {
		severity = module.SeverityInfo
	}

	detail := fmt.Sprintf("AbuseIPDB: %s tem score de abuso %d/100. %d report(s) de %d usuário(s) distinto(s).",
		ip, d.AbuseScore, d.TotalReports, d.NumDistinctUsers)
	if d.LastReportedAt != "" {
		detail += fmt.Sprintf(" Último reporte: %s.", d.LastReportedAt)
	}

	findings = append(findings, module.Finding{
		Type:     "abuse_reputation_reference",
		URL:      fmt.Sprintf("https://www.abuseipdb.com/check/%s", ip),
		Detail:   detail,
		Severity: severity,
		Extra: map[string]string{
			"ip":             ip,
			"abuse_score":    fmt.Sprintf("%d", d.AbuseScore),
			"total_reports":  fmt.Sprintf("%d", d.TotalReports),
			"distinct_users": fmt.Sprintf("%d", d.NumDistinctUsers),
			"isp":            d.ISP,
			"domain":         d.Domain,
			"country_code":   d.CountryCode,
			"last_reported":  d.LastReportedAt,
			"fonte":          "abuseipdb",
			"confidence":     "0.92",
		},
	})

	// Reports recentes (máximo 3)
	for i, r := range d.Reports {
		if i >= 3 {
			break
		}
		comment := r.Comment
		if len(comment) > 200 {
			comment = comment[:200] + "..."
		}
		findings = append(findings, module.Finding{
			Type:     "abuse_reputation_reference",
			URL:      fmt.Sprintf("https://www.abuseipdb.com/check/%s", ip),
			Detail:   fmt.Sprintf("Reporte de abuso de %s em %s: %s", r.ReporterCountryCode, r.ReportedAt, comment),
			Severity: module.SeverityLow,
			Extra: map[string]string{
				"ip":               ip,
				"reported_at":      r.ReportedAt,
				"reporter_country": r.ReporterCountryCode,
				"fonte":            "abuseipdb",
				"confidence":       "0.88",
			},
		})
	}

	return findings, nil
}

// ─── Shodan InternetDB (grátis, sem key) ─────────────────────────────────────

func (m *Module) queryShodanInternetDB(ctx context.Context, ip string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://internetdb.shodan.io/%s", url.PathEscape(ip))

	body, err := m.get(ctx, u, nil)
	if err != nil {
		// 404 = IP sem dados no Shodan
		return nil, nil
	}

	var result struct {
		IP        string   `json:"ip"`
		Ports     []int    `json:"ports"`
		Vulns     []string `json:"vulns"`
		Hostnames []string `json:"hostnames"`
		Tags      []string `json:"tags"`
		CPEs      []string `json:"cpes"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("shodan internetdb: parse: %w", err)
	}
	if !sameIP(result.IP, ip) {
		return nil, fmt.Errorf("shodan internetdb: resposta para IP inesperado %q", result.IP)
	}

	if len(result.Ports) == 0 && len(result.Vulns) == 0 {
		return nil, nil
	}

	var findings []module.Finding

	portStrs := make([]string, len(result.Ports))
	for i, p := range result.Ports {
		portStrs[i] = fmt.Sprintf("%d", p)
	}

	findings = append(findings, module.Finding{
		Type: "external_inventory_reference",
		URL:  fmt.Sprintf("https://www.shodan.io/host/%s", ip),
		Detail: fmt.Sprintf("Shodan InternetDB: %s tem %d porta(s) abertas [%s] e %d CVE(s) conhecida(s).",
			ip, len(result.Ports), strings.Join(portStrs, ","), len(result.Vulns)),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"ip":         ip,
			"ports":      strings.Join(portStrs, ","),
			"port_count": fmt.Sprintf("%d", len(result.Ports)),
			"vulns":      strings.Join(result.Vulns, ","),
			"vuln_count": fmt.Sprintf("%d", len(result.Vulns)),
			"hostnames":  strings.Join(result.Hostnames, ","),
			"tags":       strings.Join(result.Tags, ","),
			"fonte":      "shodan_internetdb",
			"confidence": "0.88",
		},
	})

	// Finding por CVE
	for _, cve := range result.Vulns {
		findings = append(findings, module.Finding{
			Type:     "external_vulnerability_reference",
			URL:      fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve),
			Detail:   fmt.Sprintf("CVE %s identificada pelo Shodan em %s.", cve, ip),
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"ip":         ip,
				"cve":        cve,
				"fonte":      "shodan_internetdb",
				"confidence": "0.82",
			},
		})
	}

	return findings, nil
}

// ─── IPQualityScore ───────────────────────────────────────────────────────────

func (m *Module) queryIPQS(ctx context.Context, ip, apiKey string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://ipqualityscore.com/api/json/ip/%s/%s?strictness=1&allow_public_access_points=true",
		url.PathEscape(apiKey), url.PathEscape(ip))

	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("ipqs: %w", err)
	}

	var result struct {
		Success        bool   `json:"success"`
		Message        string `json:"message"`
		FraudScore     int    `json:"fraud_score"`
		CountryCode    string `json:"country_code"`
		ISP            string `json:"ISP"`
		ASN            int    `json:"ASN"`
		Organization   string `json:"organization"`
		IsProxy        bool   `json:"proxy"`
		IsVPN          bool   `json:"vpn"`
		IsTor          bool   `json:"tor"`
		IsBot          bool   `json:"bot_status"`
		RecentAbuse    bool   `json:"recent_abuse"`
		AbuseVelocity  string `json:"abuse_velocity"`
		Mobile         bool   `json:"mobile"`
		ConnectionType string `json:"connection_type"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("ipqs: parse: %w", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("ipqs: %s", result.Message)
	}

	flags := []string{}
	if result.IsProxy {
		flags = append(flags, "PROXY")
	}
	if result.IsVPN {
		flags = append(flags, "VPN")
	}
	if result.IsTor {
		flags = append(flags, "TOR")
	}
	if result.IsBot {
		flags = append(flags, "BOT")
	}
	if result.RecentAbuse {
		flags = append(flags, "RECENT_ABUSE")
	}

	severity := fraudScoreToSeverity(result.FraudScore)

	detail := fmt.Sprintf("IPQS: %s tem fraud score %d/100. Flags: [%s]. Tipo: %s, ISP: %s, ASN: %d.",
		ip, result.FraudScore, strings.Join(flags, ","), result.ConnectionType, result.ISP, result.ASN)

	return []module.Finding{
		{
			Type:     "fraud_reputation_reference",
			URL:      fmt.Sprintf("https://ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/%s", ip),
			Detail:   detail,
			Severity: severity,
			Extra: map[string]string{
				"ip":              ip,
				"fraud_score":     fmt.Sprintf("%d", result.FraudScore),
				"is_proxy":        fmt.Sprintf("%v", result.IsProxy),
				"is_vpn":          fmt.Sprintf("%v", result.IsVPN),
				"is_tor":          fmt.Sprintf("%v", result.IsTor),
				"is_bot":          fmt.Sprintf("%v", result.IsBot),
				"recent_abuse":    fmt.Sprintf("%v", result.RecentAbuse),
				"abuse_velocity":  result.AbuseVelocity,
				"isp":             result.ISP,
				"asn":             fmt.Sprintf("%d", result.ASN),
				"connection_type": result.ConnectionType,
				"flags":           strings.Join(flags, ","),
				"fonte":           "ipqs",
				"confidence":      "0.88",
			},
		},
	}, nil
}

// ─── VirusTotal ───────────────────────────────────────────────────────────────

func (m *Module) queryVirusTotal(ctx context.Context, ip, apiKey string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", url.PathEscape(ip))

	body, err := m.get(ctx, u, map[string]string{
		"x-apikey": apiKey,
	})
	if err != nil {
		return nil, fmt.Errorf("virustotal: %w", err)
	}

	var result struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				Country           string `json:"country"`
				ASN               int    `json:"asn"`
				ASOwner           string `json:"as_owner"`
				Network           string `json:"network"`
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				Reputation int `json:"reputation"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("virustotal: parse: %w", err)
	}
	if !sameIP(result.Data.ID, ip) {
		return nil, fmt.Errorf("virustotal: resposta para IP inesperado %q", result.Data.ID)
	}

	attr := result.Data.Attributes
	stats := attr.LastAnalysisStats

	severity := reputationCountSeverity(stats.Malicious, stats.Suspicious)

	detail := fmt.Sprintf("VirusTotal: %s — %d malicioso, %d suspeito, %d limpo. País: %s, ASN: %d (%s), Reputação: %d.",
		ip, stats.Malicious, stats.Suspicious, stats.Harmless,
		attr.Country, attr.ASN, attr.ASOwner, attr.Reputation)

	return []module.Finding{
		{
			Type:     "malware_reputation_reference",
			URL:      fmt.Sprintf("https://www.virustotal.com/gui/ip-address/%s", ip),
			Detail:   detail,
			Severity: severity,
			Extra: map[string]string{
				"ip":         ip,
				"malicious":  fmt.Sprintf("%d", stats.Malicious),
				"suspicious": fmt.Sprintf("%d", stats.Suspicious),
				"harmless":   fmt.Sprintf("%d", stats.Harmless),
				"reputation": fmt.Sprintf("%d", attr.Reputation),
				"asn":        fmt.Sprintf("%d", attr.ASN),
				"as_owner":   attr.ASOwner,
				"country":    attr.Country,
				"network":    attr.Network,
				"fonte":      "virustotal",
				"confidence": "0.90",
			},
		},
	}, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateRanges := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128", "fc00::/7",
		"169.254.0.0/16", "0.0.0.0/8",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func abuseScoreToSeverity(score int) module.Severity {
	switch {
	case score >= 75:
		return module.SeverityMedium
	case score >= 25:
		return module.SeverityLow
	default:
		return module.SeverityInfo
	}
}

func fraudScoreToSeverity(score int) module.Severity {
	switch {
	case score >= 85:
		return module.SeverityMedium
	case score >= 40:
		return module.SeverityLow
	default:
		return module.SeverityInfo
	}
}

func reputationCountSeverity(malicious, suspicious int) module.Severity {
	switch {
	case malicious >= 5:
		return module.SeverityMedium
	case malicious > 0 || suspicious >= 3:
		return module.SeverityLow
	default:
		return module.SeverityInfo
	}
}

func sameIP(actual, expected string) bool {
	actualIP := net.ParseIP(strings.TrimSpace(actual))
	expectedIP := net.ParseIP(strings.TrimSpace(expected))
	return actualIP != nil && expectedIP != nil && actualIP.Equal(expectedIP)
}

func decorateExternalFindings(findings []module.Finding, targetIP string) []module.Finding {
	for i := range findings {
		if findings[i].Extra == nil {
			findings[i].Extra = map[string]string{}
		}
		findings[i].Extra["target_ip"] = targetIP
		findings[i].Extra["target_scope_validated"] = "true"
		findings[i].Extra["validated"] = "false"
		findings[i].Extra["validation_state"] = "third_party_reference"
		findings[i].Extra["promote_to_context"] = "false"
	}
	return findings
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
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
