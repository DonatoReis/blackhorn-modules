// Package netmon queries internet-wide scanning services to discover
// exposed hosts, open ports, services, banners and vulnerabilities
// associated with a target IP, domain or ASN.
//
// Sources integrated:
//   - Shodan   (https://api.shodan.io)      — host info, ports, banners, vulns (key required)
//   - Censys   (https://search.censys.io/api) — host search, TLS, services (key required)
//   - FOFA     (https://fofa.info/api/v1)   — Chinese internet scanner (key required)
//   - Shodan InternetDB (https://internetdb.shodan.io) — free, no key, basic info
//   - Hunter.how (https://hunter.how/api)  — free tier available
//
// Supported target types (auto-detected):
//   - IPv4 address  → direct host lookup (all sources)
//   - IPv6 address  → direct host lookup
//   - Domain/hostname → resolves to IP + domain-specific queries
//   - CIDR range (e.g. 192.168.0.0/24) → Shodan net: search
//   - ASN (e.g. AS1234) → Shodan asn: search
//
// Input:
//   - Target: IP, domain, CIDR, or ASN
//   - Options["sources"]:    comma-separated (default: all with available keys)
//   - Options["shodan_key"]: Shodan API key (or env SHODAN_API_KEY)
//   - Options["censys_id"]:  Censys API ID (or env CENSYS_API_ID)
//   - Options["censys_secret"]: Censys API secret (or env CENSYS_API_SECRET)
//   - Options["fofa_key"]:   FOFA API key  (or env FOFA_API_KEY)
//   - Options["fofa_email"]: FOFA account email
//   - Options["timeout"]:    per-request timeout seconds (default: 20)
//   - Options["min_ports"]:  minimum open ports to create finding (default: 1)
//
// Architecture:
//   - errgroup.SetLimit for bounded parallel queries (guia-go-1.26)
//   - io.LimitReader on every response body
//   - Confidence: shodan_host=0.95, censys=0.93, internetdb=0.85, fofa=0.88
//   - All credentials redacted from logs (dicas.md §18)
package netmon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/urlutil"
	"golang.org/x/sync/errgroup"
)

const (
	moduleName               = "netmon"
	maxBody                  = 2 << 20 // 2 MB
	maxParallel              = 5
	defaultMaxRuntimeSeconds = 30
)

// ─── Target type ─────────────────────────────────────────────────────────────

type TargetType string

const (
	TargetIP     TargetType = "ip"
	TargetDomain TargetType = "domain"
	TargetCIDR   TargetType = "cidr"
	TargetASN    TargetType = "asn"
)

var (
	reASN = regexp.MustCompile(`(?i)^AS\d+$`)
)

func detectTargetType(target string) TargetType {
	t := strings.TrimSpace(target)
	if net.ParseIP(t) != nil {
		return TargetIP
	}
	if _, _, err := net.ParseCIDR(t); err == nil {
		return TargetCIDR
	}
	switch {
	case reASN.MatchString(t):
		return TargetASN
	default:
		return TargetDomain
	}
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements internet-wide scanning aggregation.
type Module struct {
	client *http.Client
}

// New returns a Module with default HTTP client.
func New() *Module { return NewWithClient(defaultClient()) }

// NewWithClient injects a custom HTTP client.
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

// Name satisfies module.Module.
func (m *Module) Name() string { return moduleName }

// Run queries scanning services for the given target.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("netmon: target vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	targetType := detectTargetType(target)
	switch targetType {
	case TargetIP:
		target = net.ParseIP(target).String()
	case TargetCIDR:
		_, network, err := net.ParseCIDR(target)
		if err != nil {
			return nil, fmt.Errorf("netmon: CIDR inválido")
		}
		target = network.String()
	case TargetASN:
		target = strings.ToUpper(target)
	case TargetDomain:
		if looksLikeInvalidIP(target) {
			return nil, fmt.Errorf("netmon: endereço IP inválido")
		}
		target = urlutil.NormalizeDomain(target)
		if target == "" || !strings.Contains(target, ".") || net.ParseIP(target) != nil {
			return nil, fmt.Errorf("netmon: domínio inválido")
		}
	}
	sourcesFilter := opts["sources"]
	maxRuntimeSeconds := clampInt(optInt(opts, "max_runtime_seconds", defaultMaxRuntimeSeconds), 1, 120)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntimeSeconds)*time.Second)
	defer cancel()

	// Resolve credentials from options or environment
	shodanKey := firstNonEmpty(opts["shodan_key"], os.Getenv("SHODAN_API_KEY"))
	censysID := firstNonEmpty(opts["censys_id"], os.Getenv("CENSYS_API_ID"))
	censysSecret := firstNonEmpty(opts["censys_secret"], os.Getenv("CENSYS_API_SECRET"))
	fofaKey := firstNonEmpty(opts["fofa_key"], os.Getenv("FOFA_API_KEY"))
	fofaEmail := firstNonEmpty(opts["fofa_email"], os.Getenv("FOFA_EMAIL"))

	slog.InfoContext(runCtx, "netmon.Run iniciado",
		"target", target,
		"type", targetType,
		"sources", sourcesFilter,
	)

	type sourceFunc struct {
		name string
		fn   func(context.Context, string, TargetType, map[string]string) ([]module.Finding, error)
	}

	sources := []sourceFunc{
		{"shodan", m.queryShodan},
		{"censys", m.queryCensys},
		{"fofa", m.queryFOFA},
		{"internetdb", m.queryInternetDB}, // free, no key
	}

	var mu sync.Mutex
	var all []module.Finding

	g, gctx := errgroup.WithContext(runCtx)
	g.SetLimit(maxParallel)

	for _, s := range sources {
		s := s
		if !isWanted(sourcesFilter, s.name) {
			continue
		}

		// Skip key-dependent sources if no key
		switch s.name {
		case "shodan":
			if shodanKey == "" {
				slog.DebugContext(runCtx, "netmon: shodan skipped (no key)")
				continue
			}
		case "censys":
			if censysID == "" || censysSecret == "" {
				slog.DebugContext(runCtx, "netmon: censys skipped (no credentials)")
				continue
			}
		case "fofa":
			if fofaKey == "" || fofaEmail == "" {
				slog.DebugContext(runCtx, "netmon: fofa skipped (no credentials)")
				continue
			}
		}

		g.Go(func() error {
			optsWithKeys := make(map[string]string, len(opts)+6)
			for k, v := range opts {
				optsWithKeys[k] = v
			}
			optsWithKeys["shodan_key"] = shodanKey
			optsWithKeys["censys_id"] = censysID
			optsWithKeys["censys_secret"] = censysSecret
			optsWithKeys["fofa_key"] = fofaKey
			optsWithKeys["fofa_email"] = fofaEmail

			findings, err := s.fn(gctx, target, targetType, optsWithKeys)
			if err != nil {
				slog.WarnContext(gctx, "netmon: source erro",
					"source", s.name, "err", err)
				return nil
			}
			slog.InfoContext(gctx, "netmon: source concluído",
				"source", s.name, "findings", len(findings))
			mu.Lock()
			all = append(all, findings...)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	result := dedup(all)
	slog.InfoContext(runCtx, "netmon.Run concluído",
		"target", target, "findings", len(result))
	return result, nil
}

// ─── Shodan host lookup ───────────────────────────────────────────────────────

type shodanHost struct {
	IP        string   `json:"ip_str"`
	Hostnames []string `json:"hostnames"`
	Domains   []string `json:"domains"`
	Country   string   `json:"country_name"`
	City      string   `json:"city"`
	Org       string   `json:"org"`
	ISP       string   `json:"isp"`
	ASN       string   `json:"asn"`
	OS        string   `json:"os"`
	Ports     []int    `json:"ports"`
	Tags      []string `json:"tags"`
	Vulns     map[string]struct {
		CVSS float64 `json:"cvss"`
	} `json:"vulns"`
	Data []struct {
		Port      int    `json:"port"`
		Transport string `json:"transport"`
		Product   string `json:"product"`
		Version   string `json:"version"`
		Banner    string `json:"data"`
		Module    string `json:"_shodan"`
	} `json:"data"`
}

func (m *Module) queryShodan(ctx context.Context, target string, ttype TargetType, opts map[string]string) ([]module.Finding, error) {
	apiKey := opts["shodan_key"]
	var endpoint string

	switch ttype {
	case TargetIP:
		endpoint = fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s",
			url.PathEscape(target), url.QueryEscape(apiKey))
	case TargetDomain:
		endpoint = fmt.Sprintf("https://api.shodan.io/dns/resolve?hostnames=%s&key=%s",
			url.QueryEscape(target), url.QueryEscape(apiKey))
	case TargetCIDR:
		query := fmt.Sprintf("net:%s", target)
		endpoint = fmt.Sprintf("https://api.shodan.io/shodan/host/search?query=%s&key=%s",
			url.QueryEscape(query), url.QueryEscape(apiKey))
	case TargetASN:
		query := fmt.Sprintf("asn:%s", strings.ToUpper(target))
		endpoint = fmt.Sprintf("https://api.shodan.io/shodan/host/search?query=%s&key=%s",
			url.QueryEscape(query), url.QueryEscape(apiKey))
	default:
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-netmon/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("shodan: API key inválida")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}

	// Handle domain resolution response differently
	if ttype == TargetDomain {
		var resolved map[string]string
		if err := json.Unmarshal(body, &resolved); err != nil {
			return nil, fmt.Errorf("shodan dns: parse: %w", err)
		}
		ip, ok := resolved[target]
		if !ok || net.ParseIP(ip) == nil {
			return nil, nil
		}
		return []module.Finding{{
			Type:     "external_dns_reference",
			URL:      fmt.Sprintf("https://www.shodan.io/host/%s", ip),
			Detail:   fmt.Sprintf("[Shodan DNS] %s resolve para %s", target, ip),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":             "shodan",
				"domain":             target,
				"ip":                 ip,
				"confidence":         "0.80",
				"validated":          "false",
				"validation_state":   "third_party_dns_reference",
				"promote_to_context": "false",
			},
		}}, nil
	}

	var host shodanHost
	if err := json.Unmarshal(body, &host); err != nil {
		return nil, fmt.Errorf("shodan: parse: %w", err)
	}

	if len(host.Ports) == 0 && host.IP == "" {
		return nil, nil
	}
	if net.ParseIP(host.IP) == nil || (ttype == TargetIP && host.IP != target) {
		return nil, nil
	}

	var findings []module.Finding

	// Main host finding
	portStrs := make([]string, len(host.Ports))
	for i, p := range host.Ports {
		portStrs[i] = strconv.Itoa(p)
	}

	hostURL := fmt.Sprintf("https://www.shodan.io/host/%s", host.IP)
	detail := fmt.Sprintf("[Shodan] %s: %d portas abertas (%s). Org: %s, País: %s",
		host.IP, len(host.Ports), strings.Join(portStrs, ","), host.Org, host.Country)
	if len(host.Vulns) > 0 {
		vulnList := make([]string, 0, len(host.Vulns))
		for cve := range host.Vulns {
			vulnList = append(vulnList, cve)
		}
		detail += fmt.Sprintf(". Vulnerabilidades: %s", strings.Join(vulnList, ", "))
	}

	findings = append(findings, module.Finding{
		Type:     "external_inventory_reference",
		URL:      hostURL,
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":             "shodan",
			"ip":                 host.IP,
			"ports":              strings.Join(portStrs, ","),
			"port_count":         strconv.Itoa(len(host.Ports)),
			"org":                host.Org,
			"isp":                host.ISP,
			"country":            host.Country,
			"city":               host.City,
			"asn":                host.ASN,
			"os":                 host.OS,
			"hostnames":          strings.Join(host.Hostnames, ","),
			"tags":               strings.Join(host.Tags, ","),
			"confidence":         "0.75",
			"validated":          "false",
			"validation_state":   "third_party_inventory_reference",
			"promote_to_context": "false",
		},
	})

	// Vulnerability findings
	for cve, info := range host.Vulns {
		vulnSev := externalCVESeverity(info.CVSS)

		findings = append(findings, module.Finding{
			Type:     "external_vulnerability_reference",
			URL:      hostURL,
			Detail:   fmt.Sprintf("[Shodan] Referência externa associa %s a %s (CVSS: %.1f). Confirme versão e exposição diretamente antes de tratar como vulnerabilidade.", host.IP, cve, info.CVSS),
			Severity: vulnSev,
			Extra: map[string]string{
				"source":             "shodan",
				"ip":                 host.IP,
				"cve":                cve,
				"cvss":               fmt.Sprintf("%.1f", info.CVSS),
				"confidence":         "0.60",
				"validated":          "false",
				"validation_state":   "third_party_vulnerability_reference",
				"promote_to_context": "false",
			},
		})
	}

	// Banner / service findings
	for _, svc := range host.Data {
		if svc.Product == "" && svc.Version == "" {
			continue
		}
		svcDetail := fmt.Sprintf("[Shodan] %s porta %d/%s: %s %s",
			host.IP, svc.Port, svc.Transport, svc.Product, svc.Version)

		findings = append(findings, module.Finding{
			Type:     "external_banner_reference",
			URL:      hostURL,
			Detail:   svcDetail,
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":             "shodan",
				"ip":                 host.IP,
				"port":               strconv.Itoa(svc.Port),
				"transport":          svc.Transport,
				"product":            svc.Product,
				"version":            svc.Version,
				"confidence":         "0.70",
				"validated":          "false",
				"validation_state":   "third_party_service_reference",
				"promote_to_context": "false",
			},
		})
	}

	return findings, nil
}

// ─── Shodan InternetDB (free, no key) ─────────────────────────────────────────

type internetDBHost struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
	CPEs      []string `json:"cpes"`
	Hostnames []string `json:"hostnames"`
}

func (m *Module) queryInternetDB(ctx context.Context, target string, ttype TargetType, opts map[string]string) ([]module.Finding, error) {
	if ttype != TargetIP {
		return nil, nil // InternetDB is IP-only
	}

	endpoint := fmt.Sprintf("https://internetdb.shodan.io/%s", url.PathEscape(target))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-netmon/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("internetdb: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}

	var host internetDBHost
	if err := json.Unmarshal(body, &host); err != nil {
		return nil, fmt.Errorf("internetdb: parse: %w", err)
	}

	if len(host.Ports) == 0 {
		return nil, nil
	}

	portStrs := make([]string, len(host.Ports))
	for i, p := range host.Ports {
		portStrs[i] = strconv.Itoa(p)
	}

	detail := fmt.Sprintf("[InternetDB] %s: %d portas abertas (%s)",
		target, len(host.Ports), strings.Join(portStrs, ","))
	if len(host.Vulns) > 0 {
		detail += fmt.Sprintf(". CVEs: %s", strings.Join(host.Vulns, ", "))
	}
	if len(host.CPEs) > 0 {
		detail += fmt.Sprintf(". CPEs: %s", strings.Join(host.CPEs[:min(3, len(host.CPEs))], ", "))
	}

	return []module.Finding{{
		Type:     "external_inventory_reference",
		URL:      fmt.Sprintf("https://www.shodan.io/host/%s", target),
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":             "internetdb",
			"ip":                 target,
			"ports":              strings.Join(portStrs, ","),
			"port_count":         strconv.Itoa(len(host.Ports)),
			"vulns":              strings.Join(host.Vulns, ","),
			"cpes":               strings.Join(host.CPEs, ","),
			"hostnames":          strings.Join(host.Hostnames, ","),
			"confidence":         "0.65",
			"validated":          "false",
			"validation_state":   "third_party_inventory_reference",
			"promote_to_context": "false",
		},
	}}, nil
}

// ─── Censys ───────────────────────────────────────────────────────────────────

type censysHost struct {
	Result struct {
		IP       string `json:"ip"`
		Services []struct {
			Port            int    `json:"port"`
			TransportProto  string `json:"transport_protocol"`
			ServiceName     string `json:"service_name"`
			ExtendedService string `json:"extended_service_name"`
			Certificate     struct {
				SubjectDN string `json:"subject_dn"`
				Issuer    struct {
					O string `json:"organization"`
				} `json:"issuer"`
				Validity struct {
					End string `json:"end"`
				} `json:"validity_period"`
			} `json:"tls"`
		} `json:"services"`
		AutonomousSystem struct {
			ASN     int    `json:"asn"`
			Name    string `json:"name"`
			Country string `json:"country_code"`
		} `json:"autonomous_system"`
		Location struct {
			Country string `json:"country"`
			City    string `json:"city"`
		} `json:"location"`
	} `json:"result"`
}

func (m *Module) queryCensys(ctx context.Context, target string, ttype TargetType, opts map[string]string) ([]module.Finding, error) {
	apiID := opts["censys_id"]
	apiSecret := opts["censys_secret"]

	if ttype != TargetIP {
		return nil, nil // Censys hosts API is IP-based
	}

	endpoint := fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", url.PathEscape(target))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	// Censys uses Basic auth
	creds := base64.StdEncoding.EncodeToString([]byte(apiID + ":" + apiSecret))
	req.Header.Set("Authorization", "Basic "+creds)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "blackhorn-netmon/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("censys: credenciais inválidas")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("censys: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}

	var host censysHost
	if err := json.Unmarshal(body, &host); err != nil {
		return nil, fmt.Errorf("censys: parse: %w", err)
	}

	result := host.Result
	if len(result.Services) == 0 {
		return nil, nil
	}
	if net.ParseIP(result.IP) == nil || result.IP != target {
		return nil, nil
	}

	hostURL := fmt.Sprintf("https://search.censys.io/hosts/%s", target)
	var findings []module.Finding

	portStrs := make([]string, 0, len(result.Services))
	for _, svc := range result.Services {
		portStrs = append(portStrs, strconv.Itoa(svc.Port))
	}

	detail := fmt.Sprintf("[Censys] %s: %d serviços detectados (%s). ASN: %s, País: %s",
		result.IP, len(result.Services), strings.Join(portStrs, ","),
		result.AutonomousSystem.Name, result.Location.Country)

	findings = append(findings, module.Finding{
		Type:     "external_inventory_reference",
		URL:      hostURL,
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"source":             "censys",
			"ip":                 result.IP,
			"ports":              strings.Join(portStrs, ","),
			"port_count":         strconv.Itoa(len(result.Services)),
			"asn":                strconv.Itoa(result.AutonomousSystem.ASN),
			"asn_name":           result.AutonomousSystem.Name,
			"country":            result.Location.Country,
			"city":               result.Location.City,
			"confidence":         "0.75",
			"validated":          "false",
			"validation_state":   "third_party_inventory_reference",
			"promote_to_context": "false",
		},
	})

	// TLS certificate findings
	for _, svc := range result.Services {
		if svc.Certificate.SubjectDN == "" {
			continue
		}
		findings = append(findings, module.Finding{
			Type: "external_tls_reference",
			URL:  hostURL,
			Detail: fmt.Sprintf("[Censys] %s porta %d: certificado TLS '%s' emitido por '%s', válido até %s",
				target, svc.Port, svc.Certificate.SubjectDN,
				svc.Certificate.Issuer.O, svc.Certificate.Validity.End),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":             "censys",
				"ip":                 result.IP,
				"port":               strconv.Itoa(svc.Port),
				"subject":            svc.Certificate.SubjectDN,
				"issuer":             svc.Certificate.Issuer.O,
				"valid_until":        svc.Certificate.Validity.End,
				"confidence":         "0.75",
				"validated":          "false",
				"validation_state":   "third_party_tls_reference",
				"promote_to_context": "false",
			},
		})
	}

	return findings, nil
}

// ─── FOFA ─────────────────────────────────────────────────────────────────────

type fofaResponse struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg"`
	Results [][]string `json:"results"`
	Size    int        `json:"size"`
}

func (m *Module) queryFOFA(ctx context.Context, target string, ttype TargetType, opts map[string]string) ([]module.Finding, error) {
	apiKey := opts["fofa_key"]
	email := opts["fofa_email"]

	// Build FOFA query based on target type
	var fofaQuery string
	switch ttype {
	case TargetIP:
		fofaQuery = fmt.Sprintf(`ip="%s"`, target)
	case TargetDomain:
		fofaQuery = fmt.Sprintf(`domain="%s"`, target)
	case TargetCIDR:
		fofaQuery = fmt.Sprintf(`ip="%s"`, target)
	default:
		return nil, nil
	}

	// FOFA uses base64-encoded query
	encoded := base64.StdEncoding.EncodeToString([]byte(fofaQuery))
	endpoint := fmt.Sprintf(
		"https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&fields=ip,port,protocol,title,country,city&size=20",
		url.QueryEscape(email), url.QueryEscape(apiKey), url.QueryEscape(encoded),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-netmon/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fofa: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}

	var fofa fofaResponse
	if err := json.Unmarshal(body, &fofa); err != nil {
		return nil, fmt.Errorf("fofa: parse: %w", err)
	}

	if fofa.Error {
		return nil, fmt.Errorf("fofa: %s", fofa.ErrMsg)
	}

	var findings []module.Finding
	seen := map[string]bool{}

	for _, row := range fofa.Results {
		if len(row) < 2 {
			continue
		}
		ip, port := row[0], row[1]
		key := ip + ":" + port
		if seen[key] {
			continue
		}
		seen[key] = true

		proto := ""
		title := ""
		country := ""
		city := ""
		if len(row) > 2 {
			proto = row[2]
		}
		if len(row) > 3 {
			title = row[3]
		}
		if len(row) > 4 {
			country = row[4]
		}
		if len(row) > 5 {
			city = row[5]
		}

		detail := fmt.Sprintf("[FOFA] %s:%s/%s encontrado. Título: %q. Localização: %s/%s",
			ip, port, proto, truncate(title, 80), country, city)

		if net.ParseIP(ip) == nil {
			continue
		}
		finding := module.Finding{
			Type:     "external_inventory_reference",
			URL:      fmt.Sprintf("https://fofa.info/result?qbase64=%s", encoded),
			Detail:   detail,
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":             "fofa",
				"ip":                 ip,
				"port":               port,
				"protocol":           proto,
				"title":              truncate(title, 200),
				"country":            country,
				"city":               city,
				"confidence":         "0.65",
				"validated":          "false",
				"validation_state":   "third_party_inventory_reference",
				"promote_to_context": "false",
			},
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func isWanted(filter, name string) bool {
	if filter == "" {
		return true
	}
	for _, s := range strings.Split(filter, ",") {
		if strings.TrimSpace(s) == name {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func optInt(opts map[string]string, key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(opts[key]))
	if err != nil {
		return fallback
	}
	return value
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

func looksLikeInvalidIP(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && r != '.' && r != ':' {
			return false
		}
	}
	return strings.ContainsAny(value, ".:")
}

func externalCVESeverity(cvss float64) module.Severity {
	switch {
	case cvss >= 9:
		return module.SeverityHigh
	case cvss >= 7:
		return module.SeverityMedium
	case cvss >= 4:
		return module.SeverityLow
	default:
		return module.SeverityInfo
	}
}

func defaultClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	out := make([]module.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Extra["source"] + "|" + f.Extra["port"]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
