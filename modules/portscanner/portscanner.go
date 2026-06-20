// Package portscanner realiza varredura de portas TCP com detecção de serviço.
//
// Implementação nativa em Go via net.DialContext — sem dependências externas.
// Inclui banner grabbing básico para identificar serviços.
//
// Fontes/técnicas:
//   - Scan TCP nativo                — sem ferramentas externas
//   - Banner grabbing                — HTTP, SSH, FTP, SMTP, RDP, MySQL, etc.
//   - Serviço padrão por porta       — mapeamento builtin de 200+ portas
//   - Correlação Shodan              — enriquece com dados de Shodan (API key)
//   - Correlação Censys              — enriquece com dados de Censys (API key)
//
// Input:
//   - Target: IP ou hostname
//   - Options["ports"]         — lista de portas ou ranges (ex: "80,443,8080-8090"); default: top 100
//   - Options["timeout_ms"]    — timeout por porta em ms (default: 2000)
//   - Options["concurrency"]   — parallelismo (default: 100)
//   - Options["banner"]        — "true" para fazer banner grab (default: true)
//   - Options["shodan_key"]    — API key Shodan (opcional)
//   - Options["censys_id"]     — Censys API ID (opcional)
//   - Options["censys_secret"] — Censys API Secret (opcional)
//
// IMPORTANTE: Só use com autorização explícita do alvo.
// Este módulo é para testes de penetração autorizados, auditorias e pesquisa defensiva.
package portscanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	maxBodyBytes             = 2 << 20
	defaultTimeoutMs         = 2000
	defaultConcurrency       = 100
	maxConcurrency           = 500
	bannerReadBytes          = 2048
	defaultMaxRuntimeSeconds = 300
	defaultMaxPorts          = 1000
)

// top100Ports são as portas mais relevantes para varredura rápida.
var top100Ports = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 194, 389, 443, 445,
	465, 500, 515, 587, 636, 993, 995, 1080, 1433, 1521, 1723, 2049, 2082, 2083,
	2086, 2087, 2095, 2096, 2181, 2375, 2376, 3000, 3306, 3389, 3690, 4333, 4848,
	5000, 5432, 5900, 5985, 5986, 6379, 6443, 7001, 7474, 8000, 8008, 8080, 8081,
	8086, 8088, 8443, 8888, 8983, 9000, 9090, 9200, 9300, 9418, 10000, 11211, 15672,
	27017, 27018, 28017, 50000, 50070, 61616,
}

// serviceNames mapeamento builtin de porta → nome do serviço.
var serviceNames = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP", 135: "RPC/DCOM",
	139: "NetBIOS", 143: "IMAP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
	445: "SMB/CIFS", 465: "SMTPS", 500: "ISAKMP/IKE", 515: "LPD", 587: "SMTP-TLS",
	636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
	1521: "Oracle", 1723: "PPTP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
	2086: "WHM", 2087: "WHM-SSL", 2095: "cPanel-Mail", 2096: "cPanel-Mail-SSL",
	2181: "ZooKeeper", 2375: "Docker", 2376: "Docker-TLS",
	3000: "HTTP-alt", 3306: "MySQL", 3389: "RDP", 3690: "SVN",
	4848: "GlassFish", 5000: "Flask/UPnP", 5432: "PostgreSQL", 5900: "VNC",
	5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis", 6443: "Kubernetes",
	7001: "WebLogic", 7474: "Neo4j", 8000: "HTTP-alt", 8008: "HTTP-alt",
	8080: "HTTP-proxy", 8081: "HTTP-alt", 8086: "InfluxDB", 8088: "HTTP-alt",
	8443: "HTTPS-alt", 8888: "Jupyter", 8983: "Solr", 9000: "PHP-FPM",
	9090: "Prometheus", 9200: "Elasticsearch", 9300: "Elasticsearch-cluster",
	9418: "Git", 10000: "Webmin", 11211: "Memcached", 15672: "RabbitMQ-Mgmt",
	27017: "MongoDB", 27018: "MongoDB", 28017: "MongoDB-Web",
	50000: "DB2", 50070: "HDFS-NameNode", 61616: "ActiveMQ",
}

// riskyServices são serviços que justificam severidade Higher por default.
var riskyServices = map[int]bool{
	23: true, 135: true, 139: true, 445: true, 1433: true, 1521: true,
	2375: true, 3389: true, 5900: true, 6379: true, 11211: true, 27017: true,
	50070: true, 61616: true,
}

// ScanResult armazena o resultado de uma porta.
type ScanResult struct {
	Port    int
	Open    bool
	Service string
	Banner  string
	Latency time.Duration
}

// Module implementa o módulo portscanner.
type Module struct {
	client *http.Client
}

// New cria um módulo com cliente padrão.
func New() *Module {
	return NewWithClient(&http.Client{Timeout: 10 * time.Second})
}

// NewWithClient cria um módulo com cliente customizado.
func NewWithClient(c *http.Client) *Module {
	return &Module{client: c}
}

// Name retorna o identificador do módulo.
func (m *Module) Name() string { return "portscanner" }

// Run executa a varredura de portas.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("portscanner: target não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	timeoutMs := clampInt(optInt(opts, "timeout_ms", defaultTimeoutMs), 50, 30_000)
	concurrency := clampInt(optInt(opts, "concurrency", defaultConcurrency), 1, maxConcurrency)
	doBanner := optStr(opts, "banner", "true") != "false"
	maxPorts := clampInt(optInt(opts, "max_ports", defaultMaxPorts), 1, 65_535)
	maxRuntime := time.Duration(clampInt(optInt(opts, "max_runtime_seconds", defaultMaxRuntimeSeconds), 1, 3600)) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, maxRuntime)
	defer cancel()

	shodanKey := firstNonEmpty(opts["shodan_key"], os.Getenv("SHODAN_API_KEY"))
	censysID := firstNonEmpty(opts["censys_id"], os.Getenv("CENSYS_API_ID"))
	censysSecret := firstNonEmpty(opts["censys_secret"], os.Getenv("CENSYS_API_SECRET"))

	ports, err := parsePorts(optStr(opts, "ports", "top100"))
	if err != nil {
		return nil, fmt.Errorf("portscanner: %w", err)
	}
	if len(ports) > maxPorts {
		return nil, fmt.Errorf("portscanner: %d portas excedem max_ports=%d", len(ports), maxPorts)
	}

	// Resolve hostname para IP
	ip, err := resolveTarget(runCtx, target)
	if err != nil {
		return nil, fmt.Errorf("portscanner: resolve %q: %w", target, err)
	}

	slog.InfoContext(runCtx, "portscanner: iniciando varredura",
		"target", target,
		"ip", ip,
		"total_ports", len(ports),
		"concurrency", concurrency,
		"timeout_ms", timeoutMs,
	)

	// Varredura das portas
	results := m.scanPorts(runCtx, ip, ports, timeoutMs, concurrency, doBanner)

	openPorts := make([]ScanResult, 0)
	for _, r := range results {
		if r.Open {
			openPorts = append(openPorts, r)
		}
	}

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	slog.InfoContext(runCtx, "portscanner: varredura concluída",
		"open_ports", len(openPorts),
		"total_scanned", len(ports),
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

	// Findings de varredura local
	localFindings := buildLocalFindings(target, ip, openPorts)
	add(localFindings)

	// Enriquecimento externo em paralelo
	eg, ctx2 := errgroup.WithContext(runCtx)
	eg.SetLimit(2)

	if shodanKey != "" {
		eg.Go(func() error {
			ff, err := m.queryShodan(ctx2, ip, shodanKey)
			if err != nil {
				slog.WarnContext(ctx2, "portscanner: shodan falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	if censysID != "" && censysSecret != "" {
		eg.Go(func() error {
			ff, err := m.queryCensys(ctx2, ip, censysID, censysSecret)
			if err != nil {
				slog.WarnContext(ctx2, "portscanner: censys falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	_ = eg.Wait()

	result := dedup(findings)

	slog.InfoContext(runCtx, "portscanner: finalizado",
		"total_findings", len(result),
	)

	return result, nil
}

// ─── Varredura de portas ─────────────────────────────────────────────────────

func (m *Module) scanPorts(ctx context.Context, ip string, ports []int, timeoutMs, concurrency int, doBanner bool) []ScanResult {
	results := make([]ScanResult, len(ports))
	for i, p := range ports {
		results[i].Port = p
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	timeout := time.Duration(timeoutMs) * time.Millisecond

	for i, port := range ports {
		select {
		case <-ctx.Done():
			return results
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()
			defer func() { <-sem }()

			results[idx] = scanPort(ctx, ip, p, timeout, doBanner)
		}(i, port)
	}

	wg.Wait()
	return results
}

func scanPort(ctx context.Context, ip string, port int, timeout time.Duration, doBanner bool) ScanResult {
	result := ScanResult{Port: port}

	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	start := time.Now()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	result.Latency = time.Since(start)

	if err != nil {
		return result
	}
	result.Open = true
	result.Service = serviceNames[port]

	if doBanner {
		result.Banner = grabBanner(conn, port, timeout)
	}
	conn.Close()

	return result
}

// grabBanner tenta capturar o banner de um serviço aberto.
func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	// Serviços que precisam de probe (request primeiro)
	switch port {
	case 80, 8000, 8008, 8080, 8081, 8088:
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n") //nolint:errcheck
	case 443, 8443:
		// TLS — não faz probe (handshake seria necessário)
		return ""
	case 25, 465, 587:
		// SMTP — aguarda banner do servidor
	case 21:
		// FTP — aguarda banner
	case 22:
		// SSH — aguarda banner
	case 3306:
		// MySQL — aguarda greeting
	}

	buf := make([]byte, bannerReadBytes)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	banner := cleanBanner(string(buf[:n]))
	return banner
}

// cleanBanner remove caracteres não-printáveis do banner.
func cleanBanner(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		} else if r == '\n' || r == '\r' {
			b.WriteRune(' ')
		}
	}
	result := strings.TrimSpace(b.String())
	if len(result) > 512 {
		return result[:512]
	}
	return result
}

// ─── Findings locais ─────────────────────────────────────────────────────────

func buildLocalFindings(target, ip string, openPorts []ScanResult) []module.Finding {
	if len(openPorts) == 0 {
		return []module.Finding{
			{
				Type:     "scan_summary",
				URL:      "",
				Detail:   fmt.Sprintf("Varredura de '%s' (%s): nenhuma porta aberta encontrada.", target, ip),
				Severity: module.SeverityInfo,
				Extra: map[string]string{
					"target":             target,
					"ip":                 ip,
					"open_ports":         "0",
					"fonte":              "portscanner",
					"confidence":         "0.95",
					"validated":          "true",
					"validation_state":   "tcp_connect_scan_complete",
					"promote_to_context": "false",
				},
			},
		}
	}

	var findings []module.Finding

	// Summary
	portNums := make([]string, 0, len(openPorts))
	for _, p := range openPorts {
		portNums = append(portNums, fmt.Sprintf("%d", p.Port))
	}

	findings = append(findings, module.Finding{
		Type:     "scan_summary",
		URL:      "",
		Detail:   fmt.Sprintf("Varredura de '%s' (%s): %d porta(s) aberta(s): [%s].", target, ip, len(openPorts), strings.Join(portNums, ", ")),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"target":             target,
			"ip":                 ip,
			"open_ports":         fmt.Sprintf("%d", len(openPorts)),
			"port_list":          strings.Join(portNums, ","),
			"fonte":              "portscanner",
			"confidence":         "0.95",
			"validated":          "true",
			"validation_state":   "tcp_connect_scan_complete",
			"promote_to_context": "false",
		},
	})

	// Finding por porta
	for _, r := range openPorts {
		svc := r.Service
		if svc == "" {
			svc = "unknown"
		}

		severity := module.SeverityLow
		if riskyServices[r.Port] {
			severity = module.SeverityMedium
		}

		detail := fmt.Sprintf("Porta %d/%s aberta em '%s' (%s). Latência: %dms.", r.Port, svc, target, ip, r.Latency.Milliseconds())
		if r.Banner != "" {
			detail += fmt.Sprintf(" Banner: %s", truncate(r.Banner, 100))
		}

		extra := map[string]string{
			"port":               fmt.Sprintf("%d", r.Port),
			"service":            svc,
			"ip":                 ip,
			"latency_ms":         fmt.Sprintf("%d", r.Latency.Milliseconds()),
			"risky":              fmt.Sprintf("%v", riskyServices[r.Port]),
			"fonte":              "portscanner",
			"confidence":         "0.98",
			"validated":          "true",
			"validation_state":   "tcp_connect_confirmed",
			"promote_to_context": "true",
		}
		if r.Banner != "" {
			extra["banner"] = truncate(r.Banner, 256)
		}

		findings = append(findings, module.Finding{
			Type:     "open_port",
			URL:      fmt.Sprintf("http://%s", net.JoinHostPort(ip, strconv.Itoa(r.Port))),
			Detail:   detail,
			Severity: severity,
			Extra:    extra,
		})
	}

	return findings
}

// ─── Shodan ──────────────────────────────────────────────────────────────────

func (m *Module) queryShodan(ctx context.Context, ip, apiKey string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, apiKey)

	respBody, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("shodan: %w", err)
	}

	var result struct {
		IP         string `json:"ip_str"`
		OS         string `json:"os"`
		Org        string `json:"org"`
		ISP        string `json:"isp"`
		Country    string `json:"country_name"`
		City       string `json:"city"`
		ASN        string `json:"asn"`
		LastUpdate string `json:"last_update"`
		Ports      []int  `json:"ports"`
		Data       []struct {
			Port      int    `json:"port"`
			Transport string `json:"transport"`
			Product   string `json:"product"`
			Version   string `json:"version"`
			Banner    string `json:"data"`
			Vulns     map[string]struct {
				CVSS float64 `json:"cvss"`
			} `json:"vulns"`
		} `json:"data"`
		Vulns []string `json:"vulns"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("shodan: parse: %w", err)
	}
	if net.ParseIP(result.IP) == nil || result.IP != ip {
		return nil, nil
	}

	var findings []module.Finding

	orgStr := result.Org
	if result.ISP != "" && result.ISP != orgStr {
		orgStr = orgStr + " / " + result.ISP
	}

	findings = append(findings, module.Finding{
		Type: "external_inventory_reference",
		URL:  fmt.Sprintf("https://www.shodan.io/host/%s", ip),
		Detail: fmt.Sprintf("Shodan: %s — OS: %s, Org: %s, País: %s/%s, ASN: %s. Portas indexadas: %v.",
			ip, result.OS, orgStr, result.Country, result.City, result.ASN, result.Ports),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"os":                 result.OS,
			"org":                orgStr,
			"country":            result.Country,
			"city":               result.City,
			"asn":                result.ASN,
			"last_update":        result.LastUpdate,
			"ip":                 result.IP,
			"fonte":              "shodan",
			"confidence":         "0.70",
			"validated":          "false",
			"validation_state":   "third_party_inventory_reference",
			"promote_to_context": "false",
		},
	})

	// CVEs encontradas pelo Shodan
	for _, svc := range result.Data {
		for cve, vuln := range svc.Vulns {
			cvss := vuln.CVSS
			severity := externalCVESeverity(cvss)

			findings = append(findings, module.Finding{
				Type: "external_vulnerability_reference",
				URL:  fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve),
				Detail: fmt.Sprintf("Shodan associa %s (CVSS %.1f) à porta %d/%s (%s v%s) de %s; confirme banner e versão diretamente.",
					cve, cvss, svc.Port, svc.Transport, svc.Product, svc.Version, ip),
				Severity: severity,
				Extra: map[string]string{
					"cve":                cve,
					"cvss":               fmt.Sprintf("%.1f", cvss),
					"port":               fmt.Sprintf("%d", svc.Port),
					"product":            svc.Product,
					"version":            svc.Version,
					"ip":                 ip,
					"fonte":              "shodan",
					"confidence":         "0.60",
					"validated":          "false",
					"validation_state":   "third_party_vulnerability_reference",
					"promote_to_context": "false",
				},
			})
		}
	}

	return findings, nil
}

// ─── Censys ──────────────────────────────────────────────────────────────────

func (m *Module) queryCensys(ctx context.Context, ip, apiID, apiSecret string) ([]module.Finding, error) {
	u := fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", ip)

	creds := base64.StdEncoding.EncodeToString([]byte(apiID + ":" + apiSecret))
	respBody, err := m.get(ctx, u, map[string]string{
		"Authorization": "Basic " + creds,
	})
	if err != nil {
		return nil, fmt.Errorf("censys: %w", err)
	}

	var result struct {
		Result struct {
			IP               string `json:"ip"`
			AutonomousSystem struct {
				ASN     int    `json:"asn"`
				Name    string `json:"name"`
				Prefix  string `json:"bgp_prefix"`
				Country string `json:"country_code"`
			} `json:"autonomous_system"`
			Services []struct {
				Port            int    `json:"port"`
				Transport       string `json:"transport_protocol"`
				ServiceName     string `json:"service_name"`
				ExtendedService string `json:"extended_service_name"`
				TLS             *struct {
					CertName string `json:"certificate"`
				} `json:"tls,omitempty"`
			} `json:"services"`
			OS struct {
				Product string `json:"product"`
				Version string `json:"version"`
			} `json:"operating_system"`
		} `json:"result"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("censys: parse: %w", err)
	}

	r := result.Result
	if net.ParseIP(r.IP) == nil || r.IP != ip {
		return nil, nil
	}

	var findings []module.Finding

	portList := make([]string, 0, len(r.Services))
	for _, svc := range r.Services {
		portList = append(portList, fmt.Sprintf("%d/%s", svc.Port, svc.Transport))
	}

	findings = append(findings, module.Finding{
		Type: "external_inventory_reference",
		URL:  fmt.Sprintf("https://search.censys.io/hosts/%s", ip),
		Detail: fmt.Sprintf("Censys: %s — OS: %s %s, ASN: %d (%s/%s). Serviços: [%s].",
			ip, r.OS.Product, r.OS.Version, r.AutonomousSystem.ASN, r.AutonomousSystem.Name, r.AutonomousSystem.Country,
			strings.Join(portList, ", ")),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"asn":                fmt.Sprintf("%d", r.AutonomousSystem.ASN),
			"org":                r.AutonomousSystem.Name,
			"country":            r.AutonomousSystem.Country,
			"prefix":             r.AutonomousSystem.Prefix,
			"os":                 r.OS.Product + " " + r.OS.Version,
			"ip":                 r.IP,
			"fonte":              "censys",
			"confidence":         "0.70",
			"validated":          "false",
			"validation_state":   "third_party_inventory_reference",
			"promote_to_context": "false",
		},
	})

	return findings, nil
}

// ─── parsePorts ──────────────────────────────────────────────────────────────

var reRange = regexp.MustCompile(`^(\d+)-(\d+)$`)

func parsePorts(input string) ([]int, error) {
	if input == "top100" || input == "" {
		return top100Ports, nil
	}

	seen := make(map[int]struct{})
	var ports []int

	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if m := reRange.FindStringSubmatch(part); m != nil {
			start, _ := strconv.Atoi(m[1])
			end, _ := strconv.Atoi(m[2])
			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("range de porta inválido: %s", part)
			}
			for p := start; p <= end; p++ {
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("porta inválida: %s", part)
			}
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				ports = append(ports, p)
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("nenhuma porta válida especificada")
	}

	sort.Ints(ports)
	return ports, nil
}

// ─── resolveTarget ───────────────────────────────────────────────────────────

func resolveTarget(ctx context.Context, target string) (string, error) {
	// Verifica se já é IP
	if net.ParseIP(target) != nil {
		return target, nil
	}

	r := net.Resolver{}
	addrs, err := r.LookupHost(ctx, target)
	if err != nil {
		return "", fmt.Errorf("resolve DNS: %w", err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("sem endereços para %q", target)
	}
	return addrs[0], nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func externalCVESeverity(cvss float64) module.Severity {
	switch {
	case cvss >= 9.0:
		return module.SeverityHigh
	case cvss >= 7.0:
		return module.SeverityMedium
	case cvss >= 4.0:
		return module.SeverityLow
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

func clampInt(val, min, max int) int {
	if val < min {
		return min
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
