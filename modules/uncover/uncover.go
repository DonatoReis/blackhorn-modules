// Package uncover discovers exposed assets using internet-wide scanning engines.
// Supported sources (all free-tier or keyless modes available):
//   - shodan:    Shodan internetdb API (IP lookup, no key required)
//   - censys:    Censys.io public API (API key optional via Options)
//   - fofa:      FOFA public search API (email+key via Options)
//   - hunter:    Hunter.how API (key via Options)
//   - zoomeye:   ZoomEye public host search (key via Options)
//   - quake:     360Quake API (key via Options)
//   - netlas:    Netlas.io (key via Options)
//   - publicwww: PublicWWW source-code search (key via Options)
//
// Reference: projectdiscovery/uncover (MIT) — API endpoint patterns only;
// no source code copied. License: MIT (blackhorn-modules).
package uncover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	defaultTimeout           = 20 * time.Second
	maxBodyBytes             = 2 * 1024 * 1024 // 2 MiB
	defaultMaxRuntimeSeconds = 30
	maxSources               = 8
)

// ─── module ──────────────────────────────────────────────────────────────────

// Module implements multi-source internet asset discovery.
type Module struct {
	client *http.Client
	// Sources is the list of engines to query. Default: ["shodan"].
	Sources []string
	// Limit caps the number of results per source (0 = engine default).
	Limit int

	// Base URLs — overridable for testing.
	ShodanBaseURL    string
	CensysBaseURL    string
	FofaBaseURL      string
	HunterBaseURL    string
	ZoomeyeBaseURL   string
	QuakeBaseURL     string
	NetlasBaseURL    string
	PublicwwwBaseURL string
}

// New returns a Module with production defaults.
func New() *Module {
	return &Module{
		client:  httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		Sources: []string{"shodan"},
		Limit:   100,
	}
}

// NewWithClient creates a Module using the provided HTTP client.
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client:  c,
		Sources: []string{"shodan"},
		Limit:   100,
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "uncover" }

// Run implements module.Module.
//
// Input.Target: a query string or IP/CIDR/domain.
// Input.Options:
//   - "query":         search query (overrides Target)
//   - "sources":       comma-separated list of engines to query
//   - "limit":         max results per source (default: 100)
//   - "censys_id":     Censys API ID
//   - "censys_secret": Censys API secret
//   - "fofa_email":    FOFA email
//   - "fofa_key":      FOFA API key
//   - "hunter_key":    Hunter.how API key
//   - "zoomeye_key":   ZoomEye API key
//   - "quake_token":   360Quake token
//   - "netlas_key":    Netlas API key
//   - "publicwww_key": PublicWWW API key
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	query, sources, opts := m.parseInput(input)
	if query == "" {
		return nil, fmt.Errorf("uncover: no query provided (set Input.Target or Options[\"query\"])")
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("uncover: no sources configured")
	}
	runModule := *m
	requestedLimit := optInt(opts, "limit", m.Limit)
	if requestedLimit <= 0 {
		requestedLimit = 100
	}
	runModule.Limit = clampInt(requestedLimit, 1, 500)
	maxRuntime := time.Duration(clampInt(optInt(opts, "max_runtime_seconds", defaultMaxRuntimeSeconds), 1, 120)) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, maxRuntime)
	defer cancel()

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	g, gctx := errgroup.WithContext(runCtx)
	g.SetLimit(min(len(sources), maxSources))

	for _, src := range sources {
		src := src
		g.Go(func() error {
			ff, err := runModule.querySource(gctx, src, query, opts)
			if err != nil {
				slog.Warn("uncover: source query failed", "source", src, "err", err)
				return nil
			}
			if len(ff) > 0 {
				mu.Lock()
				findings = append(findings, ff...)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()
	return dedupFindings(findings), nil
}

// ─── input parsing ────────────────────────────────────────────────────────────

func (m *Module) parseInput(input module.Input) (query string, sources []string, opts map[string]string) {
	opts = input.Options
	if opts == nil {
		opts = make(map[string]string)
	}

	query = opts["query"]
	if query == "" {
		query = input.Target
	}

	if v := opts["sources"]; v != "" {
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(strings.ToLower(s))
			if s != "" {
				sources = append(sources, s)
			}
		}
	}
	if len(sources) == 0 {
		sources = m.Sources
	}
	sources = dedupStrings(sources)
	return
}

// ─── source dispatcher ────────────────────────────────────────────────────────

func (m *Module) querySource(ctx context.Context, source, query string, opts map[string]string) ([]module.Finding, error) {
	switch source {
	case "shodan":
		return m.queryShodan(ctx, query)
	case "censys":
		return m.queryCensys(ctx, query, opts["censys_id"], opts["censys_secret"])
	case "fofa":
		return m.queryFofa(ctx, query, opts["fofa_email"], opts["fofa_key"])
	case "hunter":
		return m.queryHunter(ctx, query, opts["hunter_key"])
	case "zoomeye":
		return m.queryZoomeye(ctx, query, opts["zoomeye_key"])
	case "quake":
		return m.queryQuake(ctx, query, opts["quake_token"])
	case "netlas":
		return m.queryNetlas(ctx, query, opts["netlas_key"])
	case "publicwww":
		return m.queryPublicwww(ctx, query, opts["publicwww_key"])
	default:
		return nil, fmt.Errorf("unknown source: %q", source)
	}
}

// ─── Shodan InternetDB (no key required) ─────────────────────────────────────

type shodanInternetDB struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
	CPEs      []string `json:"cpes"`
}

func (m *Module) shodanBase() string {
	if m.ShodanBaseURL != "" {
		return m.ShodanBaseURL
	}
	return "https://internetdb.shodan.io"
}

func (m *Module) queryShodan(ctx context.Context, query string) ([]module.Finding, error) {
	if net.ParseIP(query) == nil {
		return nil, nil
	}
	// InternetDB supports single IP lookup — if query is not a valid IP,
	// emit an info finding with the query (search API requires key).
	apiURL := fmt.Sprintf("%s/%s", m.shodanBase(), url.PathEscape(query))
	body, code, err := m.get(ctx, apiURL, "")
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		return nil, nil // no results, not an error
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("shodan internetdb returned HTTP %d", code)
	}

	var result shodanInternetDB
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("shodan: JSON parse error: %w", err)
	}

	var findings []module.Finding
	for _, port := range result.Ports {
		host := result.IP
		if net.ParseIP(host) == nil || host != query {
			continue
		}
		findings = append(findings, module.Finding{
			Type:     "external_inventory_reference",
			URL:      fmt.Sprintf("%s:%d", host, port),
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("Third-party InternetDB reference reports port %d on %s; confirm directly before treating it as exposed", port, host),
			Extra: map[string]string{
				"source":             "shodan",
				"ip":                 host,
				"port":               fmt.Sprintf("%d", port),
				"hostnames":          strings.Join(result.Hostnames, ","),
				"vulns":              strings.Join(result.Vulns, ","),
				"confidence":         "0.60",
				"validated":          "false",
				"validation_state":   "third_party_inventory_reference",
				"promote_to_context": "false",
			},
		})
	}

	// Emit finding for each known vulnerability.
	for _, vuln := range result.Vulns {
		findings = append(findings, module.Finding{
			Type:     "external_vulnerability_reference",
			URL:      result.IP,
			Severity: module.SeverityMedium,
			Detail:   fmt.Sprintf("Third-party InternetDB reference associates %s with %s; validate service version and exposure directly", result.IP, vuln),
			Extra: map[string]string{
				"source":             "shodan",
				"cve":                vuln,
				"ip":                 result.IP,
				"confidence":         "0.55",
				"validated":          "false",
				"validation_state":   "third_party_vulnerability_reference",
				"promote_to_context": "false",
			},
		})
	}
	return findings, nil
}

// ─── Censys (public search API, optional auth) ────────────────────────────────

type censysResponse struct {
	Result struct {
		Hits []struct {
			IP       string `json:"ip"`
			Services []struct {
				Port           int    `json:"port"`
				TransportProto string `json:"transport_protocol"`
				ServiceName    string `json:"service_name"`
			} `json:"services"`
		} `json:"hits"`
	} `json:"result"`
}

func (m *Module) censysBase() string {
	if m.CensysBaseURL != "" {
		return m.CensysBaseURL
	}
	return "https://search.censys.io/api/v2"
}

func (m *Module) queryCensys(ctx context.Context, query, id, secret string) ([]module.Finding, error) {
	apiURL := fmt.Sprintf("%s/hosts/search?q=%s&per_page=%d",
		m.censysBase(), url.QueryEscape(query), clampLimit(m.Limit, 25))

	auth := ""
	if id != "" && secret != "" {
		auth = id + ":" + secret
	}
	body, code, err := m.get(ctx, apiURL, auth)
	if err != nil {
		return nil, err
	}
	if code == http.StatusUnauthorized {
		return nil, fmt.Errorf("censys: authentication required (provide censys_id + censys_secret)")
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("censys: HTTP %d", code)
	}

	var resp censysResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("censys: JSON parse error: %w", err)
	}

	var findings []module.Finding
	for _, hit := range resp.Result.Hits {
		for _, svc := range hit.Services {
			if net.ParseIP(hit.IP) == nil {
				continue
			}
			findings = append(findings, module.Finding{
				Type:     "external_inventory_reference",
				URL:      fmt.Sprintf("%s:%d", hit.IP, svc.Port),
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("Third-party Censys reference reports %s/%s on %s; confirm directly", svc.ServiceName, svc.TransportProto, hit.IP),
				Extra: map[string]string{
					"source":             "censys",
					"ip":                 hit.IP,
					"port":               fmt.Sprintf("%d", svc.Port),
					"service":            svc.ServiceName,
					"confidence":         "0.65",
					"validated":          "false",
					"validation_state":   "third_party_inventory_reference",
					"promote_to_context": "false",
				},
			})
		}
	}
	return findings, nil
}

// ─── FOFA ────────────────────────────────────────────────────────────────────

type fofaResponse struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg"`
	Results [][]string `json:"results"`
}

func (m *Module) fofaBase() string {
	if m.FofaBaseURL != "" {
		return m.FofaBaseURL
	}
	return "https://fofa.info/api/v1"
}

func (m *Module) queryFofa(ctx context.Context, query, email, key string) ([]module.Finding, error) {
	if email == "" || key == "" {
		return nil, fmt.Errorf("fofa: requires fofa_email and fofa_key in Options")
	}
	apiURL := fmt.Sprintf("%s/search/all?email=%s&key=%s&qbase64=%s&size=%d&fields=host,ip,port",
		m.fofaBase(), url.QueryEscape(email), key,
		encodeBase64(query), clampLimit(m.Limit, 100))

	body, code, err := m.get(ctx, apiURL, "")
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("fofa: HTTP %d", code)
	}

	var resp fofaResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("fofa: JSON parse error: %w", err)
	}
	if resp.Error {
		return nil, fmt.Errorf("fofa API error: %s", resp.ErrMsg)
	}

	var findings []module.Finding
	for _, result := range resp.Results {
		if len(result) < 3 {
			continue
		}
		host, ip, port := result[0], result[1], result[2]
		if net.ParseIP(ip) == nil {
			continue
		}
		findings = append(findings, module.Finding{
			Type:     "external_inventory_reference",
			URL:      host,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("%s port %s found via FOFA", ip, port),
			Extra: map[string]string{
				"source":             "fofa",
				"ip":                 ip,
				"port":               port,
				"host":               host,
				"confidence":         "0.60",
				"validated":          "false",
				"validation_state":   "third_party_inventory_reference",
				"promote_to_context": "false",
			},
		})
	}
	return findings, nil
}

// ─── Hunter.how ───────────────────────────────────────────────────────────────

type hunterResponse struct {
	Data struct {
		Total int `json:"total"`
		Arr   []struct {
			IP      string `json:"ip"`
			Port    int    `json:"port"`
			Domain  string `json:"domain"`
			Company string `json:"company"`
		} `json:"arr"`
	} `json:"data"`
}

func (m *Module) hunterBase() string {
	if m.HunterBaseURL != "" {
		return m.HunterBaseURL
	}
	return "https://hunter.how/api/v1"
}

func (m *Module) queryHunter(ctx context.Context, query, key string) ([]module.Finding, error) {
	if key == "" {
		return nil, fmt.Errorf("hunter: requires hunter_key in Options")
	}
	apiURL := fmt.Sprintf("%s/asset/index?api-key=%s&search=%s&page=1&page_size=%d",
		m.hunterBase(), key, url.QueryEscape(query), clampLimit(m.Limit, 100))

	body, code, err := m.get(ctx, apiURL, "")
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("hunter: HTTP %d", code)
	}

	var resp hunterResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("hunter: JSON parse error: %w", err)
	}

	var findings []module.Finding
	for _, item := range resp.Data.Arr {
		if net.ParseIP(item.IP) == nil {
			continue
		}
		target := item.IP
		if item.Domain != "" {
			target = item.Domain
		}
		findings = append(findings, module.Finding{
			Type:     "external_inventory_reference",
			URL:      fmt.Sprintf("%s:%d", target, item.Port),
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("%s:%d found via Hunter.how", item.IP, item.Port),
			Extra: map[string]string{
				"source":             "hunter",
				"ip":                 item.IP,
				"port":               fmt.Sprintf("%d", item.Port),
				"domain":             item.Domain,
				"company":            item.Company,
				"confidence":         "0.60",
				"validated":          "false",
				"validation_state":   "third_party_inventory_reference",
				"promote_to_context": "false",
			},
		})
	}
	return findings, nil
}

// ─── ZoomEye ─────────────────────────────────────────────────────────────────

type zoomeyeResponse struct {
	Matches []struct {
		IP       string `json:"ip"`
		PortInfo struct {
			Port int `json:"port"`
		} `json:"portinfo"`
	} `json:"matches"`
}

func (m *Module) zoomeyeBase() string {
	if m.ZoomeyeBaseURL != "" {
		return m.ZoomeyeBaseURL
	}
	return "https://api.zoomeye.org"
}

func (m *Module) queryZoomeye(ctx context.Context, query, key string) ([]module.Finding, error) {
	if key == "" {
		return nil, fmt.Errorf("zoomeye: requires zoomeye_key in Options")
	}
	apiURL := fmt.Sprintf("%s/host/search?query=%s&page=1", m.zoomeyeBase(), url.QueryEscape(query))
	body, code, err := m.getWithKey(ctx, apiURL, "API-KEY", key)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("zoomeye: HTTP %d", code)
	}

	var resp zoomeyeResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("zoomeye: JSON parse error: %w", err)
	}

	var findings []module.Finding
	for _, match := range resp.Matches {
		if net.ParseIP(match.IP) == nil {
			continue
		}
		findings = append(findings, module.Finding{
			Type:     "external_inventory_reference",
			URL:      fmt.Sprintf("%s:%d", match.IP, match.PortInfo.Port),
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("%s:%d found via ZoomEye", match.IP, match.PortInfo.Port),
			Extra: map[string]string{
				"source":             "zoomeye",
				"ip":                 match.IP,
				"port":               fmt.Sprintf("%d", match.PortInfo.Port),
				"confidence":         "0.60",
				"validated":          "false",
				"validation_state":   "third_party_inventory_reference",
				"promote_to_context": "false",
			},
		})
	}
	return findings, nil
}

// ─── 360Quake ─────────────────────────────────────────────────────────────────

type quakeResponse struct {
	Data []struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"data"`
}

func (m *Module) quakeBase() string {
	if m.QuakeBaseURL != "" {
		return m.QuakeBaseURL
	}
	return "https://quake.360.net/api/v3"
}

func (m *Module) queryQuake(ctx context.Context, query, token string) ([]module.Finding, error) {
	if token == "" {
		return nil, fmt.Errorf("quake: requires quake_token in Options")
	}
	apiURL := fmt.Sprintf("%s/search/quake_host", m.quakeBase())
	payload := fmt.Sprintf(`{"query":%q,"start":0,"size":%d}`, query, clampLimit(m.Limit, 100))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-QuakeToken", token)

	body, code, err := m.doRequest(req)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("quake: HTTP %d", code)
	}

	var resp quakeResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("quake: JSON parse error: %w", err)
	}

	var findings []module.Finding
	for _, item := range resp.Data {
		if net.ParseIP(item.IP) == nil {
			continue
		}
		findings = append(findings, module.Finding{
			Type:     "external_inventory_reference",
			URL:      fmt.Sprintf("%s:%d", item.IP, item.Port),
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("%s:%d found via 360Quake", item.IP, item.Port),
			Extra: map[string]string{
				"source":             "quake",
				"ip":                 item.IP,
				"port":               fmt.Sprintf("%d", item.Port),
				"confidence":         "0.60",
				"validated":          "false",
				"validation_state":   "third_party_inventory_reference",
				"promote_to_context": "false",
			},
		})
	}
	return findings, nil
}

// ─── Netlas ───────────────────────────────────────────────────────────────────

type netlasResponse struct {
	Items []struct {
		Data struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		} `json:"data"`
	} `json:"items"`
}

func (m *Module) netlasBase() string {
	if m.NetlasBaseURL != "" {
		return m.NetlasBaseURL
	}
	return "https://app.netlas.io/api"
}

func (m *Module) queryNetlas(ctx context.Context, query, key string) ([]module.Finding, error) {
	if key == "" {
		return nil, fmt.Errorf("netlas: requires netlas_key in Options")
	}
	apiURL := fmt.Sprintf("%s/responses/?q=%s&count=%d&source_type=include",
		m.netlasBase(), url.QueryEscape(query), clampLimit(m.Limit, 100))
	body, code, err := m.getWithKey(ctx, apiURL, "X-API-Key", key)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("netlas: HTTP %d", code)
	}

	var resp netlasResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("netlas: JSON parse error: %w", err)
	}

	var findings []module.Finding
	for _, item := range resp.Items {
		d := item.Data
		if net.ParseIP(d.IP) == nil {
			continue
		}
		findings = append(findings, module.Finding{
			Type:     "external_inventory_reference",
			URL:      fmt.Sprintf("%s:%d", d.IP, d.Port),
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("%s:%d found via Netlas", d.IP, d.Port),
			Extra: map[string]string{
				"source":             "netlas",
				"ip":                 d.IP,
				"port":               fmt.Sprintf("%d", d.Port),
				"confidence":         "0.60",
				"validated":          "false",
				"validation_state":   "third_party_inventory_reference",
				"promote_to_context": "false",
			},
		})
	}
	return findings, nil
}

// ─── PublicWWW ────────────────────────────────────────────────────────────────

type publicwwwResponse struct {
	Results []struct {
		URL string `json:"url"`
	} `json:"results"`
}

func (m *Module) publicwwwBase() string {
	if m.PublicwwwBaseURL != "" {
		return m.PublicwwwBaseURL
	}
	return "https://publicwww.com"
}

func (m *Module) queryPublicwww(ctx context.Context, query, key string) ([]module.Finding, error) {
	if key == "" {
		return nil, fmt.Errorf("publicwww: requires publicwww_key in Options")
	}
	apiURL := fmt.Sprintf("%s/websites/search.json?q=%s&key=%s&n=%d",
		m.publicwwwBase(), url.QueryEscape(query), key, clampLimit(m.Limit, 100))

	body, code, err := m.get(ctx, apiURL, "")
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("publicwww: HTTP %d", code)
	}

	var resp publicwwwResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("publicwww: JSON parse error: %w", err)
	}

	var findings []module.Finding
	for _, r := range resp.Results {
		findings = append(findings, module.Finding{
			Type:     "external_source_reference",
			URL:      r.URL,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("URL %s matched query via PublicWWW", r.URL),
			Extra: map[string]string{
				"source":             "publicwww",
				"confidence":         "0.55",
				"validated":          "false",
				"validation_state":   "third_party_source_reference",
				"promote_to_context": "false",
			},
		})
	}
	return findings, nil
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

// get performs a GET request, optionally with Basic Auth (user:pass encoded).
func (m *Module) get(ctx context.Context, rawURL, basicAuth string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "blackhorn-uncover/1.0")
	if basicAuth != "" {
		parts := strings.SplitN(basicAuth, ":", 2)
		if len(parts) == 2 {
			req.SetBasicAuth(parts[0], parts[1])
		}
	}
	return m.doRequest(req)
}

// getWithKey performs a GET with a custom header API key.
func (m *Module) getWithKey(ctx context.Context, rawURL, headerName, key string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "blackhorn-uncover/1.0")
	req.Header.Set(headerName, key)
	return m.doRequest(req)
}

func (m *Module) doRequest(req *http.Request) ([]byte, int, error) {
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

// ─── helpers ─────────────────────────────────────────────────────────────────

func clampLimit(limit, def int) int {
	if limit <= 0 {
		return def
	}
	if limit > 1000 {
		return 1000
	}
	return limit
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func dedupStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func encodeBase64(s string) string {
	// Simple URL-safe base64 without padding — used by FOFA API.
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := []byte(s)
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		end := i + 3
		if end > len(b) {
			end = len(b)
		}
		chunk := b[i:end]
		n := len(chunk)
		var v uint32
		for j, c := range chunk {
			v |= uint32(c) << (uint(2-j) * 8)
		}
		for j := 0; j < n+1; j++ {
			sb.WriteByte(table[(v>>(uint(3-j)*6))&0x3F])
		}
		for j := n + 1; j < 4; j++ {
			sb.WriteByte('=')
		}
	}
	return sb.String()
}

func dedupFindings(findings []module.Finding) []module.Finding {
	seen := make(map[string]struct{})
	out := findings[:0]
	for _, f := range findings {
		key := f.Type + "|" + f.URL
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, f)
		}
	}
	return out
}
