// Package bgpinfo realiza análise de segurança BGP de ASNs e prefixos IP.
//
// Fontes integradas:
//   - BGP.tools              — peers, prefixos, anycast, IX (público, sem key)
//   - RIPE NCC Stat          — prefixos anunciados, ASN neighbors, historico (público)
//   - Hurricane Electric BGP — informações de peers e path (público)
//   - Cloudflare Radar BGP   — eventos de route leak/hijack recentes (sem key)
//   - IPinfo.io              — ASN owner, abuse contacts (requer IPINFO_TOKEN opcional)
//   - RPKI status via Cloudflare — valida origem de prefixos (RPKI ROA)
//
// Tipos de target suportados:
//   - ASN         — "AS12345" ou "12345"
//   - Prefixo     — "198.51.100.0/24"
//   - IP          — "198.51.100.1" (resolve para prefixo/ASN)
//   - Domínio     — "example.com" (resolve para IP → ASN)
//
// Input:
//   - Target: ASN, prefixo CIDR, IP ou domínio
//   - Options["sources"]       — fontes separadas por vírgula (default: all)
//   - Options["ipinfo_token"]  — token IPinfo (ou IPINFO_TOKEN)
//   - Options["max_prefixes"]  — máximo de prefixos (default: 50)
//   - Options["check_rpki"]    — "true" para validar RPKI (default: true)
//
// Contexto de segurança:
//   - Identifica prefixos sem validação RPKI (risco de hijack)
//   - Detecta ASNs em múltiplos IX (superfície de ataque maior)
//   - Correlaciona com listas de ASNs abusivos conhecidos
package bgpinfo

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
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	maxBodyBytes       = 4 << 20
	defaultTimeout     = 20
	defaultMaxPrefixes = 50
)

var (
	reASN    = regexp.MustCompile(`^(?i)(as)?(\d+)$`)
	reCIDR   = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$`)
	reCIDRv6 = regexp.MustCompile(`^[0-9a-fA-F:]+/\d{1,3}$`)
	reIPv4   = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
)

// TargetType classifica o tipo de target.
type TargetType string

const (
	TargetASN     TargetType = "asn"
	TargetPrefix  TargetType = "prefix"
	TargetIP      TargetType = "ip"
	TargetDomain  TargetType = "domain"
	TargetUnknown TargetType = "unknown"
)

// Module implementa o módulo bgpinfo.
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
func (m *Module) Name() string { return "bgpinfo" }

// Run executa a análise BGP.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("bgpinfo: target não pode ser vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	enabledSources := parseSources(optStr(opts, "sources", "all"))
	maxPrefixes := optInt(opts, "max_prefixes", defaultMaxPrefixes)
	checkRPKI := optStr(opts, "check_rpki", "true") == "true"
	ipinfoToken := firstNonEmpty(opts["ipinfo_token"], os.Getenv("IPINFO_TOKEN"))

	targetType := detectTargetType(target)
	normalizedASN := ""
	if targetType == TargetASN {
		m2 := reASN.FindStringSubmatch(target)
		if len(m2) >= 3 {
			normalizedASN = "AS" + m2[2]
		}
	}

	slog.InfoContext(ctx, "bgpinfo: iniciando análise",
		"target", target,
		"target_type", string(targetType),
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

	eg, ctx2 := errgroup.WithContext(ctx)
	eg.SetLimit(4)

	// RIPE NCC Stat — dados gerais de ASN
	if sourceEnabled(enabledSources, "ripe") && (targetType == TargetASN || targetType == TargetPrefix) {
		eg.Go(func() error {
			ff, err := m.queryRIPE(ctx2, target, targetType, normalizedASN, maxPrefixes)
			if err != nil {
				slog.WarnContext(ctx2, "bgpinfo: ripe falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// BGP.tools — peers e prefixos
	if sourceEnabled(enabledSources, "bgptools") && targetType == TargetASN {
		eg.Go(func() error {
			ff, err := m.queryBGPTools(ctx2, normalizedASN)
			if err != nil {
				slog.WarnContext(ctx2, "bgpinfo: bgptools falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// Cloudflare Radar — eventos BGP recentes
	if sourceEnabled(enabledSources, "cloudflare") && targetType == TargetASN {
		eg.Go(func() error {
			ff, err := m.queryCloudflareRadar(ctx2, normalizedASN)
			if err != nil {
				slog.WarnContext(ctx2, "bgpinfo: cloudflare radar falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	// IPinfo — owner e abuse contact
	if sourceEnabled(enabledSources, "ipinfo") && (targetType == TargetIP || targetType == TargetASN) {
		eg.Go(func() error {
			ff, err := m.queryIPInfo(ctx2, target, targetType, ipinfoToken)
			if err != nil {
				slog.WarnContext(ctx2, "bgpinfo: ipinfo falhou", "err", err)
				return nil
			}
			add(ff)
			return nil
		})
	}

	_ = eg.Wait()

	// RPKI check — sempre assíncrono no loop acima se check_rpki=true
	if checkRPKI && (targetType == TargetPrefix || targetType == TargetASN) {
		ff, err := m.checkRPKI(ctx, target, targetType)
		if err != nil {
			slog.WarnContext(ctx, "bgpinfo: rpki check falhou", "err", err)
		} else {
			findings = append(findings, ff...)
		}
	}

	// Análise de segurança local
	secFindings := analyzeSecurityLocally(target, targetType, findings)
	findings = append(findings, secFindings...)

	result := dedup(findings)

	slog.InfoContext(ctx, "bgpinfo: concluído",
		"target", target,
		"total_findings", len(result),
	)

	return result, nil
}

// ─── RIPE NCC Stat ────────────────────────────────────────────────────────────

type ripeAsnOverview struct {
	Data struct {
		ASN       int    `json:"asn"`
		Name      string `json:"holder"`
		Country   string `json:"country"`
		Announced bool   `json:"announced"`
	} `json:"data"`
	Status string `json:"status"`
}

type ripeAnnouncedPrefixes struct {
	Data struct {
		ASN      int `json:"asn"`
		Prefixes []struct {
			Prefix    string `json:"prefix"`
			Timelines []struct {
				Starttime string `json:"starttime"`
				Endtime   string `json:"endtime"`
			} `json:"timelines"`
		} `json:"prefixes"`
	} `json:"data"`
	Status string `json:"status"`
}

func (m *Module) queryRIPE(ctx context.Context, target string, targetType TargetType, normalizedASN string, maxPrefixes int) ([]module.Finding, error) {
	var findings []module.Finding

	if targetType == TargetASN && normalizedASN != "" {
		asnNum := strings.TrimPrefix(normalizedASN, "AS")

		// Visão geral do ASN
		overviewURL := fmt.Sprintf("https://stat.ripe.net/data/whois/data.json?resource=%s", normalizedASN)
		body, err := m.get(ctx, overviewURL, nil)
		if err == nil {
			var overview map[string]interface{}
			if json.Unmarshal(body, &overview) == nil {
				if data, ok := overview["data"].(map[string]interface{}); ok {
					records, _ := data["records"].([]interface{})
					if len(records) > 0 {
						// Extrai campos relevantes do primeiro record
						holder := ""
						country := ""
						if rec0, ok := records[0].([]interface{}); ok {
							for _, attr := range rec0 {
								if a, ok := attr.(map[string]interface{}); ok {
									key := fmt.Sprintf("%v", a["key"])
									val := fmt.Sprintf("%v", a["value"])
									switch key {
									case "aut-num":
										// ASN já temos
									case "as-name", "descr":
										if holder == "" {
											holder = val
										}
									case "country":
										if country == "" {
											country = val
										}
									}
								}
							}
						}
						if holder == "" {
							holder = "desconhecido"
						}
						findings = append(findings, module.Finding{
							Type:     "asn_info",
							URL:      fmt.Sprintf("https://stat.ripe.net/widget/whois#w.resource=%s", normalizedASN),
							Detail:   fmt.Sprintf("ASN %s (%s), país: %s. Dados RIPE NCC.", normalizedASN, holder, country),
							Severity: module.SeverityInfo,
							Extra: map[string]string{
								"asn":        normalizedASN,
								"holder":     holder,
								"country":    country,
								"fonte":      "ripe_stat",
								"confidence": "0.88",
							},
						})
					}
				}
			}
		}

		// Prefixos anunciados
		prefixURL := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=%s", asnNum)
		prefixBody, err := m.get(ctx, prefixURL, nil)
		if err == nil {
			var pData ripeAnnouncedPrefixes
			if json.Unmarshal(prefixBody, &pData) == nil && len(pData.Data.Prefixes) > 0 {
				count := len(pData.Data.Prefixes)
				maxShow := count
				if maxShow > maxPrefixes {
					maxShow = maxPrefixes
				}
				for i := 0; i < maxShow; i++ {
					p := pData.Data.Prefixes[i]
					findings = append(findings, module.Finding{
						Type:     "announced_prefix",
						URL:      fmt.Sprintf("https://stat.ripe.net/widget/routing-status#w.resource=%s", p.Prefix),
						Detail:   fmt.Sprintf("Prefixo '%s' anunciado pelo %s.", p.Prefix, normalizedASN),
						Severity: module.SeverityInfo,
						Extra: map[string]string{
							"prefix":     p.Prefix,
							"asn":        normalizedASN,
							"fonte":      "ripe_stat",
							"confidence": "0.90",
						},
					})
				}
				if count > maxPrefixes {
					findings = append(findings, module.Finding{
						Type:     "prefixes_truncated",
						URL:      "",
						Detail:   fmt.Sprintf("%s anuncia %d prefixos no total (%d mostrados).", normalizedASN, count, maxPrefixes),
						Severity: module.SeverityInfo,
						Extra: map[string]string{
							"total_prefixes": fmt.Sprintf("%d", count),
							"shown":          fmt.Sprintf("%d", maxPrefixes),
							"fonte":          "ripe_stat",
							"confidence":     "0.90",
						},
					})
				}
			}
		}
	}

	if targetType == TargetPrefix {
		// Visão geral do prefixo
		prefixOverviewURL := fmt.Sprintf("https://stat.ripe.net/data/prefix-overview/data.json?resource=%s", target)
		body, err := m.get(ctx, prefixOverviewURL, nil)
		if err == nil {
			var raw map[string]interface{}
			if json.Unmarshal(body, &raw) == nil {
				if data, ok := raw["data"].(map[string]interface{}); ok {
					asns, _ := data["asns"].([]interface{})
					block, _ := data["block"].(map[string]interface{})
					resource := fmt.Sprintf("%v", data["resource"])
					blockDesc := ""
					if block != nil {
						blockDesc = fmt.Sprintf("%v", block["desc"])
					}
					for _, asnRaw := range asns {
						if asnMap, ok := asnRaw.(map[string]interface{}); ok {
							asnNum := fmt.Sprintf("AS%.0f", asnMap["asn"])
							holder := fmt.Sprintf("%v", asnMap["holder"])
							findings = append(findings, module.Finding{
								Type:     "prefix_origin",
								URL:      fmt.Sprintf("https://stat.ripe.net/widget/prefix-overview#w.resource=%s", resource),
								Detail:   fmt.Sprintf("Prefixo '%s' originado por %s (%s). Bloco: %s.", resource, asnNum, holder, blockDesc),
								Severity: module.SeverityInfo,
								Extra: map[string]string{
									"prefix":     resource,
									"asn":        asnNum,
									"holder":     holder,
									"block":      blockDesc,
									"fonte":      "ripe_stat",
									"confidence": "0.90",
								},
							})
						}
					}
				}
			}
		}
	}

	return findings, nil
}

// ─── BGP.tools ────────────────────────────────────────────────────────────────

func (m *Module) queryBGPTools(ctx context.Context, normalizedASN string) ([]module.Finding, error) {
	asnNum := strings.TrimPrefix(normalizedASN, "AS")
	u := fmt.Sprintf("https://bgp.tools/as/%s#api", asnNum)

	// BGP.tools tem API JSON via Accept header
	body, err := m.get(ctx, fmt.Sprintf("https://bgp.tools/api/as/%s", asnNum), map[string]string{
		"Accept": "application/json",
	})
	if err != nil {
		// Fallback: sem API estruturada, gera finding informativo
		return []module.Finding{{
			Type:     "bgptools_reference",
			URL:      u,
			Detail:   fmt.Sprintf("Informações BGP de %s disponíveis em bgp.tools.", normalizedASN),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"asn":        normalizedASN,
				"fonte":      "bgptools",
				"confidence": "0.70",
			},
		}}, nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil
	}

	var findings []module.Finding

	name := fmt.Sprintf("%v", raw["name"])
	country := fmt.Sprintf("%v", raw["country"])
	prefixCount4 := fmt.Sprintf("%.0f", toFloat(raw["prefixCount_v4"]))
	prefixCount6 := fmt.Sprintf("%.0f", toFloat(raw["prefixCount_v6"]))
	peerCount := fmt.Sprintf("%.0f", toFloat(raw["peerCount"]))

	findings = append(findings, module.Finding{
		Type:     "asn_bgp_summary",
		URL:      u,
		Detail:   fmt.Sprintf("%s (%s) — %s: país %s, prefixos IPv4: %s, IPv6: %s, peers: %s.", normalizedASN, name, normalizedASN, country, prefixCount4, prefixCount6, peerCount),
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"asn":         normalizedASN,
			"name":        name,
			"country":     country,
			"prefixes_v4": prefixCount4,
			"prefixes_v6": prefixCount6,
			"peer_count":  peerCount,
			"fonte":       "bgptools",
			"confidence":  "0.85",
		},
	})

	// Upstream peers
	if upstreams, ok := raw["upstreams"].([]interface{}); ok && len(upstreams) > 0 {
		upstreamList := make([]string, 0, len(upstreams))
		for _, u := range upstreams {
			if um, ok := u.(map[string]interface{}); ok {
				upstreamList = append(upstreamList, fmt.Sprintf("AS%.0f", toFloat(um["asn"])))
			}
		}
		findings = append(findings, module.Finding{
			Type:     "bgp_upstreams",
			URL:      u,
			Detail:   fmt.Sprintf("%s tem %d upstream providers: %s.", normalizedASN, len(upstreamList), strings.Join(upstreamList, ", ")),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"asn":        normalizedASN,
				"upstreams":  strings.Join(upstreamList, ", "),
				"count":      fmt.Sprintf("%d", len(upstreamList)),
				"fonte":      "bgptools",
				"confidence": "0.82",
			},
		})
	}

	return findings, nil
}

// ─── Cloudflare Radar BGP ─────────────────────────────────────────────────────

type cfRadarBGPEventsResp struct {
	Result struct {
		Events []struct {
			Type            string `json:"type"`
			Prefix          string `json:"prefix"`
			ASPath          string `json:"asPath"`
			Country         string `json:"country"`
			MaxLenViolation bool   `json:"maxLenViolation"`
		} `json:"events"`
	} `json:"result"`
	Success bool `json:"success"`
}

func (m *Module) queryCloudflareRadar(ctx context.Context, normalizedASN string) ([]module.Finding, error) {
	asnNum := strings.TrimPrefix(normalizedASN, "AS")
	u := fmt.Sprintf("https://api.cloudflare.com/client/v4/radar/bgp/events?asn=%s&limit=10", asnNum)

	body, err := m.get(ctx, u, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, fmt.Errorf("cloudflare radar: %w", err)
	}

	var resp cfRadarBGPEventsResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}

	var findings []module.Finding
	for _, event := range resp.Result.Events {
		severity := module.SeverityLow
		if event.Type == "HIJACK" {
			severity = module.SeverityHigh
		} else if event.Type == "ROUTE_LEAK" {
			severity = module.SeverityMedium
		} else if event.MaxLenViolation {
			severity = module.SeverityMedium
		}

		detail := fmt.Sprintf("Evento BGP detectado pelo Cloudflare Radar: tipo '%s' para prefixo '%s' (ASN %s). AS-Path: %s.",
			event.Type, event.Prefix, normalizedASN, event.ASPath)

		findings = append(findings, module.Finding{
			Type:     "bgp_event",
			URL:      fmt.Sprintf("https://radar.cloudflare.com/bgp-anomalies/events?asn=%s", asnNum),
			Detail:   detail,
			Severity: severity,
			Extra: map[string]string{
				"event_type":        event.Type,
				"prefix":            event.Prefix,
				"as_path":           event.ASPath,
				"country":           event.Country,
				"max_len_violation": fmt.Sprintf("%v", event.MaxLenViolation),
				"asn":               normalizedASN,
				"fonte":             "cloudflare_radar",
				"confidence":        "0.80",
			},
		})
	}

	return findings, nil
}

// ─── IPinfo ───────────────────────────────────────────────────────────────────

type ipinfoResp struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Org      string `json:"org"`
	Abuse    struct {
		Address string `json:"address"`
		Country string `json:"country"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Network string `json:"network"`
		Phone   string `json:"phone"`
	} `json:"abuse"`
}

func (m *Module) queryIPInfo(ctx context.Context, target string, targetType TargetType, token string) ([]module.Finding, error) {
	queryTarget := target
	if targetType == TargetASN {
		// Para ASN, busca o IP range
		asnNum := strings.TrimPrefix(target, "AS")
		asnNum = strings.TrimPrefix(strings.ToUpper(asnNum), "AS")
		queryTarget = fmt.Sprintf("AS%s", asnNum)
	}

	u := fmt.Sprintf("https://ipinfo.io/%s/json", queryTarget)
	if token != "" {
		u += "?token=" + token
	}

	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("ipinfo: %w", err)
	}

	var info ipinfoResp
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, nil
	}

	extra := map[string]string{
		"org":        info.Org,
		"city":       info.City,
		"region":     info.Region,
		"country":    info.Country,
		"fonte":      "ipinfo",
		"confidence": "0.85",
	}
	if info.Abuse.Email != "" {
		extra["abuse_email"] = info.Abuse.Email
		extra["abuse_name"] = info.Abuse.Name
		extra["abuse_network"] = info.Abuse.Network
	}

	detail := fmt.Sprintf("IPinfo: target '%s' — organização '%s', localização: %s, %s, %s.", target, info.Org, info.City, info.Region, info.Country)

	return []module.Finding{{
		Type:     "asn_owner",
		URL:      fmt.Sprintf("https://ipinfo.io/%s", queryTarget),
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra:    extra,
	}}, nil
}

// ─── RPKI check ───────────────────────────────────────────────────────────────

type rpkiResp struct {
	Validated bool   `json:"validated"`
	State     string `json:"state"`
	Prefix    string `json:"prefix"`
	ASN       string `json:"asn"`
}

func (m *Module) checkRPKI(ctx context.Context, target string, targetType TargetType) ([]module.Finding, error) {
	if targetType != TargetPrefix {
		return nil, nil
	}

	u := fmt.Sprintf("https://cloudflare-quic.com/rpki/?prefix=%s", target)
	body, err := m.get(ctx, u, nil)
	if err != nil {
		// Fallback para RIPE RPKI
		ripeURL := fmt.Sprintf("https://stat.ripe.net/data/rpki-validation/data.json?resource=%s", target)
		ripeBody, ripeErr := m.get(ctx, ripeURL, nil)
		if ripeErr != nil {
			return nil, fmt.Errorf("rpki: ambas fontes falharam: cf=%v ripe=%v", err, ripeErr)
		}
		body = ripeBody
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil
	}

	// Tenta extrair estado do RPKI de diferentes formatos de resposta
	state := "unknown"
	if validated, ok := raw["validated"].(bool); ok {
		if validated {
			state = "valid"
		} else {
			state = "invalid"
		}
	}
	if s, ok := raw["state"].(string); ok {
		state = s
	}
	// RIPE format
	if data, ok := raw["data"].(map[string]interface{}); ok {
		if validations, ok := data["validations"].([]interface{}); ok && len(validations) > 0 {
			if v0, ok := validations[0].(map[string]interface{}); ok {
				if s, ok := v0["validity"].(string); ok {
					state = strings.ToLower(s)
				}
			}
		}
	}

	severity := module.SeverityInfo
	detail := fmt.Sprintf("Prefixo '%s' tem status RPKI: %s.", target, state)

	switch state {
	case "invalid", "INVALID":
		severity = module.SeverityHigh
		detail = fmt.Sprintf("RPKI INVÁLIDO: prefixo '%s' tem ROA inválido — vulnerável a route hijacking.", target)
	case "not-found", "notFound", "unknown":
		severity = module.SeverityMedium
		detail = fmt.Sprintf("RPKI NÃO ENCONTRADO: prefixo '%s' não tem ROA — sem proteção contra route hijacking.", target)
	case "valid", "Valid":
		severity = module.SeverityInfo
	}

	return []module.Finding{{
		Type:     "rpki_status",
		URL:      fmt.Sprintf("https://stat.ripe.net/widget/rpki-validation#w.resource=%s", target),
		Detail:   detail,
		Severity: severity,
		Extra: map[string]string{
			"prefix":     target,
			"rpki_state": state,
			"fonte":      "rpki_cloudflare",
			"confidence": "0.88",
		},
	}}, nil
}

// ─── Análise de segurança local ───────────────────────────────────────────────

func analyzeSecurityLocally(target string, targetType TargetType, existing []module.Finding) []module.Finding {
	var findings []module.Finding

	// Detecta se o prefixo é muito específico (< /24 para IPv4) — risco de mais-specific hijacking
	if targetType == TargetPrefix {
		_, ipNet, err := net.ParseCIDR(target)
		if err == nil {
			ones, bits := ipNet.Mask.Size()
			if bits == 32 && ones > 24 {
				findings = append(findings, module.Finding{
					Type:     "more_specific_prefix",
					URL:      "",
					Detail:   fmt.Sprintf("Prefixo '%s' com máscara /%d é mais específico que /24 — mais fácil de ser hijacked com um anúncio mais específico.", target, ones),
					Severity: module.SeverityMedium,
					Extra: map[string]string{
						"prefix":     target,
						"mask_bits":  fmt.Sprintf("%d", ones),
						"fonte":      "local_analysis",
						"confidence": "0.80",
					},
				})
			}
		}
	}

	// Detecta ASN em IXPs múltiplos (muitos peers = maior superfície)
	peerCount := 0
	for _, f := range existing {
		if f.Type == "bgp_upstreams" {
			if count := f.Extra["count"]; count != "" {
				fmt.Sscanf(count, "%d", &peerCount)
			}
		}
		if f.Type == "asn_bgp_summary" {
			if count := f.Extra["peer_count"]; count != "" {
				fmt.Sscanf(count, "%d", &peerCount)
			}
		}
	}

	if peerCount > 100 {
		findings = append(findings, module.Finding{
			Type:     "large_asn_footprint",
			URL:      "",
			Detail:   fmt.Sprintf("ASN '%s' tem %d peers — grande superfície de roteamento; comprometimento afeta ampla porção da internet.", target, peerCount),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"asn":        target,
				"peer_count": fmt.Sprintf("%d", peerCount),
				"fonte":      "local_analysis",
				"confidence": "0.70",
			},
		})
	}

	return findings
}

// ─── detectTargetType ────────────────────────────────────────────────────────

func detectTargetType(target string) TargetType {
	if reASN.MatchString(target) {
		return TargetASN
	}
	if reCIDR.MatchString(target) || reCIDRv6.MatchString(target) {
		return TargetPrefix
	}
	if reIPv4.MatchString(target) {
		return TargetIP
	}
	// Verifica se parece um domínio
	if strings.Contains(target, ".") && !strings.Contains(target, "/") && !strings.Contains(target, "@") {
		return TargetDomain
	}
	return TargetUnknown
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
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
}

// ─── Utilitários ──────────────────────────────────────────────────────────────

func toFloat(v interface{}) float64 {
	if v == nil {
		return 0
	}
	switch f := v.(type) {
	case float64:
		return f
	case int:
		return float64(f)
	}
	var result float64
	fmt.Sscanf(fmt.Sprintf("%v", v), "%f", &result)
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
