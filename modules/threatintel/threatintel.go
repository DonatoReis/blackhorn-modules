// Package threatintel aggregates threat intelligence from multiple sources to
// classify IPs, domains, URLs, file hashes and email addresses.
//
// Sources integrated:
//   - VirusTotal  (https://www.virustotal.com/api/v3) — VT score, detections, behavior
//   - OTX AlienVault (https://otx.alienvault.com/api/v1) — pulses, indicators
//   - ThreatFox   (https://threatfox-api.abuse.ch)    — IOCs, malware families
//   - MalwareBazaar (https://bazaar.abuse.ch/api/)    — malware samples
//   - URLhaus     (https://urlhaus-api.abuse.ch/v1/)  — malicious URLs
//   - PhishTank   (https://www.phishtank.com)         — phishing URLs (free)
//   - CIRCL CVE   (https://cve.circl.lu/api/)         — vulnerability enrichment
//
// All abuse.ch APIs (ThreatFox, MalwareBazaar, URLhaus) are free with no key.
// VirusTotal free tier: 4 lookups/min. OTX free tier: no key required for public.
//
// Supported target types (auto-detected):
//   - IPv4/IPv6 address   → IP reputation
//   - Domain / hostname   → domain reputation, passive DNS, subdomains
//   - URL                 → URL reputation, screenshot, final destination
//   - SHA256/MD5/SHA1 hash → file reputation, behavior, YARA matches
//   - Email address        → email reputation, domain check
//
// Input:
//   - Target: IP, domain, URL, file hash, or email
//   - Options["sources"]:      comma-separated (default: all with available keys)
//   - Options["vt_key"]:       VirusTotal API key (or env VT_API_KEY)
//   - Options["otx_key"]:      OTX API key (or env OTX_API_KEY)
//   - Options["min_detections"]: minimum VT detections to create finding (default: 1)
//   - Options["timeout"]:      per-request timeout seconds (default: 20)
//
// Architecture:
//   - Target type auto-detected via regex (dicas.md §11)
//   - All applicable sources queried in parallel (errgroup.SetLimit)
//   - io.LimitReader on every body (guia-go-1.26)
//   - Confidence based on source authority + detection count (dicas.md §4)
//   - Detail explains detections + source names (dicas.md §17)
//   - API keys never logged (dicas.md §18)
package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	moduleName               = "threatintel"
	maxBody                  = 2 << 20 // 2 MB
	maxParallel              = 6
	defaultMaxRuntimeSeconds = 30
	defaultMaxResults        = 100
)

// ─── Target type ─────────────────────────────────────────────────────────────

type TargetType string

const (
	TargetIP      TargetType = "ip"
	TargetDomain  TargetType = "domain"
	TargetURL     TargetType = "url"
	TargetHash    TargetType = "hash"
	TargetEmail   TargetType = "email"
	TargetUnknown TargetType = "unknown"
)

var (
	reIPv4   = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	reIPv6   = regexp.MustCompile(`^[0-9a-fA-F:]{3,39}$`)
	reSHA256 = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	reMD5    = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	reSHA1   = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	reEmail  = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	reDomain = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$`)
)

func detectTargetType(target string) TargetType {
	t := strings.TrimSpace(target)
	switch {
	case strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://"):
		return TargetURL
	case reEmail.MatchString(t):
		return TargetEmail
	case reIPv4.MatchString(t) || reIPv6.MatchString(t):
		return TargetIP
	case reSHA256.MatchString(t) || reMD5.MatchString(t) || reSHA1.MatchString(t):
		return TargetHash
	case reDomain.MatchString(t):
		return TargetDomain
	default:
		return TargetUnknown
	}
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements multi-source threat intelligence aggregation.
type Module struct {
	client *http.Client
}

// New returns a Module with default HTTP client.
func New() *Module { return NewWithClient(defaultClient()) }

// NewWithClient injects a custom HTTP client.
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

// Name satisfies module.Module.
func (m *Module) Name() string { return moduleName }

// Run gathers threat intelligence for the given target.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("threatintel: target vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	targetType := detectTargetType(target)
	if targetType == TargetUnknown {
		return nil, fmt.Errorf("threatintel: tipo de target não suportado")
	}
	target = canonicalTarget(target, targetType)
	sourcesFilter := opts["sources"]
	vtKey := firstNonEmpty(opts["vt_key"], os.Getenv("VT_API_KEY"))
	otxKey := firstNonEmpty(opts["otx_key"], os.Getenv("OTX_API_KEY"))
	minDet := optInt(opts, "min_detections", 1)
	maxResults := clampInt(optInt(opts, "max_results", defaultMaxResults), 1, 500)
	maxRuntime := clampInt(optInt(opts, "max_runtime_seconds", defaultMaxRuntimeSeconds), 1, 300)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntime)*time.Second)
	defer cancel()

	slog.InfoContext(runCtx, "threatintel.Run iniciado",
		"target", target,
		"type", targetType,
		"sources", sourcesFilter,
		// Never log API keys
	)

	type sourceFunc struct {
		name string
		fn   func(context.Context, string, TargetType, map[string]string) ([]module.Finding, error)
	}

	sources := []sourceFunc{
		{"virustotal", m.queryVirusTotal},
		{"otx", m.queryOTX},
		{"threatfox", m.queryThreatFox},
		{"malwarebazaar", m.queryMalwareBazaar},
		{"urlhaus", m.queryURLhaus},
		{"phishtank", m.queryPhishTank},
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
		// Skip sources that need a key when no key provided
		if s.name == "virustotal" && vtKey == "" {
			slog.DebugContext(ctx, "threatintel: virustotal skipped (no key)")
			continue
		}
		if s.name == "otx" && otxKey == "" {
			slog.DebugContext(ctx, "threatintel: otx skipped (no key)")
			// OTX public API still works without key for basic lookups
		}

		g.Go(func() error {
			optsWithKeys := make(map[string]string, len(opts)+3)
			for k, v := range opts {
				optsWithKeys[k] = v
			}
			optsWithKeys["vt_key"] = vtKey
			optsWithKeys["otx_key"] = otxKey
			optsWithKeys["min_detections"] = strconv.Itoa(minDet)

			findings, err := s.fn(gctx, target, targetType, optsWithKeys)
			if err != nil {
				slog.WarnContext(gctx, "threatintel: source erro",
					"source", s.name, "err", err)
				return nil
			}
			slog.InfoContext(gctx, "threatintel: source concluído",
				"source", s.name, "findings", len(findings))
			mu.Lock()
			all = append(all, findings...)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	result := decorateThreatReferences(dedup(all), target, targetType)
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
	slog.InfoContext(runCtx, "threatintel.Run concluído",
		"target", target, "findings", len(result))
	return result, nil
}

// ─── VirusTotal ───────────────────────────────────────────────────────────────

type vtResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			LastAnalysisResults map[string]struct {
				Category string `json:"category"`
				Result   string `json:"result"`
			} `json:"last_analysis_results"`
			Reputation    int      `json:"reputation"`
			Country       string   `json:"country"`
			ASOwner       string   `json:"as_owner"`
			Network       string   `json:"network"`
			ASNS          int      `json:"asn"`
			Tags          []string `json:"tags"`
			LastHTTPSCert struct {
				Issuer struct {
					O string `json:"O"`
				} `json:"issuer"`
			} `json:"last_https_certificate"`
			// Hash-specific
			MD5    string   `json:"md5"`
			SHA256 string   `json:"sha256"`
			Names  []string `json:"names"`
			// Domain-specific
			CreationDate int64 `json:"creation_date"`
		} `json:"attributes"`
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
}

func (m *Module) queryVirusTotal(ctx context.Context, target string, ttype TargetType, opts map[string]string) ([]module.Finding, error) {
	apiKey := opts["vt_key"]
	if apiKey == "" {
		return nil, fmt.Errorf("virustotal: vt_key não configurado")
	}

	var endpoint string
	switch ttype {
	case TargetIP:
		endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", url.PathEscape(target))
	case TargetDomain:
		endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", url.PathEscape(target))
	case TargetURL:
		// VT URL lookup requires base64url-encoded URL without padding
		encoded := base64URLEncode(target)
		endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/urls/%s", encoded)
	case TargetHash:
		endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", url.PathEscape(target))
	default:
		return nil, fmt.Errorf("virustotal: tipo de target não suportado: %s", ttype)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", apiKey) // key never logged per dicas §18
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // target not in VT database
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("virustotal: rate limited (free tier: 4 req/min)")
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("virustotal: API key inválida (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("virustotal: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}

	var vt vtResponse
	if err := json.Unmarshal(body, &vt); err != nil {
		return nil, fmt.Errorf("virustotal: parse: %w", err)
	}

	stats := vt.Data.Attributes.LastAnalysisStats
	minDet := optInt(opts, "min_detections", 1)
	total := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected

	if stats.Malicious+stats.Suspicious < minDet {
		// Clean — still return an info finding
		return []module.Finding{{
			Type:     "threat_clean",
			URL:      fmt.Sprintf("https://www.virustotal.com/gui/%s/%s", vtTypeStr(ttype), target),
			Detail:   fmt.Sprintf("[VirusTotal] %s limpo: %d/%d detecções maliciosas.", target, stats.Malicious, total),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"source":      "virustotal",
				"malicious":   strconv.Itoa(stats.Malicious),
				"suspicious":  strconv.Itoa(stats.Suspicious),
				"harmless":    strconv.Itoa(stats.Harmless),
				"total":       strconv.Itoa(total),
				"confidence":  "0.96",
				"target_type": string(ttype),
			},
		}}, nil
	}

	// Build detection engine list (up to 10)
	var engines []string
	for engine, result := range vt.Data.Attributes.LastAnalysisResults {
		if result.Category == "malicious" || result.Category == "suspicious" {
			engines = append(engines, fmt.Sprintf("%s=%s", engine, result.Result))
		}
		if len(engines) >= 10 {
			break
		}
	}

	severity := module.SeverityMedium
	confidence := 0.88
	if stats.Malicious >= 10 {
		severity = module.SeverityCritical
		confidence = 0.97
	} else if stats.Malicious >= 5 {
		severity = module.SeverityHigh
		confidence = 0.94
	} else if stats.Malicious >= 2 {
		severity = module.SeverityMedium
		confidence = 0.90
	}

	detail := fmt.Sprintf("[VirusTotal] %s: %d/%d engines detectaram como malicioso/suspeito. Engines: %s",
		target, stats.Malicious+stats.Suspicious, total, strings.Join(engines, "; "))

	extra := map[string]string{
		"source":      "virustotal",
		"malicious":   strconv.Itoa(stats.Malicious),
		"suspicious":  strconv.Itoa(stats.Suspicious),
		"harmless":    strconv.Itoa(stats.Harmless),
		"total":       strconv.Itoa(total),
		"confidence":  fmt.Sprintf("%.2f", confidence),
		"target_type": string(ttype),
		"engines":     strings.Join(engines, ","),
	}
	if vt.Data.Attributes.Country != "" {
		extra["country"] = vt.Data.Attributes.Country
	}
	if vt.Data.Attributes.ASOwner != "" {
		extra["as_owner"] = vt.Data.Attributes.ASOwner
	}
	if vt.Data.Attributes.MD5 != "" {
		extra["md5"] = vt.Data.Attributes.MD5
	}
	if vt.Data.Attributes.SHA256 != "" {
		extra["sha256"] = vt.Data.Attributes.SHA256
	}

	return []module.Finding{{
		Type:     "threat_detected",
		URL:      fmt.Sprintf("https://www.virustotal.com/gui/%s/%s", vtTypeStr(ttype), target),
		Detail:   detail,
		Severity: severity,
		Extra:    extra,
	}}, nil
}

// ─── OTX AlienVault ───────────────────────────────────────────────────────────

type otxIndicator struct {
	Pulse_info struct {
		Count  int `json:"count"`
		Pulses []struct {
			Name            string   `json:"name"`
			Description     string   `json:"description"`
			Tags            []string `json:"tags"`
			MalwareFamilies []struct {
				DisplayName string `json:"display_name"`
			} `json:"malware_families"`
		} `json:"pulses"`
	} `json:"pulse_info"`
	General struct {
		Country string `json:"country_name"`
		ASN     string `json:"asn"`
		City    string `json:"city"`
	} `json:"general"`
	Reputation int `json:"reputation"`
}

func (m *Module) queryOTX(ctx context.Context, target string, ttype TargetType, opts map[string]string) ([]module.Finding, error) {
	apiKey := opts["otx_key"]

	var section, indicator string
	switch ttype {
	case TargetIP:
		section = "IPv4"
		indicator = target
	case TargetDomain:
		section = "domain"
		indicator = target
	case TargetURL:
		section = "url"
		indicator = target
	case TargetHash:
		section = "file"
		indicator = target
	default:
		return nil, nil // OTX doesn't support all types
	}

	endpoint := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/%s/%s/general",
		section, url.PathEscape(indicator))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("X-OTX-API-KEY", apiKey)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "blackhorn-threatintel/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("otx: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}

	var otx otxIndicator
	if err := json.Unmarshal(body, &otx); err != nil {
		return nil, fmt.Errorf("otx: parse: %w", err)
	}

	count := otx.Pulse_info.Count
	if count == 0 {
		return nil, nil // no pulses = clean
	}

	// Collect malware families
	malwareFamilies := map[string]bool{}
	var pulseNames []string
	for i, p := range otx.Pulse_info.Pulses {
		if i < 5 {
			pulseNames = append(pulseNames, p.Name)
		}
		for _, mf := range p.MalwareFamilies {
			if mf.DisplayName != "" {
				malwareFamilies[mf.DisplayName] = true
			}
		}
	}

	var mfList []string
	for k := range malwareFamilies {
		mfList = append(mfList, k)
	}

	severity := module.SeverityMedium
	confidence := 0.82
	if count >= 10 {
		severity = module.SeverityHigh
		confidence = 0.90
	}
	if len(malwareFamilies) > 0 {
		severity = module.SeverityHigh
		confidence = 0.88
	}

	detail := fmt.Sprintf("[OTX] %s presente em %d pulso(s) de threat intelligence. Pulses: %s",
		target, count, strings.Join(pulseNames, "; "))
	if len(mfList) > 0 {
		detail += fmt.Sprintf(". Famílias de malware: %s", strings.Join(mfList, ", "))
	}

	return []module.Finding{{
		Type:     "threat_detected",
		URL:      fmt.Sprintf("https://otx.alienvault.com/indicator/%s/%s", strings.ToLower(section), target),
		Detail:   detail,
		Severity: severity,
		Extra: map[string]string{
			"source":           "otx",
			"pulse_count":      strconv.Itoa(count),
			"malware_families": strings.Join(mfList, ","),
			"confidence":       fmt.Sprintf("%.2f", confidence),
			"target_type":      string(ttype),
		},
	}}, nil
}

// ─── ThreatFox ────────────────────────────────────────────────────────────────

func (m *Module) queryThreatFox(ctx context.Context, target string, ttype TargetType, opts map[string]string) ([]module.Finding, error) {
	// ThreatFox uses POST with JSON body
	var query map[string]interface{}
	switch ttype {
	case TargetHash:
		query = map[string]interface{}{"query": "search_hash", "hash": target}
	case TargetIP, TargetDomain, TargetURL:
		query = map[string]interface{}{"query": "search_ioc", "search_term": target}
	default:
		return nil, nil
	}

	bodyBytes, _ := json.Marshal(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://threatfox-api.abuse.ch/api/v1/", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "blackhorn-threatintel/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("threatfox: HTTP %d", resp.StatusCode)
	}

	bodyData, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}

	var result struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			IOCType          string   `json:"ioc_type"`
			IOC              string   `json:"ioc"`
			ThreatType       string   `json:"threat_type"`
			MalwarePrintable string   `json:"malware_printable"`
			Confidence       int      `json:"confidence_level"`
			Tags             []string `json:"tags"`
			FirstSeen        string   `json:"first_seen"`
			LastSeen         string   `json:"last_seen"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bodyData, &result); err != nil {
		return nil, fmt.Errorf("threatfox: parse: %w", err)
	}

	if result.QueryStatus == "no_result" || len(result.Data) == 0 {
		return nil, nil
	}

	var findings []module.Finding
	for _, ioc := range result.Data {
		if !iocMatchesTarget(ioc.IOC, target, ttype) {
			continue
		}
		confidence := float64(ioc.Confidence) / 100.0
		if confidence < 0.10 {
			confidence = 0.70
		}

		severity := module.SeverityMedium
		if confidence >= 0.90 {
			severity = module.SeverityHigh
		}
		if strings.Contains(strings.ToLower(ioc.ThreatType), "botnet") ||
			strings.Contains(strings.ToLower(ioc.ThreatType), "ransomware") {
			severity = module.SeverityCritical
		}

		detail := fmt.Sprintf("[ThreatFox] IOC %q tipo=%s, malware=%s, confiança=%d%%. Visto: %s a %s",
			ioc.IOC, ioc.ThreatType, ioc.MalwarePrintable, ioc.Confidence, ioc.FirstSeen, ioc.LastSeen)

		findings = append(findings, module.Finding{
			Type:     "threat_detected",
			URL:      "https://threatfox.abuse.ch/browse.php?search=ioc:" + url.QueryEscape(target),
			Detail:   detail,
			Severity: severity,
			Extra: map[string]string{
				"source":      "threatfox",
				"ioc_type":    ioc.IOCType,
				"threat_type": ioc.ThreatType,
				"malware":     ioc.MalwarePrintable,
				"first_seen":  ioc.FirstSeen,
				"last_seen":   ioc.LastSeen,
				"confidence":  fmt.Sprintf("%.2f", confidence),
				"target_type": string(ttype),
			},
		})
	}
	return findings, nil
}

// ─── MalwareBazaar ────────────────────────────────────────────────────────────

func (m *Module) queryMalwareBazaar(ctx context.Context, target string, ttype TargetType, opts map[string]string) ([]module.Finding, error) {
	if ttype != TargetHash {
		return nil, nil // MalwareBazaar only for file hashes
	}

	query := fmt.Sprintf("query=get_info&hash=%s", url.QueryEscape(target))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://mb-api.abuse.ch/api/v1/",
		strings.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "blackhorn-threatintel/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("malwarebazaar: HTTP %d", resp.StatusCode)
	}

	bodyData, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}

	var result struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			SHA256        string   `json:"sha256_hash"`
			MD5           string   `json:"md5_hash"`
			FileName      string   `json:"file_name"`
			FileType      string   `json:"file_type_mime"`
			MalwareFamily string   `json:"signature"`
			Tags          []string `json:"tags"`
			FirstSeen     string   `json:"first_seen"`
			LastSeen      string   `json:"last_seen"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bodyData, &result); err != nil {
		return nil, fmt.Errorf("malwarebazaar: parse: %w", err)
	}

	if result.QueryStatus != "ok" || len(result.Data) == 0 {
		return nil, nil
	}

	d := result.Data[0]
	detail := fmt.Sprintf("[MalwareBazaar] Hash %s identificado como '%s' (tipo: %s). Família: %s. Visto: %s",
		d.SHA256[:16]+"...", d.FileName, d.FileType, d.MalwareFamily, d.FirstSeen)

	return []module.Finding{{
		Type:     "malware_sample",
		URL:      "https://bazaar.abuse.ch/sample/" + d.SHA256,
		Detail:   detail,
		Severity: module.SeverityCritical,
		Extra: map[string]string{
			"source":         "malwarebazaar",
			"sha256":         d.SHA256,
			"md5":            d.MD5,
			"file_name":      d.FileName,
			"file_type":      d.FileType,
			"malware_family": d.MalwareFamily,
			"first_seen":     d.FirstSeen,
			"tags":           strings.Join(d.Tags, ","),
			"confidence":     "0.95",
			"target_type":    string(ttype),
		},
	}}, nil
}

// ─── URLhaus ──────────────────────────────────────────────────────────────────

func (m *Module) queryURLhaus(ctx context.Context, target string, ttype TargetType, opts map[string]string) ([]module.Finding, error) {
	if ttype != TargetURL && ttype != TargetDomain && ttype != TargetIP {
		return nil, nil
	}

	var query string
	switch ttype {
	case TargetURL:
		query = fmt.Sprintf("url=%s", url.QueryEscape(target))
	case TargetDomain:
		query = fmt.Sprintf("host=%s", url.QueryEscape(target))
	case TargetIP:
		query = fmt.Sprintf("host=%s", url.QueryEscape(target))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://urlhaus-api.abuse.ch/v1/url/",
		strings.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "blackhorn-threatintel/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("urlhaus: HTTP %d", resp.StatusCode)
	}

	bodyData, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}

	var result struct {
		QueryStatus string   `json:"query_status"`
		URLStatus   string   `json:"url_status"`
		Threat      string   `json:"threat"`
		Tags        []string `json:"tags"`
		DateAdded   string   `json:"date_added"`
		Payloads    []struct {
			MD5         string `json:"response_md5"`
			ContentType string `json:"content_type"`
			Signature   string `json:"signature"`
		} `json:"payloads"`
	}
	if err := json.Unmarshal(bodyData, &result); err != nil {
		return nil, fmt.Errorf("urlhaus: parse: %w", err)
	}

	if result.QueryStatus == "no_results" {
		return nil, nil
	}

	severity := module.SeverityHigh
	if result.URLStatus == "online" {
		severity = module.SeverityCritical
	}

	var payloadSigs []string
	for _, p := range result.Payloads {
		if p.Signature != "" {
			payloadSigs = append(payloadSigs, p.Signature)
		}
	}

	detail := fmt.Sprintf("[URLhaus] URL maliciosa: status=%s, ameaça=%s, adicionada em %s",
		result.URLStatus, result.Threat, result.DateAdded)
	if len(payloadSigs) > 0 {
		detail += fmt.Sprintf(". Payloads: %s", strings.Join(payloadSigs, ", "))
	}

	return []module.Finding{{
		Type:     "malicious_url",
		URL:      target,
		Detail:   detail,
		Severity: severity,
		Extra: map[string]string{
			"source":      "urlhaus",
			"url_status":  result.URLStatus,
			"threat":      result.Threat,
			"date_added":  result.DateAdded,
			"tags":        strings.Join(result.Tags, ","),
			"payloads":    strings.Join(payloadSigs, ","),
			"confidence":  "0.92",
			"target_type": string(ttype),
		},
	}}, nil
}

// ─── PhishTank ────────────────────────────────────────────────────────────────

func (m *Module) queryPhishTank(ctx context.Context, target string, ttype TargetType, opts map[string]string) ([]module.Finding, error) {
	if ttype != TargetURL && ttype != TargetDomain {
		return nil, nil
	}

	checkURL := target
	if ttype == TargetDomain {
		checkURL = "http://" + target
	}

	formData := url.Values{
		"url":    {checkURL},
		"format": {"json"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://checkurl.phishtank.com/checkurl/",
		strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "phishtank/blackhorn-threatintel")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("phishtank: HTTP %d", resp.StatusCode)
	}

	bodyData, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}

	var result struct {
		Results struct {
			URL        string `json:"url"`
			InDatabase bool   `json:"in_database"`
			IsPhish    bool   `json:"valid"`
			Verified   bool   `json:"verified"`
			VerifiedAt string `json:"verified_at"`
		} `json:"results"`
	}
	if err := json.Unmarshal(bodyData, &result); err != nil {
		return nil, fmt.Errorf("phishtank: parse: %w", err)
	}

	if !result.Results.InDatabase || !result.Results.IsPhish {
		return nil, nil
	}

	confidence := 0.80
	severity := module.SeverityHigh
	if result.Results.Verified {
		confidence = 0.95
		severity = module.SeverityCritical
	}

	detail := fmt.Sprintf("[PhishTank] URL de phishing confirmada: %s. Verificada: %v (em %s)",
		result.Results.URL, result.Results.Verified, result.Results.VerifiedAt)

	return []module.Finding{{
		Type:     "phishing_url",
		URL:      target,
		Detail:   detail,
		Severity: severity,
		Extra: map[string]string{
			"source":      "phishtank",
			"verified":    strconv.FormatBool(result.Results.Verified),
			"verified_at": result.Results.VerifiedAt,
			"confidence":  fmt.Sprintf("%.2f", confidence),
			"target_type": string(ttype),
		},
	}}, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func vtTypeStr(t TargetType) string {
	switch t {
	case TargetIP:
		return "ip-address"
	case TargetDomain:
		return "domain"
	case TargetURL:
		return "url"
	case TargetHash:
		return "file"
	default:
		return "search"
	}
}

// base64URLEncode encodes a URL for VirusTotal's URL endpoint (base64url, no padding).
func base64URLEncode(s string) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	data := []byte(s)
	result := make([]byte, 0, (len(data)*4/3)+4)
	for i := 0; i < len(data); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], data[i:])
		b0 := chunk[0] >> 2
		b1 := (chunk[0]&0x3)<<4 | chunk[1]>>4
		b2 := (chunk[1]&0xF)<<2 | chunk[2]>>6
		b3 := chunk[2] & 0x3F
		result = append(result, table[b0], table[b1])
		if n > 1 {
			result = append(result, table[b2])
		}
		if n > 2 {
			result = append(result, table[b3])
		}
	}
	// URL-safe: replace + with - and / with _
	for i, c := range result {
		if c == '+' {
			result[i] = '-'
		} else if c == '/' {
			result[i] = '_'
		}
	}
	return string(result)
}

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

func optInt(opts map[string]string, key string, def int) int {
	if opts == nil {
		return def
	}
	v, ok := opts[key]
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return def
	}
	return n
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
		key := f.Type + "|" + f.URL + "|" + f.Extra["source"]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func canonicalTarget(target string, targetType TargetType) string {
	target = strings.TrimSpace(target)
	switch targetType {
	case TargetIP:
		if parsed := net.ParseIP(target); parsed != nil {
			return parsed.String()
		}
	case TargetDomain:
		return strings.ToLower(strings.TrimSuffix(target, "."))
	case TargetHash:
		return strings.ToLower(target)
	case TargetEmail:
		return strings.ToLower(target)
	}
	return target
}

func iocMatchesTarget(ioc, target string, targetType TargetType) bool {
	ioc = strings.TrimSpace(ioc)
	switch targetType {
	case TargetIP:
		iocIP := net.ParseIP(ioc)
		if iocIP == nil {
			if host, _, err := net.SplitHostPort(ioc); err == nil {
				iocIP = net.ParseIP(host)
			}
		}
		targetIP := net.ParseIP(target)
		return iocIP != nil && targetIP != nil && iocIP.Equal(targetIP)
	case TargetDomain:
		return strings.EqualFold(strings.TrimSuffix(ioc, "."), strings.TrimSuffix(target, "."))
	case TargetURL:
		return canonicalURL(ioc) == canonicalURL(target)
	case TargetHash:
		return strings.EqualFold(ioc, target)
	default:
		return false
	}
}

func canonicalURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Fragment = ""
	return parsed.String()
}

func decorateThreatReferences(findings []module.Finding, target string, targetType TargetType) []module.Finding {
	for i := range findings {
		if findings[i].Extra == nil {
			findings[i].Extra = map[string]string{}
		}
		findings[i].Extra["target"] = target
		findings[i].Extra["target_type"] = string(targetType)
		findings[i].Extra["target_scope_validated"] = "true"
		findings[i].Extra["validated"] = "false"
		findings[i].Extra["validation_state"] = "third_party_threat_intelligence_reference"
		findings[i].Extra["promote_to_context"] = "false"

		switch targetType {
		case TargetIP, TargetDomain, TargetEmail:
			if findings[i].Severity == module.SeverityCritical || findings[i].Severity == module.SeverityHigh {
				findings[i].Severity = module.SeverityMedium
			}
		case TargetURL:
			if findings[i].Severity == module.SeverityCritical {
				findings[i].Severity = module.SeverityHigh
			}
		}
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
