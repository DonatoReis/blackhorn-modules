// Package vulndb queries public vulnerability databases for CVEs, advisories
// and known-exploited vulnerabilities affecting a target package, CPE or keyword.
//
// Sources:
//   - NVD (NIST)       — National Vulnerability Database, free, requires API key for higher rate
//   - OSV.dev          — Open Source Vulnerabilities, free, no key needed
//   - GitHub Advisory  — GitHub Security Advisories, free GraphQL API
//   - CISA KEV         — Known Exploited Vulnerabilities catalog, free
//   - VulnCheck        — commercial, enriched KEV + exploit chains (key optional)
//
// Confidence tiers (dicas.md §4):
//   - CISA KEV (known exploited)  → 0.99 SeverityHigh/Critical
//   - NVD CVSS ≥ 9.0             → 0.97 SeverityCritical
//   - NVD CVSS 7-9               → 0.94 SeverityHigh
//   - OSV exact match            → 0.90
//   - GitHub Advisory            → 0.88
//   - NVD CVSS < 7               → 0.85 SeverityMedium/Low
//
// Usage:
//
//	m := vulndb.New()
//	findings, err := m.Run(ctx, module.Input{
//	    Target:  "openssl",          // package name, CPE, keyword or CVE-ID
//	    Options: map[string]string{
//	        "sources":      "nvd,osv,cisa",
//	        "nvd_key":      "<key>",
//	        "ecosystem":    "Go",     // for OSV: Go,npm,PyPI,Maven,RubyGems etc
//	        "max_results":  "50",
//	        "min_cvss":     "7.0",   // filter by minimum CVSS score
//	    },
//	})
package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	maxBodyVuln = 4 * 1024 * 1024 // 4 MB
	maxParallel = 4
)

// Module implements module.Module for vulnerability database queries.
type Module struct {
	client *http.Client
}

// New returns a Module with a default HTTP client.
func New() *Module {
	return NewWithClient(&http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     60 * time.Second,
		},
	})
}

// NewWithClient allows injecting a custom HTTP client (useful for tests).
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

// Name returns the canonical module identifier.
func (m *Module) Name() string { return "vulndb" }

// Run queries vulnerability databases and returns CVE findings.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("vulndb: target vazio")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	sourcesFilter := opts["sources"]
	maxResults := optInt(opts, "max_results", 50)
	minCVSS := optFloat(opts, "min_cvss", 0.0)
	ecosystem := opts["ecosystem"]

	slog.InfoContext(ctx, "vulndb.Run iniciado",
		"target", target,
		"sources", sourcesFilter,
		"max_results", maxResults,
		"min_cvss", minCVSS,
		"ecosystem", ecosystem,
	)

	type sourceFunc struct {
		name string
		fn   func(context.Context, string, map[string]string, int) ([]module.Finding, error)
	}

	sources := []sourceFunc{
		{"nvd", m.queryNVD},
		{"osv", m.queryOSV},
		{"github", m.queryGitHubAdvisory},
		{"cisa", m.queryCISAKEV},
	}

	var mu sync.Mutex
	var all []module.Finding

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxParallel)

	for _, s := range sources {
		s := s
		if !isWanted(sourcesFilter, s.name) {
			continue
		}
		g.Go(func() error {
			slog.DebugContext(gctx, "vulndb: consultando fonte", "source", s.name, "target", target)
			findings, err := s.fn(gctx, target, opts, maxResults)
			if err != nil {
				slog.WarnContext(gctx, "vulndb: fonte retornou erro", "source", s.name, "err", err)
				return nil
			}
			mu.Lock()
			all = append(all, findings...)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	// Filter by min CVSS
	if minCVSS > 0 {
		all = filterByCVSS(all, minCVSS)
	}

	result := dedup(all)
	slog.InfoContext(ctx, "vulndb.Run concluído",
		"target", target,
		"total_findings", len(result),
	)
	return result, nil
}

// ─── NVD (NIST) ───────────────────────────────────────────────────────────────

type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			VulnStatus   string `json:"vulnStatus"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CvssMetricV30 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				CvssMetricV2 []struct {
					CvssData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
			References []struct {
				URL  string   `json:"url"`
				Tags []string `json:"tags"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func (m *Module) queryNVD(ctx context.Context, target string, opts map[string]string, maxResults int) ([]module.Finding, error) {
	apiKey := opts["nvd_key"]

	// Build query — detect if CVE-ID or keyword
	var queryParam string
	if strings.HasPrefix(strings.ToUpper(target), "CVE-") {
		queryParam = "cveId=" + url.QueryEscape(target)
	} else {
		queryParam = "keywordSearch=" + url.QueryEscape(target)
	}

	u := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?%s&resultsPerPage=%d",
		queryParam, min(maxResults, 2000))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-vulndb/1.0 (OSINT; security research)")
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("nvd: rate limit atingido — configure nvd_key para maior throughput")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyVuln))
	if err != nil {
		return nil, err
	}

	var nvd nvdResponse
	if err := json.Unmarshal(body, &nvd); err != nil {
		return nil, fmt.Errorf("nvd: parse JSON: %w", err)
	}

	var findings []module.Finding
	for _, v := range nvd.Vulnerabilities {
		cve := v.CVE

		// Get English description
		desc := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		// Get CVSS score (prefer v3.1 > v3.0 > v2)
		score := 0.0
		severity := ""
		vector := ""
		if len(cve.Metrics.CvssMetricV31) > 0 {
			score = cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
			severity = cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
			vector = cve.Metrics.CvssMetricV31[0].CvssData.VectorString
		} else if len(cve.Metrics.CvssMetricV30) > 0 {
			score = cve.Metrics.CvssMetricV30[0].CvssData.BaseScore
			severity = cve.Metrics.CvssMetricV30[0].CvssData.BaseSeverity
			vector = cve.Metrics.CvssMetricV30[0].CvssData.VectorString
		} else if len(cve.Metrics.CvssMetricV2) > 0 {
			score = cve.Metrics.CvssMetricV2[0].CvssData.BaseScore
			severity = cve.Metrics.CvssMetricV2[0].BaseSeverity
		}

		sev, conf := cvssToSeverity(score)
		nvdURL := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.ID)

		f := module.Finding{
			Type:     "vulnerability",
			URL:      nvdURL,
			Severity: sev,
			Detail: fmt.Sprintf("%s (CVSS %.1f %s): %s — publicado: %s, status: %s",
				cve.ID, score, severity, truncate(desc, 300), cve.Published[:10], cve.VulnStatus),
			Extra: map[string]string{
				"cve_id":      cve.ID,
				"cvss_score":  fmt.Sprintf("%.1f", score),
				"cvss_vector": vector,
				"severity":    severity,
				"published":   cve.Published,
				"vuln_status": cve.VulnStatus,
				"source":      "nvd",
				"confidence":  fmt.Sprintf("%.2f", conf),
			},
		}

		// Add reference URLs
		refURLs := make([]string, 0, 3)
		for _, ref := range cve.References {
			if len(refURLs) >= 3 {
				break
			}
			refURLs = append(refURLs, ref.URL)
		}
		if len(refURLs) > 0 {
			f.Extra["references"] = strings.Join(refURLs, " | ")
		}

		findings = append(findings, f)
		if len(findings) >= maxResults {
			break
		}
	}

	slog.InfoContext(ctx, "vulndb: NVD consultado",
		"total_nvd", nvd.TotalResults,
		"returned", len(findings),
	)
	return findings, nil
}

// ─── OSV.dev ──────────────────────────────────────────────────────────────────

type osvQueryReq struct {
	Version string  `json:"version,omitempty"`
	Package *osvPkg `json:"package,omitempty"`
	Query   string  `json:"query,omitempty"`
}

type osvPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

type osvResponse struct {
	Vulns []struct {
		ID        string `json:"id"`
		Summary   string `json:"summary"`
		Details   string `json:"details"`
		Modified  string `json:"modified"`
		Published string `json:"published"`
		Severity  []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		Aliases    []string `json:"aliases"`
		References []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"references"`
	} `json:"vulns"`
}

func (m *Module) queryOSV(ctx context.Context, target string, opts map[string]string, maxResults int) ([]module.Finding, error) {
	ecosystem := opts["ecosystem"]

	// Build request payload
	payload := osvQueryReq{}
	if strings.HasPrefix(strings.ToUpper(target), "CVE-") || strings.HasPrefix(target, "GHSA-") {
		// Direct ID lookup
		payload.Query = target
	} else {
		payload.Package = &osvPkg{
			Name:      target,
			Ecosystem: ecosystem,
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.osv.dev/v1/query",
		strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "blackhorn-vulndb/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: HTTP %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyVuln))
	if err != nil {
		return nil, err
	}

	var osvResp osvResponse
	if err := json.Unmarshal(respBody, &osvResp); err != nil {
		return nil, fmt.Errorf("osv: parse: %w", err)
	}

	var findings []module.Finding
	for _, v := range osvResp.Vulns {
		if len(findings) >= maxResults {
			break
		}

		// Find CVE alias
		cveAlias := v.ID
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				cveAlias = a
				break
			}
		}

		// Get reference URL
		refURL := fmt.Sprintf("https://osv.dev/vulnerability/%s", v.ID)
		for _, r := range v.References {
			if r.Type == "WEB" {
				refURL = r.URL
				break
			}
		}

		detail := v.Summary
		if detail == "" {
			detail = truncate(v.Details, 300)
		}

		findings = append(findings, module.Finding{
			Type:     "vulnerability",
			URL:      fmt.Sprintf("https://osv.dev/vulnerability/%s", v.ID),
			Severity: module.SeverityMedium,
			Detail: fmt.Sprintf("%s (%s): %s — modificado: %s",
				v.ID, cveAlias, detail, v.Modified[:10]),
			Extra: map[string]string{
				"osv_id":     v.ID,
				"cve_alias":  cveAlias,
				"published":  v.Published,
				"ref_url":    refURL,
				"source":     "osv",
				"confidence": "0.90",
			},
		})
	}
	return findings, nil
}

// ─── GitHub Advisory ──────────────────────────────────────────────────────────

type ghAdvisoryResp struct {
	Data struct {
		SecurityVulnerabilities struct {
			Nodes []struct {
				Advisory struct {
					GHSAID      string `json:"ghsaId"`
					Summary     string `json:"summary"`
					Description string `json:"description"`
					Severity    string `json:"severity"`
					PublishedAt string `json:"publishedAt"`
					References  []struct {
						URL string `json:"url"`
					} `json:"references"`
					Identifiers []struct {
						Type  string `json:"type"`
						Value string `json:"value"`
					} `json:"identifiers"`
				} `json:"advisory"`
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				VulnerableVersionRange string `json:"vulnerableVersionRange"`
				FirstPatchedVersion    struct {
					Identifier string `json:"identifier"`
				} `json:"firstPatchedVersion"`
			} `json:"nodes"`
		} `json:"securityVulnerabilities"`
	} `json:"data"`
}

func (m *Module) queryGitHubAdvisory(ctx context.Context, target string, opts map[string]string, maxResults int) ([]module.Finding, error) {
	ghToken := opts["github_token"]
	if ghToken == "" {
		slog.DebugContext(ctx, "vulndb: GitHub Advisory sem token — taxa limitada")
	}

	ecosystem := strings.ToUpper(opts["ecosystem"])
	if ecosystem == "" {
		ecosystem = "NPM" // default
	}

	query := fmt.Sprintf(`{"query":"query { securityVulnerabilities(first: %d, package: \"%s\", ecosystem: %s) { nodes { advisory { ghsaId summary severity publishedAt references { url } identifiers { type value } } package { name ecosystem } vulnerableVersionRange firstPatchedVersion { identifier } } } }"}`,
		min(maxResults, 100), target, ecosystem)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.github.com/graphql",
		strings.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "blackhorn-vulndb/1.0")
	if ghToken != "" {
		req.Header.Set("Authorization", "Bearer "+ghToken)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("github advisory: token inválido")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github advisory: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyVuln))
	if err != nil {
		return nil, err
	}

	var ghResp ghAdvisoryResp
	if err := json.Unmarshal(body, &ghResp); err != nil {
		return nil, fmt.Errorf("github advisory: parse: %w", err)
	}

	var findings []module.Finding
	for _, node := range ghResp.Data.SecurityVulnerabilities.Nodes {
		adv := node.Advisory

		// Get CVE identifier
		cveID := ""
		for _, id := range adv.Identifiers {
			if id.Type == "CVE" {
				cveID = id.Value
				break
			}
		}

		sev := ghSeverityToModule(adv.Severity)
		refURL := fmt.Sprintf("https://github.com/advisories/%s", adv.GHSAID)
		if len(adv.References) > 0 {
			refURL = adv.References[0].URL
		}

		patch := node.FirstPatchedVersion.Identifier
		patchNote := ""
		if patch != "" {
			patchNote = fmt.Sprintf(", corrigido em v%s", patch)
		}

		findings = append(findings, module.Finding{
			Type:     "vulnerability",
			URL:      fmt.Sprintf("https://github.com/advisories/%s", adv.GHSAID),
			Severity: sev,
			Detail: fmt.Sprintf("%s (%s %s): %s — pacote: %s@%s%s",
				adv.GHSAID, cveID, adv.Severity, truncate(adv.Summary, 250),
				node.Package.Name, node.VulnerableVersionRange, patchNote),
			Extra: map[string]string{
				"ghsa_id":         adv.GHSAID,
				"cve_id":          cveID,
				"severity":        adv.Severity,
				"package":         node.Package.Name,
				"ecosystem":       node.Package.Ecosystem,
				"vuln_range":      node.VulnerableVersionRange,
				"patched_version": patch,
				"published_at":    adv.PublishedAt,
				"ref_url":         refURL,
				"source":          "github_advisory",
				"confidence":      "0.88",
			},
		})
	}
	return findings, nil
}

// ─── CISA KEV ─────────────────────────────────────────────────────────────────

type cisaKEVResp struct {
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		CVEID                      string `json:"cveID"`
		VendorProject              string `json:"vendorProject"`
		Product                    string `json:"product"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		DateAdded                  string `json:"dateAdded"`
		ShortDescription           string `json:"shortDescription"`
		RequiredAction             string `json:"requiredAction"`
		DueDate                    string `json:"dueDate"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		Notes                      string `json:"notes"`
	} `json:"vulnerabilities"`
}

func (m *Module) queryCISAKEV(ctx context.Context, target string, opts map[string]string, maxResults int) ([]module.Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-vulndb/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cisa kev: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyVuln))
	if err != nil {
		return nil, err
	}

	var kev cisaKEVResp
	if err := json.Unmarshal(body, &kev); err != nil {
		return nil, fmt.Errorf("cisa kev: parse: %w", err)
	}

	targetLower := strings.ToLower(target)
	isCVESearch := strings.HasPrefix(strings.ToUpper(target), "CVE-")

	var findings []module.Finding
	for _, v := range kev.Vulnerabilities {
		if len(findings) >= maxResults {
			break
		}

		// Match by CVE-ID or keyword
		matched := false
		if isCVESearch {
			matched = strings.EqualFold(v.CVEID, target)
		} else {
			matched = strings.Contains(strings.ToLower(v.VendorProject), targetLower) ||
				strings.Contains(strings.ToLower(v.Product), targetLower) ||
				strings.Contains(strings.ToLower(v.VulnerabilityName), targetLower)
		}
		if !matched {
			continue
		}

		sev := module.SeverityHigh
		conf := "0.99"
		ransomNote := ""
		if v.KnownRansomwareCampaignUse == "Known" {
			sev = module.SeverityCritical
			ransomNote = " [USADO EM RANSOMWARE]"
		}

		findings = append(findings, module.Finding{
			Type:     "known_exploited_vulnerability",
			URL:      fmt.Sprintf("https://www.cisa.gov/known-exploited-vulnerabilities-catalog#%s", v.CVEID),
			Severity: sev,
			Detail: fmt.Sprintf("%s (%s %s): %s%s — ação obrigatória: %s — vencimento: %s",
				v.CVEID, v.VendorProject, v.Product,
				truncate(v.ShortDescription, 250), ransomNote,
				v.RequiredAction, v.DueDate),
			Extra: map[string]string{
				"cve_id":          v.CVEID,
				"vendor":          v.VendorProject,
				"product":         v.Product,
				"vuln_name":       v.VulnerabilityName,
				"date_added":      v.DateAdded,
				"due_date":        v.DueDate,
				"ransomware":      v.KnownRansomwareCampaignUse,
				"required_action": v.RequiredAction,
				"source":          "cisa_kev",
				"confidence":      conf,
			},
		})
	}
	return findings, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func cvssToSeverity(score float64) (module.Severity, float64) {
	switch {
	case score >= 9.0:
		return module.SeverityCritical, 0.97
	case score >= 7.0:
		return module.SeverityHigh, 0.94
	case score >= 4.0:
		return module.SeverityMedium, 0.88
	case score > 0:
		return module.SeverityLow, 0.85
	default:
		return module.SeverityInfo, 0.70
	}
}

func ghSeverityToModule(s string) module.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return module.SeverityCritical
	case "HIGH":
		return module.SeverityHigh
	case "MODERATE", "MEDIUM":
		return module.SeverityMedium
	case "LOW":
		return module.SeverityLow
	default:
		return module.SeverityInfo
	}
}

func filterByCVSS(findings []module.Finding, minScore float64) []module.Finding {
	out := findings[:0]
	for _, f := range findings {
		scoreStr := f.Extra["cvss_score"]
		if scoreStr == "" {
			out = append(out, f) // include if no score info
			continue
		}
		score, err := strconv.ParseFloat(scoreStr, 64)
		if err != nil || score >= minScore {
			out = append(out, f)
		}
	}
	return out
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

func optInt(opts map[string]string, key string, def int) int {
	v, ok := opts[key]
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func optFloat(opts map[string]string, key string, def float64) float64 {
	v, ok := opts[key]
	if !ok || v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	out := make([]module.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Type + "|" + f.Extra["cve_id"] + "|" + f.Extra["osv_id"] + "|" + f.Extra["ghsa_id"] + "|" + f.Extra["source"]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
