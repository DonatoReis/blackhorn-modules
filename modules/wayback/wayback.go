// Package wayback fetches historical URLs for a target domain from multiple
// sources: Wayback Machine CDX, Common Crawl, and VirusTotal (optional).
//
// Core logic ported from tomnomnom/waybackurls (MIT License).
// Original: https://github.com/tomnomnom/waybackurls
// Adapted to the blackhorn-modules Module interface: structured []Finding
// output, context cancellation, injectable HTTP client, and typed options.
package wayback

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/urlutil"
)

const (
	moduleName            = "wayback"
	defaultMaxURLs        = 1000
	defaultRuntimeSeconds = 60
	maxSourceBodyBytes    = 8 * 1024 * 1024
)

// wurl is a URL with its capture timestamp, mirroring the original struct.
type wurl struct {
	date string // "20060102150405" format
	url  string
	src  string // source: "wayback" | "commoncrawl" | "virustotal"
}

// Module implements module.Module for historical URL discovery.
type Module struct {
	client *http.Client
}

func New() *Module                         { return &Module{client: httpclient.Default()} }
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

func (m *Module) Name() string { return moduleName }

// Run queries all available sources for historical URLs of input.Target.
//
// Supported options:
//   - "no_subs":      "true"  — exclude subdomain URLs (default: false)
//   - "dates":        "true"  — include capture date in Finding.Extra (default: false)
//   - "get_versions": "true"  — return versioned Wayback URLs instead of originals
//   - "vt_api_key":   "<key>" — VirusTotal API key; falls back to VT_API_KEY env var
//   - "max_urls":      maximum references returned (default: 1000)
//   - "max_runtime_seconds": global execution budget (default: 60)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	if input.Target == "" {
		return nil, fmt.Errorf("wayback: target is required")
	}

	noSubs := optBool(input.Options, "no_subs", false)
	showDates := optBool(input.Options, "dates", false)
	getVersions := optBool(input.Options, "get_versions", false)
	maxURLs := optInt(input.Options, "max_urls", defaultMaxURLs)
	maxRuntime := optInt(input.Options, "max_runtime_seconds", defaultRuntimeSeconds)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntime)*time.Second)
	defer cancel()
	slog.Debug("wayback: starting", "target", input.Target, "no_subs", noSubs, "get_versions", getVersions)

	// --- get-versions mode (ported directly from original) ---
	if getVersions {
		versions, err := m.fetchVersions(runCtx, input.Target)
		if err != nil {
			return nil, fmt.Errorf("wayback get_versions: %w", err)
		}
		if len(versions) > maxURLs {
			versions = versions[:maxURLs]
		}
		findings := make([]module.Finding, 0, len(versions))
		for _, v := range versions {
			findings = append(findings, module.Finding{
				Type:     "archived_version",
				URL:      v.url,
				Detail:   fmt.Sprintf("Archived version captured %s", v.date),
				Severity: module.SeverityInfo,
				Extra: map[string]string{
					"captured_at": v.date,
					"source":      "wayback",
					"confidence":  "0.75", // archived URL — may be stale or no longer reachable
				},
			})
		}
		return findings, nil
	}

	domain := urlutil.NormalizeDomain(input.Target)
	if domain == "" {
		return nil, fmt.Errorf("wayback: invalid target domain")
	}

	// --- normal mode: fan out to all sources in parallel ---
	vtKey := optStr(input.Options, "vt_api_key", os.Getenv("VT_API_KEY"))

	type fetchFn func(ctx context.Context, domain string, noSubs bool) ([]wurl, error)
	sources := []fetchFn{
		m.fetchWayback,
		m.fetchCommonCrawl,
	}
	if vtKey != "" {
		sources = append(sources, func(ctx context.Context, domain string, noSubs bool) ([]wurl, error) {
			return m.fetchVirusTotal(ctx, domain, vtKey)
		})
	}

	ch := make(chan wurl, 256)
	var wg sync.WaitGroup

	for _, fn := range sources {
		wg.Add(1)
		f := fn
		go func() {
			defer wg.Done()
			results, err := f(runCtx, domain, noSubs)
			if err != nil {
				return
			}
			for _, r := range results {
				if noSubs && isSubdomain(r.url, domain) {
					continue
				}
				select {
				case ch <- r:
				case <-runCtx.Done():
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	seen := make(map[string]bool)
	var findings []module.Finding

	for w := range ch {
		if len(findings) >= maxURLs {
			continue
		}
		canonical, ok := urlutil.CanonicalHTTP(w.url)
		if !ok || !urlutil.InDomainScope(canonical, domain) || seen[canonical] {
			continue
		}
		seen[canonical] = true

		extra := map[string]string{
			"source":             w.src,
			"confidence":         "0.85",
			"state":              "historical_unverified",
			"promote_to_context": "false",
		}
		detail := fmt.Sprintf("Historical URL from %s", w.src)

		if showDates && w.date != "" {
			d, err := time.Parse("20060102150405", w.date)
			if err == nil {
				extra["captured_at"] = d.Format(time.RFC3339)
				detail = fmt.Sprintf("Historical URL from %s (captured %s)", w.src, d.Format(time.RFC3339))
			}
		}

		findings = append(findings, module.Finding{
			Type:     "historical_reference",
			URL:      canonical,
			Detail:   detail,
			Severity: module.SeverityInfo,
			Extra:    extra,
		})
		if len(findings) >= maxURLs {
			cancel()
		}
	}

	return findings, nil
}

// fetchWayback queries the Wayback Machine CDX API.
// Ported from getWaybackURLs in the original, adapted for context and JSON output.
func (m *Module) fetchWayback(ctx context.Context, domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	reqURL := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey",
		subsWildcard, domain,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback HTTP %d", resp.StatusCode)
	}

	// Response is a JSON array of arrays:
	// [["urlkey","timestamp","original","mimetype","statuscode","digest","length"], ...]
	var wrapper [][]string
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSourceBodyBytes)).Decode(&wrapper); err != nil {
		return nil, err
	}

	out := make([]wurl, 0, len(wrapper))
	skip := true
	for _, row := range wrapper {
		if skip {
			skip = false // first row is the header
			continue
		}
		if len(row) < 3 {
			continue
		}
		out = append(out, wurl{date: row[1], url: row[2], src: "wayback"})
	}
	return out, nil
}

// fetchCommonCrawl queries the Common Crawl index.
// Ported from getCommonCrawlURLs in the original.
func (m *Module) fetchCommonCrawl(ctx context.Context, domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	reqURL := fmt.Sprintf(
		"https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=%s%s/*&output=json",
		subsWildcard, domain,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("commoncrawl HTTP %d", resp.StatusCode)
	}

	// Common Crawl returns one JSON object per line (NDJSON).
	var out []wurl
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxSourceBodyBytes))
	for sc.Scan() {
		var row struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			continue
		}
		out = append(out, wurl{date: row.Timestamp, url: row.URL, src: "commoncrawl"})
	}
	return out, sc.Err()
}

// fetchVirusTotal queries the VirusTotal domain report API.
// Ported from getVirusTotalURLs in the original.
func (m *Module) fetchVirusTotal(ctx context.Context, domain, apiKey string) ([]wurl, error) {
	reqURL := fmt.Sprintf(
		"https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s",
		apiKey, domain,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("virustotal HTTP %d", resp.StatusCode)
	}

	var wrapper struct {
		URLs []struct {
			URL string `json:"url"`
		} `json:"detected_urls"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSourceBodyBytes)).Decode(&wrapper); err != nil {
		return nil, err
	}

	out := make([]wurl, 0, len(wrapper.URLs))
	for _, u := range wrapper.URLs {
		out = append(out, wurl{url: u.URL, src: "virustotal"})
	}
	return out, nil
}

// fetchVersions returns all archived versions of a URL from Wayback Machine.
// Ported from getVersions in the original.
func (m *Module) fetchVersions(ctx context.Context, target string) ([]wurl, error) {
	reqURL := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s&output=json",
		target,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback versions HTTP %d", resp.StatusCode)
	}

	var rows [][]string
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSourceBodyBytes)).Decode(&rows); err != nil {
		return nil, err
	}

	// fields: urlkey, timestamp, original, mimetype, statuscode, digest, length
	seen := make(map[string]bool)
	var out []wurl
	first := true
	for _, row := range rows {
		if first {
			first = false
			continue
		}
		if len(row) < 7 {
			continue
		}
		digest := row[5]
		if seen[digest] {
			continue
		}
		seen[digest] = true
		out = append(out, wurl{
			date: row[1],
			url:  fmt.Sprintf("https://web.archive.org/web/%sif_/%s", row[1], row[2]),
			src:  "wayback",
		})
	}
	return out, nil
}

// isSubdomain reports whether rawURL's hostname differs from domain.
// Ported directly from the original.
func isSubdomain(rawURL, domain string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.ToLower(u.Hostname()) != strings.ToLower(domain)
}

func optBool(opts map[string]string, key string, def bool) bool {
	if opts == nil {
		return def
	}
	v, ok := opts[key]
	if !ok {
		return def
	}
	return strings.ToLower(v) != "false"
}

func optStr(opts map[string]string, key, def string) string {
	if opts == nil {
		return def
	}
	if v, ok := opts[key]; ok {
		return v
	}
	return def
}

func optInt(opts map[string]string, key string, def int) int {
	if opts == nil {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(opts[key]))
	if err != nil || n < 1 {
		return def
	}
	return n
}
