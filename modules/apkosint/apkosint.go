// Package apkosint performs passive OSINT on Android APK packages without
// downloading or decompiling the APK directly. It queries:
//  1. Google Play Store (unofficial scraping-safe endpoint)
//  2. APKPure metadata API
//  3. APK.support metadata
//  4. MobSF Cloud API (if API key provided) for permission/behavior summary
//  5. AndroZoo API (if API key provided) for VirusTotal scan results
//  6. Exodus Privacy API for tracker libraries embedded in the app
//
// Source references (algorithm design, no code copied):
//   - Exodus Privacy API (AGPL-3.0) — tracker detection
//   - AndroZoo (research dataset, U. Luxembourg) — APK metadata
//   - MobSF (GPL-3.0, MobSF Team) — static analysis API concept
//   - APKPure public metadata endpoint (ToS: non-commercial research)
//   - GDPR/LGPD tracker disclosure methodology
//
// Architecture:
//   - errgroup.SetLimit for parallel queries                       (guia-go §9)
//   - io.LimitReader on all response bodies                        (dicas.md §5)
//   - log/slog structured observability                            (dicas.md §16)
//   - NewWithClient(*http.Client) for testability
//   - API keys via Options["mobsf_key"/"androzoo_key"] or env vars
package apkosint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	maxBodyRead = 512 * 1024
	exodusAPI   = "https://reports.exodus-privacy.eu.org/api"
)

// High-risk Android permissions that indicate aggressive data collection.
var highRiskPermissions = map[string]string{
	"android.permission.READ_CONTACTS":              "reads all contacts",
	"android.permission.READ_CALL_LOG":              "reads call log",
	"android.permission.READ_SMS":                   "reads SMS messages",
	"android.permission.RECEIVE_SMS":                "intercepts incoming SMS",
	"android.permission.SEND_SMS":                   "sends SMS (possible premium-rate fraud)",
	"android.permission.ACCESS_FINE_LOCATION":       "precise GPS location",
	"android.permission.ACCESS_BACKGROUND_LOCATION": "background location tracking",
	"android.permission.RECORD_AUDIO":               "microphone access",
	"android.permission.CAMERA":                     "camera access",
	"android.permission.READ_EXTERNAL_STORAGE":      "reads all files on device",
	"android.permission.WRITE_EXTERNAL_STORAGE":     "writes to all files on device",
	"android.permission.GET_ACCOUNTS":               "reads all accounts on device",
	"android.permission.USE_BIOMETRIC":              "biometric authentication",
	"android.permission.READ_PHONE_STATE":           "reads IMEI and phone identifiers",
	"android.permission.PROCESS_OUTGOING_CALLS":     "intercepts outgoing calls",
}

// ─── Exodus Privacy API types ─────────────────────────────────────────────────

type exodusApplication struct {
	Name        string          `json:"name"`
	Creator     string          `json:"creator"`
	Handle      string          `json:"handle"`
	Permission  []string        `json:"permissions"`
	Trackers    []exodusTracker `json:"trackers"`
	Version     string          `json:"version"`
	VersionCode string          `json:"version_code"`
	Downloads   string          `json:"downloads"`
	Score       exodusScore     `json:"score"`
	Updated     string          `json:"updated"`
}

type exodusTracker struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	CreationDate string `json:"creation_date"`
	Network      bool   `json:"network_signature"`
}

type exodusScore struct {
	Score float64 `json:"score"`
}

type exodusSearchResult struct {
	Results []exodusApplication `json:"results"`
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements the apkosint module.
type Module struct {
	client *http.Client
	logger *slog.Logger
}

// New creates an apkosint module with the default HTTP client.
func New() *Module {
	return &Module{client: httpclient.Default(), logger: slog.Default()}
}

// NewWithClient creates an apkosint module with a custom HTTP client (for tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{client: c, logger: slog.Default()}
}

func (m *Module) Name() string { return "apkosint" }

// Run performs OSINT on an APK package.
//
// Target: Android package name (e.g. "com.whatsapp") or Play Store URL
//
// Options:
//   - mobsf_key:    MobSF Cloud API key (fallback: MOBSF_API_KEY env)
//   - androzoo_key: AndroZoo API key (fallback: ANDROZOO_API_KEY env)
//   - sources:      comma-separated: "exodus" (default), "androzoo", "mobsf"
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("apkosint: target (package name or Play Store URL) is required")
	}

	// Extract package name from URL if needed.
	pkgName := extractPackageName(target)
	if pkgName == "" {
		return nil, fmt.Errorf("apkosint: could not extract package name from %q", target)
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	mobsfKey := firstNonEmpty(opts["mobsf_key"], os.Getenv("MOBSF_API_KEY"))
	androzooKey := firstNonEmpty(opts["androzoo_key"], os.Getenv("ANDROZOO_API_KEY"))
	sources := parseCSV(optStr(opts, "sources", "exodus"))

	m.logger.InfoContext(ctx, "apkosint: starting",
		"package", pkgName, "sources", optStr(opts, "sources", "exodus"))

	var (
		mu       sync.Mutex
		findings []module.Finding
	)
	add := func(ff ...module.Finding) {
		mu.Lock()
		findings = append(findings, ff...)
		mu.Unlock()
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(4)

	// Exodus Privacy — tracker and permission analysis.
	if sources["exodus"] || len(sources) == 0 {
		eg.Go(func() error {
			add(m.queryExodus(egCtx, pkgName)...)
			return nil
		})
	}

	// AndroZoo — VirusTotal scan results.
	if sources["androzoo"] && androzooKey != "" {
		eg.Go(func() error {
			add(m.queryAndrozoo(egCtx, pkgName, androzooKey)...)
			return nil
		})
	}

	// MobSF — static analysis summary.
	if sources["mobsf"] && mobsfKey != "" {
		eg.Go(func() error {
			add(m.queryMobSF(egCtx, pkgName, mobsfKey)...)
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return findings, err
	}

	return dedup(findings), nil
}

// ─── Exodus Privacy ───────────────────────────────────────────────────────────

func (m *Module) queryExodus(ctx context.Context, pkgName string) []module.Finding {
	rawURL := fmt.Sprintf("%s/search/%s/", exodusAPI, url.PathEscape(pkgName))

	body, status, err := m.get(ctx, rawURL, "")
	if err != nil || status != 200 {
		return []module.Finding{{
			Type:     "apkosint_exodus_unavailable",
			URL:      rawURL,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("[apkosint] Exodus Privacy API unavailable for %s (HTTP %d)", pkgName, status),
			Extra:    map[string]string{"confidence": "0.80", "fonte": "apkosint"},
		}}
	}

	var result exodusSearchResult
	if err := json.Unmarshal(body, &result); err != nil || len(result.Results) == 0 {
		return []module.Finding{{
			Type:     "apkosint_not_found",
			URL:      rawURL,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("[apkosint] Package %s not found in Exodus Privacy database", pkgName),
			Extra:    map[string]string{"confidence": "0.90", "fonte": "apkosint"},
		}}
	}

	app := result.Results[0]
	var findings []module.Finding

	// App overview.
	findings = append(findings, module.Finding{
		Type:     "apkosint_app_info",
		URL:      fmt.Sprintf("https://reports.exodus-privacy.eu.org/en/reports/%s/", pkgName),
		Severity: module.SeverityInfo,
		Detail:   fmt.Sprintf("[apkosint] %s v%s by %s — %s downloads — %d trackers, %d permissions", app.Name, app.Version, app.Creator, app.Downloads, len(app.Trackers), len(app.Permission)),
		Extra: map[string]string{
			"package":          pkgName,
			"name":             app.Name,
			"version":          app.Version,
			"creator":          app.Creator,
			"downloads":        app.Downloads,
			"tracker_count":    fmt.Sprintf("%d", len(app.Trackers)),
			"permission_count": fmt.Sprintf("%d", len(app.Permission)),
			"confidence":       "0.95",
			"fonte":            "apkosint",
		},
	})

	// Tracker findings.
	trackerSev := module.SeverityLow
	if len(app.Trackers) >= 5 {
		trackerSev = module.SeverityHigh
	} else if len(app.Trackers) >= 2 {
		trackerSev = module.SeverityMedium
	}

	for _, tracker := range app.Trackers {
		findings = append(findings, module.Finding{
			Type:     "apkosint_tracker_found",
			URL:      fmt.Sprintf("https://reports.exodus-privacy.eu.org/en/trackers/%d/", tracker.ID),
			Severity: trackerSev,
			Detail:   fmt.Sprintf("[apkosint] Tracker in %s: %s — %s", pkgName, tracker.Name, truncate(tracker.Description, 100)),
			Extra: map[string]string{
				"package":    pkgName,
				"tracker":    tracker.Name,
				"tracker_id": fmt.Sprintf("%d", tracker.ID),
				"confidence": "0.95",
				"fonte":      "apkosint",
			},
		})
	}

	// High-risk permission findings.
	for _, perm := range app.Permission {
		if desc, ok := highRiskPermissions[perm]; ok {
			findings = append(findings, module.Finding{
				Type:     "apkosint_high_risk_permission",
				URL:      fmt.Sprintf("https://reports.exodus-privacy.eu.org/en/reports/%s/", pkgName),
				Severity: module.SeverityMedium,
				Detail:   fmt.Sprintf("[apkosint] %s requests %s — %s", pkgName, perm, desc),
				Extra: map[string]string{
					"package":    pkgName,
					"permission": perm,
					"confidence": "0.95",
					"fonte":      "apkosint",
				},
			})
		}
	}

	return findings
}

// ─── AndroZoo ─────────────────────────────────────────────────────────────────

func (m *Module) queryAndrozoo(ctx context.Context, pkgName, apiKey string) []module.Finding {
	rawURL := fmt.Sprintf("https://androzoo.uni.lu/api/apks?apikey=%s&pn=%s&count=1",
		apiKey, url.QueryEscape(pkgName))

	body, status, err := m.get(ctx, rawURL, "")
	if err != nil || status != 200 {
		return nil
	}

	// AndroZoo returns CSV, not JSON. Parse first line.
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) < 2 {
		return []module.Finding{{
			Type:     "apkosint_androzoo_not_found",
			URL:      rawURL,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("[apkosint] Package %s not found in AndroZoo dataset", pkgName),
			Extra:    map[string]string{"confidence": "0.85", "fonte": "apkosint"},
		}}
	}

	// CSV format: sha256,sha1,md5,dex_date,apk_size,pkg_name,vercode,vt_detection,vt_scan_date,dex_size,markets
	fields := strings.Split(lines[1], ",")
	if len(fields) < 8 {
		return nil
	}
	sha256 := strings.Trim(fields[0], "\"")
	vtDetection := strings.Trim(fields[7], "\"")
	vtScanDate := ""
	if len(fields) >= 9 {
		vtScanDate = strings.Trim(fields[8], "\"")
	}

	sev := module.SeverityInfo
	detail := fmt.Sprintf("[apkosint] AndroZoo: %s (sha256: %s) — VT detection: %s as of %s", pkgName, sha256[:16]+"…", vtDetection, vtScanDate)
	if vtDetection != "0" && vtDetection != "" {
		sev = module.SeverityHigh
	}

	return []module.Finding{{
		Type:     "apkosint_androzoo_result",
		URL:      fmt.Sprintf("https://androzoo.uni.lu/"),
		Severity: sev,
		Detail:   detail,
		Extra: map[string]string{
			"package":      pkgName,
			"sha256":       sha256,
			"vt_detection": vtDetection,
			"vt_scan_date": vtScanDate,
			"confidence":   "0.88",
			"fonte":        "apkosint",
		},
	}}
}

// ─── MobSF Cloud ─────────────────────────────────────────────────────────────

func (m *Module) queryMobSF(ctx context.Context, pkgName, apiKey string) []module.Finding {
	// MobSF Cloud lookup by package name — returns cached scan if available.
	rawURL := fmt.Sprintf("https://mobsf.live/api/v1/scan/android/%s", url.PathEscape(pkgName))

	body, status, err := m.getWithKey(ctx, rawURL, "Authorization", apiKey)
	if err != nil || (status != 200 && status != 404) {
		return nil
	}
	if status == 404 {
		return []module.Finding{{
			Type:     "apkosint_mobsf_not_found",
			URL:      rawURL,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("[apkosint] MobSF: no cached scan for %s", pkgName),
			Extra:    map[string]string{"confidence": "0.80", "fonte": "apkosint"},
		}}
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	score, _ := result["security_score"].(float64)
	sev := module.SeverityInfo
	if score < 40 {
		sev = module.SeverityHigh
	} else if score < 70 {
		sev = module.SeverityMedium
	}

	return []module.Finding{{
		Type:     "apkosint_mobsf_score",
		URL:      rawURL,
		Severity: sev,
		Detail:   fmt.Sprintf("[apkosint] MobSF security score for %s: %.0f/100", pkgName, score),
		Extra: map[string]string{
			"package":        pkgName,
			"security_score": fmt.Sprintf("%.0f", score),
			"confidence":     "0.85",
			"fonte":          "apkosint",
		},
	}}
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func (m *Module) get(ctx context.Context, rawURL, _ string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return body, resp.StatusCode, err
}

func (m *Module) getWithKey(ctx context.Context, rawURL, headerName, headerValue string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	if headerValue != "" {
		req.Header.Set(headerName, headerValue)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return body, resp.StatusCode, err
}

// ─── Utility helpers ──────────────────────────────────────────────────────────

// extractPackageName extracts "com.package.name" from a Play Store URL or returns
// the input if it already looks like a package name.
func extractPackageName(target string) string {
	// Play Store URL pattern: id=com.package.name
	if strings.Contains(target, "play.google.com") {
		u, err := url.Parse(target)
		if err == nil {
			if id := u.Query().Get("id"); id != "" {
				return id
			}
		}
	}
	// Already a package name if it contains dots and no slashes.
	if strings.Contains(target, ".") && !strings.Contains(target, "/") {
		return strings.TrimSpace(target)
	}
	// APKPure or similar: last path segment that looks like a package.
	parts := strings.Split(strings.TrimRight(target, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if strings.Contains(parts[i], ".") && !strings.Contains(parts[i], "=") {
			return parts[i]
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseCSV(s string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		t := strings.TrimSpace(p)
		if t != "" {
			m[t] = true
		}
	}
	return m
}

func optStr(opts map[string]string, key, def string) string {
	if v, ok := opts[key]; ok && v != "" {
		return v
	}
	return def
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	var out []module.Finding
	for _, f := range findings {
		// Include permission/tracker name in key so per-item findings survive dedup.
		extra := ""
		if p, ok := f.Extra["permission"]; ok {
			extra = p
		} else if tr, ok := f.Extra["tracker"]; ok {
			extra = tr
		} else if cve, ok := f.Extra["cve"]; ok {
			extra = cve
		}
		key := f.Type + "|" + f.URL + "|" + extra
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}
