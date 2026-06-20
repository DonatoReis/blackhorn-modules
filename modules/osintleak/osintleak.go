// Package osintleak queries breach/leak intelligence APIs to discover exposed
// credentials, emails and data associated with a target.
//
// Sources integrated:
//   - DeHashed  (https://dehashed.com)          — paid, requires api_key + email
//   - LeakCheck (https://leakcheck.io)          — paid, requires api_key
//   - HaveIBeenPwned (https://haveibeenpwned.com) — free/paid, requires api_key
//   - IntelX    (https://intelx.io)             — paid, requires api_key
//   - BreachDirectory (https://rapidapi.com)    — RapidAPI wrapper, requires api_key
//
// Source reference: public API docs for each service (no source copied).
// Logic reimplemented independently following blackhorn-modules patterns.
//
// Input options:
//   - "sources"      — comma-separated list of sources to query (default: all enabled)
//   - "dehashed_key" — DeHashed API key  (or env DEHASHED_API_KEY)
//   - "dehashed_email" — DeHashed account email
//   - "leakcheck_key" — LeakCheck API key (or env LEAKCHECK_API_KEY)
//   - "hibp_key"     — HIBP API key (or env HIBP_API_KEY)
//   - "intelx_key"   — IntelX API key (or env INTELX_API_KEY)
//   - "rapidapi_key" — RapidAPI key for BreachDirectory (or env RAPIDAPI_KEY)
//   - "max_results"  — cap per source (default: 100)
//   - "include_passwords" — "true" to include hashed/cleartext passwords in Extra
//
// Architecture:
//   - All sources queried in parallel via errgroup
//   - Deduplication by (email+source) pair
//   - confidence based on source reliability tier
//   - slog observability on every decision
//   - io.LimitReader on all responses (maxBody = 10 MB)
package osintleak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	moduleName  = "osintleak"
	maxBody     = 10 << 20 // 10 MB
	defaultMax  = 100
	defaultConc = 5
)

// ─── Module ──────────────────────────────────────────────────────────────────

// Module implements the osintleak breach/leak intelligence aggregator.
type Module struct {
	client *http.Client
	logger *slog.Logger
}

// New returns a Module with production defaults.
func New() *Module {
	return &Module{
		client: httpclient.New(httpclient.Options{Timeout: 30 * time.Second}),
		logger: slog.Default().With("module", moduleName),
	}
}

// NewWithClient returns a Module using the supplied HTTP client (testability).
func NewWithClient(c *http.Client) *Module {
	m := New()
	m.client = c
	return m
}

// Name satisfies module.Module.
func (m *Module) Name() string { return moduleName }

// Run queries configured leak sources for the given target (email/domain/username/IP).
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" && len(input.URLs) > 0 {
		target = strings.TrimSpace(input.URLs[0])
	}
	if target == "" {
		return nil, fmt.Errorf("osintleak: target required (email, domain, username or IP)")
	}

	opts := input.Options
	maxResults := optInt(opts, "max_results", defaultMax)
	inclPasswords := optStr(opts, "include_passwords", "") == "true"
	sourcesFilter := optStr(opts, "sources", "")

	// Resolve API keys: option → env fallback
	dehKey := firstNonEmpty(optStr(opts, "dehashed_key", ""), os.Getenv("DEHASHED_API_KEY"))
	dehEmail := firstNonEmpty(optStr(opts, "dehashed_email", ""), os.Getenv("DEHASHED_EMAIL"))
	lcKey := firstNonEmpty(optStr(opts, "leakcheck_key", ""), os.Getenv("LEAKCHECK_API_KEY"))
	hibpKey := firstNonEmpty(optStr(opts, "hibp_key", ""), os.Getenv("HIBP_API_KEY"))
	ixKey := firstNonEmpty(optStr(opts, "intelx_key", ""), os.Getenv("INTELX_API_KEY"))
	rapidKey := firstNonEmpty(optStr(opts, "rapidapi_key", ""), os.Getenv("RAPIDAPI_KEY"))

	m.logger.InfoContext(ctx, "osintleak: starting",
		"target", target,
		"max_results", maxResults,
		"sources_filter", sourcesFilter,
	)

	sources := m.buildSources(target, maxResults, inclPasswords,
		dehKey, dehEmail, lcKey, hibpKey, ixKey, rapidKey)

	// Filter by sources option if set
	if sourcesFilter != "" {
		wanted := strings.Split(sourcesFilter, ",")
		wmap := make(map[string]bool, len(wanted))
		for _, w := range wanted {
			wmap[strings.TrimSpace(strings.ToLower(w))] = true
		}
		filtered := sources[:0]
		for _, s := range sources {
			if wmap[s.name] {
				filtered = append(filtered, s)
			}
		}
		sources = filtered
	}

	if len(sources) == 0 {
		m.logger.WarnContext(ctx, "osintleak: no sources enabled — configure API keys")
		return nil, nil
	}

	var (
		mu      sync.Mutex
		seen    = make(map[string]struct{})
		results []module.Finding
	)

	add := func(fs []module.Finding) {
		mu.Lock()
		defer mu.Unlock()
		for _, f := range fs {
			key := f.Type + "|" + f.URL + "|" + f.Extra["source"] + "|" + f.Extra["email"]
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			results = append(results, f)
		}
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(defaultConc)

	for _, src := range sources {
		src := src
		eg.Go(func() error {
			m.logger.DebugContext(egCtx, "osintleak: querying source", "source", src.name)
			fs, err := src.fetch(egCtx, m.client)
			if err != nil {
				m.logger.WarnContext(egCtx, "osintleak: source error",
					"source", src.name, "err", err)
				return nil // non-fatal: other sources still run
			}
			m.logger.InfoContext(egCtx, "osintleak: source done",
				"source", src.name, "findings", len(fs))
			add(fs)
			return nil
		})
	}

	_ = eg.Wait()

	// Sort for deterministic output: by source then email
	sort.Slice(results, func(i, j int) bool {
		if results[i].Extra["source"] != results[j].Extra["source"] {
			return results[i].Extra["source"] < results[j].Extra["source"]
		}
		return results[i].Extra["email"] < results[j].Extra["email"]
	})

	m.logger.InfoContext(ctx, "osintleak: done",
		"target", target, "total_findings", len(results))
	return results, nil
}

// ─── Source abstraction ───────────────────────────────────────────────────────

type sourceFunc struct {
	name  string
	fetch func(ctx context.Context, c *http.Client) ([]module.Finding, error)
}

func (m *Module) buildSources(
	target string, maxResults int, inclPasswords bool,
	dehKey, dehEmail, lcKey, hibpKey, ixKey, rapidKey string,
) []sourceFunc {
	var sources []sourceFunc

	if dehKey != "" && dehEmail != "" {
		sources = append(sources, sourceFunc{
			name:  "dehashed",
			fetch: m.fetchDehashed(target, maxResults, inclPasswords, dehKey, dehEmail),
		})
	}
	if lcKey != "" {
		sources = append(sources, sourceFunc{
			name:  "leakcheck",
			fetch: m.fetchLeakCheck(target, maxResults, lcKey),
		})
	}
	if hibpKey != "" {
		sources = append(sources, sourceFunc{
			name:  "hibp",
			fetch: m.fetchHIBP(target, hibpKey),
		})
	}
	if ixKey != "" {
		sources = append(sources, sourceFunc{
			name:  "intelx",
			fetch: m.fetchIntelX(target, maxResults, ixKey),
		})
	}
	if rapidKey != "" {
		sources = append(sources, sourceFunc{
			name:  "breachdirectory",
			fetch: m.fetchBreachDirectory(target, rapidKey),
		})
	}
	return sources
}

// ─── DeHashed ─────────────────────────────────────────────────────────────────
// API: https://dehashed.com/docs
// Endpoint: GET https://api.dehashed.com/search?query=<target>&size=<max>
// Auth: Basic(email:apikey)

func (m *Module) fetchDehashed(target string, max int, inclPasswords bool, apiKey, email string) func(ctx context.Context, c *http.Client) ([]module.Finding, error) {
	return func(ctx context.Context, c *http.Client) ([]module.Finding, error) {
		endpoint := fmt.Sprintf(
			"https://api.dehashed.com/search?query=%s&size=%d",
			url.QueryEscape(target), min(max, 10000),
		)
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(email, apiKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "blackhorn-osintleak/1.0")

		resp, err := c.Do(req)
		if err != nil {
			return nil, fmt.Errorf("dehashed: request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("dehashed: invalid credentials (401)")
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			return nil, fmt.Errorf("dehashed: unexpected status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err != nil {
			return nil, err
		}

		var raw struct {
			Total   int `json:"total"`
			Entries []struct {
				ID             string `json:"id"`
				Email          string `json:"email"`
				Username       string `json:"username"`
				Password       string `json:"password"`
				HashedPassword string `json:"hashed_password"`
				Name           string `json:"name"`
				DatabaseName   string `json:"database_name"`
				Address        string `json:"address"`
				Phone          string `json:"phone"`
				IPAddress      string `json:"ip_address"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, fmt.Errorf("dehashed: parse error: %w", err)
		}

		var findings []module.Finding
		for _, e := range raw.Entries {
			identity := e.Email
			if identity == "" {
				identity = e.Username
			}
			if identity == "" {
				continue
			}

			extra := map[string]string{
				"source":     "dehashed",
				"email":      e.Email,
				"username":   e.Username,
				"name":       e.Name,
				"database":   e.DatabaseName,
				"phone":      e.Phone,
				"ip":         e.IPAddress,
				"address":    e.Address,
				"record_id":  e.ID,
				"confidence": "0.90", // direct DeHashed index match — high reliability
			}
			if inclPasswords {
				extra["password_hint"] = redact(e.Password)
				extra["hash_hint"] = redact(e.HashedPassword)
			}

			sev := module.SeverityHigh
			if e.Password != "" || e.HashedPassword != "" {
				sev = module.SeverityCritical
			}

			findings = append(findings, module.Finding{
				Type:     "breach_record",
				URL:      target,
				Detail:   fmt.Sprintf("[DeHashed] %q found in breach database %q", identity, e.DatabaseName),
				Severity: sev,
				Extra:    extra,
			})
		}
		return findings, nil
	}
}

// ─── LeakCheck ────────────────────────────────────────────────────────────────
// API: https://leakcheck.io/api
// Endpoint: GET https://leakcheck.io/api/v2/query/<target>
// Auth: Header X-API-Key

func (m *Module) fetchLeakCheck(target string, max int, apiKey string) func(ctx context.Context, c *http.Client) ([]module.Finding, error) {
	return func(ctx context.Context, c *http.Client) ([]module.Finding, error) {
		endpoint := fmt.Sprintf("https://leakcheck.io/api/v2/query/%s", url.PathEscape(target))
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "blackhorn-osintleak/1.0")

		resp, err := c.Do(req)
		if err != nil {
			return nil, fmt.Errorf("leakcheck: request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("leakcheck: invalid API key (%d)", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil // not found = no breaches
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("leakcheck: unexpected status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err != nil {
			return nil, err
		}

		var raw struct {
			Success bool `json:"success"`
			Found   int  `json:"found"`
			Result  []struct {
				Email    string   `json:"email"`
				Sources  []string `json:"sources"`
				Password string   `json:"password"`
				Hash     string   `json:"hash"`
				Line     string   `json:"line"`
			} `json:"result"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, fmt.Errorf("leakcheck: parse error: %w", err)
		}

		var findings []module.Finding
		for i, r := range raw.Result {
			if i >= max {
				break
			}
			sev := module.SeverityMedium
			if r.Password != "" || r.Hash != "" {
				sev = module.SeverityCritical
			}
			findings = append(findings, module.Finding{
				Type:     "breach_record",
				URL:      target,
				Detail:   fmt.Sprintf("[LeakCheck] %q found in %d source(s): %s", r.Email, len(r.Sources), strings.Join(r.Sources, ", ")),
				Severity: sev,
				Extra: map[string]string{
					"source":     "leakcheck",
					"email":      r.Email,
					"databases":  strings.Join(r.Sources, ","),
					"line_hint":  truncate(r.Line, 80),
					"confidence": "0.88", // LeakCheck verified deduplication
				},
			})
		}
		return findings, nil
	}
}

// ─── HaveIBeenPwned ───────────────────────────────────────────────────────────
// API: https://haveibeenpwned.com/API/v3
// Endpoint: GET https://haveibeenpwned.com/api/v3/breachedaccount/<account>
// Auth: Header hibp-api-key

func (m *Module) fetchHIBP(target, apiKey string) func(ctx context.Context, c *http.Client) ([]module.Finding, error) {
	return func(ctx context.Context, c *http.Client) ([]module.Finding, error) {
		endpoint := fmt.Sprintf(
			"https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=false",
			url.PathEscape(target),
		)
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("hibp-api-key", apiKey)
		req.Header.Set("User-Agent", "blackhorn-osintleak/1.0")

		resp, err := c.Do(req)
		if err != nil {
			return nil, fmt.Errorf("hibp: request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return nil, nil // no breaches — clean result
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("hibp: invalid API key")
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("hibp: rate limited")
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("hibp: unexpected status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err != nil {
			return nil, err
		}

		var breaches []struct {
			Name        string   `json:"Name"`
			Title       string   `json:"Title"`
			Domain      string   `json:"Domain"`
			BreachDate  string   `json:"BreachDate"`
			PwnCount    int      `json:"PwnCount"`
			DataClasses []string `json:"DataClasses"`
			IsVerified  bool     `json:"IsVerified"`
			IsSensitive bool     `json:"IsSensitive"`
		}
		if err := json.Unmarshal(body, &breaches); err != nil {
			return nil, fmt.Errorf("hibp: parse error: %w", err)
		}

		var findings []module.Finding
		for _, b := range breaches {
			hasPasswords := false
			for _, dc := range b.DataClasses {
				if strings.Contains(strings.ToLower(dc), "password") {
					hasPasswords = true
					break
				}
			}
			sev := module.SeverityMedium
			if hasPasswords || b.IsSensitive {
				sev = module.SeverityHigh
			}
			conf := "0.95" // HIBP is authoritative and verified
			if !b.IsVerified {
				conf = "0.70"
			}
			findings = append(findings, module.Finding{
				Type:     "breach_record",
				URL:      target,
				Detail:   fmt.Sprintf("[HIBP] %q breached in %q (%s) — data: %s", target, b.Title, b.BreachDate, strings.Join(b.DataClasses, ", ")),
				Severity: sev,
				Extra: map[string]string{
					"source":        "hibp",
					"email":         target,
					"breach_name":   b.Name,
					"breach_title":  b.Title,
					"breach_date":   b.BreachDate,
					"breach_domain": b.Domain,
					"pwn_count":     strconv.Itoa(b.PwnCount),
					"data_classes":  strings.Join(b.DataClasses, ","),
					"is_verified":   strconv.FormatBool(b.IsVerified),
					"is_sensitive":  strconv.FormatBool(b.IsSensitive),
					"confidence":    conf,
				},
			})
		}
		return findings, nil
	}
}

// ─── IntelX ───────────────────────────────────────────────────────────────────
// API: https://intelx.io/product#api
// Phase 1: POST /phonebook/search → get id
// Phase 2: GET  /phonebook/search/result?id=<id>&k=<key>&limit=<max>

func (m *Module) fetchIntelX(target string, max int, apiKey string) func(ctx context.Context, c *http.Client) ([]module.Finding, error) {
	return func(ctx context.Context, c *http.Client) ([]module.Finding, error) {
		// Phase 1: submit search
		searchBody := fmt.Sprintf(`{"term":%q,"buckets":[],"lookuplevel":0,"maxresults":%d,"timeout":20,"datefrom":"","dateto":"","sort":4,"media":0,"terminate":[]}`, target, max)
		reqSearch, err := http.NewRequestWithContext(ctx, "POST",
			"https://2.intelx.io/phonebook/search",
			strings.NewReader(searchBody))
		if err != nil {
			return nil, err
		}
		reqSearch.Header.Set("x-key", apiKey)
		reqSearch.Header.Set("Content-Type", "application/json")
		reqSearch.Header.Set("User-Agent", "blackhorn-osintleak/1.0")

		respSearch, err := c.Do(reqSearch)
		if err != nil {
			return nil, fmt.Errorf("intelx: search request failed: %w", err)
		}
		defer respSearch.Body.Close()

		if respSearch.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("intelx: invalid API key")
		}
		if respSearch.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("intelx: search status %d", respSearch.StatusCode)
		}

		bodySearch, _ := io.ReadAll(io.LimitReader(respSearch.Body, 1<<20))
		var searchResp struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(bodySearch, &searchResp); err != nil || searchResp.ID == "" {
			return nil, fmt.Errorf("intelx: no search ID in response")
		}

		// Brief pause to let IntelX process
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}

		// Phase 2: fetch results
		resultsURL := fmt.Sprintf(
			"https://2.intelx.io/phonebook/search/result?id=%s&k=%s&limit=%d",
			url.QueryEscape(searchResp.ID), url.QueryEscape(apiKey), max,
		)
		reqResults, err := http.NewRequestWithContext(ctx, "GET", resultsURL, nil)
		if err != nil {
			return nil, err
		}
		reqResults.Header.Set("User-Agent", "blackhorn-osintleak/1.0")

		respResults, err := c.Do(reqResults)
		if err != nil {
			return nil, fmt.Errorf("intelx: results request failed: %w", err)
		}
		defer respResults.Body.Close()

		bodyResults, _ := io.ReadAll(io.LimitReader(respResults.Body, maxBody))
		var results struct {
			Selectors []struct {
				Selectortype int    `json:"selectortype"`
				Selector     string `json:"selector"`
			} `json:"selectors"`
		}
		if err := json.Unmarshal(bodyResults, &results); err != nil {
			return nil, fmt.Errorf("intelx: results parse error: %w", err)
		}

		var findings []module.Finding
		for _, sel := range results.Selectors {
			if sel.Selector == "" {
				continue
			}
			findings = append(findings, module.Finding{
				Type:     "leaked_identifier",
				URL:      target,
				Detail:   fmt.Sprintf("[IntelX] selector found: %q (type=%d)", sel.Selector, sel.Selectortype),
				Severity: module.SeverityMedium,
				Extra: map[string]string{
					"source":        "intelx",
					"email":         sel.Selector,
					"selector_type": strconv.Itoa(sel.Selectortype),
					"confidence":    "0.80", // IntelX phonebook — unverified selectors
				},
			})
		}
		return findings, nil
	}
}

// ─── BreachDirectory (RapidAPI) ───────────────────────────────────────────────
// API: https://rapidapi.com/rohan-patra/api/breachdirectory
// Endpoint: GET https://breachdirectory.p.rapidapi.com/?func=auto&term=<target>

func (m *Module) fetchBreachDirectory(target, rapidKey string) func(ctx context.Context, c *http.Client) ([]module.Finding, error) {
	return func(ctx context.Context, c *http.Client) ([]module.Finding, error) {
		endpoint := fmt.Sprintf(
			"https://breachdirectory.p.rapidapi.com/?func=auto&term=%s",
			url.QueryEscape(target),
		)
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("x-rapidapi-host", "breachdirectory.p.rapidapi.com")
		req.Header.Set("x-rapidapi-key", rapidKey)
		req.Header.Set("User-Agent", "blackhorn-osintleak/1.0")

		resp, err := c.Do(req)
		if err != nil {
			return nil, fmt.Errorf("breachdirectory: request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("breachdirectory: invalid API key (%d)", resp.StatusCode)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("breachdirectory: unexpected status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err != nil {
			return nil, err
		}

		var raw struct {
			Found  bool `json:"found"`
			Result []struct {
				Email    string `json:"email"`
				Password string `json:"password"`
				Hash     string `json:"hash"`
				SHA1     string `json:"sha1"`
				Sources  string `json:"sources"`
			} `json:"result"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, fmt.Errorf("breachdirectory: parse error: %w", err)
		}

		if !raw.Found {
			return nil, nil
		}

		var findings []module.Finding
		for _, r := range raw.Result {
			sev := module.SeverityMedium
			if r.Password != "" || r.Hash != "" || r.SHA1 != "" {
				sev = module.SeverityHigh
			}
			findings = append(findings, module.Finding{
				Type:     "breach_record",
				URL:      target,
				Detail:   fmt.Sprintf("[BreachDirectory] %q found; sources: %s", r.Email, r.Sources),
				Severity: sev,
				Extra: map[string]string{
					"source":     "breachdirectory",
					"email":      r.Email,
					"sources":    r.Sources,
					"has_hash":   strconv.FormatBool(r.Hash != "" || r.SHA1 != ""),
					"confidence": "0.82", // BreachDirectory aggregates multiple sources
				},
			})
		}
		return findings, nil
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// redact masks all but the first 4 characters of a secret.
func redact(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-4)
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
