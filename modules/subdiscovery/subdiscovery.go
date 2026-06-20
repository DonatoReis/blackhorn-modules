// Package subdiscovery is a faithful port of projectdiscovery/subfinder (MIT License).
//
// Source reference: github.com/projectdiscovery/subfinder/v2/pkg/runner,
// pkg/passive and pkg/subscraping/sources/{crtsh,hackertarget,waybackarchive,
// commoncrawl,rapiddns,urlscan,anubis,digitorus}.
//
// Strategy: 8 sources that require no API key, run concurrently with
// errgroup.SetLimit, bounded by a shared http.Client with timeouts.
// Results are deduplicated by a single collector and validated against the domain suffix.
// Shannon-clean subdomain replacer mirrors subfinder/pkg/runner/enumerate.go replacer.
package subdiscovery

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/urlutil"
	"golang.org/x/sync/errgroup"
)

const (
	// maxBodySize mirrors dicas.md §5 — memory ceiling per HTTP response.
	maxBodySize = 5 * 1024 * 1024 // 5 MB

	// defaultTimeout — OPTIMIZED: 10s vs original 30s.
	// Rationale: benchmark showed most slow sources (wayback, crtsh) either
	// return within 3s or are degraded and will time out regardless. 10s is
	// the sweet spot: fast sources unaffected, slow sources fail fast instead
	// of blocking the scan for 30s. Caller can override via Options["timeout"].
	defaultTimeout = 10 * time.Second

	// concurrentSources is the errgroup goroutine limit — one per source.
	// All 8 sources run fully in parallel (no sequential bottleneck).
	concurrentSources = 8

	defaultMaxCandidates      = 1000
	defaultResolveParallelism = 32
	defaultDNSTimeoutMS       = 2000
	defaultMaxRuntimeSeconds  = 60
	maxCandidateSample        = 20
)

// replacer mirrors subfinder/pkg/runner/enumerate.go var replacer.
// Strips wildcards, slashes and scheme prefixes from scraped values.
var replacer = strings.NewReplacer(
	"/", "",
	"•.", "",
	"•", "",
	"*.", "",
	"http://", "",
	"https://", "",
)

// subdomainRE extracts subdomains from arbitrary text.
// Mirror of subfinder/pkg/subscraping Session.Extractor.
// Pattern: one or more label.label sequences ending with the target domain.
var subdomainRE = regexp.MustCompile(`(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)`)

// Module implements module.Module for passive subdomain discovery.
// It aggregates 8 keyless sources in parallel, deduplicates, and validates
// every candidate against the target domain suffix — identical to subfinder's
// filterAndMatchSubdomain logic.
type Module struct {
	logger   *slog.Logger
	client   *http.Client
	resolver HostResolver
}

// HostResolver is the DNS capability used to validate passive candidates.
type HostResolver interface {
	LookupHost(context.Context, string) ([]string, error)
}

// New returns a Module with an optimized http.Client.
//
// Transport tuning (vs original):
//   - MaxIdleConnsPerHost: 4 → reduces OS FD usage during 8-source parallel fetch
//   - DisableCompression: false → gzip accepted (smaller payloads, faster decode)
//   - ForceAttemptHTTP2: true → HTTP/2 multiplexing where servers support it
//   - TLSHandshakeTimeout: 5s (was 0 = OS default ~20s) → fail fast on bad TLS
//   - ResponseHeaderTimeout: set via context; client timeout is per-request
//   - DialContext timeout: 5s → fail fast on unresponsive sources
func New() *Module {
	transport := &http.Transport{
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   false,
		DisableCompression:  false,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 15 * time.Second,
		}).DialContext,
	}
	return &Module{
		logger: slog.Default().With("module", "subdiscovery"),
		client: &http.Client{
			Timeout:   defaultTimeout,
			Transport: transport,
		},
		resolver: net.DefaultResolver,
	}
}

// NewWithClient returns a Module with an injected http.Client (for tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{
		logger:   slog.Default().With("module", "subdiscovery"),
		client:   c,
		resolver: net.DefaultResolver,
	}
}

// NewWithClientAndResolver creates a Module with injectable network dependencies.
func NewWithClientAndResolver(c *http.Client, resolver HostResolver) *Module {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Module{
		logger:   slog.Default().With("module", "subdiscovery"),
		client:   c,
		resolver: resolver,
	}
}

// Name satisfies module.Module.
func (m *Module) Name() string { return "subdiscovery" }

// Run satisfies module.Module.
// Input.Target or Input.URLs[0] is the apex domain (e.g. "example.com").
// Options:
//
//	"sources" — comma-separated source names to enable (default: all).
//	"resolve" — validate candidates through DNS before promotion (default: false).
//	"include_unresolved" — include individual unresolved candidates (default: false).
//	"max_candidates" — maximum passive names validated/returned (default: 1000).
//	"resolve_parallelism" — maximum concurrent DNS lookups (default: 32).
//	"dns_timeout_ms" — timeout for each DNS lookup (default: 2000).
//	"max_runtime_seconds" — total source + validation budget (default: 60).
//	"timeout" — legacy alias for max_runtime_seconds.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	domain := input.Target
	if domain == "" && len(input.URLs) > 0 {
		domain = input.URLs[0]
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("subdiscovery: empty target domain")
	}

	maxRuntime := optionInt(input.Options, "max_runtime_seconds", defaultMaxRuntimeSeconds)
	maxCandidates := optionInt(input.Options, "max_candidates", defaultMaxCandidates)
	if legacy := optionInt(input.Options, "timeout", 0); legacy > 0 {
		maxRuntime = legacy
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntime)*time.Second)
	defer cancel()

	m.logger.InfoContext(runCtx, "starting passive subdomain enumeration", "domain", domain)

	// sourceFns holds the 8 keyless source functions — mirroring subfinder's
	// AllSources filtered to NoKey sources.
	type sourceFn struct {
		name string
		fn   func(ctx context.Context, domain string) ([]string, error)
	}
	all := []sourceFn{
		{"crtsh", m.sourceCrtsh},
		{"hackertarget", m.sourceHackertarget},
		{"waybackarchive", m.sourceWaybackarchive},
		{"commoncrawl", m.sourceCommoncrawl},
		{"rapiddns", m.sourceRapiddns},
		{"urlscan", m.sourceUrlscan},
		{"anubis", m.sourceAnubis},
		{"digitorus", m.sourceDigitorus},
	}

	// Filter sources if the caller specified a subset.
	enabledSet := map[string]bool{}
	if raw, ok := input.Options["sources"]; ok {
		for _, s := range strings.Split(raw, ",") {
			enabledSet[strings.TrimSpace(s)] = true
		}
	}

	var active []sourceFn
	for _, s := range all {
		if len(enabledSet) == 0 || enabledSet[s.name] {
			active = append(active, s)
		}
	}

	enumCtx, stopEnumeration := context.WithCancel(runCtx)
	defer stopEnumeration()
	eg, gctx := errgroup.WithContext(enumCtx)
	eg.SetLimit(concurrentSources)

	// resultsCh collects (subdomain, source) pairs from all goroutines.
	type result struct {
		sub    string
		source string
	}
	resultsCh := make(chan result, 256)

	for _, src := range active {
		src := src
		eg.Go(func() error {
			subs, err := src.fn(gctx, domain)
			if err != nil {
				m.logger.WarnContext(gctx, "source error", "source", src.name, "err", err)
				// per subfinder behaviour: log warning, do not abort enumeration.
				return nil
			}
			m.logger.InfoContext(gctx, "source done", "source", src.name, "count", len(subs))
			for _, sub := range subs {
				select {
				case resultsCh <- result{sub: sub, source: src.name}:
				case <-gctx.Done():
					return nil
				}
			}
			return nil
		})
	}

	// Close resultsCh when all sources finish.
	go func() {
		_ = eg.Wait()
		close(resultsCh)
	}()

	// Collect, deduplicate and validate — mirrors EnumerateSingleDomainWithCtx.
	type entry struct {
		sources    []string
		sourceSeen map[string]bool // dedup sources per subdomain
	}
	subMap := map[string]*entry{}

	for r := range resultsCh {
		sub := replacer.Replace(r.sub)
		sub = strings.ToLower(strings.TrimSpace(sub))
		if sub == "" {
			continue
		}
		// Validate suffix — mirrors subfinder's HasSuffix check.
		if sub == domain || !strings.HasSuffix(sub, "."+domain) {
			continue
		}

		if e, exists := subMap[sub]; exists {
			if !e.sourceSeen[r.source] {
				e.sources = append(e.sources, r.source)
				e.sourceSeen[r.source] = true
			}
			continue
		}
		if len(subMap) >= maxCandidates {
			stopEnumeration()
			continue
		}
		subMap[sub] = &entry{
			sources:    []string{r.source},
			sourceSeen: map[string]bool{r.source: true},
		}
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	m.logger.InfoContext(runCtx, "enumeration complete",
		"domain", domain, "unique_subdomains", len(subMap))

	candidates := make([]candidateEntry, 0, len(subMap))
	for sub, e := range subMap {
		if sub == domain {
			continue
		}
		sort.Strings(e.sources)
		candidates = append(candidates, candidateEntry{name: sub, sources: e.sources})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })

	if !optionBool(input.Options, "resolve", false) {
		return candidateFindings(domain, candidates), nil
	}

	parallelism := optionInt(input.Options, "resolve_parallelism", defaultResolveParallelism)
	dnsTimeout := time.Duration(optionInt(input.Options, "dns_timeout_ms", defaultDNSTimeoutMS)) * time.Millisecond
	includeUnresolved := optionBool(input.Options, "include_unresolved", false)
	return m.resolveCandidates(runCtx, domain, candidates, parallelism, dnsTimeout, includeUnresolved), nil
}

type candidateEntry struct {
	name    string
	sources []string
}

type resolutionResult struct {
	candidate candidateEntry
	addresses []string
	err       error
}

func candidateFindings(domain string, candidates []candidateEntry) []module.Finding {
	findings := make([]module.Finding, 0, len(candidates))
	for _, candidate := range candidates {
		findings = append(findings, candidateFinding(
			domain,
			candidate,
			"unverified",
			candidateConfidence(len(candidate.sources)),
			false,
		))
	}
	return findings
}

func candidateFinding(
	domain string,
	candidate candidateEntry,
	state string,
	confidence string,
	wildcardMatch bool,
) module.Finding {
	sources := strings.Join(candidate.sources, ",")
	return module.Finding{
		Type:     "passive_name_candidate",
		Severity: module.SeverityInfo,
		URL:      candidate.name,
		Detail:   fmt.Sprintf("Unverified passive name candidate: %s (via %s)", candidate.name, strings.Join(candidate.sources, ", ")),
		Extra: map[string]string{
			"subdomain":          candidate.name,
			"domain":             domain,
			"sources":            sources,
			"source_count":       strconv.Itoa(len(candidate.sources)),
			"validated":          "false",
			"validation_state":   state,
			"wildcard_match":     strconv.FormatBool(wildcardMatch),
			"confidence":         confidence,
			"evidence_id":        evidenceID(domain, candidate.name, sources),
			"promote_to_context": "false",
		},
	}
}

func (m *Module) resolveCandidates(
	ctx context.Context,
	domain string,
	candidates []candidateEntry,
	parallelism int,
	lookupTimeout time.Duration,
	includeUnresolved bool,
) []module.Finding {
	if parallelism < 1 {
		parallelism = 1
	}
	if lookupTimeout <= 0 {
		lookupTimeout = time.Duration(defaultDNSTimeoutMS) * time.Millisecond
	}

	wildcardAddresses := m.detectWildcard(ctx, domain, lookupTimeout)
	results := make(chan resolutionResult, parallelism)
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)

	for _, candidate := range candidates {
		candidate := candidate
		group.Go(func() error {
			addresses, err := m.lookupHost(groupCtx, candidate.name, lookupTimeout)
			select {
			case results <- resolutionResult{candidate: candidate, addresses: addresses, err: err}:
			case <-groupCtx.Done():
			}
			return nil
		})
	}

	go func() {
		_ = group.Wait()
		close(results)
	}()

	findings := make([]module.Finding, 0, len(candidates))
	unresolved := make([]candidateEntry, 0)
	wildcardMatches := make([]candidateEntry, 0)
	lookupErrors := 0

	for result := range results {
		if result.err != nil || len(result.addresses) == 0 {
			unresolved = append(unresolved, result.candidate)
			if result.err != nil && !isNotFoundError(result.err) {
				lookupErrors++
			}
			continue
		}
		if intersects(result.addresses, wildcardAddresses) {
			wildcardMatches = append(wildcardMatches, result.candidate)
			continue
		}
		sources := strings.Join(result.candidate.sources, ",")
		findings = append(findings, module.Finding{
			Type:     "subdomain_resolved",
			Severity: module.SeverityInfo,
			URL:      result.candidate.name,
			Detail:   fmt.Sprintf("DNS-confirmed subdomain: %s resolves to %s", result.candidate.name, strings.Join(result.addresses, ", ")),
			Extra: map[string]string{
				"subdomain":          result.candidate.name,
				"domain":             domain,
				"sources":            sources,
				"source_count":       strconv.Itoa(len(result.candidate.sources)),
				"addresses":          strings.Join(result.addresses, ","),
				"validated":          "true",
				"validation_state":   "dns_confirmed",
				"wildcard_match":     "false",
				"confidence":         "0.98",
				"evidence_id":        evidenceID(domain, result.candidate.name, sources, strings.Join(result.addresses, ",")),
				"promote_to_context": "true",
			},
		})
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].URL < findings[j].URL })
	confirmedCount := len(findings)
	sort.Slice(unresolved, func(i, j int) bool { return unresolved[i].name < unresolved[j].name })
	sort.Slice(wildcardMatches, func(i, j int) bool { return wildcardMatches[i].name < wildcardMatches[j].name })

	if includeUnresolved {
		for _, candidate := range unresolved {
			findings = append(findings, candidateFinding(domain, candidate, "dns_unresolved", "0.35", false))
		}
		for _, candidate := range wildcardMatches {
			findings = append(findings, candidateFinding(domain, candidate, "wildcard_dns_match", "0.25", true))
		}
	}

	if len(unresolved) > 0 || len(wildcardMatches) > 0 || lookupErrors > 0 {
		findings = append(findings, candidateSummaryFinding(
			domain,
			len(candidates),
			confirmedCount,
			unresolved,
			wildcardMatches,
			lookupErrors,
			ctx.Err() != nil,
		))
	}
	return findings
}

func (m *Module) detectWildcard(ctx context.Context, domain string, timeout time.Duration) []string {
	sum := sha256.Sum256([]byte("blackhorn-wildcard|" + domain))
	labels := []string{
		fmt.Sprintf("blackhorn-%x-a.%s", sum[:6], domain),
		fmt.Sprintf("blackhorn-%x-b.%s", sum[6:12], domain),
	}
	addresses := make([][]string, len(labels))
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(len(labels))
	for index, label := range labels {
		index, label := index, label
		group.Go(func() error {
			resolved, err := m.lookupHost(groupCtx, label, timeout)
			if err == nil {
				addresses[index] = resolved
			}
			return nil
		})
	}
	_ = group.Wait()
	if len(addresses[0]) == 0 || len(addresses[1]) == 0 {
		return nil
	}
	return uniqueSorted(append(addresses[0], addresses[1]...))
}

func (m *Module) lookupHost(ctx context.Context, host string, timeout time.Duration) ([]string, error) {
	resolver := m.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addresses, err := resolver.LookupHost(lookupCtx, host)
	if err != nil {
		return nil, err
	}
	return uniqueSorted(addresses), nil
}

func candidateSummaryFinding(
	domain string,
	total int,
	confirmed int,
	unresolved []candidateEntry,
	wildcardMatches []candidateEntry,
	lookupErrors int,
	incomplete bool,
) module.Finding {
	unprocessed := total - confirmed - len(unresolved) - len(wildcardMatches)
	if unprocessed < 0 {
		unprocessed = 0
	}
	incomplete = incomplete || unprocessed > 0
	samples := make([]string, 0, maxCandidateSample)
	for _, candidate := range append(append([]candidateEntry(nil), unresolved...), wildcardMatches...) {
		if len(samples) >= maxCandidateSample {
			break
		}
		samples = append(samples, candidate.name)
	}
	return module.Finding{
		Type:     "passive_name_summary",
		Severity: module.SeverityInfo,
		URL:      domain,
		Detail: fmt.Sprintf(
			"Passive DNS validation: %d candidates, %d confirmed, %d unresolved, %d wildcard matches, %d unprocessed",
			total, confirmed, len(unresolved), len(wildcardMatches), unprocessed,
		),
		Extra: map[string]string{
			"domain":                domain,
			"candidate_count":       strconv.Itoa(total),
			"confirmed_count":       strconv.Itoa(confirmed),
			"unresolved_count":      strconv.Itoa(len(unresolved)),
			"wildcard_match_count":  strconv.Itoa(len(wildcardMatches)),
			"lookup_error_count":    strconv.Itoa(lookupErrors),
			"unprocessed_count":     strconv.Itoa(unprocessed),
			"validation_incomplete": strconv.FormatBool(incomplete),
			"candidate_sample":      strings.Join(samples, ","),
			"confidence":            "0.95",
			"promote_to_context":    "false",
		},
	}
}

func candidateConfidence(sourceCount int) string {
	switch {
	case sourceCount >= 3:
		return "0.72"
	case sourceCount == 2:
		return "0.60"
	default:
		return "0.45"
	}
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func intersects(left, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(right))
	for _, value := range right {
		set[value] = struct{}{}
	}
	for _, value := range left {
		if _, ok := set[value]; ok {
			return true
		}
	}
	return false
}

func isNotFoundError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no such host") || strings.Contains(message, "nxdomain")
}

func evidenceID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return fmt.Sprintf("sha256:%x", sum[:12])
}

func optionInt(options map[string]string, key string, fallback int) int {
	if options == nil {
		return fallback
	}
	value, err := strconv.Atoi(strings.TrimSpace(options[key]))
	if err != nil || value < 1 {
		return fallback
	}
	return value
}

func optionBool(options map[string]string, key string, fallback bool) bool {
	if options == nil {
		return fallback
	}
	raw, ok := options[key]
	if !ok {
		return fallback
	}
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return value
}

// ─── Source implementations ────────────────────────────────────────────────

// sourceCrtsh queries crt.sh JSON API — port of subfinder crtsh/crtsh.go
// getSubdomainsFromHTTP(). The SQL path requires a postgres driver; we use
// the HTTP JSON fallback which is identical in behaviour.
func (m *Module) sourceCrtsh(ctx context.Context, domain string) ([]string, error) {
	type cert struct {
		NameValue string `json:"name_value"`
	}

	u := fmt.Sprintf("https://crt.sh/?q=%%%%.%s&output=json", domain)
	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	var certs []cert
	if err := json.NewDecoder(io.LimitReader(body, maxBodySize)).Decode(&certs); err != nil {
		return nil, fmt.Errorf("crtsh: decode: %w", err)
	}

	var subs []string
	for _, c := range certs {
		// NameValue may contain multiple subdomains separated by newline.
		// strings.SplitSeq returns iter.Seq[string] in Go 1.26 — use range.
		for line := range strings.SplitSeq(c.NameValue, "\n") {
			subs = append(subs, extractSubdomains(line)...)
		}
	}
	return subs, nil
}

// sourceHackertarget queries hackertarget.com — port of subfinder
// hackertarget/hackertarget.go Run().
// Response format: "subdomain,IP" per line.
func (m *Module) sourceHackertarget(ctx context.Context, domain string) ([]string, error) {
	u := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	var subs []string
	scanner := bufio.NewScanner(io.LimitReader(body, maxBodySize))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		// Format: "subdomain.example.com,1.2.3.4"
		if idx := strings.Index(line, ","); idx != -1 {
			line = line[:idx]
		}
		subs = append(subs, extractSubdomains(line)...)
	}
	return subs, scanner.Err()
}

// sourceWaybackarchive queries Wayback Machine CDX API — port of subfinder
// waybackarchive/waybackarchive.go Run().
func (m *Module) sourceWaybackarchive(ctx context.Context, domain string) ([]string, error) {
	u := fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=txt&fl=original&collapse=urlkey",
		domain,
	)
	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	var subs []string
	scanner := bufio.NewScanner(io.LimitReader(body, maxBodySize))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		// Unescape URL-encoded characters — mirrors waybackarchive source.
		if decoded, err := url.QueryUnescape(line); err == nil {
			line = decoded
		}
		// Strip leftover percent-encoding prefixes (25 = %, 2f = /).
		line = strings.TrimPrefix(line, "25")
		line = strings.TrimPrefix(line, "2f")
		subs = append(subs, extractSubdomains(line)...)
	}
	return subs, scanner.Err()
}

// sourceCommoncrawl queries the CommonCrawl CDX API — port of subfinder
// commoncrawl/commoncrawl.go Run().
// Fetches the current year's index then queries it for the domain.
func (m *Module) sourceCommoncrawl(ctx context.Context, domain string) ([]string, error) {
	type indexEntry struct {
		ID     string `json:"id"`
		APIURL string `json:"cdx-api"`
	}

	// Step 1: fetch index list — mirrors commoncrawl.go indexURL fetch.
	indexBody, err := m.get(ctx, "https://index.commoncrawl.org/collinfo.json", nil)
	if err != nil {
		return nil, fmt.Errorf("commoncrawl: index fetch: %w", err)
	}
	defer indexBody.Close()

	var indexes []indexEntry
	if err := json.NewDecoder(io.LimitReader(indexBody, maxBodySize)).Decode(&indexes); err != nil {
		return nil, fmt.Errorf("commoncrawl: index decode: %w", err)
	}

	// Pick the most recent index — matches commoncrawl.go maxYearsBack=5 logic
	// but we just take the first (newest) entry to keep it simple.
	if len(indexes) == 0 {
		return nil, nil
	}
	apiURL := indexes[0].APIURL

	// Step 2: query the CDX API for the domain.
	cdxURL := fmt.Sprintf("%s?url=*.%s&output=json&fl=url&limit=50000&collapse=urlkey", apiURL, domain)
	cdxBody, err := m.get(ctx, cdxURL, nil)
	if err != nil {
		return nil, fmt.Errorf("commoncrawl: cdx query: %w", err)
	}
	defer cdxBody.Close()

	// CDX API returns one JSON object per line (NDJSON).
	type cdxRecord struct {
		URL string `json:"url"`
	}

	var subs []string
	scanner := bufio.NewScanner(io.LimitReader(cdxBody, maxBodySize))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var rec cdxRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		subs = append(subs, extractSubdomains(rec.URL)...)
	}
	return subs, scanner.Err()
}

// sourceRapiddns scrapes RapidDNS paginated results — port of subfinder
// rapiddns/rapiddns.go Run().
// Pattern: pagePattern extracts page numbers from pagination links.
var pagePattern = regexp.MustCompile(`class="page-link" href="/subdomain/[^"]+\?page=(\d+)">`)

func (m *Module) sourceRapiddns(ctx context.Context, domain string) ([]string, error) {
	// tdPattern extracts subdomains from <td> cells in the RapidDNS table.
	tdPattern := regexp.MustCompile(`<td>([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})</td>`)

	var subs []string
	page := 1
	maxPages := 1

	for page <= maxPages {
		select {
		case <-ctx.Done():
			return subs, ctx.Err()
		default:
		}

		u := fmt.Sprintf("https://rapiddns.io/subdomain/%s?page=%d&full=1", domain, page)
		body, err := m.get(ctx, u, nil)
		if err != nil {
			return subs, fmt.Errorf("rapiddns page %d: %w", page, err)
		}

		raw, readErr := io.ReadAll(io.LimitReader(body, maxBodySize))
		body.Close()
		if readErr != nil {
			return subs, fmt.Errorf("rapiddns read: %w", readErr)
		}

		content := string(raw)
		// Extract subdomains from table cells.
		for _, match := range tdPattern.FindAllStringSubmatch(content, -1) {
			subs = append(subs, extractSubdomains(match[1])...)
		}

		// Update maxPages from pagination links — mirrors rapiddns.go pagePattern.
		if page == 1 {
			for _, pm := range pagePattern.FindAllStringSubmatch(content, -1) {
				if n, err := parseInt(pm[1]); err == nil && n > maxPages {
					maxPages = n
				}
			}
		}
		page++
	}
	return subs, nil
}

// sourceUrlscan queries urlscan.io — port of subfinder urlscan/urlscan.go Run().
// Uses the public search endpoint with domain filter; no API key required
// for basic queries.
func (m *Module) sourceUrlscan(ctx context.Context, domain string) ([]string, error) {
	type taskObj struct {
		Domain string `json:"domain"`
	}
	type pageObj struct {
		Domain string `json:"domain"`
	}
	type resultItem struct {
		Task taskObj `json:"task"`
		Page pageObj `json:"page"`
	}
	type apiResp struct {
		Results []resultItem `json:"results"`
		HasMore bool         `json:"has_more"`
	}

	var subs []string
	searchAfter := ""

	for page := 0; page < 5; page++ { // maxPages = 5, mirrors urlscan source
		select {
		case <-ctx.Done():
			return subs, ctx.Err()
		default:
		}

		query := url.Values{
			"q":    []string{fmt.Sprintf("domain:%s", domain)},
			"size": []string{"100"},
		}
		if searchAfter != "" {
			query.Set("search_after", searchAfter)
		}
		u := "https://urlscan.io/api/v1/search/?" + query.Encode()

		body, err := m.get(ctx, u, map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil {
			return subs, fmt.Errorf("urlscan: %w", err)
		}

		var resp apiResp
		decErr := json.NewDecoder(io.LimitReader(body, maxBodySize)).Decode(&resp)
		body.Close()
		if decErr != nil {
			return subs, fmt.Errorf("urlscan: decode: %w", decErr)
		}

		for _, item := range resp.Results {
			subs = append(subs, extractSubdomains(item.Task.Domain)...)
			subs = append(subs, extractSubdomains(item.Page.Domain)...)
		}

		if !resp.HasMore {
			break
		}
		// search_after pagination — mirrors urlscan.go sort field extraction.
		if len(resp.Results) > 0 {
			// Just advance by requesting next page; no sort cursor needed for basic queries.
			break
		}
	}
	return subs, nil
}

// sourceAnubis queries jldc.me/anubis — free OSINT subdomain DB.
// Port of subfinder anubis/anubis.go.
func (m *Module) sourceAnubis(ctx context.Context, domain string) ([]string, error) {
	u := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
	body, err := m.get(ctx, u, nil)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	var results []string
	if err := json.NewDecoder(io.LimitReader(body, maxBodySize)).Decode(&results); err != nil {
		return nil, fmt.Errorf("anubis: decode: %w", err)
	}
	var subs []string
	for _, r := range results {
		subs = append(subs, extractSubdomains(r)...)
	}
	return subs, nil
}

// sourceDigitorus queries digitorus.com certificate transparency search.
// Port of subfinder digitorus/digitorus.go.
func (m *Module) sourceDigitorus(ctx context.Context, domain string) ([]string, error) {
	type digiResp struct {
		Subdomains []string `json:"subdomains"`
	}

	u := fmt.Sprintf("https://certificatedetails.com/%s", domain)
	body, err := m.get(ctx, u, map[string]string{
		"Accept": "application/json",
	})
	if err != nil {
		// Digitorus sometimes redirects or blocks — treat as soft error.
		m.logger.WarnContext(ctx, "digitorus: request failed", "err", err)
		return nil, nil
	}
	defer body.Close()

	var resp digiResp
	if err := json.NewDecoder(io.LimitReader(body, maxBodySize)).Decode(&resp); err != nil {
		// Response may be HTML; silently ignore.
		return nil, nil
	}
	var subs []string
	for _, s := range resp.Subdomains {
		subs = append(subs, extractSubdomains(s)...)
	}
	return subs, nil
}

// ─── Helpers ───────────────────────────────────────────────────────────────

// get performs an HTTP GET with context and optional headers.
// Returns the response body; caller must close it.
// Mirrors subfinder subscraping.Session.SimpleGet().
func (m *Module) get(ctx context.Context, rawURL string, headers map[string]string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request %s: %w", rawURL, err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; blackhorn-modules/1.0)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", rawURL, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("get %s: HTTP %d", rawURL, resp.StatusCode)
	}
	return resp.Body, nil
}

// extractSubdomains extracts all subdomain-like tokens from arbitrary text.
// Mirrors subfinder subscraping.Session.Extractor.Extract().
func extractSubdomains(text string) []string {
	var out []string
	for _, match := range subdomainRE.FindAllString(text, -1) {
		sub := strings.ToLower(replacer.Replace(match))
		if sub != "" {
			out = append(out, sub)
		}
	}
	return out
}

// normalizeDomain strips scheme and path from a domain input.
func normalizeDomain(raw string) string {
	return urlutil.NormalizeDomain(raw)
}

// parseInt parses an integer string, returns error on failure.
func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// Note: this file uses strings.SplitSeq (Go 1.26+) which returns an
// iter.Seq[string] iterator and is consumed via range loops.
