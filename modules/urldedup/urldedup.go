// Package urldedup reduces a large URL set to a minimal representative subset.
//
// Ported from s0md3v/uro (GPL-3.0 — logic reimplemented independently in Go).
// Original: https://github.com/s0md3v/uro
// Reference used for algorithm only; no source code copied.
//
// Deduplication strategy (mirrors uro exactly):
//  1. Static extensions (css, png, jpg, …) are dropped by default.
//  2. Paths with integer segments are collapsed to a single pattern
//     (e.g. /user/123/profile and /user/456/profile → one entry).
//  3. Two URLs with the same path but different param keys → kept separately.
//  4. Two URLs with the same path+param-keys but different values → one kept
//     (unless a new key not seen before is introduced).
//  5. Content-style paths (blog posts, docs with lots of hyphens) are dropped.
package urldedup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/urlutil"
)

const moduleName = "urldedup"

const (
	defaultMaxInputs  = 10000
	defaultMaxResults = 2000
)

// defaultDropExts mirrors uro's default blacklist.
var defaultDropExts = map[string]bool{
	"css": true, "png": true, "jpg": true, "jpeg": true, "svg": true,
	"ico": true, "webp": true, "scss": true, "tif": true, "tiff": true,
	"ttf": true, "otf": true, "woff": true, "woff2": true, "gif": true,
	"pdf": true, "bmp": true, "eot": true, "mp3": true, "mp4": true,
	"avi": true,
}

// reInt matches a path segment that is purely numeric, optionally followed
// by ? or / or end-of-string — same regex as uro: r'/\d+([?/]|$)'
var reInt = regexp.MustCompile(`/\d+([?/]|$)`)

// contentPattern detects "content" URLs (blog posts, docs) — uro heuristic:
// a path segment with more than 3 hyphens is likely a slug.
var reSlug = regexp.MustCompile(`[^/]+-[^/]+-[^/]+-[^/]+-[^/]+`)

// Module implements module.Module for URL deduplication.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }

// Run deduplicates input.URLs using the uro algorithm.
// Returns one non-promoting candidate per kept URL.
//
// Supported options:
//   - "drop_exts":  comma-separated extensions to drop (default: uro's list)
//   - "keep_exts":  comma-separated extensions to keep (overrides drop_exts)
//   - "keep_content": "true" to keep content-style URLs (default: drop them)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	urls := input.URLs
	if len(urls) == 0 && input.Target != "" {
		urls = []string{input.Target}
	}
	if len(urls) == 0 {
		return nil, errors.New("urldedup: no URLs provided")
	}

	dropExts := buildDropExts(input.Options)
	keepContent := optBool(input.Options, "keep_content", false)
	maxInputs := clampInt(optInt(input.Options, "max_inputs", defaultMaxInputs), 1, 50000)
	maxResults := clampInt(optInt(input.Options, "max_results", defaultMaxResults), 1, 10000)
	slog.Debug("urldedup: starting", "urls", len(urls), "keep_content", keepContent)

	normalized := make([]string, 0, min(len(urls), maxInputs))
	seenInputs := make(map[string]struct{}, min(len(urls), maxInputs))
	for _, raw := range urls {
		u, err := parseURL(strings.TrimRight(strings.TrimSpace(raw), "/"))
		if err != nil {
			continue
		}
		canonical := u.String()
		if _, exists := seenInputs[canonical]; exists {
			continue
		}
		seenInputs[canonical] = struct{}{}
		normalized = append(normalized, canonical)
		if len(normalized) >= maxInputs {
			break
		}
	}
	sort.Strings(normalized)

	// urlmap[host][path] = []map[string]string  — mirrors uro's urlmap dict
	type paramSet = map[string]string
	urlmap := make(map[string]map[string][]paramSet)

	// paramsSeen tracks all param keys ever seen across all URLs — uro behaviour
	paramsSeen := make(map[string]bool)

	// patternsSeen tracks integer-collapsed path patterns — uro behaviour
	patternsSeen := make(map[string]bool)

	for _, raw := range normalized {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("urldedup: canceled: %w", err)
		}
		u, err := parseURL(raw)
		if err != nil {
			continue
		}

		host := u.Scheme + "://" + u.Host
		path := u.Path
		params := queryToMap(u.RawQuery)

		// --- filter: drop static extensions ---
		ext := pathExt(path)
		if !shouldKeep(ext, dropExts) {
			continue
		}

		// --- filter: drop content-style paths ---
		if !keepContent && isContentPath(path) {
			continue
		}

		if urlmap[host] == nil {
			urlmap[host] = make(map[string][]map[string]string)
		}

		// --- new params introduced by this URL ---
		var newParams []string
		for k := range params {
			if !paramsSeen[k] {
				newParams = append(newParams, k)
			}
		}

		// --- integer path collapsing (uro: create_pattern) ---
		if reInt.MatchString(path) {
			pattern := intPattern(path)
			if patternsSeen[pattern] {
				continue
			}
			patternsSeen[pattern] = true
		}

		// --- path-level dedup (uro: process_url logic) ---
		existing, pathSeen := urlmap[host][path]
		if !pathSeen {
			// first time we see this path
			urlmap[host][path] = []map[string]string{}
			if len(params) > 0 {
				urlmap[host][path] = append(urlmap[host][path], params)
			}
			for _, k := range newParams {
				paramsSeen[k] = true
			}
			continue
		}

		// path already seen — only keep if new param keys are introduced
		// or the combination of keys hasn't been seen yet
		if len(newParams) > 0 {
			urlmap[host][path] = append(existing, params)
			for _, k := range newParams {
				paramsSeen[k] = true
			}
		} else if len(params) > 0 && !paramCombSeen(existing, params) {
			urlmap[host][path] = append(existing, params)
		}
		// else: pure duplicate → drop
	}

	// --- build findings from urlmap (mirrors uro's output loop) ---
	var findings []module.Finding
	hosts := make([]string, 0, len(urlmap))
	for host := range urlmap {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		paths := urlmap[host]
		// sort for deterministic output
		sortedPaths := make([]string, 0, len(paths))
		for p := range paths {
			sortedPaths = append(sortedPaths, p)
		}
		sort.Strings(sortedPaths)

		for _, path := range sortedPaths {
			if len(findings) >= maxResults {
				return findings, nil
			}
			paramSets := paths[path]
			if len(paramSets) == 0 {
				finalURL := host + path
				findings = append(findings, finding(finalURL, path, ""))
			} else {
				for _, ps := range paramSets {
					if len(findings) >= maxResults {
						return findings, nil
					}
					finalURL := host + path + mapToQuery(ps)
					findings = append(findings, finding(finalURL, path, mapToQuery(ps)))
				}
			}
		}
	}
	return findings, nil
}

// --- helpers ---

func finding(rawURL, path, query string) module.Finding {
	detail := fmt.Sprintf("unique path: %s", path)
	if query != "" {
		detail += " " + query
	}
	return module.Finding{
		Type:     "deduplicated_url_candidate",
		URL:      rawURL,
		Detail:   detail,
		Severity: module.SeverityInfo,
		Extra: map[string]string{
			"confidence":         "0.80",
			"validated":          "false",
			"validation_state":   "syntactic_deduplication_only",
			"promote_to_context": "false",
		},
	}
}

func parseURL(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	canonical, ok := urlutil.CanonicalHTTP(raw)
	if !ok {
		return nil, fmt.Errorf("invalid HTTP URL")
	}
	return url.Parse(canonical)
}

func queryToMap(rawQuery string) map[string]string {
	m := make(map[string]string)
	if rawQuery == "" {
		return m
	}
	for _, pair := range strings.Split(rawQuery, "&") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 && parts[0] != "" {
			m[parts[0]] = parts[1]
		}
	}
	return m
}

func mapToQuery(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return "?" + strings.Join(parts, "&")
}

func pathExt(path string) string {
	segments := strings.Split(path, "/")
	last := segments[len(segments)-1]
	if i := strings.LastIndex(last, "."); i >= 0 {
		return strings.ToLower(last[i+1:])
	}
	return ""
}

func shouldKeep(ext string, dropExts map[string]bool) bool {
	if ext == "" {
		return true
	}
	return !dropExts[ext]
}

func isContentPath(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if reSlug.MatchString(seg) {
			return true
		}
	}
	return false
}

// intPattern collapses integer segments to \d+ — mirrors uro's create_pattern.
func intPattern(path string) string {
	parts := strings.Split(path, "/")
	lastInt := 0
	for i, p := range parts {
		if isDigits(p) {
			lastInt = i
			parts[i] = `\d+`
		}
	}
	return strings.Join(parts[:lastInt+1], "/")
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// paramCombSeen returns true if the same set of param keys already appears
// in existing (regardless of values) — mirrors uro's compare_params logic.
func paramCombSeen(existing []map[string]string, candidate map[string]string) bool {
	candKeys := sortedKeys(candidate)
	for _, ps := range existing {
		if strings.Join(sortedKeys(ps), ",") == strings.Join(candKeys, ",") {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func buildDropExts(opts map[string]string) map[string]bool {
	if opts == nil {
		return defaultDropExts
	}
	if keep, ok := opts["keep_exts"]; ok && keep != "" {
		drop := make(map[string]bool)
		for k, v := range defaultDropExts {
			drop[k] = v
		}
		for _, ext := range strings.Split(keep, ",") {
			delete(drop, strings.TrimSpace(strings.ToLower(ext)))
		}
		return drop
	}
	if custom, ok := opts["drop_exts"]; ok && custom != "" {
		drop := make(map[string]bool)
		for _, ext := range strings.Split(custom, ",") {
			drop[strings.TrimSpace(strings.ToLower(ext))] = true
		}
		return drop
	}
	return defaultDropExts
}

func optInt(opts map[string]string, key string, fallback int) int {
	if opts == nil {
		return fallback
	}
	value, err := strconv.Atoi(strings.TrimSpace(opts[key]))
	if err != nil {
		return fallback
	}
	return value
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
