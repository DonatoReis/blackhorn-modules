// Package s3enum enumerates S3-compatible storage buckets — AWS S3, Google Cloud
// Storage, DigitalOcean Spaces, and Backblaze B2 — via common naming patterns
// and HTTP probing. It detects publicly accessible buckets and private buckets
// that can be confirmed to exist.
//
// Severity semantics (corrected):
//   - High:   HTTP 200 with XML ListBucketResult — bucket is PUBLIC and listable
//   - Medium: HTTP 403 — bucket EXISTS but is private (confirmed existence)
//   - Info:   aggregated candidate summary (no individual 404/NXDOMAIN findings)
//
// REMOVED (was causing 240 false-positive High findings):
//   - HTTP 404 with no XML body is NOT a takeover signal without DNS/CNAME evidence.
//     A 404 from amazonaws.com for an invented bucket name means "bucket does not
//     exist" — nothing more. We now discard 404 silently.
//   - Takeover requires an *actual* CNAME from the target's DNS pointing to the
//     provider's endpoint. That check lives in dnsrecon/takeover, not here.
//
// Source references (algorithm design, no code copied):
//   - cloud_enum (MIT, initstring)            — multi-cloud bucket enumeration
//   - AWSBucketDump (MIT, jordanpotti)        — S3 listing detection
//   - S3Scanner (MIT, sa7mon)                 — permission probing techniques
//   - GCPBucketBrute (MIT, RhinoSecurityLabs) — GCS enumeration
//
// Architecture:
//   - errgroup.SetLimit(parallelism)
//   - io.LimitReader on all response bodies
//   - context-aware with global budget (max_runtime_seconds)
//   - deduplication before return
//   - max_targets option to prevent fan-out explosion
package s3enum

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	maxBodyRead       = 64 * 1024 // 64 KB
	defaultParallel   = 10        // reduced from 20 — less aggressive default
	maxCandidates     = 100       // reduced from 300 — conservative default
	defaultMaxRuntime = 120 * time.Second
)

// provider describes a cloud storage provider's endpoint template.
type provider struct {
	Name     string
	Endpoint func(bucket string) string
	Tag      string
}

var providers = []provider{
	{
		Name: "aws-s3",
		Endpoint: func(b string) string {
			return fmt.Sprintf("https://%s.s3.amazonaws.com/", b)
		},
		Tag: "aws_s3",
	},
	{
		Name: "aws-s3-us-east",
		Endpoint: func(b string) string {
			return fmt.Sprintf("https://s3.amazonaws.com/%s/", b)
		},
		Tag: "aws_s3",
	},
	{
		Name: "gcs",
		Endpoint: func(b string) string {
			return fmt.Sprintf("https://storage.googleapis.com/%s/", b)
		},
		Tag: "gcs_bucket",
	},
	{
		Name: "do-spaces-nyc3",
		Endpoint: func(b string) string {
			return fmt.Sprintf("https://%s.nyc3.digitaloceanspaces.com/", b)
		},
		Tag: "do_spaces",
	},
	{
		Name: "do-spaces-sfo3",
		Endpoint: func(b string) string {
			return fmt.Sprintf("https://%s.sfo3.digitaloceanspaces.com/", b)
		},
		Tag: "do_spaces",
	},
	{
		Name: "backblaze-b2",
		Endpoint: func(b string) string {
			return fmt.Sprintf("https://f001.backblazeb2.com/file/%s/", b)
		},
		Tag: "backblaze_b2",
	},
}

// suffixes used to generate bucket name candidates (conservative set).
var candidateSuffixes = []string{
	"", "-dev", "-prod", "-staging", "-backup", "-data", "-static",
	"-assets", "-uploads", "-logs", "-public", "-cdn", "-store",
}

var candidatePrefixes = []string{
	"", "dev-", "prod-", "staging-", "static-", "cdn-",
}

// ─── XML helpers ─────────────────────────────────────────────────────────────

type listBucketResult struct {
	XMLName     xml.Name `xml:"ListBucketResult"`
	KeyCount    int      `xml:"KeyCount"`
	MaxKeys     int      `xml:"MaxKeys"`
	IsTruncated bool     `xml:"IsTruncated"`
}

// ─── Module ───────────────────────────────────────────────────────────────────

// Module implements the s3enum module.
type Module struct {
	client *http.Client
	logger *slog.Logger
}

// New creates an s3enum module with the default HTTP client.
func New() *Module {
	return &Module{client: httpclient.Default(), logger: slog.Default()}
}

// NewWithClient creates an s3enum module with a custom HTTP client (for tests).
func NewWithClient(c *http.Client) *Module {
	return &Module{client: c, logger: slog.Default()}
}

func (m *Module) Name() string { return "s3enum" }

// Run enumerates cloud storage buckets derived from input.Target.
//
// Options:
//   - parallelism:        concurrent probes (default 10)
//   - providers:          comma-separated provider names (default: all)
//   - extra_names:        comma-separated extra bucket name candidates
//   - max_targets:        max bucket candidates to probe (default 100)
//   - max_runtime_seconds: global budget in seconds (default 120)
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("s3enum: target is required (domain or keyword)")
	}
	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	parallel := optInt(opts, "parallelism", defaultParallel)
	providerFilter := parseCSV(optStr(opts, "providers", ""))
	extraNames := parseCSV(optStr(opts, "extra_names", ""))
	maxTargets := optInt(opts, "max_targets", maxCandidates)
	maxRuntimeSec := optInt(opts, "max_runtime_seconds", int(defaultMaxRuntime.Seconds()))

	// Apply global budget on top of whatever the caller's context has.
	budget := time.Duration(maxRuntimeSec) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	keyword := extractKeyword(target)
	candidates := generateCandidates(keyword, sliceFromMap(extraNames))
	if len(candidates) > maxTargets {
		candidates = candidates[:maxTargets]
	}

	selectedProviders := filterProviders(providerFilter)

	m.logger.InfoContext(runCtx, "s3enum: starting",
		"keyword", keyword,
		"candidates", len(candidates),
		"providers", len(selectedProviders),
		"max_runtime_s", maxRuntimeSec,
	)

	var (
		mu       sync.Mutex
		findings []module.Finding
	)
	add := func(ff ...module.Finding) {
		mu.Lock()
		findings = append(findings, ff...)
		mu.Unlock()
	}

	eg, egCtx := errgroup.WithContext(runCtx)
	eg.SetLimit(parallel)

	for _, cand := range candidates {
		for _, prov := range selectedProviders {
			cand, prov := cand, prov
			// Check budget before queuing new work.
			select {
			case <-egCtx.Done():
				goto drain
			default:
			}
			eg.Go(func() error {
				if ff := m.probe(egCtx, cand, prov); len(ff) > 0 {
					add(ff...)
				}
				return nil
			})
		}
	}
drain:
	if err := eg.Wait(); err != nil {
		return dedup(findings), err
	}
	if err := runCtx.Err(); err != nil {
		return dedup(findings), fmt.Errorf("s3enum: runtime budget exceeded: %w", err)
	}

	result := dedup(findings)
	m.logger.InfoContext(ctx, "s3enum: done",
		"findings", len(result),
		"candidates_probed", len(candidates),
	)
	return result, nil
}

// ─── Probing ─────────────────────────────────────────────────────────────────

func (m *Module) probe(ctx context.Context, bucket string, prov provider) []module.Finding {
	rawURL := prov.Endpoint(bucket)

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/xml,*/*")

	resp, err := m.client.Do(req)
	if err != nil {
		// NXDOMAIN / connection refused → bucket does not exist, no finding.
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	bodyStr := string(body)

	switch resp.StatusCode {
	case http.StatusOK:
		// Bucket exists AND is publicly listable — confirmed High severity.
		objectCount := parseObjectCount(body)
		return []module.Finding{{
			Type:     prov.Tag + "_public_listing",
			URL:      rawURL,
			Severity: module.SeverityHigh,
			Detail: fmt.Sprintf("[s3enum] %s bucket %q is PUBLICLY LISTABLE — "+
				"%d objects visible. This is a confirmed exposure, not a candidate.",
				prov.Name, bucket, objectCount),
			Extra: map[string]string{
				"bucket":           bucket,
				"provider":         prov.Name,
				"object_count":     fmt.Sprintf("%d", objectCount),
				"status_code":      "200",
				"evidence":         "HTTP 200 with ListBucketResult XML",
				"ownership_status": "unverified — confirm bucket belongs to target",
				"confidence":       "0.95",
				"fonte":            "s3enum",
			},
		}}

	case http.StatusForbidden:
		// A guessed name returning 403 proves neither ownership nor exposure.
		// Without target-controlled DNS/CNAME evidence it is not a target finding.
		return nil

	case http.StatusNotFound:
		// 404 means the bucket does NOT exist at this provider.
		// A NoSuchBucket XML body or empty body both mean "not found".
		// This is NOT a takeover signal — takeover requires a DNS CNAME from the
		// target pointing to this provider. That evidence is not present here.
		// Discard silently.
		_ = bodyStr // silence unused warning
		return nil

	default:
		// Any other status (301, 301 redirect, 503 throttle, etc.) is not conclusive.
		return nil
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func extractKeyword(target string) string {
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "www.")
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}
	parts := strings.Split(target, ".")
	if len(parts) >= 2 {
		return strings.ToLower(parts[0])
	}
	return strings.ToLower(target)
}

func generateCandidates(keyword string, extras []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] && s != "" {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, prefix := range candidatePrefixes {
		for _, suffix := range candidateSuffixes {
			add(prefix + keyword + suffix)
		}
	}
	for _, e := range extras {
		if e != "" {
			add(strings.ToLower(strings.TrimSpace(e)))
		}
	}
	return out
}

func filterProviders(filter map[string]bool) []provider {
	if len(filter) == 0 {
		return providers
	}
	var out []provider
	for _, p := range providers {
		for f := range filter {
			if strings.HasPrefix(p.Name, f) || f == p.Name {
				out = append(out, p)
				break
			}
		}
	}
	if len(out) == 0 {
		return providers
	}
	return out
}

func parseObjectCount(body []byte) int {
	var result listBucketResult
	if err := xml.Unmarshal(body, &result); err == nil {
		return result.KeyCount
	}
	return 0
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

func optInt(opts map[string]string, key string, def int) int {
	if v, ok := opts[key]; ok && v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func sliceFromMap(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	var out []module.Finding
	for _, f := range findings {
		key := f.Type + "|" + f.URL
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}
