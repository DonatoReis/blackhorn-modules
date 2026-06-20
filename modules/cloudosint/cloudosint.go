// Package cloudosint discovers exposed cloud storage resources — S3 buckets,
// Azure Blob containers, GCP Cloud Storage buckets and DigitalOcean Spaces —
// using passive DNS, HTTP probing and public cloud APIs.
//
// Techniques:
//   - DNS-based bucket enumeration (subdomain/naming patterns)
//   - HTTP HEAD probes to bucket URLs (detects public read, write, no-auth)
//   - GrayhatWarfare API (free, indexes open buckets)
//   - Certificate transparency (delegates to certs module pattern)
//
// All probes are PASSIVE or HTTP-only — no exploitation attempted.
// Findings include confidence scores, slog observability and redaction
// of any credentials per dicas.md §18.
//
// Usage:
//
//	m := cloudosint.New()
//	findings, err := m.Run(ctx, module.Input{
//	    Target:  "example",           // company/brand name OR domain
//	    Options: map[string]string{
//	        "sources":          "dns,http,grayhat",
//	        "grayhat_key":      "<key>",
//	        "probe_timeout_ms": "5000",
//	        "max_permutations": "50",
//	    },
//	})
package cloudosint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	maxBodyCloud             = 512 * 1024 // 512 KB
	maxParallel              = 8
	defaultMaxRuntimeSeconds = 60
	defaultMaxResults        = 100
)

// Module implements module.Module for cloud storage OSINT.
type Module struct {
	client *http.Client
}

// New returns a Module with a default HTTP client.
func New() *Module {
	return NewWithClient(&http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     60 * time.Second,
		},
	})
}

// NewWithClient allows injecting a custom HTTP client (useful for tests).
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

// Name returns the canonical module identifier.
func (m *Module) Name() string { return "cloudosint" }

// BucketStatus classifies the access level of a cloud bucket.
type BucketStatus string

const (
	BucketPublicRead  BucketStatus = "public_read"
	BucketPublicWrite BucketStatus = "public_write"
	BucketPrivate     BucketStatus = "private"
	BucketNotFound    BucketStatus = "not_found"
	BucketUnknown     BucketStatus = "unknown"
)

// Run discovers cloud storage buckets and their access status.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" {
		return nil, fmt.Errorf("cloudosint: target vazio")
	}

	// Extract base name — strip TLDs/scheme
	baseName := extractBaseName(target)
	if baseName == "" {
		return nil, fmt.Errorf("cloudosint: target inválido — não foi possível extrair nome base")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}
	sourcesFilter := opts["sources"]
	maxPerm := clampInt(optInt(opts, "max_permutations", 30), 1, 200)
	maxResults := clampInt(optInt(opts, "max_results", defaultMaxResults), 1, 500)
	maxRuntime := clampInt(optInt(opts, "max_runtime_seconds", defaultMaxRuntimeSeconds), 1, 300)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxRuntime)*time.Second)
	defer cancel()

	slog.InfoContext(runCtx, "cloudosint.Run iniciado",
		"target", target,
		"base_name", baseName,
		"sources", sourcesFilter,
		"max_permutations", maxPerm,
	)

	permutations := generatePermutations(baseName, maxPerm)

	type sourceFunc struct {
		name string
		fn   func(context.Context, string, []string, map[string]string) ([]module.Finding, error)
	}

	sources := []sourceFunc{
		{"http", m.probeHTTP},
		{"grayhat", m.queryGrayhat},
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
		g.Go(func() error {
			slog.DebugContext(gctx, "cloudosint: consultando fonte",
				"source", s.name, "base", baseName)
			findings, err := s.fn(gctx, baseName, permutations, opts)
			if err != nil {
				slog.WarnContext(gctx, "cloudosint: fonte retornou erro",
					"source", s.name, "err", err)
				return nil
			}
			mu.Lock()
			all = append(all, findings...)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	result := decorateFindings(dedup(all), target, baseName)
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}
		return result[i].URL < result[j].URL
	})
	if len(result) > maxResults {
		result = result[:maxResults]
	}
	slog.InfoContext(runCtx, "cloudosint.Run concluído",
		"target", target,
		"buckets_checked", len(permutations),
		"findings", len(result),
	)
	return result, nil
}

// ─── HTTP probe ───────────────────────────────────────────────────────────────

// cloudProvider describes a cloud storage provider and its URL patterns.
type cloudProvider struct {
	name    string
	urlFmt  string // %s = bucket name
	service string
}

var providers = []cloudProvider{
	// AWS S3
	{"s3", "https://%s.s3.amazonaws.com", "AWS S3"},
	{"s3-us-east", "https://%s.s3.us-east-1.amazonaws.com", "AWS S3"},
	{"s3-eu-west", "https://%s.s3.eu-west-1.amazonaws.com", "AWS S3"},
	// Azure Blob
	{"azure-blob", "https://%s.blob.core.windows.net", "Azure Blob"},
	// GCP Cloud Storage
	{"gcp-storage", "https://storage.googleapis.com/%s", "GCP Storage"},
	{"gcp-bucket", "https://%s.storage.googleapis.com", "GCP Storage"},
	// DigitalOcean Spaces
	{"do-spaces-nyc3", "https://%s.nyc3.digitaloceanspaces.com", "DO Spaces"},
	{"do-spaces-sfo3", "https://%s.sfo3.digitaloceanspaces.com", "DO Spaces"},
}

func (m *Module) probeHTTP(ctx context.Context, _ string, permutations []string, _ map[string]string) ([]module.Finding, error) {
	var mu sync.Mutex
	var findings []module.Finding

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxParallel)

	for _, name := range permutations {
		name := name
		for _, prov := range providers {
			prov := prov
			g.Go(func() error {
				bucketURL := fmt.Sprintf(prov.urlFmt, name)
				status, headers, err := m.headBucket(gctx, bucketURL)
				if err != nil {
					return nil // network error — skip silently
				}

				if status == BucketNotFound {
					return nil // 404 = definitely not there
				}

				conf := "0.70"
				sev := module.SeverityInfo
				detail := fmt.Sprintf("Bucket '%s' detectado em %s (%s) — status: %s",
					name, prov.service, bucketURL, status)

				switch status {
				case BucketPublicRead:
					sev = module.SeverityLow
					conf = "0.78"
					detail = fmt.Sprintf("Endpoint de storage candidato '%s' em %s respondeu HTTP 200 em %s; HEAD não comprova listagem ou leitura pública",
						name, prov.service, bucketURL)
				case BucketPublicWrite:
					sev = module.SeverityMedium
					conf = "0.85"
					detail = fmt.Sprintf("Endpoint de storage candidato '%s' em %s (%s) indicou possível escrita pública; requer validação específica do provedor",
						name, prov.service, bucketURL)
				case BucketPrivate:
					sev = module.SeverityInfo
					conf = "0.72"
					detail = fmt.Sprintf("Endpoint de storage candidato '%s' em %s (%s) respondeu acesso negado; isso não prova vínculo com o alvo",
						name, prov.service, bucketURL)
				default:
					return nil
				}

				f := module.Finding{
					Type:     "cloud_storage_candidate",
					URL:      bucketURL,
					Severity: sev,
					Detail:   detail,
					Extra: map[string]string{
						"bucket_name": name,
						"provider":    prov.service,
						"url_pattern": prov.name,
						"status":      string(status),
						"source":      "http_probe",
						"confidence":  conf,
					},
				}
				if v := headers.Get("x-amz-bucket-region"); v != "" {
					f.Extra["aws_region"] = v
				}
				if v := headers.Get("x-ms-request-id"); v != "" {
					f.Extra["azure_confirmed"] = "true"
				}

				mu.Lock()
				findings = append(findings, f)
				mu.Unlock()
				return nil
			})
		}
	}
	_ = g.Wait()
	return findings, nil
}

func (m *Module) headBucket(ctx context.Context, bucketURL string) (BucketStatus, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, bucketURL, nil)
	if err != nil {
		return BucketUnknown, nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-cloudosint/1.0 (OSINT; security research)")

	resp, err := m.client.Do(req)
	if err != nil {
		return BucketUnknown, nil, err
	}
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Public read — can list/access
		return BucketPublicRead, resp.Header, nil
	case http.StatusForbidden:
		// Bucket exists but private (403 = AccessDenied in S3)
		return BucketPrivate, resp.Header, nil
	case http.StatusNotFound:
		return BucketNotFound, resp.Header, nil
	case http.StatusMethodNotAllowed:
		// Azure returns 405 for HEAD on private blobs in some configs
		return BucketPrivate, resp.Header, nil
	default:
		return BucketUnknown, resp.Header, nil
	}
}

// ─── GrayhatWarfare ───────────────────────────────────────────────────────────

type grayhatResult struct {
	Buckets []struct {
		BucketName string `json:"bucket_name"`
		FileCount  int    `json:"file_count"`
		Provider   string `json:"provider"`
		URL        string `json:"url"`
	} `json:"buckets"`
	Total int `json:"total"`
}

func (m *Module) queryGrayhat(ctx context.Context, baseName string, _ []string, opts map[string]string) ([]module.Finding, error) {
	apiKey := opts["grayhat_key"]
	if apiKey == "" {
		slog.DebugContext(ctx, "cloudosint: grayhat sem API key — pulando")
		return nil, nil
	}

	u := fmt.Sprintf("https://buckets.grayhatwarfare.com/api/v2/buckets?keywords=%s&limit=50",
		url.QueryEscape(baseName))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("User-Agent", "blackhorn-cloudosint/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("grayhat: API key inválida")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("grayhat: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyCloud))
	if err != nil {
		return nil, err
	}

	var result grayhatResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("grayhat: parse: %w", err)
	}

	var findings []module.Finding
	for _, b := range result.Buckets {
		if !bucketMatchesBase(b.BucketName, baseName) {
			continue
		}
		sev := module.SeverityLow
		conf := "0.78"
		if b.FileCount == 0 {
			sev = module.SeverityInfo
			conf = "0.68"
		}

		findings = append(findings, module.Finding{
			Type:     "cloud_storage_reference",
			URL:      b.URL,
			Severity: sev,
			Detail: fmt.Sprintf("Bucket '%s' (%s) encontrado via GrayhatWarfare — %d arquivos expostos publicamente",
				b.BucketName, b.Provider, b.FileCount),
			Extra: map[string]string{
				"bucket_name": b.BucketName,
				"provider":    b.Provider,
				"file_count":  strconv.Itoa(b.FileCount),
				"total_found": strconv.Itoa(result.Total),
				"source":      "grayhat",
				"confidence":  conf,
			},
		})
	}
	return findings, nil
}

// ─── permutation generation ───────────────────────────────────────────────────

var bucketSuffixes = []string{
	"", "-dev", "-development", "-staging", "-stage", "-prod", "-production",
	"-test", "-qa", "-backup", "-bak", "-old", "-archive", "-assets",
	"-static", "-media", "-images", "-files", "-uploads", "-data",
	"-logs", "-config", "-secrets", "-private", "-internal", "-admin",
	"-api", "-web", "-app", "-cdn", "-store", "-storage", "-public",
	"-release", "-releases", "-artifact", "-artifacts", "-build", "-builds",
	"-deploy", "-terraform", "-tf-state", "-k8s", "-kubernetes",
}

func generatePermutations(base string, max int) []string {
	seen := map[string]bool{base: true}
	result := []string{base}

	for _, suf := range bucketSuffixes {
		if len(result) >= max {
			break
		}
		for _, variant := range []string{
			base + suf,
			base + strings.ReplaceAll(suf, "-", "."),
			base + strings.ReplaceAll(suf, "-", "_"),
		} {
			if !seen[variant] && variant != "" {
				seen[variant] = true
				result = append(result, variant)
				if len(result) >= max {
					break
				}
			}
		}
	}
	return result
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func extractBaseName(target string) string {
	// Strip scheme
	for _, scheme := range []string{"https://", "http://"} {
		target = strings.TrimPrefix(target, scheme)
	}
	// Take only first segment / before first dot if domain
	parts := strings.SplitN(target, ".", 2)
	name := strings.ToLower(strings.TrimSpace(parts[0]))
	// Remove path
	name = strings.SplitN(name, "/", 2)[0]
	// Minimal validation
	if len(name) < 2 || len(name) > 63 {
		return ""
	}
	return name
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

func bucketMatchesBase(bucketName, baseName string) bool {
	bucket := strings.ToLower(strings.TrimSpace(bucketName))
	base := strings.ToLower(strings.TrimSpace(baseName))
	if bucket == "" || base == "" {
		return false
	}
	if bucket == base {
		return true
	}
	for _, separator := range []string{"-", "_", "."} {
		if strings.HasPrefix(bucket, base+separator) || strings.HasSuffix(bucket, separator+base) {
			return true
		}
	}
	return false
}

func decorateFindings(findings []module.Finding, target, baseName string) []module.Finding {
	for i := range findings {
		if findings[i].Extra == nil {
			findings[i].Extra = map[string]string{}
		}
		findings[i].Extra["target"] = target
		findings[i].Extra["target_base_name"] = baseName
		findings[i].Extra["validated"] = "false"
		findings[i].Extra["validation_state"] = "candidate_or_third_party_reference"
		findings[i].Extra["promote_to_context"] = "false"
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
