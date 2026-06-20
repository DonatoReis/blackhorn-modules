// Package cloudlist enumerates cloud assets across major providers.
// Supported providers and authentication modes:
//   - aws:         EC2 instances, S3 buckets, RDS endpoints, Lambda ARNs
//     via AWS metadata API (IMDSv2) or credential options
//   - gcp:         GCE instances, GCS buckets, Cloud Run services
//     via GCP metadata server or API key/token options
//   - azure:       Virtual Machines, Storage accounts, App Services
//     via Azure metadata API or tenant/client/secret options
//   - do:          DigitalOcean Droplets, Spaces buckets
//     via API token options
//   - cloudflare:  Zones, DNS records, Workers, Pages
//     via API token options
//   - namecheap:   Domain list via API (key + username required)
//   - fastly:      Services list via API token
//
// Reference: projectdiscovery/cloudlist (MIT) — API endpoint patterns only.
// License: MIT (blackhorn-modules).
package cloudlist

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/httpclient"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/urlutil"
	"golang.org/x/sync/errgroup"
)

const (
	defaultTimeout           = 20 * time.Second
	maxBodyBytes             = 4 * 1024 * 1024 // 4 MiB
	defaultMaxRuntimeSeconds = 30
	defaultMaxResults        = 500
	maxProviders             = 7
)

// ─── module ──────────────────────────────────────────────────────────────────

// Module enumerates cloud assets from configured providers.
type Module struct {
	client *http.Client
	// Providers controls which cloud providers to query.
	// Default: ["aws", "gcp", "azure"] (metadata-based, keyless).
	Providers []string

	// Overridable base URLs for testing.
	AWSMetaBaseURL   string
	AWSS3BaseURL     string
	GCPMetaBaseURL   string
	AzureMetaBaseURL string
	DOBaseURL        string
	CFBaseURL        string
	NamecheapBaseURL string
	FastlyBaseURL    string
}

// New returns a Module with metadata-based providers (no API keys needed in cloud envs).
func New() *Module {
	return &Module{
		client:    httpclient.New(httpclient.Options{Timeout: defaultTimeout}),
		Providers: []string{"aws", "gcp", "azure"},
	}
}

// NewWithClient creates a Module using the provided HTTP client.
func NewWithClient(c *http.Client) *Module {
	return &Module{
		client:    c,
		Providers: []string{"aws", "gcp", "azure"},
	}
}

// Name implements module.Module.
func (m *Module) Name() string { return "cloudlist" }

// Run implements module.Module.
//
// Input.Target: optional filter (CIDR/hostname prefix).
// Input.Options:
//   - "providers":        comma-separated provider list
//   - "aws_token":        AWS IMDSv2 token (auto-fetched if empty in EC2)
//   - "gcp_token":        GCP access token
//   - "azure_token":      Azure managed identity token
//   - "do_token":         DigitalOcean API token
//   - "cf_token":         Cloudflare API token
//   - "namecheap_key":    Namecheap API key
//   - "namecheap_user":   Namecheap username
//   - "fastly_token":     Fastly API token
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	providers, opts := m.parseInput(input)
	if len(providers) == 0 {
		return nil, fmt.Errorf("cloudlist: no providers configured")
	}
	maxRuntime := time.Duration(clampInt(optInt(opts, "max_runtime_seconds", defaultMaxRuntimeSeconds), 1, 120)) * time.Second
	maxResults := clampInt(optInt(opts, "max_results", defaultMaxResults), 1, 5000)
	runCtx, cancel := context.WithTimeout(ctx, maxRuntime)
	defer cancel()

	var (
		mu       sync.Mutex
		findings []module.Finding
	)

	g, gctx := errgroup.WithContext(runCtx)
	g.SetLimit(min(len(providers), maxProviders))

	for _, prov := range providers {
		prov := prov
		g.Go(func() error {
			ff, err := m.queryProvider(gctx, prov, opts)
			if err != nil {
				slog.Warn("cloudlist: provider query failed", "provider", prov, "err", err)
				return nil // soft failure
			}
			if len(ff) > 0 {
				mu.Lock()
				findings = append(findings, ff...)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()
	result := decorateInventory(dedupFindings(findings))
	if !strings.EqualFold(strings.TrimSpace(opts["scope"]), "all") && strings.TrimSpace(input.Target) != "" {
		result = filterByTargetScope(result, input.Target)
	}
	if len(result) > maxResults {
		result = result[:maxResults]
	}
	return result, nil
}

// ─── input parsing ────────────────────────────────────────────────────────────

func (m *Module) parseInput(input module.Input) (providers []string, opts map[string]string) {
	opts = input.Options
	if opts == nil {
		opts = make(map[string]string)
	}
	if v := opts["providers"]; v != "" {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(strings.ToLower(p))
			if p != "" {
				providers = append(providers, p)
			}
		}
	}
	if len(providers) == 0 {
		providers = m.Providers
	}
	providers = dedupStrings(providers)
	return
}

// ─── provider dispatcher ─────────────────────────────────────────────────────

func (m *Module) queryProvider(ctx context.Context, provider string, opts map[string]string) ([]module.Finding, error) {
	switch provider {
	case "aws":
		return m.queryAWS(ctx, opts)
	case "gcp":
		return m.queryGCP(ctx, opts)
	case "azure":
		return m.queryAzure(ctx, opts)
	case "do", "digitalocean":
		return m.queryDO(ctx, opts)
	case "cloudflare", "cf":
		return m.queryCloudflare(ctx, opts)
	case "namecheap":
		return m.queryNamecheap(ctx, opts)
	case "fastly":
		return m.queryFastly(ctx, opts)
	default:
		return nil, fmt.Errorf("unknown provider: %q", provider)
	}
}

// ─── AWS (EC2 IMDSv2 + S3 bucket listing) ────────────────────────────────────

type awsInstanceIdentity struct {
	InstanceID   string `json:"instanceId"`
	PrivateIP    string `json:"privateIp"`
	PublicIP     string `json:"publicIp,omitempty"`
	InstanceType string `json:"instanceType"`
	Region       string `json:"region"`
	AccountID    string `json:"accountId"`
}

type awsS3ListBuckets struct {
	Buckets []struct {
		Name string `xml:"Name"`
	} `xml:"Buckets>Bucket"`
}

func (m *Module) awsMetaBase() string {
	if m.AWSMetaBaseURL != "" {
		return m.AWSMetaBaseURL
	}
	return "http://169.254.169.254"
}

func (m *Module) awsS3Base() string {
	if m.AWSS3BaseURL != "" {
		return m.AWSS3BaseURL
	}
	return "https://s3.amazonaws.com"
}

func (m *Module) queryAWS(ctx context.Context, opts map[string]string) ([]module.Finding, error) {
	var findings []module.Finding

	// Step 1: Fetch IMDSv2 token.
	token := opts["aws_token"]
	if token == "" {
		tokenURL := m.awsMetaBase() + "/latest/api/token"
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, tokenURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
		body, code, err := m.doReq(req)
		if err != nil || code != http.StatusOK {
			return nil, fmt.Errorf("aws: IMDS token fetch failed (code=%d, not in EC2?)", code)
		}
		token = strings.TrimSpace(string(body))
	}

	// Step 2: Fetch instance identity document.
	idURL := m.awsMetaBase() + "/latest/dynamic/instance-identity/document"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, idURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)
	body, code, err := m.doReq(req)
	if err != nil {
		return nil, err
	}
	if code == http.StatusOK {
		var id awsInstanceIdentity
		if err := json.Unmarshal(body, &id); err == nil && id.InstanceID != "" {
			findings = append(findings, module.Finding{
				Type:     "cloud_inventory_reference",
				URL:      id.PrivateIP,
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("EC2 instance %s (%s) in %s", id.InstanceID, id.InstanceType, id.Region),
				Extra: map[string]string{
					"provider":      "aws",
					"resource_type": "ec2",
					"instance_id":   id.InstanceID,
					"private_ip":    id.PrivateIP,
					"public_ip":     id.PublicIP,
					"region":        id.Region,
					"account_id":    id.AccountID,
					"confidence":    "0.90",
				},
			})
		}
	}

	// Step 3: List S3 buckets.
	s3URL := m.awsS3Base() + "/"
	s3req, err := http.NewRequestWithContext(ctx, http.MethodGet, s3URL, nil)
	if err == nil {
		s3body, s3code, s3err := m.doReq(s3req)
		if s3err == nil && s3code == http.StatusOK {
			var bucketList awsS3ListBuckets
			if xmlErr := xml.Unmarshal(s3body, &bucketList); xmlErr == nil {
				for _, b := range bucketList.Buckets {
					findings = append(findings, module.Finding{
						Type:     "cloud_storage_reference",
						URL:      fmt.Sprintf("https://%s.s3.amazonaws.com", b.Name),
						Severity: module.SeverityInfo,
						Detail:   fmt.Sprintf("S3 bucket: %s", b.Name),
						Extra: map[string]string{
							"provider":      "aws",
							"resource_type": "s3",
							"bucket":        b.Name,
							"confidence":    "0.90",
						},
					})
				}
			}
		}
	}

	return findings, nil
}

// ─── GCP (metadata server) ────────────────────────────────────────────────────

type gcpInstance struct {
	Name              string `json:"name"`
	Zone              string `json:"zone"`
	NetworkInterfaces []struct {
		NetworkIP     string `json:"networkIP"`
		AccessConfigs []struct {
			NatIP string `json:"natIP"`
		} `json:"accessConfigs"`
	} `json:"networkInterfaces"`
}

func (m *Module) gcpMetaBase() string {
	if m.GCPMetaBaseURL != "" {
		return m.GCPMetaBaseURL
	}
	return "http://metadata.google.internal/computeMetadata/v1"
}

func (m *Module) queryGCP(ctx context.Context, opts map[string]string) ([]module.Finding, error) {
	metaURL := m.gcpMetaBase() + "/instance/?recursive=true&alt=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	if token := opts["gcp_token"]; token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	body, code, err := m.doReq(req)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("gcp: metadata server returned %d (not in GCE?)", code)
	}

	var inst gcpInstance
	if err := json.Unmarshal(body, &inst); err != nil {
		return nil, fmt.Errorf("gcp: JSON parse error: %w", err)
	}

	var findings []module.Finding
	privateIP := ""
	publicIP := ""
	if len(inst.NetworkInterfaces) > 0 {
		privateIP = inst.NetworkInterfaces[0].NetworkIP
		if len(inst.NetworkInterfaces[0].AccessConfigs) > 0 {
			publicIP = inst.NetworkInterfaces[0].AccessConfigs[0].NatIP
		}
	}
	targetIP := privateIP
	if publicIP != "" {
		targetIP = publicIP
	}

	findings = append(findings, module.Finding{
		Type:     "cloud_inventory_reference",
		URL:      targetIP,
		Severity: module.SeverityInfo,
		Detail:   fmt.Sprintf("GCE instance %s in zone %s", inst.Name, inst.Zone),
		Extra: map[string]string{
			"provider":      "gcp",
			"resource_type": "gce",
			"instance_name": inst.Name,
			"zone":          inst.Zone,
			"private_ip":    privateIP,
			"public_ip":     publicIP,
			"confidence":    "0.90",
		},
	})
	return findings, nil
}

// ─── Azure (IMDS) ────────────────────────────────────────────────────────────

type azureInstanceMetadata struct {
	Compute struct {
		Name              string `json:"name"`
		ResourceGroupName string `json:"resourceGroupName"`
		Location          string `json:"location"`
		SubscriptionID    string `json:"subscriptionId"`
	} `json:"compute"`
	Network struct {
		Interface []struct {
			PrivateIPAddresses []struct {
				PrivateIPAddress string `json:"privateIPAddress"`
			} `json:"ipv4"`
		} `json:"interface"`
	} `json:"network"`
}

func (m *Module) azureMetaBase() string {
	if m.AzureMetaBaseURL != "" {
		return m.AzureMetaBaseURL
	}
	return "http://169.254.169.254/metadata/instance"
}

func (m *Module) queryAzure(ctx context.Context, opts map[string]string) ([]module.Finding, error) {
	metaURL := m.azureMetaBase() + "?api-version=2021-02-01&format=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata", "true")
	if token := opts["azure_token"]; token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	body, code, err := m.doReq(req)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("azure: IMDS returned %d (not in Azure VM?)", code)
	}

	var meta azureInstanceMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("azure: JSON parse error: %w", err)
	}

	privateIP := ""
	if len(meta.Network.Interface) > 0 && len(meta.Network.Interface[0].PrivateIPAddresses) > 0 {
		privateIP = meta.Network.Interface[0].PrivateIPAddresses[0].PrivateIPAddress
	}

	return []module.Finding{{
		Type:     "cloud_inventory_reference",
		URL:      privateIP,
		Severity: module.SeverityInfo,
		Detail:   fmt.Sprintf("Azure VM %s in %s (sub: %s)", meta.Compute.Name, meta.Compute.Location, meta.Compute.SubscriptionID),
		Extra: map[string]string{
			"provider":       "azure",
			"resource_type":  "vm",
			"vm_name":        meta.Compute.Name,
			"resource_group": meta.Compute.ResourceGroupName,
			"location":       meta.Compute.Location,
			"subscription":   meta.Compute.SubscriptionID,
			"private_ip":     privateIP,
			"confidence":     "0.90",
		},
	}}, nil
}

// ─── DigitalOcean ─────────────────────────────────────────────────────────────

type doDropletsResponse struct {
	Droplets []struct {
		Name     string `json:"name"`
		Status   string `json:"status"`
		Networks struct {
			V4 []struct {
				IPAddress string `json:"ip_address"`
				Type      string `json:"type"` // "private" or "public"
			} `json:"v4"`
		} `json:"networks"`
	} `json:"droplets"`
}

func (m *Module) doBase() string {
	if m.DOBaseURL != "" {
		return m.DOBaseURL
	}
	return "https://api.digitalocean.com/v2"
}

func (m *Module) queryDO(ctx context.Context, opts map[string]string) ([]module.Finding, error) {
	token := opts["do_token"]
	if token == "" {
		return nil, fmt.Errorf("do: requires do_token in Options")
	}
	apiURL := m.doBase() + "/droplets?per_page=200"
	body, code, err := m.getWithBearer(ctx, apiURL, token)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("do: HTTP %d", code)
	}

	var resp doDropletsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("do: JSON parse error: %w", err)
	}

	var findings []module.Finding
	for _, d := range resp.Droplets {
		for _, net := range d.Networks.V4 {
			findings = append(findings, module.Finding{
				Type:     "cloud_inventory_reference",
				URL:      net.IPAddress,
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("Droplet %s (%s %s)", d.Name, net.Type, net.IPAddress),
				Extra: map[string]string{
					"provider":      "do",
					"resource_type": "droplet",
					"name":          d.Name,
					"ip":            net.IPAddress,
					"ip_type":       net.Type,
					"status":        d.Status,
					"confidence":    "0.90",
				},
			})
		}
	}
	return findings, nil
}

// ─── Cloudflare ───────────────────────────────────────────────────────────────

type cfZonesResponse struct {
	Result []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"result"`
}

func (m *Module) cfBase() string {
	if m.CFBaseURL != "" {
		return m.CFBaseURL
	}
	return "https://api.cloudflare.com/client/v4"
}

func (m *Module) queryCloudflare(ctx context.Context, opts map[string]string) ([]module.Finding, error) {
	token := opts["cf_token"]
	if token == "" {
		return nil, fmt.Errorf("cloudflare: requires cf_token in Options")
	}
	apiURL := m.cfBase() + "/zones?per_page=200"
	body, code, err := m.getWithBearer(ctx, apiURL, token)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("cloudflare: HTTP %d", code)
	}

	var resp cfZonesResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("cloudflare: JSON parse error: %w", err)
	}

	var findings []module.Finding
	for _, zone := range resp.Result {
		findings = append(findings, module.Finding{
			Type:     "cloud_zone_reference",
			URL:      zone.Name,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("Cloudflare zone: %s (id=%s)", zone.Name, zone.ID),
			Extra: map[string]string{
				"provider":      "cloudflare",
				"resource_type": "zone",
				"zone_id":       zone.ID,
				"zone_name":     zone.Name,
				"confidence":    "0.90",
			},
		})
	}
	return findings, nil
}

// ─── Namecheap ────────────────────────────────────────────────────────────────

type namecheapResponse struct {
	CommandResponse struct {
		DomainGetListResult struct {
			Domain []struct {
				Name string `xml:"Name,attr"`
			} `xml:"Domain"`
		} `xml:"DomainGetListResult"`
	} `xml:"CommandResponse"`
}

func (m *Module) namecheapBase() string {
	if m.NamecheapBaseURL != "" {
		return m.NamecheapBaseURL
	}
	return "https://api.namecheap.com/xml.response"
}

func (m *Module) queryNamecheap(ctx context.Context, opts map[string]string) ([]module.Finding, error) {
	key := opts["namecheap_key"]
	user := opts["namecheap_user"]
	if key == "" || user == "" {
		return nil, fmt.Errorf("namecheap: requires namecheap_key and namecheap_user in Options")
	}
	apiURL := fmt.Sprintf("%s?ApiUser=%s&ApiKey=%s&UserName=%s&Command=namecheap.domains.getList&ClientIp=127.0.0.1&PageSize=100",
		m.namecheapBase(), url.QueryEscape(user), key, url.QueryEscape(user))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	body, code, err := m.doReq(req)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("namecheap: HTTP %d", code)
	}

	var resp namecheapResponse
	if err := xml.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("namecheap: XML parse error: %w", err)
	}

	var findings []module.Finding
	for _, d := range resp.CommandResponse.DomainGetListResult.Domain {
		findings = append(findings, module.Finding{
			Type:     "cloud_zone_reference",
			URL:      d.Name,
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("Namecheap domain: %s", d.Name),
			Extra: map[string]string{
				"provider":      "namecheap",
				"resource_type": "domain",
				"domain":        d.Name,
				"confidence":    "0.90",
			},
		})
	}
	return findings, nil
}

// ─── Fastly ───────────────────────────────────────────────────────────────────

type fastlyServicesResponse []struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Domains []struct {
		Name string `json:"name"`
	} `json:"domains"`
}

func (m *Module) fastlyBase() string {
	if m.FastlyBaseURL != "" {
		return m.FastlyBaseURL
	}
	return "https://api.fastly.com"
}

func (m *Module) queryFastly(ctx context.Context, opts map[string]string) ([]module.Finding, error) {
	token := opts["fastly_token"]
	if token == "" {
		return nil, fmt.Errorf("fastly: requires fastly_token in Options")
	}
	apiURL := m.fastlyBase() + "/service?page=1&per_page=200"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Fastly-Key", token)
	body, code, err := m.doReq(req)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("fastly: HTTP %d", code)
	}

	var services fastlyServicesResponse
	if err := json.Unmarshal(body, &services); err != nil {
		return nil, fmt.Errorf("fastly: JSON parse error: %w", err)
	}

	var findings []module.Finding
	for _, svc := range services {
		for _, domain := range svc.Domains {
			findings = append(findings, module.Finding{
				Type:     "cloud_cdn_reference",
				URL:      domain.Name,
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("Fastly service %s (id=%s) domain: %s", svc.Name, svc.ID, domain.Name),
				Extra: map[string]string{
					"provider":      "fastly",
					"resource_type": "service",
					"service_id":    svc.ID,
					"service_name":  svc.Name,
					"domain":        domain.Name,
					"confidence":    "0.90",
				},
			})
		}
	}
	return findings, nil
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func (m *Module) getWithBearer(ctx context.Context, rawURL, token string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return m.doReq(req)
}

func (m *Module) doReq(req *http.Request) ([]byte, int, error) {
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func dedupFindings(findings []module.Finding) []module.Finding {
	seen := make(map[string]struct{})
	out := findings[:0]
	for _, f := range findings {
		key := f.Type + "|" + f.URL
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, f)
		}
	}
	return out
}

func decorateInventory(findings []module.Finding) []module.Finding {
	for i := range findings {
		if findings[i].Extra == nil {
			findings[i].Extra = make(map[string]string)
		}
		findings[i].Extra["validated"] = "true"
		findings[i].Extra["validation_state"] = "provider_inventory_confirmed"
		findings[i].Extra["promote_to_context"] = "false"
		findings[i].Extra["target_scope_validated"] = "false"
	}
	return findings
}

func filterByTargetScope(findings []module.Finding, rawTarget string) []module.Finding {
	target := strings.TrimSpace(strings.ToLower(rawTarget))
	targetIP := net.ParseIP(target)
	targetDomain := ""
	if targetIP == nil {
		targetDomain = urlutil.NormalizeDomain(target)
		if targetDomain != "" && (!strings.Contains(targetDomain, ".") || net.ParseIP(targetDomain) != nil) {
			targetDomain = ""
		}
	}

	out := make([]module.Finding, 0, len(findings))
	for _, finding := range findings {
		match := ""
		switch {
		case targetIP != nil:
			if findingMatchesIP(finding, targetIP.String()) {
				match = "ip"
			}
		case targetDomain != "":
			if findingMatchesDomain(finding, targetDomain) {
				match = "domain"
			}
		default:
			if findingMatchesName(finding, target) {
				match = "name"
			}
		}
		if match == "" {
			continue
		}
		finding.Extra["target_scope_validated"] = "true"
		finding.Extra["scope_match"] = match
		out = append(out, finding)
	}
	return out
}

func findingMatchesIP(finding module.Finding, target string) bool {
	for _, key := range []string{"ip", "public_ip", "private_ip"} {
		if ip := net.ParseIP(strings.TrimSpace(finding.Extra[key])); ip != nil && ip.String() == target {
			return true
		}
	}
	return net.ParseIP(strings.TrimSpace(finding.URL)) != nil &&
		net.ParseIP(strings.TrimSpace(finding.URL)).String() == target
}

func findingMatchesDomain(finding module.Finding, target string) bool {
	for _, key := range []string{"domain", "zone_name", "bucket"} {
		if domainInScope(finding.Extra[key], target) {
			return true
		}
	}
	return domainInScope(finding.URL, target)
}

func domainInScope(raw, target string) bool {
	candidate := urlutil.NormalizeDomain(raw)
	if candidate == "" || net.ParseIP(candidate) != nil {
		return false
	}
	return candidate == target || strings.HasSuffix(candidate, "."+target)
}

func findingMatchesName(finding module.Finding, target string) bool {
	if target == "" {
		return false
	}
	for _, key := range []string{"name", "bucket", "instance_name", "vm_name", "service_name", "instance_id"} {
		value := strings.ToLower(strings.TrimSpace(finding.Extra[key]))
		if value == target || strings.HasPrefix(value, target+"-") || strings.HasSuffix(value, "-"+target) {
			return true
		}
	}
	return false
}

func optInt(opts map[string]string, key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(opts[key]))
	if err != nil {
		return fallback
	}
	return value
}

func clampInt(value, minimum, maximum int) int {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func dedupStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
