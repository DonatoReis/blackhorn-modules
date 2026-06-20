package cloudlist

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func hasType(findings []module.Finding, t string) bool {
	for _, f := range findings {
		if f.Type == t {
			return true
		}
	}
	return false
}

func hasProvider(findings []module.Finding, p string) bool {
	for _, f := range findings {
		if f.Extra["provider"] == p {
			return true
		}
	}
	return false
}

func jsonSrv(t *testing.T, v any) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(v)
	}))
}

func xmlSrv(t *testing.T, v any) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		xml.NewEncoder(w).Encode(v)
	}))
}

func errorSrv(code int) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
	}))
}

// ─── basic ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "cloudlist" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoProviders(t *testing.T) {
	m := New()
	m.Providers = nil
	_, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"providers": ""},
	})
	if err == nil {
		t.Fatal("expected error for empty providers")
	}
}

// ─── AWS ─────────────────────────────────────────────────────────────────────

func TestAWS_IMDSv2_Instance(t *testing.T) {
	// Simulate IMDSv2: PUT token → GET instance identity.
	tokenVal := "fake-imds-token"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(200)
			w.Write([]byte(tokenVal))
			return
		}
		if strings.Contains(r.URL.Path, "instance-identity") {
			json.NewEncoder(w).Encode(awsInstanceIdentity{
				InstanceID:   "i-1234567890abcdef0",
				PrivateIP:    "10.0.0.5",
				PublicIP:     "52.1.2.3",
				InstanceType: "t3.micro",
				Region:       "us-east-1",
				AccountID:    "123456789012",
			})
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.AWSMetaBaseURL = srv.URL
	m.AWSS3BaseURL = srv.URL // will 404, that's OK
	m.Providers = []string{"aws"}

	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "cloud_inventory_reference") {
		t.Fatal("expected cloud inventory reference from AWS IMDS")
	}
	if !hasProvider(findings, "aws") {
		t.Fatal("expected provider=aws")
	}
	// Check instance details.
	found := false
	for _, f := range findings {
		if f.Extra["instance_id"] == "i-1234567890abcdef0" {
			found = true
			if f.Extra["region"] != "us-east-1" {
				t.Errorf("expected region=us-east-1, got %q", f.Extra["region"])
			}
		}
	}
	if !found {
		t.Fatal("expected instance_id=i-1234567890abcdef0 in findings")
	}
}

func TestAWS_TokenFail_SoftFail(t *testing.T) {
	srv := errorSrv(403)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.AWSMetaBaseURL = srv.URL
	m.Providers = []string{"aws"}

	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatal("expected soft failure for AWS token fetch error")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on IMDS failure, got %d", len(findings))
	}
}

func TestAWS_S3_Buckets(t *testing.T) {
	tokenVal := "tok"
	bucketXML := `<?xml version="1.0"?><ListAllMyBucketsResult><Buckets><Bucket><Name>my-bucket</Name></Bucket></Buckets></ListAllMyBucketsResult>`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.Write([]byte(tokenVal))
			return
		}
		if strings.Contains(r.URL.Path, "instance-identity") {
			w.WriteHeader(404) // No EC2 instance; only S3
			return
		}
		// S3 list buckets.
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(bucketXML))
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.AWSMetaBaseURL = srv.URL
	m.AWSS3BaseURL = srv.URL
	m.Providers = []string{"aws"}

	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "cloud_storage_reference") {
		t.Fatal("expected cloud storage reference from S3")
	}
}

// ─── GCP ─────────────────────────────────────────────────────────────────────

func TestGCP_InstanceMetadata(t *testing.T) {
	inst := gcpInstance{
		Name: "my-gce-instance",
		Zone: "projects/12345/zones/us-central1-a",
	}
	inst.NetworkInterfaces = []struct {
		NetworkIP     string `json:"networkIP"`
		AccessConfigs []struct {
			NatIP string `json:"natIP"`
		} `json:"accessConfigs"`
	}{
		{
			NetworkIP: "10.128.0.5",
			AccessConfigs: []struct {
				NatIP string `json:"natIP"`
			}{{NatIP: "34.1.2.3"}},
		},
	}
	srv := jsonSrv(t, inst)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.GCPMetaBaseURL = srv.URL
	m.Providers = []string{"gcp"}

	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "cloud_inventory_reference") {
		t.Fatal("expected cloud inventory reference from GCP metadata")
	}
	if !hasProvider(findings, "gcp") {
		t.Fatal("expected provider=gcp")
	}
}

func TestGCP_MetadataFail_SoftFail(t *testing.T) {
	srv := errorSrv(404)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.GCPMetaBaseURL = srv.URL
	m.Providers = []string{"gcp"}

	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatal("expected soft failure")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// ─── Azure ────────────────────────────────────────────────────────────────────

func TestAzure_IMDSMetadata(t *testing.T) {
	meta := azureInstanceMetadata{}
	meta.Compute.Name = "my-azure-vm"
	meta.Compute.Location = "eastus"
	meta.Compute.SubscriptionID = "sub-12345"
	meta.Compute.ResourceGroupName = "rg-prod"
	meta.Network.Interface = []struct {
		PrivateIPAddresses []struct {
			PrivateIPAddress string `json:"privateIPAddress"`
		} `json:"ipv4"`
	}{
		{PrivateIPAddresses: []struct {
			PrivateIPAddress string `json:"privateIPAddress"`
		}{{PrivateIPAddress: "10.0.0.10"}}},
	}
	srv := jsonSrv(t, meta)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.AzureMetaBaseURL = srv.URL
	m.Providers = []string{"azure"}

	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "cloud_inventory_reference") {
		t.Fatal("expected cloud inventory reference from Azure IMDS")
	}
	if !hasProvider(findings, "azure") {
		t.Fatal("expected provider=azure")
	}
	for _, f := range findings {
		if f.Extra["vm_name"] == "my-azure-vm" {
			if f.Extra["location"] != "eastus" {
				t.Errorf("expected location=eastus, got %q", f.Extra["location"])
			}
			return
		}
	}
	t.Fatal("expected vm_name=my-azure-vm in findings")
}

func TestAzure_IMDSFail_SoftFail(t *testing.T) {
	srv := errorSrv(400)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.AzureMetaBaseURL = srv.URL
	m.Providers = []string{"azure"}

	findings, _ := m.Run(context.Background(), module.Input{})
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// ─── DigitalOcean ─────────────────────────────────────────────────────────────

func TestDO_Droplets(t *testing.T) {
	resp := doDropletsResponse{}
	resp.Droplets = []struct {
		Name     string `json:"name"`
		Status   string `json:"status"`
		Networks struct {
			V4 []struct {
				IPAddress string `json:"ip_address"`
				Type      string `json:"type"`
			} `json:"v4"`
		} `json:"networks"`
	}{
		{Name: "prod-web-01", Status: "active"},
	}
	resp.Droplets[0].Networks.V4 = []struct {
		IPAddress string `json:"ip_address"`
		Type      string `json:"type"`
	}{
		{IPAddress: "10.0.0.1", Type: "private"},
		{IPAddress: "159.65.1.2", Type: "public"},
	}
	srv := jsonSrv(t, resp)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.DOBaseURL = srv.URL
	m.Providers = []string{"do"}

	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"do_token": "testtoken"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "cloud_inventory_reference") {
		t.Fatal("expected cloud inventory reference from DO")
	}
	// Public addressing is inventory, not a vulnerability by itself.
	for _, f := range findings {
		if f.Extra["ip_type"] == "public" && f.Severity != module.SeverityInfo {
			t.Errorf("expected Info severity for public DO IP, got %q", f.Severity)
		}
	}
}

func TestDO_NoToken_SoftFail(t *testing.T) {
	srv := jsonSrv(t, doDropletsResponse{})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.DOBaseURL = srv.URL
	m.Providers = []string{"do"}

	findings, _ := m.Run(context.Background(), module.Input{})
	if len(findings) != 0 {
		t.Fatal("expected 0 findings without do_token")
	}
}

// ─── Cloudflare ───────────────────────────────────────────────────────────────

func TestCloudflare_Zones(t *testing.T) {
	resp := cfZonesResponse{
		Result: []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{
			{ID: "abc123", Name: "example.com"},
			{ID: "def456", Name: "acme.org"},
		},
	}
	srv := jsonSrv(t, resp)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CFBaseURL = srv.URL
	m.Providers = []string{"cloudflare"}

	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"cf_token": "testtoken"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "cloud_zone_reference") {
		t.Fatal("expected cloud zone references from Cloudflare")
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 zones, got %d", len(findings))
	}
}

func TestCloudflare_NoToken_SoftFail(t *testing.T) {
	srv := jsonSrv(t, cfZonesResponse{})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CFBaseURL = srv.URL
	m.Providers = []string{"cloudflare"}

	findings, _ := m.Run(context.Background(), module.Input{})
	if len(findings) != 0 {
		t.Fatal("expected 0 findings without cf_token")
	}
}

// ─── Fastly ───────────────────────────────────────────────────────────────────

func TestFastly_Services(t *testing.T) {
	resp := fastlyServicesResponse{
		{
			ID:   "svc123",
			Name: "prod-cdn",
			Domains: []struct {
				Name string `json:"name"`
			}{{Name: "cdn.example.com"}},
		},
	}
	srv := jsonSrv(t, resp)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FastlyBaseURL = srv.URL
	m.Providers = []string{"fastly"}

	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"fastly_token": "testtoken"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "cloud_cdn_reference") {
		t.Fatal("expected cloud CDN reference from Fastly")
	}
}

func TestFastly_NoToken_SoftFail(t *testing.T) {
	srv := jsonSrv(t, fastlyServicesResponse{})
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.FastlyBaseURL = srv.URL
	m.Providers = []string{"fastly"}

	findings, _ := m.Run(context.Background(), module.Input{})
	if len(findings) != 0 {
		t.Fatal("expected 0 findings without fastly_token")
	}
}

// ─── Namecheap (XML) ─────────────────────────────────────────────────────────

func TestNamecheap_Domains(t *testing.T) {
	xmlBody := `<?xml version="1.0"?><ApiResponse><CommandResponse><DomainGetListResult><Domain Name="example.com"/><Domain Name="acme.org"/></DomainGetListResult></CommandResponse></ApiResponse>`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(xmlBody))
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.NamecheapBaseURL = srv.URL
	m.Providers = []string{"namecheap"}

	findings, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{
			"namecheap_key":  "mykey",
			"namecheap_user": "myuser",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "cloud_zone_reference") {
		t.Fatal("expected cloud zone references from Namecheap")
	}
}

func TestNamecheap_NoCredentials_SoftFail(t *testing.T) {
	srv := errorSrv(200)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.NamecheapBaseURL = srv.URL
	m.Providers = []string{"namecheap"}

	findings, _ := m.Run(context.Background(), module.Input{})
	if len(findings) != 0 {
		t.Fatal("expected 0 findings without namecheap credentials")
	}
}

// ─── providers option parsing ─────────────────────────────────────────────────

func TestProviders_FromOptions(t *testing.T) {
	srv := errorSrv(200)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.AWSMetaBaseURL = srv.URL
	m.GCPMetaBaseURL = srv.URL

	// Override to only query aws+gcp via Options.
	_, err := m.Run(context.Background(), module.Input{
		Options: map[string]string{"providers": "aws, gcp"},
	})
	// Will soft-fail for both (metadata not available in test), but no parse error.
	_ = err
}

// ─── unknown provider ─────────────────────────────────────────────────────────

func TestUnknownProvider_SoftFail(t *testing.T) {
	m := New()
	m.Providers = []string{"unknowncloud"}
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatal("expected soft failure for unknown provider")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// ─── dedup ────────────────────────────────────────────────────────────────────

func TestDedupFindings(t *testing.T) {
	ff := []module.Finding{
		{Type: "cloud_inventory_reference", URL: "10.0.0.1"},
		{Type: "cloud_inventory_reference", URL: "10.0.0.1"},
		{Type: "cloud_inventory_reference", URL: "10.0.0.2"},
	}
	got := dedupFindings(ff)
	if len(got) != 2 {
		t.Fatalf("expected 2 after dedup, got %d", len(got))
	}
}

func TestCloudflare_TargetScopeFiltersUnrelatedZones(t *testing.T) {
	resp := cfZonesResponse{
		Result: []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{
			{ID: "target", Name: "example.com"},
			{ID: "other", Name: "unrelated.org"},
		},
	}
	srv := jsonSrv(t, resp)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CFBaseURL = srv.URL
	m.Providers = []string{"cloudflare"}
	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"cf_token": "testtoken",
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 || findings[0].Extra["zone_name"] != "example.com" {
		t.Fatalf("target scope should keep only example.com: %+v", findings)
	}
	if findings[0].Extra["target_scope_validated"] != "true" ||
		findings[0].Extra["promote_to_context"] != "false" {
		t.Fatalf("scope metadata missing: %+v", findings[0].Extra)
	}
}

func TestCloudflare_ScopeAllKeepsAccountInventory(t *testing.T) {
	resp := cfZonesResponse{
		Result: []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{
			{ID: "target", Name: "example.com"},
			{ID: "other", Name: "unrelated.org"},
		},
	}
	srv := jsonSrv(t, resp)
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.CFBaseURL = srv.URL
	m.Providers = []string{"cloudflare"}
	findings, err := m.Run(context.Background(), module.Input{
		Target: "example.com",
		Options: map[string]string{
			"cf_token": "testtoken",
			"scope":    "all",
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("scope=all should keep account inventory: %+v", findings)
	}
}
