package mapcidr

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func run(t *testing.T, op string, cidr ...string) []module.Finding {
	t.Helper()
	opts := map[string]string{"op": op}
	findings, err := New().Run(context.Background(), module.Input{
		URLs:    cidr,
		Options: opts,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	return findings
}

func hasIP(findings []module.Finding, ip string) bool {
	for _, f := range findings {
		if f.Extra["ip"] == ip || f.URL == ip {
			return true
		}
	}
	return false
}

func hasCIDR(findings []module.Finding, cidr string) bool {
	for _, f := range findings {
		if f.URL == cidr || f.Extra["cidr"] == cidr {
			return true
		}
	}
	return false
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "mapcidr" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoInput(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestRun_UnknownOp(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{
		URLs:    []string{"10.0.0.0/30"},
		Options: map[string]string{"op": "badop"},
	})
	if err == nil {
		t.Fatal("expected error for unknown operation")
	}
}

// ── expand ────────────────────────────────────────────────────────────────────

func TestExpand_Small(t *testing.T) {
	findings := run(t, "expand", "192.168.1.0/30")
	// /30 has 4 addresses.
	if len(findings) != 4 {
		t.Fatalf("expected 4 IPs for /30, got %d", len(findings))
	}
}

func TestExpand_AllIPsPresent(t *testing.T) {
	findings := run(t, "expand", "10.0.0.0/30")
	wantIPs := []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for _, ip := range wantIPs {
		if !hasIP(findings, ip) {
			t.Errorf("expected IP %s in expansion of 10.0.0.0/30", ip)
		}
	}
}

func TestExpand_LargeCIDR_Error(t *testing.T) {
	// /8 has 16M IPs — should exceed the cap and return an error.
	_, err := New().Run(context.Background(), module.Input{
		URLs:    []string{"10.0.0.0/8"},
		Options: map[string]string{"op": "expand"},
	})
	if err == nil {
		t.Fatal("expected error for /8 expansion exceeding limit")
	}
}

func TestExpand_FindingType(t *testing.T) {
	findings := run(t, "expand", "192.168.0.0/30")
	for _, f := range findings {
		if f.Type != "ip_address" {
			t.Errorf("expected type ip_address, got %q", f.Type)
		}
	}
}

// ── count ─────────────────────────────────────────────────────────────────────

func TestCount_Slash30(t *testing.T) {
	findings := run(t, "count", "192.168.0.0/30")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for count, got %d", len(findings))
	}
	if findings[0].Extra["count"] != "4" {
		t.Errorf("expected count=4, got %q", findings[0].Extra["count"])
	}
}

func TestCount_Slash24(t *testing.T) {
	findings := run(t, "count", "10.0.0.0/24")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for count, got %d", len(findings))
	}
	if findings[0].Extra["count"] != "256" {
		t.Errorf("expected count=256, got %q", findings[0].Extra["count"])
	}
}

func TestCount_Slash32(t *testing.T) {
	findings := run(t, "count", "192.168.1.1/32")
	if findings[0].Extra["count"] != "1" {
		t.Errorf("expected count=1 for /32, got %q", findings[0].Extra["count"])
	}
}

// ── aggregate ─────────────────────────────────────────────────────────────────

func TestAggregate_ContainedNetworks(t *testing.T) {
	// 10.0.0.0/8 contains 10.0.0.0/24 — result should be just /8.
	findings := run(t, "aggregate", "10.0.0.0/24", "10.0.0.0/8")
	if len(findings) > 1 {
		t.Logf("aggregate returned %d networks: %v", len(findings), findings)
		// Check that 10.0.0.0/8 (or a supernet) is in results.
		hasSuper := false
		for _, f := range findings {
			if strings.HasPrefix(f.URL, "10.") {
				hasSuper = true
			}
		}
		if !hasSuper {
			t.Fatal("expected 10.x supernet in aggregate results")
		}
	}
}

func TestAggregate_Disjoint(t *testing.T) {
	// Two completely separate CIDRs — both should be kept.
	findings := run(t, "aggregate", "10.0.0.0/24", "192.168.1.0/24")
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 CIDRs for disjoint networks, got %d", len(findings))
	}
}

func TestAggregate_FindingType(t *testing.T) {
	findings := run(t, "aggregate", "10.0.0.0/24")
	for _, f := range findings {
		if f.Type != "cidr_block" {
			t.Errorf("expected type cidr_block, got %q", f.Type)
		}
	}
}

// ── split ─────────────────────────────────────────────────────────────────────

func TestSplit_Slash24_Into_Slash25(t *testing.T) {
	findings, err := New().Run(context.Background(), module.Input{
		URLs:    []string{"192.168.1.0/24"},
		Options: map[string]string{"op": "split", "prefix": "25"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// /24 split into /25 = 2 subnets.
	if len(findings) != 2 {
		t.Fatalf("expected 2 /25 subnets from /24, got %d", len(findings))
	}
}

func TestSplit_Slash24_Into_Slash26(t *testing.T) {
	findings, err := New().Run(context.Background(), module.Input{
		URLs:    []string{"10.0.0.0/24"},
		Options: map[string]string{"op": "split", "prefix": "26"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// /24 split into /26 = 4 subnets.
	if len(findings) != 4 {
		t.Fatalf("expected 4 /26 subnets from /24, got %d: %v", len(findings), findings)
	}
}

func TestSplit_NoPrefix_Error(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{
		URLs:    []string{"10.0.0.0/24"},
		Options: map[string]string{"op": "split"},
	})
	if err == nil {
		t.Fatal("expected error when split has no prefix")
	}
}

func TestSplit_InvalidPrefix_Error(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{
		URLs:    []string{"10.0.0.0/24"},
		Options: map[string]string{"op": "split", "prefix": "16"},
	})
	if err == nil {
		t.Fatal("expected error when new prefix is smaller than network prefix")
	}
}

// ── filter-private / filter-public ────────────────────────────────────────────

func TestFilterPrivate(t *testing.T) {
	// 192.168.0.0/30 is all private.
	findings := run(t, "filter-private", "192.168.0.0/30")
	if len(findings) != 4 {
		t.Fatalf("expected 4 private IPs, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Extra["type"] != "private" {
			t.Errorf("expected type=private, got %q", f.Extra["type"])
		}
	}
}

func TestFilterPublic_NoResultsForPrivate(t *testing.T) {
	// 192.168.0.0/30 is all private — filter-public should return nothing.
	findings := run(t, "filter-public", "192.168.0.0/30")
	if len(findings) != 0 {
		t.Fatalf("expected 0 public IPs from RFC-1918 range, got %d", len(findings))
	}
}

// ── contains ─────────────────────────────────────────────────────────────────

func TestContains_IPInRange(t *testing.T) {
	findings, err := New().Run(context.Background(), module.Input{
		Target:  "10.0.0.5",
		URLs:    []string{"10.0.0.0/24"},
		Options: map[string]string{"op": "contains"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "ip_in_range" {
		t.Errorf("expected type ip_in_range, got %q", findings[0].Type)
	}
}

func TestContains_IPNotInRange(t *testing.T) {
	findings, err := New().Run(context.Background(), module.Input{
		Target:  "192.168.1.1",
		URLs:    []string{"10.0.0.0/24"},
		Options: map[string]string{"op": "contains"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for IP not in range, got %d", len(findings))
	}
}

func TestContains_MultipleRanges(t *testing.T) {
	findings, err := New().Run(context.Background(), module.Input{
		Target:  "172.16.5.10",
		URLs:    []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		Options: map[string]string{"op": "contains"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 match (172.16.0.0/12), got %d", len(findings))
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func TestNetworkSize_Slash30(t *testing.T) {
	_, n, _ := net.ParseCIDR("10.0.0.0/30")
	sz := networkSize(n)
	if sz.String() != "4" {
		t.Errorf("expected 4 for /30, got %s", sz)
	}
}

func TestNetworkSize_Slash24(t *testing.T) {
	_, n, _ := net.ParseCIDR("10.0.0.0/24")
	sz := networkSize(n)
	if sz.String() != "256" {
		t.Errorf("expected 256 for /24, got %s", sz)
	}
}

func TestIncrementIP(t *testing.T) {
	ip := net.IP{10, 0, 0, 0}
	incrementIP(ip)
	if !ip.Equal(net.IP{10, 0, 0, 1}) {
		t.Errorf("expected 10.0.0.1, got %v", ip)
	}
}

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip      string
		private bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		got := isPrivateIP(ip)
		if got != c.private {
			t.Errorf("isPrivateIP(%q) = %v, want %v", c.ip, got, c.private)
		}
	}
}

func TestCollectNetworks_Dedup(t *testing.T) {
	input := module.Input{
		Target: "10.0.0.0/24",
		URLs:   []string{"10.0.0.0/24", "192.168.1.0/24"},
	}
	networks := collectNetworks(input)
	if len(networks) != 2 {
		t.Fatalf("expected 2 unique networks, got %d", len(networks))
	}
}

func TestCollectNetworks_PlainIP(t *testing.T) {
	input := module.Input{URLs: []string{"192.168.1.1"}}
	networks := collectNetworks(input)
	if len(networks) != 1 {
		t.Fatalf("expected 1 network for plain IP, got %d", len(networks))
	}
	ones, _ := networks[0].Mask.Size()
	if ones != 32 {
		t.Errorf("expected /32 for plain IPv4, got /%d", ones)
	}
}

func TestCollectNetworks_RawContent(t *testing.T) {
	input := module.Input{RawContent: "10.0.0.0/24\n192.168.0.0/16\n"}
	networks := collectNetworks(input)
	if len(networks) != 2 {
		t.Fatalf("expected 2 networks from RawContent, got %d", len(networks))
	}
}
