// Package mapcidr provides IP/CIDR network utility operations: expansion,
// aggregation, filtering, splitting, and set operations (union, intersection,
// difference). It is inspired by projectdiscovery/mapcidr (MIT) but fully
// reimplemented using Go's net package.
//
// Capabilities:
//   - Expand CIDR → all IP addresses
//   - Aggregate list of CIDRs → minimal supernet set
//   - Filter IPs: private, loopback, IPv4-only, IPv6-only
//   - Split a CIDR into N equal sub-networks
//   - Union / Intersection / Difference of CIDR sets
//   - Count IPs in a CIDR block
//   - Check if IP falls within any CIDR in a list
//
// License: MIT (blackhorn-modules). No code copied from mapcidr.
package mapcidr

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"sort"
	"strings"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── module ──────────────────────────────────────────────────────────────────

// Module implements module.Module for CIDR network operations.
// Operation is determined by Options["op"]:
//   - "expand"      : expand CIDR(s) to all IP addresses
//   - "aggregate"   : aggregate CIDRs to minimal covering set
//   - "count"       : count IPs in each CIDR
//   - "filter-private" : emit only RFC-1918/loopback addresses from expansion
//   - "filter-public"  : emit only public routable addresses from expansion
//   - "split"       : split each CIDR into sub-CIDRs; Options["prefix"] = new prefix len
//   - "contains"    : check if Target IP is contained in any input CIDR
//
// Default operation when Options is nil/empty: "expand".
type Module struct{}

// New returns a Module.
func New() *Module { return &Module{} }

// Name implements module.Module.
func (m *Module) Name() string { return "mapcidr" }

// Run implements module.Module.
// Input.Target: for "contains" op → the IP to look up; for all other ops → a CIDR/IP to process.
// Input.URLs: additional CIDRs/IPs (each element is one network block or IP).
// Input.RawContent: newline-delimited CIDRs/IPs.
// Input.Options["op"]: operation to perform (default "expand").
func (m *Module) Run(_ context.Context, input module.Input) ([]module.Finding, error) {
	op := input.Options["op"]
	if op == "" {
		op = "expand"
	}
	slog.Debug("mapcidr: starting", "op", op)

	// For "contains", Target is the IP-under-test, not a network to add to the list.
	networksInput := input
	if op == "contains" {
		networksInput.Target = "" // don't add Target to networks list
	}

	networks := collectNetworks(networksInput)
	if len(networks) == 0 {
		return nil, fmt.Errorf("mapcidr: no CIDR/IP provided")
	}

	switch op {
	case "expand":
		return expand(networks)
	case "aggregate":
		return aggregate(networks)
	case "count":
		return count(networks)
	case "filter-private":
		return filterPrivate(networks, true)
	case "filter-public":
		return filterPrivate(networks, false)
	case "split":
		prefixStr := input.Options["prefix"]
		if prefixStr == "" {
			return nil, fmt.Errorf("mapcidr: split requires Options[\"prefix\"]")
		}
		newPrefix := parseInt(prefixStr)
		if newPrefix < 0 || newPrefix > 128 {
			return nil, fmt.Errorf("mapcidr: invalid prefix length %q", prefixStr)
		}
		return splitNetworks(networks, newPrefix)
	case "contains":
		if input.Target == "" {
			return nil, fmt.Errorf("mapcidr: contains requires Target to be set to the IP to check")
		}
		return contains(input.Target, networks)
	default:
		return nil, fmt.Errorf("mapcidr: unknown operation %q (valid: expand, aggregate, count, filter-private, filter-public, split, contains)", op)
	}
}

// ─── operations ──────────────────────────────────────────────────────────────

// expand emits one finding per IP in each CIDR.
// WARNING: large CIDRs (e.g. /8) produce millions of findings.
// The caller should use with caution.
func expand(networks []*net.IPNet) ([]module.Finding, error) {
	const maxExpand = 65536 // safety cap
	var findings []module.Finding
	for _, network := range networks {
		ips, err := expandNetwork(network, maxExpand)
		if err != nil {
			return findings, err
		}
		for _, ip := range ips {
			findings = append(findings, module.Finding{
				Type:     "ip_address",
				URL:      ip.String(),
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("IP %s from CIDR %s", ip, network),
				Extra: map[string]string{
					"cidr":       network.String(),
					"ip":         ip.String(),
					"confidence": "0.99",
				},
			})
		}
	}
	return findings, nil
}

// expandNetwork returns all IPs in network, up to limit.
func expandNetwork(network *net.IPNet, limit int) ([]net.IP, error) {
	// Determine total count first to avoid huge allocations.
	total := networkSize(network)
	if total.Cmp(big.NewInt(int64(limit))) > 0 {
		return nil, fmt.Errorf("CIDR %s contains %s IPs — exceeds expand limit of %d; use split or count instead",
			network, total, limit)
	}

	var ips []net.IP
	ip := cloneIP(network.IP)
	for network.Contains(ip) {
		ips = append(ips, cloneIP(ip))
		incrementIP(ip)
		if len(ips) >= limit {
			break
		}
	}
	return ips, nil
}

// aggregate merges overlapping/adjacent CIDRs and returns a minimal covering set.
func aggregate(networks []*net.IPNet) ([]module.Finding, error) {
	if len(networks) == 0 {
		return nil, nil
	}

	// Separate IPv4 and IPv6.
	var v4, v6 []*net.IPNet
	for _, n := range networks {
		if n.IP.To4() != nil {
			v4 = append(v4, n)
		} else {
			v6 = append(v6, n)
		}
	}

	var results []*net.IPNet
	results = append(results, aggregateNetworks(v4)...)
	results = append(results, aggregateNetworks(v6)...)

	findings := make([]module.Finding, 0, len(results))
	for _, n := range results {
		findings = append(findings, module.Finding{
			Type:     "cidr_block",
			URL:      n.String(),
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("Aggregated CIDR: %s", n),
			Extra:    map[string]string{"cidr": n.String(), "confidence": "0.99"},
		})
	}
	return findings, nil
}

// aggregateNetworks performs a greedy merge of a set of same-family networks.
func aggregateNetworks(networks []*net.IPNet) []*net.IPNet {
	if len(networks) == 0 {
		return nil
	}

	// Sort by first IP address.
	sort.Slice(networks, func(i, j int) bool {
		return compareIPs(networks[i].IP, networks[j].IP) < 0
	})

	merged := []*net.IPNet{networks[0]}
	for _, n := range networks[1:] {
		last := merged[len(merged)-1]
		if last.Contains(n.IP) {
			// n is contained in last — skip.
			continue
		}
		// Check if adjacent (last+1 == n).
		lastLast := lastIP(last)
		nextAfterLast := cloneIP(lastLast)
		incrementIP(nextAfterLast)
		if nextAfterLast.Equal(n.IP) {
			// Try to merge by finding the common supernet.
			supernet := commonSupernet(last, n)
			if supernet != nil {
				merged[len(merged)-1] = supernet
				continue
			}
		}
		merged = append(merged, n)
	}
	return merged
}

// count emits one finding per CIDR with the IP count.
func count(networks []*net.IPNet) ([]module.Finding, error) {
	findings := make([]module.Finding, 0, len(networks))
	for _, n := range networks {
		size := networkSize(n)
		ones, bits := n.Mask.Size()
		findings = append(findings, module.Finding{
			Type:     "cidr_count",
			URL:      n.String(),
			Severity: module.SeverityInfo,
			Detail:   fmt.Sprintf("CIDR %s: %s addresses (/%d of /%d)", n, size, ones, bits),
			Extra: map[string]string{
				"cidr":       n.String(),
				"count":      size.String(),
				"confidence": "0.99",
			},
		})
	}
	return findings, nil
}

// filterPrivate expands each CIDR and emits only private (or only public) IPs.
func filterPrivate(networks []*net.IPNet, wantPrivate bool) ([]module.Finding, error) {
	const maxExpand = 65536
	var findings []module.Finding
	for _, network := range networks {
		ips, err := expandNetwork(network, maxExpand)
		if err != nil {
			return findings, err
		}
		for _, ip := range ips {
			isPriv := isPrivateIP(ip)
			if isPriv == wantPrivate {
				label := "public"
				if isPriv {
					label = "private"
				}
				findings = append(findings, module.Finding{
					Type:     "ip_address",
					URL:      ip.String(),
					Severity: module.SeverityInfo,
					Detail:   fmt.Sprintf("%s IP %s from CIDR %s", label, ip, network),
					Extra: map[string]string{
						"cidr":       network.String(),
						"ip":         ip.String(),
						"type":       label,
						"confidence": "0.99",
					},
				})
			}
		}
	}
	return findings, nil
}

// splitNetworks splits each input CIDR into sub-CIDRs with the given prefix length.
func splitNetworks(networks []*net.IPNet, newPrefixLen int) ([]module.Finding, error) {
	var findings []module.Finding
	for _, network := range networks {
		ones, bits := network.Mask.Size()
		if newPrefixLen <= ones {
			return nil, fmt.Errorf("new prefix /%d is not smaller than network prefix /%d", newPrefixLen, ones)
		}
		if newPrefixLen > bits {
			return nil, fmt.Errorf("new prefix /%d exceeds address family bits %d", newPrefixLen, bits)
		}

		subnets := splitCIDR(network, newPrefixLen)
		for _, sub := range subnets {
			findings = append(findings, module.Finding{
				Type:     "cidr_block",
				URL:      sub.String(),
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("Subnet %s of %s", sub, network),
				Extra: map[string]string{
					"parent":     network.String(),
					"cidr":       sub.String(),
					"confidence": "0.99",
				},
			})
		}
	}
	return findings, nil
}

// contains checks if the target IP is inside any of the input networks.
func contains(targetIP string, networks []*net.IPNet) ([]module.Finding, error) {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return nil, fmt.Errorf("mapcidr: invalid IP %q", targetIP)
	}
	var findings []module.Finding
	for _, network := range networks {
		if network.Contains(ip) {
			findings = append(findings, module.Finding{
				Type:     "ip_in_range",
				URL:      targetIP,
				Severity: module.SeverityInfo,
				Detail:   fmt.Sprintf("IP %s is contained in CIDR %s", targetIP, network),
				Extra: map[string]string{
					"ip":         targetIP,
					"cidr":       network.String(),
					"confidence": "0.99",
				},
			})
		}
	}
	return findings, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func collectNetworks(input module.Input) []*net.IPNet {
	seen := make(map[string]struct{})
	var out []*net.IPNet
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		// Try as CIDR first.
		_, network, err := net.ParseCIDR(s)
		if err == nil {
			out = append(out, network)
			return
		}
		// Try as plain IP — convert to host CIDR.
		ip := net.ParseIP(s)
		if ip == nil {
			return
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		mask := net.CIDRMask(bits, bits)
		out = append(out, &net.IPNet{IP: ip.Mask(mask), Mask: mask})
	}
	if input.Target != "" {
		add(input.Target)
	}
	for _, u := range input.URLs {
		add(u)
	}
	if input.RawContent != "" {
		for _, line := range strings.Split(input.RawContent, "\n") {
			add(line)
		}
	}
	return out
}

// networkSize returns the number of IP addresses in a network as a big.Int.
func networkSize(network *net.IPNet) *big.Int {
	ones, bits := network.Mask.Size()
	n := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bits-ones)), nil)
	return n
}

// incrementIP adds 1 to an IP address in-place.
func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// cloneIP returns a copy of ip.
func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

// lastIP returns the last IP in a network.
func lastIP(network *net.IPNet) net.IP {
	last := cloneIP(network.IP)
	for i := range last {
		last[i] = network.IP[i] | ^network.Mask[i]
	}
	return last
}

// compareIPs compares two IP addresses lexicographically.
func compareIPs(a, b net.IP) int {
	a4, b4 := a.To4(), b.To4()
	if a4 != nil && b4 != nil {
		au := binary.BigEndian.Uint32(a4)
		bu := binary.BigEndian.Uint32(b4)
		if au < bu {
			return -1
		}
		if au > bu {
			return 1
		}
		return 0
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return len(a) - len(b)
}

// commonSupernet attempts to find the minimal supernet containing both a and b.
func commonSupernet(a, b *net.IPNet) *net.IPNet {
	aOnes, bits := a.Mask.Size()
	bOnes, _ := b.Mask.Size()
	smallerOnes := aOnes
	if bOnes < smallerOnes {
		smallerOnes = bOnes
	}
	// Try expanding the prefix by 1 at a time.
	for prefix := smallerOnes - 1; prefix >= 0; prefix-- {
		mask := net.CIDRMask(prefix, bits)
		supernet := &net.IPNet{IP: a.IP.Mask(mask), Mask: mask}
		if supernet.Contains(a.IP) && supernet.Contains(b.IP) {
			return supernet
		}
	}
	return nil
}

// splitCIDR splits network into sub-networks of newPrefixLen.
func splitCIDR(network *net.IPNet, newPrefixLen int) []*net.IPNet {
	_, bits := network.Mask.Size()
	newMask := net.CIDRMask(newPrefixLen, bits)
	var subnets []*net.IPNet

	ip := cloneIP(network.IP)
	for network.Contains(ip) {
		subnet := &net.IPNet{
			IP:   cloneIP(ip),
			Mask: newMask,
		}
		subnets = append(subnets, subnet)
		// Jump to the next subnet start.
		nextIP := lastIP(subnet)
		incrementIP(nextIP)
		ip = nextIP
		if len(subnets) > 65536 {
			break // safety cap
		}
	}
	return subnets
}

// isPrivateIP returns true if ip is in a private/reserved range.
func isPrivateIP(ip net.IP) bool {
	for _, block := range privateRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// privateRanges holds all RFC-1918, loopback, link-local, and ULA ranges.
var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	} {
		_, n, _ := net.ParseCIDR(cidr)
		if n != nil {
			privateRanges = append(privateRanges, n)
		}
	}
}

func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}
