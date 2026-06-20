// Package wifite2 provides a wrapper around the wifite2 wireless auditing tool.
//
// Wifite2 (https://github.com/derv82/wifite2) automates WPA/WPA2/WEP/WPS
// attacks against wireless access points using captured handshakes, PMKID
// attacks and WPS PINs.
//
// # Authorization Required
//
// Wireless auditing requires explicit written authorization from the network
// owner. This module enforces the presence of Options["authorized"]="true"
// before executing any scan or attack phase. Unauthorized use is illegal under
// CFAA, Brazil's Lei 12.737/2012, and similar legislation worldwide.
//
// # Architecture
//
// The module orchestrates wifite2 via exec.CommandContext. Three operating
// modes are supported:
//
//	"scan"   — passive scan only (no attack); lists nearby APs and clients
//	"audit"  — full automated attack sequence (WPS → PMKID → handshake crack)
//	"crack"  — offline crack of a previously captured .cap/.hccapx file
//
// wifite2 must be installed and accessible in PATH (or via Options["wifite_path"]).
// Requires root/sudo and a monitor-mode capable wireless adapter.
//
// # Input Options
//
//	"authorized"   — REQUIRED: must be "true" to run
//	"mode"         — "scan" | "audit" | "crack" (default: "scan")
//	"interface"    — wireless interface, e.g. "wlan0mon" (default: first suitable)
//	"wifite_path"  — path to wifite2 binary (default: "wifite")
//	"timeout"      — seconds before process is killed (default: 120)
//	"channel"      — restrict to specific channel, e.g. "6"
//	"wordlist"     — path to wordlist for offline crack
//	"target_bssid" — restrict scan/audit to specific BSSID
//	"target_essid" — restrict scan/audit to specific ESSID
//	"crack_file"   — .cap/.hccapx file path for "crack" mode
//	"extra_args"   — raw extra arguments appended to wifite2 command
//
// # Output
//
// Findings include:
//   - "wifi_ap"       — discovered access point with BSSID, ESSID, channel, power, encryption
//   - "wifi_client"   — client associated with an AP
//   - "wifi_crack"    — successfully cracked PSK with plaintext password
//   - "wifi_handshake"— captured WPA handshake (.cap file path)
//   - "wifi_pmkid"    — captured PMKID (clientless attack)
//   - "wifi_wps_pin"  — cracked WPS PIN
package wifite2

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const (
	moduleName     = "wifite2"
	defaultTimeout = 120 * time.Second
)

// ─── Module ───────────────────────────────────────────────────────────────────

// Module wraps the wifite2 tool.
type Module struct {
	logger     *slog.Logger
	wifitePath string // resolved binary path
}

// New returns a Module with production defaults.
func New() *Module {
	return &Module{
		logger:     slog.Default().With("module", moduleName),
		wifitePath: "wifite",
	}
}

// NewWithPath returns a Module using the given wifite2 binary path (testability).
func NewWithPath(path string) *Module {
	m := New()
	m.wifitePath = path
	return m
}

// Name satisfies module.Module.
func (m *Module) Name() string { return moduleName }

// Run orchestrates wifite2.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	opts := input.Options

	// ── Authorization gate ───────────────────────────────────────────────────
	if !strings.EqualFold(optStr(opts, "authorized", ""), "true") {
		return nil, fmt.Errorf(
			"wifite2: authorization required — set Options[\"authorized\"]=\"true\" to confirm you have explicit written permission from the network owner",
		)
	}

	mode := strings.ToLower(optStr(opts, "mode", "scan"))
	timeout := time.Duration(optInt(opts, "timeout", 120)) * time.Second

	wifitePath := optStr(opts, "wifite_path", m.wifitePath)
	// Resolve path
	if resolved, err := exec.LookPath(wifitePath); err == nil {
		wifitePath = resolved
	}

	m.logger.InfoContext(ctx, "wifite2: starting",
		"mode", mode, "timeout", timeout, "binary", wifitePath)

	switch mode {
	case "scan":
		return m.runScan(ctx, opts, wifitePath, timeout)
	case "audit":
		return m.runAudit(ctx, opts, wifitePath, timeout)
	case "crack":
		return m.runCrack(ctx, opts, wifitePath, timeout)
	default:
		return nil, fmt.Errorf("wifite2: unknown mode %q — use scan|audit|crack", mode)
	}
}

// ─── Scan mode ────────────────────────────────────────────────────────────────

// runScan passively discovers APs and clients without attacking.
func (m *Module) runScan(ctx context.Context, opts map[string]string, wifite string, timeout time.Duration) ([]module.Finding, error) {
	args := []string{"--kill", "--no-deauth", "--dict", "/dev/null"}

	if iface := optStr(opts, "interface", ""); iface != "" {
		args = append(args, "-i", iface)
	}
	if ch := optStr(opts, "channel", ""); ch != "" {
		args = append(args, "--channel", ch)
	}
	if bssid := optStr(opts, "target_bssid", ""); bssid != "" {
		args = append(args, "--bssid", bssid)
	}
	if essid := optStr(opts, "target_essid", ""); essid != "" {
		args = append(args, "--essid", essid)
	}
	if extra := optStr(opts, "extra_args", ""); extra != "" {
		args = append(args, strings.Fields(extra)...)
	}

	out, err := m.runBinary(ctx, wifite, args, timeout)
	if err != nil {
		return nil, fmt.Errorf("wifite2 scan: %w", err)
	}

	return parseScanOutput(out), nil
}

// ─── Audit mode ───────────────────────────────────────────────────────────────

// runAudit runs a full automated attack sequence.
func (m *Module) runAudit(ctx context.Context, opts map[string]string, wifite string, timeout time.Duration) ([]module.Finding, error) {
	args := []string{"--kill", "--no-deauth"}

	if iface := optStr(opts, "interface", ""); iface != "" {
		args = append(args, "-i", iface)
	}
	if ch := optStr(opts, "channel", ""); ch != "" {
		args = append(args, "--channel", ch)
	}
	if bssid := optStr(opts, "target_bssid", ""); bssid != "" {
		args = append(args, "--bssid", bssid)
	}
	if essid := optStr(opts, "target_essid", ""); essid != "" {
		args = append(args, "--essid", essid)
	}
	if wl := optStr(opts, "wordlist", ""); wl != "" {
		args = append(args, "--dict", wl)
	}
	if extra := optStr(opts, "extra_args", ""); extra != "" {
		args = append(args, strings.Fields(extra)...)
	}

	out, err := m.runBinary(ctx, wifite, args, timeout)
	if err != nil && !isPartialOutput(out) {
		return nil, fmt.Errorf("wifite2 audit: %w", err)
	}

	return parseAuditOutput(out), nil
}

// ─── Crack mode ───────────────────────────────────────────────────────────────

// runCrack runs an offline crack against a captured .cap/.hccapx file.
func (m *Module) runCrack(ctx context.Context, opts map[string]string, wifite string, timeout time.Duration) ([]module.Finding, error) {
	capFile := optStr(opts, "crack_file", "")
	if capFile == "" && len(optStr(opts, "target", "")) > 0 {
		// fall back to Target field
		capFile = optStr(opts, "target", "")
	}
	if capFile == "" {
		return nil, fmt.Errorf("wifite2 crack: provide Options[\"crack_file\"] with path to .cap or .hccapx")
	}

	wordlist := optStr(opts, "wordlist", "")
	if wordlist == "" {
		return nil, fmt.Errorf("wifite2 crack: provide Options[\"wordlist\"] with path to wordlist file")
	}

	args := []string{"--crack", "--capfile", capFile, "--dict", wordlist}
	if extra := optStr(opts, "extra_args", ""); extra != "" {
		args = append(args, strings.Fields(extra)...)
	}

	out, err := m.runBinary(ctx, wifite, args, timeout)
	if err != nil && !isPartialOutput(out) {
		return nil, fmt.Errorf("wifite2 crack: %w", err)
	}

	return parseCrackOutput(out, capFile), nil
}

// ─── Binary execution ─────────────────────────────────────────────────────────

func (m *Module) runBinary(ctx context.Context, wifite string, args []string, timeout time.Duration) ([]byte, error) {
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Check binary exists before running
	if _, err := exec.LookPath(wifite); err != nil {
		return nil, fmt.Errorf("wifite2 binary not found in PATH (%q): install via 'pip install wifite2' or 'apt install wifite'", wifite)
	}

	cmd := exec.CommandContext(tctx, wifite, args...)
	m.logger.DebugContext(ctx, "wifite2: exec", "cmd", cmd.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	if stderr.Len() > 0 {
		m.logger.DebugContext(ctx, "wifite2 stderr", "output", stderr.String())
	}

	combined := append(stdout.Bytes(), stderr.Bytes()...)
	return combined, err
}

// ─── Output parsers ───────────────────────────────────────────────────────────

var (
	// AP line: columns vary; look for BSSID (MAC), power, channel, encryption, essid
	reMAC       = regexp.MustCompile(`(?i)([0-9a-f]{2}(?::[0-9a-f]{2}){5})`)
	reChannel   = regexp.MustCompile(`(?i)(?:CH|channel)\s*(\d+)`)
	rePower     = regexp.MustCompile(`(?i)(-?\d+)\s*dBm`)
	reEncrypt   = regexp.MustCompile(`(?i)(WPA[23]?[-_/]?(?:CCMP|TKIP|EAP)?|WEP|OPEN|OWE)`)
	rePassword  = regexp.MustCompile(`(?i)(?:password|psk|key|pass)\s*[=:]\s*(\S+)`)
	reCracked   = regexp.MustCompile(`(?i)(?:cracked|found)\s+(?:psk|password|key|pass):\s*(\S+)`)
	reHandshake = regexp.MustCompile(`(?i)handshake\s+(?:saved|captured|found).*?([^\s]+\.cap)`)
	rePMKID     = regexp.MustCompile(`(?i)pmkid\s+(?:saved|captured|found).*?([^\s]+\.pmkid)`)
	reWPSPin    = regexp.MustCompile(`(?i)wps\s+pin\s*[=:]\s*(\d{4,8})`)
)

// parseScanOutput extracts AP and client findings from wifite2 scan output.
func parseScanOutput(out []byte) []module.Finding {
	var findings []module.Finding
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		lc := strings.ToLower(line)

		// Skip noise
		if isNoiseLine(lc) {
			continue
		}

		bssidMatches := reMAC.FindAllString(line, -1)
		if len(bssidMatches) == 0 {
			continue
		}

		bssid := bssidMatches[0]
		if seen[bssid] {
			continue
		}

		extra := map[string]string{
			"bssid":      bssid,
			"raw_line":   strings.TrimSpace(line),
			"confidence": "0.90", // MAC address confirmed in scan output
		}

		if m := rePower.FindStringSubmatch(line); len(m) > 1 {
			extra["power_dbm"] = m[1]
		}
		if m := reChannel.FindStringSubmatch(line); len(m) > 1 {
			extra["channel"] = m[1]
		}
		if m := reEncrypt.FindStringSubmatch(line); len(m) > 1 {
			extra["encryption"] = strings.ToUpper(m[1])
		}

		// Second MAC = client
		isClient := len(bssidMatches) > 1 && strings.Contains(lc, "client")
		findingType := "wifi_ap"
		detail := fmt.Sprintf("AP discovered: BSSID %s", bssid)
		if isClient {
			findingType = "wifi_client"
			extra["ap_bssid"] = bssidMatches[0]
			extra["client_mac"] = bssidMatches[1]
			detail = fmt.Sprintf("Client %s associated to AP %s", bssidMatches[1], bssidMatches[0])
			extra["confidence"] = "0.85" // association inferred from output line
		}

		seen[bssid] = true
		findings = append(findings, module.Finding{
			Type:     findingType,
			URL:      "",
			Detail:   detail,
			Severity: module.SeverityInfo,
			Extra:    extra,
		})
	}

	return findings
}

// parseAuditOutput extracts results from an active audit run.
func parseAuditOutput(out []byte) []module.Finding {
	findings := parseScanOutput(out)

	// Crack results
	if m := reCracked.FindSubmatch(out); len(m) > 1 {
		password := string(m[1])
		findings = append(findings, module.Finding{
			Type:     "wifi_crack",
			Detail:   fmt.Sprintf("WPA PSK cracked: password recovered"),
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"password":   password, // dicas.md §18: in audit reports, PSK is the evidence
				"confidence": "0.99",   // wifite2 confirms PSK via 4-way handshake validation
			},
		})
	}

	// Handshake capture
	if m := reHandshake.FindSubmatch(out); len(m) > 1 {
		capPath := string(m[1])
		findings = append(findings, module.Finding{
			Type:     "wifi_handshake",
			Detail:   fmt.Sprintf("WPA handshake captured to %s", filepath.Base(capPath)),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"cap_file":   capPath,
				"confidence": "0.95", // file path confirmed in wifite2 output
			},
		})
	}

	// PMKID
	if m := rePMKID.FindSubmatch(out); len(m) > 1 {
		findings = append(findings, module.Finding{
			Type:     "wifi_pmkid",
			Detail:   fmt.Sprintf("PMKID captured to %s (clientless attack possible)", filepath.Base(string(m[1]))),
			Severity: module.SeverityMedium,
			Extra: map[string]string{
				"pmkid_file": string(m[1]),
				"confidence": "0.95",
			},
		})
	}

	// WPS PIN
	if m := reWPSPin.FindSubmatch(out); len(m) > 1 {
		pin := string(m[1])
		findings = append(findings, module.Finding{
			Type:     "wifi_wps_pin",
			Detail:   fmt.Sprintf("WPS PIN cracked: %s", pin),
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"wps_pin":    pin,
				"confidence": "0.99",
			},
		})
	}

	return findings
}

// parseCrackOutput extracts crack results from offline mode.
func parseCrackOutput(out []byte, capFile string) []module.Finding {
	var findings []module.Finding

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()

		if m := reCracked.FindStringSubmatch(line); len(m) > 1 {
			findings = append(findings, module.Finding{
				Type:     "wifi_crack",
				Detail:   fmt.Sprintf("PSK recovered from %s", filepath.Base(capFile)),
				Severity: module.SeverityHigh,
				Extra: map[string]string{
					"password":   m[1],
					"cap_file":   capFile,
					"confidence": "0.99",
				},
			})
		} else if m := rePassword.FindStringSubmatch(line); len(m) > 1 {
			findings = append(findings, module.Finding{
				Type:     "wifi_crack",
				Detail:   fmt.Sprintf("PSK recovered from %s", filepath.Base(capFile)),
				Severity: module.SeverityHigh,
				Extra: map[string]string{
					"password":   m[1],
					"cap_file":   capFile,
					"confidence": "0.98",
				},
			})
		}
	}

	if len(findings) == 0 {
		// Crack ran but found nothing
		findings = append(findings, module.Finding{
			Type:     "wifi_crack",
			Detail:   fmt.Sprintf("Crack completed on %s — no PSK found in wordlist", filepath.Base(capFile)),
			Severity: module.SeverityInfo,
			Extra: map[string]string{
				"cap_file":   capFile,
				"result":     "not_cracked",
				"confidence": "0.95",
			},
		})
	}

	return findings
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func isNoiseLine(lc string) bool {
	noise := []string{
		"[+]", "[*]", "[!]", "starting", "enabling", "monitor mode",
		"ctrl+c", "press", "scanning", "no targets", "---",
	}
	for _, n := range noise {
		if strings.Contains(lc, n) {
			return true
		}
	}
	return false
}

// isPartialOutput returns true when wifite2 produced usable output before dying.
func isPartialOutput(out []byte) bool {
	return reMAC.Match(out) || reCracked.Match(out) || reHandshake.Match(out)
}

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
