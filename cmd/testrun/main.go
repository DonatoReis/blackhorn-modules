// testrun — runner temporário para testar módulos blackhorn contra um alvo real.
// Uso: go run ./cmd/testrun <target>
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"

	"github.com/DonatoReis/blackhorn-modules/modules/alterx"
	"github.com/DonatoReis/blackhorn-modules/modules/asnmap"
	"github.com/DonatoReis/blackhorn-modules/modules/cdncheck"
	"github.com/DonatoReis/blackhorn-modules/modules/corsaudit"
	"github.com/DonatoReis/blackhorn-modules/modules/crawler"
	"github.com/DonatoReis/blackhorn-modules/modules/dnsaudit"
	"github.com/DonatoReis/blackhorn-modules/modules/dnsprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/ffuf"
	"github.com/DonatoReis/blackhorn-modules/modules/fingerprint"
	"github.com/DonatoReis/blackhorn-modules/modules/gau"
	"github.com/DonatoReis/blackhorn-modules/modules/graphql"
	"github.com/DonatoReis/blackhorn-modules/modules/headeraudit"
	"github.com/DonatoReis/blackhorn-modules/modules/httpxpro"
	"github.com/DonatoReis/blackhorn-modules/modules/katana"
	"github.com/DonatoReis/blackhorn-modules/modules/mapcidr"
	"github.com/DonatoReis/blackhorn-modules/modules/oauthprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/openredirect"
	"github.com/DonatoReis/blackhorn-modules/modules/paramdisc"
	"github.com/DonatoReis/blackhorn-modules/modules/paramspider"
	"github.com/DonatoReis/blackhorn-modules/modules/pathprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/portscanner"
	"github.com/DonatoReis/blackhorn-modules/modules/recon"
	"github.com/DonatoReis/blackhorn-modules/modules/shuffledns"
	"github.com/DonatoReis/blackhorn-modules/modules/subdiscovery"
	"github.com/DonatoReis/blackhorn-modules/modules/takeover"
	"github.com/DonatoReis/blackhorn-modules/modules/tlsaudit"
	"github.com/DonatoReis/blackhorn-modules/modules/tlsfinder"
	"github.com/DonatoReis/blackhorn-modules/modules/truffler"
	"github.com/DonatoReis/blackhorn-modules/modules/udpprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/urlparse"
	"github.com/DonatoReis/blackhorn-modules/modules/verbtamper"
	"github.com/DonatoReis/blackhorn-modules/modules/vulnscan"
	"github.com/DonatoReis/blackhorn-modules/modules/vulnx"
	"github.com/DonatoReis/blackhorn-modules/modules/wayback"
	"github.com/DonatoReis/blackhorn-modules/modules/webprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/whois"
	"github.com/DonatoReis/blackhorn-modules/modules/xssreflect"
)

const target = "tetraquimicametal.com.br"
const targetURL = "https://tetraquimicametal.com.br"

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	type result struct {
		module   string
		findings []module.Finding
		err      error
		elapsed  time.Duration
	}

	type runner struct {
		name string
		run  func(ctx context.Context) ([]module.Finding, error)
	}

	runners := []runner{
		// ── DNS / Network ──────────────────────────────────────────────────
		{
			name: "dnsprobe",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return dnsprobe.New().Run(ctx, module.Input{Target: target})
			},
		},
		{
			name: "whois",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return whois.New().Run(ctx, module.Input{Target: target})
			},
		},
		{
			name: "dnsaudit",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return dnsaudit.New().Run(ctx, module.Input{Target: target})
			},
		},
		{
			name: "subdiscovery",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return subdiscovery.New().Run(ctx, module.Input{Target: target})
			},
		},
		{
			name: "recon",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return recon.New().Run(ctx, module.Input{Target: target})
			},
		},
		{
			name: "tlsfinder",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return tlsfinder.New().Run(ctx, module.Input{Target: target})
			},
		},
		{
			name: "asnmap",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return asnmap.New().Run(ctx, module.Input{Target: target})
			},
		},
		{
			name: "cdncheck",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return cdncheck.New().Run(ctx, module.Input{Target: target})
			},
		},
		{
			name: "alterx",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return alterx.New().Run(ctx, module.Input{
					Target:  target,
					Options: map[string]string{"max_results": "20"},
				})
			},
		},
		{
			name: "shuffledns",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return shuffledns.New().Run(ctx, module.Input{
					Target:  target,
					Options: map[string]string{"max_results": "30"},
				})
			},
		},
		{
			name: "mapcidr",
			run: func(ctx context.Context) ([]module.Finding, error) {
				// resolve IP first
				return mapcidr.New().Run(ctx, module.Input{
					Target:  "189.112.0.0/16",
					Options: map[string]string{"op": "count"},
				})
			},
		},

		// ── HTTP probing ────────────────────────────────────────────────────
		{
			name: "webprobe",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return webprobe.New().Run(ctx, module.Input{Target: targetURL})
			},
		},
		{
			name: "httpxpro",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return httpxpro.New().Run(ctx, module.Input{Target: targetURL})
			},
		},
		{
			name: "fingerprint",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return fingerprint.New().Run(ctx, module.Input{Target: targetURL})
			},
		},
		{
			name: "headeraudit",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return headeraudit.New().Run(ctx, module.Input{Target: targetURL})
			},
		},
		{
			name: "tlsaudit",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return tlsaudit.New().Run(ctx, module.Input{Target: target})
			},
		},
		{
			name: "corsaudit",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return corsaudit.New().Run(ctx, module.Input{Target: targetURL})
			},
		},

		// ── URL discovery ───────────────────────────────────────────────────
		{
			name: "wayback",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return wayback.New().Run(ctx, module.Input{Target: target})
			},
		},
		{
			name: "gau",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return gau.New().Run(ctx, module.Input{
					Target:  target,
					Options: map[string]string{"max_urls": "50"},
				})
			},
		},
		{
			name: "urlparse",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return urlparse.New().Run(ctx, module.Input{
					Target: targetURL,
					URLs:   []string{targetURL + "/contato", targetURL + "/produtos?cat=metal"},
				})
			},
		},

		// ── Crawling ────────────────────────────────────────────────────────
		{
			name: "crawler",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return crawler.New().Run(ctx, module.Input{
					Target:  targetURL,
					Options: map[string]string{"depth": "2", "parallelism": "5"},
				})
			},
		},
		{
			name: "katana",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return katana.New().Run(ctx, module.Input{
					Target:  targetURL,
					Options: map[string]string{"depth": "2", "parallelism": "4"},
				})
			},
		},
		{
			name: "paramspider",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return paramspider.New().Run(ctx, module.Input{Target: target})
			},
		},
		{
			name: "paramdisc",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return paramdisc.New().Run(ctx, module.Input{
					Target:  targetURL,
					Options: map[string]string{"wordlist": "small"},
				})
			},
		},

		// ── Fuzzing / Path ──────────────────────────────────────────────────
		{
			name: "pathprobe",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return pathprobe.New().Run(ctx, module.Input{
					Target:  targetURL,
					Options: map[string]string{"parallelism": "10"},
				})
			},
		},
		{
			name: "ffuf",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return ffuf.New().Run(ctx, module.Input{
					Target:  targetURL,
					Options: map[string]string{"mode": "dir", "max_urls": "30"},
				})
			},
		},

		// ── Port scanning ───────────────────────────────────────────────────
		{
			name: "portscanner",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return portscanner.New().Run(ctx, module.Input{
					Target:  target,
					Options: map[string]string{"ports": "top100", "timeout_ms": "3000"},
				})
			},
		},
		{
			name: "udpprobe",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return udpprobe.New().Run(ctx, module.Input{
					Target:  target,
					Options: map[string]string{"service": "dns,ntp,snmp", "timeout_ms": "3000"},
				})
			},
		},

		// ── Vulnerability scanning ──────────────────────────────────────────
		{
			name: "vulnscan",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return vulnscan.New().Run(ctx, module.Input{
					Target:  targetURL,
					Options: map[string]string{"parallelism": "10"},
				})
			},
		},
		{
			name: "vulnx",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return vulnx.New().Run(ctx, module.Input{Target: targetURL})
			},
		},
		{
			name: "headeraudit (sec)",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return headeraudit.New().Run(ctx, module.Input{Target: targetURL})
			},
		},

		// ── Attack surface ──────────────────────────────────────────────────
		{
			name: "xssreflect",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return xssreflect.New().Run(ctx, module.Input{
					Target: targetURL + "/?q=test",
					URLs:   []string{targetURL + "/busca?s=test"},
				})
			},
		},
		{
			name: "openredirect",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return openredirect.New().Run(ctx, module.Input{
					Target: targetURL + "/?url=FUZZ",
					URLs:   []string{targetURL + "/?redirect=FUZZ"},
				})
			},
		},
		{
			name: "verbtamper",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return verbtamper.New().Run(ctx, module.Input{
					Target: targetURL,
					URLs:   []string{targetURL + "/admin", targetURL + "/api"},
				})
			},
		},
		{
			name: "takeover",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return takeover.New().Run(ctx, module.Input{Target: target})
			},
		},
		{
			name: "graphql",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return graphql.New().Run(ctx, module.Input{Target: targetURL})
			},
		},
		{
			name: "oauthprobe",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return oauthprobe.New().Run(ctx, module.Input{Target: targetURL})
			},
		},
		{
			name: "truffler",
			run: func(ctx context.Context) ([]module.Finding, error) {
				return truffler.New().Run(ctx, module.Input{Target: targetURL})
			},
		},
	}

	results := make([]result, 0, len(runners))

	fmt.Printf("\n╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  BLACKHORN MODULES — Teste real: %-28s║\n", target)
	fmt.Printf("╚══════════════════════════════════════════════════════════════╝\n\n")

	for _, r := range runners {
		fmt.Printf("  ▶ %-22s", r.name)
		start := time.Now()
		findings, err := r.run(ctx)
		elapsed := time.Since(start)

		if err != nil {
			fmt.Printf(" ✗ ERRO: %v\n", err)
		} else {
			fmt.Printf(" ✓ %3d findings  (%s)\n", len(findings), elapsed.Round(time.Millisecond))
		}

		results = append(results, result{
			module:   r.name,
			findings: findings,
			err:      err,
			elapsed:  elapsed,
		})
	}

	// Print detailed findings per module
	fmt.Printf("\n\n═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("  FINDINGS DETALHADOS\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")

	severityOrder := map[module.Severity]int{
		module.SeverityCritical: 0,
		module.SeverityHigh:     1,
		module.SeverityMedium:   2,
		module.SeverityLow:      3,
		module.SeverityInfo:     4,
	}

	for _, r := range results {
		if len(r.findings) == 0 {
			continue
		}

		// Sort by severity
		sort.Slice(r.findings, func(i, j int) bool {
			return severityOrder[r.findings[i].Severity] < severityOrder[r.findings[j].Severity]
		})

		fmt.Printf("\n┌─ [%s] — %d findings\n", strings.ToUpper(r.module), len(r.findings))
		for i, f := range r.findings {
			if i >= 20 {
				fmt.Printf("│  ... e mais %d findings\n", len(r.findings)-20)
				break
			}
			icon := severityIcon(f.Severity)
			fmt.Printf("│  %s [%s] %s\n", icon, f.Severity, f.Type)
			if f.URL != "" {
				fmt.Printf("│    URL: %s\n", f.URL)
			}
			if f.Detail != "" {
				detail := f.Detail
				if len(detail) > 100 {
					detail = detail[:100] + "..."
				}
				fmt.Printf("│    %s\n", detail)
			}
			// Print key Extra fields
			keyFields := []string{"tech", "version", "server", "status_code", "record_type", "value", "service", "port", "asn", "cidr"}
			for _, k := range keyFields {
				if v, ok := f.Extra[k]; ok && v != "" {
					fmt.Printf("│    %s: %s\n", k, v)
				}
			}
		}
		fmt.Printf("└─────────────────────────────────────────────\n")
	}

	// Summary table
	fmt.Printf("\n\n═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("  SUMÁRIO\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("  %-25s  %7s  %8s  %8s\n", "Módulo", "Findings", "Tempo", "Status")
	fmt.Printf("  %s\n", strings.Repeat("─", 55))

	totalFindings := 0
	totalModules := 0
	okModules := 0
	for _, r := range results {
		totalModules++
		status := "✓ ok"
		if r.err != nil {
			status = "✗ err"
		} else {
			okModules++
		}
		totalFindings += len(r.findings)
		fmt.Printf("  %-25s  %7d  %8s  %s\n", r.module, len(r.findings), r.elapsed.Round(time.Millisecond), status)
	}
	fmt.Printf("  %s\n", strings.Repeat("─", 55))
	fmt.Printf("  %-25s  %7d  %8s  %d/%d ok\n\n", "TOTAL", totalFindings, "", okModules, totalModules)

	// JSON output to file
	outFile := "/tmp/blackhorn_test_results.json"
	type jsonResult struct {
		Module    string           `json:"module"`
		Findings  []module.Finding `json:"findings"`
		Error     string           `json:"error,omitempty"`
		ElapsedMs int64            `json:"elapsed_ms"`
	}
	var jsonResults []jsonResult
	for _, r := range results {
		jr := jsonResult{
			Module:    r.module,
			Findings:  r.findings,
			ElapsedMs: r.elapsed.Milliseconds(),
		}
		if r.err != nil {
			jr.Error = r.err.Error()
		}
		jsonResults = append(jsonResults, jr)
	}
	if b, err := json.MarshalIndent(jsonResults, "", "  "); err == nil {
		if err := os.WriteFile(outFile, b, 0644); err == nil {
			fmt.Printf("  JSON completo salvo em: %s\n\n", outFile)
		}
	}
}

func severityIcon(s module.Severity) string {
	switch s {
	case module.SeverityCritical:
		return "🔴"
	case module.SeverityHigh:
		return "🟠"
	case module.SeverityMedium:
		return "🟡"
	case module.SeverityLow:
		return "🔵"
	default:
		return "⚪"
	}
}
