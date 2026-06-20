// osint-personal — valida módulos OSINT contra dados pessoais reais.
// Uso: go run ./cmd/osint-personal
package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/anatel"
	"github.com/DonatoReis/blackhorn-modules/modules/emailosint"
	"github.com/DonatoReis/blackhorn-modules/modules/hibp"
	"github.com/DonatoReis/blackhorn-modules/modules/namesearch"
	"github.com/DonatoReis/blackhorn-modules/modules/phonelookup"
	"github.com/DonatoReis/blackhorn-modules/modules/sherlock"
	"github.com/DonatoReis/blackhorn-modules/modules/socialscan"
	"github.com/DonatoReis/blackhorn-modules/modules/userlookup"
	"github.com/DonatoReis/blackhorn-modules/modules/whatsapp"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Alvos ───────────────────────────────────────────────────────────────────

const (
	targetEmail    = "caique.hbarreto@gmail.com"
	targetUsername = "creisbarreto"
	targetPhone    = "17996499505"
	targetName     = "Caique Henrique Barreto"
)

// ─── Impressão ───────────────────────────────────────────────────────────────

func printFindings(modName string, findings []module.Finding, err error, elapsed time.Duration) {
	bar := strings.Repeat("─", 60)
	fmt.Printf("\n%s\n", bar)
	fmt.Printf("  Módulo: %-20s  [%s]\n", modName, elapsed.Round(time.Millisecond))
	fmt.Printf("%s\n", bar)

	if err != nil {
		fmt.Printf("  ERRO: %v\n", err)
		return
	}

	if len(findings) == 0 {
		fmt.Println("  (sem findings)")
		return
	}

	// Ordena por severity decrescente
	order := map[module.Severity]int{
		module.SeverityCritical: 5,
		module.SeverityHigh:     4,
		module.SeverityMedium:   3,
		module.SeverityLow:      2,
		module.SeverityInfo:     1,
	}
	sort.Slice(findings, func(i, j int) bool {
		return order[findings[i].Severity] > order[findings[j].Severity]
	})

	for i, f := range findings {
		sevIcon := severityIcon(f.Severity)
		fmt.Printf("  [%d] %s %-10s  %s\n", i+1, sevIcon, string(f.Severity), f.Type)
		if f.URL != "" {
			fmt.Printf("       URL:    %s\n", f.URL)
		}
		if f.Detail != "" {
			fmt.Printf("       Detail: %s\n", f.Detail)
		}
		if conf, ok := f.Extra["confidence"]; ok {
			fmt.Printf("       Conf:   %s\n", conf)
		}
		// Extras relevantes
		for k, v := range f.Extra {
			if k == "confidence" || v == "" {
				continue
			}
			fmt.Printf("       %s: %s\n", k, v)
		}
		fmt.Println()
	}
}

func severityIcon(s module.Severity) string {
	switch s {
	case module.SeverityCritical:
		return "!!"
	case module.SeverityHigh:
		return "! "
	case module.SeverityMedium:
		return "~ "
	case module.SeverityLow:
		return "- "
	default:
		return "  "
	}
}

// ─── Execução de um módulo ───────────────────────────────────────────────────

func run(ctx context.Context, m interface {
	Name() string
	Run(context.Context, module.Input) ([]module.Finding, error)
}, input module.Input) {
	start := time.Now()
	ff, err := m.Run(ctx, input)
	printFindings(m.Name(), ff, err, time.Since(start))
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║          OSINT PESSOAL — VALIDAÇÃO DE MÓDULOS           ║")
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Printf("║  E-mail:   %-46s║\n", targetEmail)
	fmt.Printf("║  Username: %-46s║\n", "@"+targetUsername)
	fmt.Printf("║  Telefone: %-46s║\n", targetPhone)
	fmt.Printf("║  Nome:     %-46s║\n", targetName)
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Opções comuns — chaves de API via env vars
	commonOpts := map[string]string{}

	// ─── 1. E-MAIL ───────────────────────────────────────────────────────────

	fmt.Println("\n══════════ E-MAIL ══════════")

	run(ctx, hibp.New(), module.Input{
		Target:  targetEmail,
		Options: commonOpts,
	})

	run(ctx, emailosint.New(), module.Input{
		Target:  targetEmail,
		Options: commonOpts,
	})

	// ─── 2. USERNAME ─────────────────────────────────────────────────────────

	fmt.Println("\n══════════ USERNAME ══════════")

	run(ctx, sherlock.New(), module.Input{
		Target:  targetUsername,
		Options: commonOpts,
	})

	run(ctx, userlookup.New(), module.Input{
		Target:  targetUsername,
		Options: commonOpts,
	})

	run(ctx, socialscan.New(), module.Input{
		Target:  targetUsername,
		Options: commonOpts,
	})

	// ─── 3. TELEFONE ─────────────────────────────────────────────────────────

	fmt.Println("\n══════════ TELEFONE ══════════")

	run(ctx, anatel.New(), module.Input{
		Target:  targetPhone,
		Options: commonOpts,
	})

	run(ctx, phonelookup.New(), module.Input{
		Target:  targetPhone,
		Options: commonOpts,
	})

	run(ctx, whatsapp.New(), module.Input{
		Target:  targetPhone,
		Options: commonOpts,
	})

	// ─── 4. NOME ─────────────────────────────────────────────────────────────

	fmt.Println("\n══════════ NOME ══════════")

	run(ctx, namesearch.New(), module.Input{
		Target:  targetName,
		Options: commonOpts,
	})

	// ─── Sumário ─────────────────────────────────────────────────────────────

	fmt.Println()
	fmt.Println(strings.Repeat("═", 62))
	fmt.Println("  Execução concluída.")
	fmt.Println(strings.Repeat("═", 62))
	os.Exit(0)
}
