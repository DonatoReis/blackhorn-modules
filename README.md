# BLACKHORN Modules

Native Go security modules used by the
[BLACKHORN](https://github.com/DonatoReis/blackhorn) desktop orchestrator.

The repository contains 122 registered modules for reconnaissance, DNS,
network discovery, HTTP auditing, web vulnerability checks, cloud analysis,
threat intelligence, Brazilian OSINT, and utility workflows. Modules return
typed findings and run in-process without requiring a separate executable.

## Design goals

- High precision: candidates and confirmed observations are explicitly
  separated.
- Bounded execution: network fan-out has context, concurrency, response-size,
  runtime, and result limits.
- Explainability: findings carry source, confidence, validation state, and
  context-promotion metadata.
- Testability: network integrations use injected clients, resolvers, or
  dialers and local test servers.
- Composability: every module implements one small interface and is described
  in the central registry.

## Requirements

- Go 1.26.4 or a newer compatible patch release.

## Use

```go
package main

import (
	"context"
	"log"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/registry"
)

func main() {
	native, err := registry.New("headeraudit")
	if err != nil {
		log.Fatal(err)
	}

	findings, err := native.Run(context.Background(), module.Input{
		Target: "https://example.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%d findings", len(findings))
}
```

Browse available modules through `registry.All()` or
[`pkg/registry/catalog.go`](pkg/registry/catalog.go).

## Validate

```bash
go fmt ./...
go vet ./...
go test -race ./...
go build ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Benchmarks live in [`benchmarks`](benchmarks), and fuzz targets live in
[`fuzz`](fuzz).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and the
[Code of Conduct](CODE_OF_CONDUCT.md). Contributions should include
deterministic tests and explain how evidence, confidence, false positives, and
execution limits are handled.

## Responsible use

Use these modules only on assets you own or are explicitly authorized to
assess. Do not submit real credentials, private target data, or unauthorized
scan output.

## License

[MIT](LICENSE)
