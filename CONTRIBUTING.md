# Contributing to BLACKHORN Modules

Contributions are welcome through issues and pull requests.

## Requirements

- Go 1.26.4 or a newer compatible patch release.
- Tests must not depend on public targets. Use local test servers, injected
  clients, resolvers, dialers, and deterministic fixtures.
- Modules must implement `pkg/module.Module` and be registered in
  `pkg/registry/catalog.go`.
- Network fan-out must propagate `context.Context`, enforce concurrency and
  runtime limits, and cap response bodies and result counts.
- Candidate data must not be presented as confirmed. Use explicit evidence
  metadata such as `validated`, `validation_state`, `confidence`, and
  `promote_to_context`.
- Never commit real credentials, private targets, scan results, or personal
  data.

## Local checks

```bash
go fmt ./...
go vet ./...
go test -race ./...
go build ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
gitleaks git --redact --no-banner
```

## Pull requests

Keep changes focused. Describe the behavior changed, the evidence behind the
classification, limits introduced, tests added, and any remaining uncertainty.
Security modules must favor precision over finding volume.

By contributing, you agree that your contribution is licensed under the MIT
License.
