# Rule Engine CLI

This directory contains the Go implementation of the rule-based API security testing engine CLI.

## Build

From the `go` directory, run:

```powershell
cd C:\Users\Vishal\go\pkg\prasenjit-interview\go
go build ./cmd/engine
```

This produces `engine.exe` in the `go` directory.

## Run

Run the CLI with a rules directory and an OpenAPI spec file:

```powershell
cd C:\Users\Vishal\go\pkg\prasenjit-interview\go
.\engine.exe --rules ..\rules --spec ..\sample_specs\petstore.yaml
```

### Optional flags

- `--output <file>`
  - Write JSON results to the specified file instead of stdout.
- `--recursive`
  - Recursively search the rules directory for `.yaml` and `.yml` files.
- `--send`
  - Placeholder flag for request dispatch; the current version does not actually send HTTP requests.

## Example

```powershell
cd C:\Users\Vishal\go\pkg\prasenjit-interview\go
.\engine.exe --rules ..\rules --spec ..\sample_specs\petstore.yaml --output results.json
```

The CLI loads YAML rules from `..\rules`, parses endpoints from `..\sample_specs\petstore.yaml`, generates mutated attack requests, and prints structured results as JSON.

## Notes

- Rules are expected to be YAML files defining a `rule`, `target`, `mutations`, and optional `detection` section.
- The engine supports `parameter_swap` and `header_inject` mutation types.
- The `--send` flag is available for future request dispatch support, but it currently only generates results without making network calls.
