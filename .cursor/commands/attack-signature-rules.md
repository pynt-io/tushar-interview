# attack-signature-rules

Implement a **configurable Attack Signature Rules engine in Go only** (ignore Python). Build it as a production-style CLI feature/service that loads YAML rules, matches OpenAPI endpoints, applies mutations, evaluates detection conditions, and prints structured results — then exits.

Use any text after this command as optional extra constraints (e.g. scope cuts, package names). If none is provided, implement the full prioritized feature below.

---

## Goal

Externalize hardcoded attack patterns into YAML rules so security researchers can add/modify/version signatures without redeploying engine code.

Given `--rules <dir>` and `--spec <file>`, the engine must:

1. Load all YAML rules from the directory (skip invalid files gracefully with a clear warning)
2. Parse OpenAPI endpoints via the existing `go/pkg/specparser` package (reuse; do not rewrite unless necessary)
3. Match rules to endpoints by path pattern + HTTP method
4. Apply mutations to produce attack request variants
5. Evaluate detection conditions against a response (or a simulated/stub response if HTTP is out of scope)
6. Emit structured results: rule ID, target endpoint, pass/fail (vulnerable / not), evidence
7. Exit successfully after printing results

**Expected usage (from `go/` module root):**

```bash
go run ./cmd/engine --rules ../rules --spec ../sample_specs/petstore.yaml
```

Do **not** modify existing input fixtures: `rules/`, `sample_specs/`.

---

## Prioritization (ship working code first)

Prefer an end-to-end runnable path over incomplete breadth:

1. **Must have:** rule loader + validation + path/method matcher + `parameter_swap` + CLI wiring + structured output
2. **Should have:** `header_inject` + detection evaluation
3. **Nice to have:** real HTTP execution of mutated requests

A working loader + matcher + `parameter_swap` beats a non-running full design.

---

## Rule semantics (implement exactly)

### Rule schema (YAML)

Each file describes one attack test with fields: `rule`, `name`, `severity`, `target.path_pattern`, `target.methods`, `mutations[]`, `detection[]`.

**Examples already in repo:**

- `rules/bola_users.yaml` — `parameter_swap` / BOLA
- `rules/auth_bypass.yaml` — `header_inject`
- `rules/invalid_rule.yaml` — intentionally invalid (missing `target`); must not crash the process

### Matching

- Match when method is in `target.methods` **and** path matches `target.path_pattern`
- `{param}` in a pattern is a named path segment placeholder (e.g. `/users/{userId}` matches `/users/{userId}` from the OpenAPI template, and also concrete paths like `/users/42` if present)
- `*` matches **exactly one** path segment: `/admin/*` matches `/admin/dashboard`, does **not** match `/admin/dashboard/settings`

### Mutations (extensible by design)

Implement these two types; design so new types are easy to add (strategy / registry, not a giant switch buried in the engine):

**`parameter_swap`**

- Target like `path.userId`
- Strategy `increment`: for a concrete numeric segment value `N`, produce variants with `N+1` and `N-1` (do not mutate the original request object in place — clone/copy)
- When the endpoint path is still a template (e.g. `/users/{userId}`), derive a concrete demo value (e.g. `42`) for swap variants so the tool still produces useful output on the sample OpenAPI templates

**`header_inject`**

- Target like `header.Authorization`
- Set/replace that header to the given `value` on a cloned request variant

### Detection

A detection entry matches when **all** of its conditions are true:

- `status_code` equals response status
- `body_contains` (if set) is found in response body

If any detection entry matches → vulnerability found (fail / vulnerable). Otherwise pass / not vulnerable. Include evidence (matched status, body snippet, mutation applied).

---

## Required Go project structure (MNC / idiomatic layout)

Work inside the existing `go/` module (`module interview`). Expand into a layered layout used by large Go orgs. Prefer `internal/` for app code; keep reusable parsers in `pkg/`.

```text
go/
├── cmd/
│   └── engine/
│       └── main.go              # thin CLI: flags, wiring, os.Exit only
├── internal/
│   ├── domain/                  # pure types: Rule, Mutation, Detection, EndpointResult, RequestVariant
│   ├── loader/                  # load + validate YAML rules from a directory
│   ├── matcher/                 # path pattern + method matching
│   ├── mutation/                # Mutator interface + registry; parameter_swap, header_inject
│   ├── detection/               # evaluate detection conditions against a Response
│   ├── engine/                  # orchestrates: load → match → mutate → (optional) detect → results
│   ├── output/                  # format structured results (JSON and/or human-readable table)
│   └── config/                  # CLI/runtime options (rules dir, spec path, output format)
├── pkg/
│   └── specparser/              # EXISTING — reuse ParseSpec / Endpoint
├── go.mod
└── go.sum
```

**Layer rules:**

| Layer | Responsibility | May depend on |
|-------|----------------|---------------|
| `cmd/engine` | flags, DI/wiring, print, exit codes | `internal/*`, `pkg/*` |
| `internal/engine` | use-case orchestration | domain, loader, matcher, mutation, detection |
| `internal/loader` | YAML I/O + schema validation | domain |
| `internal/matcher` | path/method match | domain |
| `internal/mutation` | produce request variants | domain |
| `internal/detection` | match response to detection rules | domain |
| `internal/domain` | types + small pure helpers only | stdlib only |
| `pkg/specparser` | OpenAPI → endpoints | stdlib + yaml |

Do **not** put business logic in `main.go`. Do **not** invent a long-running HTTP server — this is a batch CLI.

---

## Go design patterns to apply

1. **Strategy + Registry** for mutations: `type Mutator interface { Type() string; Apply(req Request, m Mutation) ([]RequestVariant, error) }` registered by type name (`parameter_swap`, `header_inject`). Adding a new mutation = new file + register.
2. **Constructor injection** (`NewEngine(loader, matcher, mutators, detector)`), no global mutable state.
3. **Fail soft on bad rules:** invalid YAML / missing required fields → log/warn and continue with valid rules; only hard-fail if zero rules loaded when the directory is empty/unreadable, or flags are missing.
4. **Immutable-ish request flow:** clone before mutate; never share mutable header maps across variants.
5. **Table-driven unit tests** for matcher, loader validation, and each mutator.
6. **Errors wrapped** with `%w` and context (`fmt.Errorf("load rule %s: %w", path, err)`).
7. **Interfaces at the consumer side** only where they enable extension/testing (mutator, optional HTTP client). Avoid interface bloat.

---

## Implementation steps (follow in order)

1. Define `internal/domain` types mirroring the YAML schema and result/evidence structs.
2. Implement `internal/loader` with validation (require `rule`, `name`, `target.path_pattern`, `target.methods`, at least one mutation).
3. Implement `internal/matcher` with segment-aware `{param}` and single-segment `*` matching; cover with tests.
4. Implement mutation registry + `parameter_swap` (+ `header_inject` if time).
5. Implement `internal/detection` (even if responses are stubbed for dry-run).
6. Wire `internal/engine` to: parse spec → load rules → for each endpoint find matching rules → apply mutations → evaluate detection (stub or real) → collect results.
7. Update `cmd/engine/main.go` to call the engine and print results; keep `main` thin.
8. Run against repo test data and fix until it works:

```bash
cd go
go test ./...
go run ./cmd/engine --rules ../rules --spec ../sample_specs/petstore.yaml
```

---

## Output contract

Print structured results for each rule×endpoint execution. Prefer JSON lines or a single JSON array plus a short human summary. Each result must include at least:

- `rule_id`
- `rule_name` / `severity` (optional but useful)
- `endpoint` (method + path)
- `status`: `vulnerable` | `not_vulnerable` | `skipped` | `error`
- `mutations_applied` (type + key details)
- `variants` (mutated path/headers)
- `evidence` (why detection matched or not; or skip reason)

Also report how many rule files were loaded vs skipped as invalid.

---

## Acceptance checklist

- [ ] `go run ./cmd/engine --rules ../rules --spec ../sample_specs/petstore.yaml` runs and exits
- [ ] Invalid rule file does not crash the process
- [ ] `BOLA-001` matches `GET/PUT /users/{userId}` and produces increment variants
- [ ] `AUTH-BYPASS-001` matches `GET /admin/dashboard` and `GET /admin/users`, not deeper paths
- [ ] Mutation types are pluggable via interface/registry
- [ ] Layout uses `cmd/` + `internal/` layers as above
- [ ] `go test ./...` passes for loader/matcher/mutation packages
- [ ] No Python code added; do not change `rules/` or `sample_specs/` fixtures

---

## Out of scope / constraints

- Do not build a long-running microservice, gRPC API, or web UI
- Do not rewrite `pkg/specparser` unless a bug blocks you
- Do not add unrelated refactors or docs unless needed to run the tool
- Keep dependencies minimal (stdlib + existing `gopkg.in/yaml.v3`)

When done, briefly summarize: package layout created, how to run, and any intentional scope cuts.
