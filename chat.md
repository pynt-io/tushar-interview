# Configurable attack signature rules
_Exported on 7/17/2026 at 16:51:53 GMT+5:30 from Cursor (3.11.19)_

---

**User**

Write commands in @.cursor/commands/attack-signature-rules.md to create new service/feature based on below feature/service in golang.
The Scenario
Radware's engine container runs automated security tests against customer APIs. Today, attack patterns are hardcoded in the engine. We want to externalize these patterns into configurable rules so that our security research team can add, modify, and version attack signatures without deploying new engine code.

Your job is to build the core of this rule engine.

Feature Request: Configurable Attack Signature Rules
We want to externalize our attack patterns into a rule format that security researchers can author without writing code. Here's what we need:

Rules are defined in YAML files. Each rule describes one attack test.
A rule specifies: which API endpoints it targets (by path pattern and HTTP method), how to mutate the original request (headers, query params, body), and what response pattern indicates a vulnerability was found.
The engine loads all rules from a directory, matches them against a given API endpoint, and executes the matching rules.
Each rule execution should produce a structured result: rule ID, target endpoint, pass/fail, evidence.
The Rule Format
Below are the two mutation types your engine needs to support: parameter_swap and header_inject. Implement these two types - you don't need to invent others, but your design should make it easy to add new types in the future.

parameter_swap - Replaces a path parameter with modified values

This rule says: "For any endpoint matching /users/{userId} on GET or PUT, try swapping the user ID (e.g., change 42 to 43). If the API still returns 200 with an email field in the body, it's likely vulnerable to Broken Object Level Authorization."

rule: BOLA-001
name: "Broken Object Level Authorization"
severity: high
target:
  path_pattern: "/users/{userId}"
  methods: [GET, PUT]
mutations:
  - type: parameter_swap
    target: path.userId
    strategy: increment    # try id+1 and id-1
detection:
  - status_code: 200
    body_contains: "email"
How parameter_swap works: Given an endpoint /users/42, the increment strategy produces two attack variants: one with /users/43 and one with /users/41. The original request is not modified.

header_inject - Sets or replaces an HTTP header

rule: AUTH-BYPASS-001
name: "Authorization Header Bypass"
severity: critical
target:
  path_pattern: "/api/v1/admin/*"
  methods: [GET, POST]
mutations:
  - type: header_inject
    target: header.Authorization
    value: ""
detection:
  - status_code: 200
How header_inject works: Takes the original request and creates a variant with the specified header set to the given value. If the header already exists, it's replaced.

Detection (what "vulnerability found" means)
The detection section describes what response pattern indicates the endpoint is vulnerable. A detection matches when all its conditions are true:

status_code — the HTTP response status code equals this value
body_contains — the response body contains this string
If a rule has status_code: 200 and body_contains: "email", it only triggers when both are true.

API Endpoints Input
The repo includes a ready-to-use OpenAPI parser (spec_parser.py , parser.go) that reads a spec file and returns typed Endpoint objects.

Each Endpoint has .path (e.g., "/users/{userId}"), .method (e.g., "GET"), and an optional .operation_id. You can use this parser as-is or modify it if needed.

Your engine matches rules against these endpoints. For example, the rule targeting /users/{userId} with methods [GET, PUT] should match both GET /users/{userId} and PUT /users/{userId}, but not GET /products.

A * wildcard in a rule pattern matches exactly one path segment: /admin/* matches /admin/dashboard but NOT /admin/dashboard/settings.

What We Need
Given a directory of YAML rule files and an API endpoint, the engine should:

Load the rules
Figure out which rules apply to the endpoint
Modify the request according to the rule's mutations
Determine if the response indicates a vulnerability

Expected usage:

go main.go --rules ./rules --spec ./sample_specs/petstore.yaml
It’s not a long-running service. It runs, produces output, and exits.

Test Data
The rules/ directory in this repo contains sample YAML files you can use to test your implementation. One of them is intentionally invalid - your engine should handle that gracefully.

The sample_specs/ directory contains an OpenAPI spec you can use.

You can (and should) run your tool against this test data before submitting to verify it works

What to Prioritize
We'd rather see a code that runs end-to-end on the test data with fewer features, than more code that doesn't execute.

Specifically:

A working loader + matcher + at least parameter_swap is more valuable than a non-working full implementation

Write feature/code in golang which follows go design patterns, write go project structure which is used by all mnc's. Add all the layers whichever is needed to write any new feature/service

We need to write code in go only so you can ignore python related stuff. Use python reference if needed to write code in golang.

---

**Cursor**

I'll read the existing command file and look at how other commands in this repo are structured so the new ones match.

I'll inspect the existing Go layout and sample rules so the command can target the right structure and 

layers.

Writing a detailed `/attack-signature-rules` command that instructs the agent to build the Go rule engine with enterprise-style layers and design patterns.

Updated `.cursor/commands/attack-signature-rules.md` into a slash command you can run with `/attack-signature-rules`.

It tells the agent to:

- Build a **Go-only** batch CLI (reuse `pkg/specparser`, ignore Python)
- Use an **MNC-style layout**: `cmd/engine` + `internal/{domain,loader,matcher,mutation,detection,engine,output,config}`
- Apply **strategy/registry** for mutations so new types are easy to add
- Ship in priority order: loader → matcher → `parameter_swap` → then `header_inject` / detection
- Handle invalid rules gracefully and verify against `../rules` + `../sample_specs/petstore.yaml`

Invoke it in chat as `/attack-signature-rules` (optionally add scope notes after the command).

---

**User**

Okay now use @.cursor/commands/attack-signature-rules.md  to write the code of this feature. Let me know if you need any info from my side.

The Scenario
Radware's engine container runs automated security tests against customer APIs. Today, attack patterns are hardcoded in the engine. We want to externalize these patterns into configurable rules so that our security research team can add, modify, and version attack signatures without deploying new engine code.

Your job is to build the core of this rule engine.

Feature Request: Configurable Attack Signature Rules
We want to externalize our attack patterns into a rule format that security researchers can author without writing code. Here's what we need:

Rules are defined in YAML files. Each rule describes one attack test.
A rule specifies: which API endpoints it targets (by path pattern and HTTP method), how to mutate the original request (headers, query params, body), and what response pattern indicates a vulnerability was found.
The engine loads all rules from a directory, matches them against a given API endpoint, and executes the matching rules.
Each rule execution should produce a structured result: rule ID, target endpoint, pass/fail, evidence.
The Rule Format
Below are the two mutation types your engine needs to support: parameter_swap and header_inject. Implement these two types - you don't need to invent others, but your design should make it easy to add new types in the future.

parameter_swap - Replaces a path parameter with modified values

This rule says: "For any endpoint matching /users/{userId} on GET or PUT, try swapping the user ID (e.g., change 42 to 43). If the API still returns 200 with an email field in the body, it's likely vulnerable to Broken Object Level Authorization."

rule: BOLA-001
name: "Broken Object Level Authorization"
severity: high
target:
  path_pattern: "/users/{userId}"
  methods: [GET, PUT]
mutations:
  - type: parameter_swap
    target: path.userId
    strategy: increment    # try id+1 and id-1
detection:
  - status_code: 200
    body_contains: "email"
How parameter_swap works: Given an endpoint /users/42, the increment strategy produces two attack variants: one with /users/43 and one with /users/41. The original request is not modified.

header_inject - Sets or replaces an HTTP header

rule: AUTH-BYPASS-001
name: "Authorization Header Bypass"
severity: critical
target:
  path_pattern: "/api/v1/admin/*"
  methods: [GET, POST]
mutations:
  - type: header_inject
    target: header.Authorization
    value: ""
detection:
  - status_code: 200
How header_inject works: Takes the original request and creates a variant with the specified header set to the given value. If the header already exists, it's replaced.

Detection (what "vulnerability found" means)
The detection section describes what response pattern indicates the endpoint is vulnerable. A detection matches when all its conditions are true:

status_code — the HTTP response status code equals this value
body_contains — the response body contains this string
If a rule has status_code: 200 and body_contains: "email", it only triggers when both are true.

API Endpoints Input
The repo includes a ready-to-use OpenAPI parser (spec_parser.py , parser.go) that reads a spec file and returns typed Endpoint objects.

Each Endpoint has .path (e.g., "/users/{userId}"), .method (e.g., "GET"), and an optional .operation_id. You can use this parser as-is or modify it if needed.

Your engine matches rules against these endpoints. For example, the rule targeting /users/{userId} with methods [GET, PUT] should match both GET /users/{userId} and PUT /users/{userId}, but not GET /products.

A * wildcard in a rule pattern matches exactly one path segment: /admin/* matches /admin/dashboard but NOT /admin/dashboard/settings.

What We Need
Given a directory of YAML rule files and an API endpoint, the engine should:

Load the rules
Figure out which rules apply to the endpoint
Modify the request according to the rule's mutations
Determine if the response indicates a vulnerability

Expected usage:

go main.go --rules ./rules --spec ./sample_specs/petstore.yaml
It’s not a long-running service. It runs, produces output, and exits.

Test Data
The rules/ directory in this repo contains sample YAML files you can use to test your implementation. One of them is intentionally invalid - your engine should handle that gracefully.

The sample_specs/ directory contains an OpenAPI spec you can use.

You can (and should) run your tool against this test data before submitting to verify it works

What to Prioritize
We'd rather see a code that runs end-to-end on the test data with fewer features, than more code that doesn't execute.

Specifically:

A working loader + matcher + at least parameter_swap is more valuable than a non-working full implementation

---

**Cursor**

I have enough to implement this — no blockers. Building the Go rule engine per the command: layered `internal/` packages, both mutation types, and an end-to-end CLI run against the sample data.

Creating the domain layer and core packages next.

Refactoring to avoid double-loading rules, then adding tests.

Improving JSON field names on `Request` for cleaner output.

Implemented and verified end-to-end. No extra info needed from you.

### Layout
```text
go/
├── cmd/engine/main.go
├── internal/
│   ├── domain/       # Rule, Request, Result types
│   ├── loader/       # YAML load + validate (skips invalid)
│   ├── matcher/      # path `{param}` + single-segment `*`
│   ├── mutation/     # registry + parameter_swap + header_inject
│   ├── detection/    # AND conditions per detection entry
│   ├── engine/       # orchestration
│   ├── output/       # human + JSON
│   └── config/
└── pkg/specparser/   # reused as-is
```

### Run
```bash
cd go
go test ./...
go run ./cmd/engine --rules ../rules --spec ../sample_specs/petstore.yaml
```

### Verified against fixtures
- Loads 2 valid rules, skips `invalid_rule.yaml` with a warning
- `BOLA-001` → `GET/PUT /users/{userId}` with variants `/users/43` and `/users/41`
- `AUTH-BYPASS-001` → `GET /admin/dashboard` and `GET /admin/users` (not deeper paths)
- Mutations are pluggable via a registry

### Scope cut
No live HTTP calls — results are `skipped` (dry-run) with generated variants and detection criteria recorded. Detection evaluation is implemented and unit-tested for when responses are available.

---

**User**

There are lot of error I can see in files. for e.g this kind of error:
could not import interview/internal/config (cannot find package "interview/internal/config" in GOROOT or GOPATH)
How to fix this error? 

---

**Cursor**

Those import errors usually mean the IDE is resolving packages from the wrong module root. Checking the Go module layout and how the workspace is set up.

The code is fine — `go.mod` lives under `go/`, but the workspace is the repo root, so the language server can't find the module. Adding a `go.work` at the repo root so imports resolve.

**Cause:** The module root is `go/go.mod` (`module interview`), but Cursor is opened at the repo root. Without a workspace file, gopls falls back to GOPATH and can’t resolve `interview/...`.

**Fix applied:**
1. Added `go.work` at the repo root pointing at `./go`
2. Added `.vscode/settings.json` with `go.workingDirectory` set to `go/` (local only — `.vscode/` is gitignored)

**If red squiggles remain:** reload the window — Command Palette → **Developer: Reload Window** (or restart the Go language server).

The imports are correct; the tooling just wasn’t looking at the right `go.mod`.

---

**User**

Now explain me the code whatever you have written step by step with example so that if anybody ask I can explain them too

---

**Cursor**

I'll walk through the code against the actual packages so the explanation matches what's in the repo.

# How the Attack Signature Rules Engine Works

## What problem does this solve?

Security attack patterns used to be hardcoded in the engine. Now researchers write YAML rules, and the engine:

1. Loads rules  
2. Matches them to API endpoints from an OpenAPI spec  
3. Mutates requests (attack variants)  
4. Checks if the response looks like a vulnerability  

It is a **CLI batch tool**: run once, print results, exit.

---

## Big picture: request flow

```text
go run ./cmd/engine --rules ../rules --spec ../sample_specs/petstore.yaml
        │
        ▼
   cmd/engine/main.go          ← flags only, wires dependencies
        │
        ▼
   internal/engine             ← orchestrator
        │
        ├── loader      → read YAML rules (skip bad ones)
        ├── specparser  → read OpenAPI → endpoints
        ├── matcher     → which rules apply to which endpoint?
        ├── mutation    → create attack request variants
        ├── detection   → would this response mean “vulnerable”?
        └── output      → print human + JSON results
```

**One-liner for interviews:**  
*“`main` is thin. `engine` orchestrates. Each package has one job: load, match, mutate, detect, print.”*

---

## Why this folder layout?

| Package | Job | Analogy |
|---------|-----|---------|
| `domain` | Shared types only (`Rule`, `Request`, `Result`) | Shared vocabulary |
| `loader` | Read + validate YAML | Config ingestion |
| `matcher` | Path/method matching | Filter |
| `mutation` | Pluggable attack transforms | Strategy pattern |
| `detection` | Response → vulnerable? | Predicate |
| `engine` | Glue the pipeline | Use-case / service |
| `cmd/engine` | CLI entrypoint | Thin adapter |

This is the usual Go / MNC style: `cmd/` for binaries, `internal/` for app code, `pkg/` for reusable libs.

---

## Step 1 — Entry point (`cmd/engine/main.go`)

```20:43:go/cmd/engine/main.go
func main() {
	rulesDir := flag.String("rules", "", "Path to rules directory")
	specPath := flag.String("spec", "", "Path to OpenAPI spec file")
	flag.Parse()
	// ...
	eng := engine.New(mutation.DefaultRegistry())
	summary, err := eng.Run(config.Options{...})
	output.WriteHuman(os.Stdout, summary, summary.Warnings)
}
```

**What to say:**  
*“`main` only parses flags, builds the engine with a mutator registry, runs it, and prints. No business logic here.”*

---

## Step 2 — Domain types (`internal/domain`)

These mirror the YAML.

Example rule (`rules/bola_users.yaml`):

```yaml
rule: BOLA-001
name: "Broken Object Level Authorization"
target:
  path_pattern: "/users/{userId}"
  methods: [GET, PUT]
mutations:
  - type: parameter_swap
    target: path.userId
    strategy: increment
detection:
  - status_code: 200
    body_contains: "email"
```

Maps to Go roughly as:

- `Rule` → whole file  
- `Target` → who it applies to  
- `Mutation` → how to change the request  
- `Detection` → what response means “vulnerable”  
- `Request` / `RequestVariant` → original vs attack requests  
- `ExecutionResult` → one rule × one endpoint outcome  

`Request.Clone()` is important: mutations never change the original request in place.

---

## Step 3 — Loader (`internal/loader`)

**Job:** read every `.yaml` in a directory, validate, soft-fail on bad files.

**Validation requires:** `rule`, `name`, `target.path_pattern`, `target.methods`, at least one mutation.

**Example with repo data:**

| File | Result |
|------|--------|
| `bola_users.yaml` | Loaded |
| `auth_bypass.yaml` | Loaded |
| `invalid_rule.yaml` | Skipped (missing `target`) + warning |

**What to say:**  
*“One bad rule must not crash the run. We warn and continue with valid rules.”*

---

## Step 4 — Spec parser (`pkg/specparser`)

Existing helper. Petstore becomes endpoints like:

- `GET /users/{userId}`
- `PUT /users/{userId}`
- `GET /admin/dashboard`
- `GET /admin/users`
- `GET /products`
- …

Engine matches **rules × these endpoints**.

---

## Step 5 — Matcher (`internal/matcher`)

A rule matches if **method is allowed AND path matches**.

Path matching is **segment by segment**:

| Pattern segment | Meaning |
|-----------------|--------|
| `users` | Must equal `users` |
| `{userId}` | Any one segment (`42` or `{userId}`) |
| `*` | Exactly one segment |

**Examples:**

| Rule pattern | Endpoint | Match? |
|--------------|----------|--------|
| `/users/{userId}` + GET | `GET /users/{userId}` | Yes |
| `/users/{userId}` + GET | `GET /products` | No |
| `/admin/*` + GET | `GET /admin/dashboard` | Yes |
| `/admin/*` + GET | `GET /admin/dashboard/settings` | No (`*` is one segment only) |

That last point is a common interview question — answer: *“`*` is one segment, not a recursive wildcard.”*

---

## Step 6 — Mutations (Strategy + Registry)

### Design pattern

```go
type Mutator interface {
    Type() string
    Apply(req Request, m Mutation) ([]RequestVariant, error)
}
```

Registry is a map: `"parameter_swap"` → `ParameterSwap{}`, `"header_inject"` → `HeaderInject{}`.

**Why?** Adding `query_inject` later = new file + `Register(...)`. Engine code does not grow a giant `switch`.

### `parameter_swap` example

Rule says: swap `path.userId` with strategy `increment`.

Input path from OpenAPI: `/users/{userId}`  
(We don’t have a real ID, so we use demo value `42`.)

Produces **two clones**:

1. `/users/43` (id + 1)  
2. `/users/41` (id - 1)  

Original `/users/{userId}` is unchanged.

If path were already concrete `/users/10` → variants `/users/11` and `/users/9`.

### `header_inject` example

Rule: set `header.Authorization` to `""`.

Base request has `Authorization: Bearer demo-token`.  
Variant has `Authorization: ""` (empty = bypass attempt).  
Original headers stay intact because we clone first.

---

## Step 7 — Engine orchestration (`internal/engine`)

Pseudo-code of what `Run` does:

```text
rules = load(rulesDir)
endpoints = parse(spec)

for each endpoint:
  for each rule:
    if matcher.Match(rule, endpoint):
      variants = registry.Apply(baseRequest, rule.mutations)
      record result (rule_id, endpoint, variants, evidence)
```

**Concrete run on sample data:**

| Endpoint | Matching rule | Variants |
|----------|---------------|----------|
| `GET /users/{userId}` | BOLA-001 | `/users/43`, `/users/41` |
| `PUT /users/{userId}` | BOLA-001 | same |
| `GET /admin/dashboard` | AUTH-BYPASS-001 | Authorization cleared |
| `GET /admin/users` | AUTH-BYPASS-001 | same |
| `GET /products` | none | — |

---

## Step 8 — Detection (`internal/detection`)

Logic:

- Within **one** detection entry: conditions are **AND**  
- Across **multiple** entries: **OR** (any entry match ⇒ vulnerable)

Example:

```yaml
detection:
  - status_code: 200
    body_contains: "email"
```

| Response | Vulnerable? |
|----------|-------------|
| `200` + body has `"email"` | Yes |
| `200` + body `{"id":1}` | No |
| `403` + body has `"email"` | No |

**Current scope cut:** we do **not** send real HTTP. Detection code exists and is unit-tested; live run marks status `skipped` (dry-run) and records *what would be checked*.

If asked “how would you finish this?”:  
*“Add an HTTP client, send each variant, pass `Response` into `detection.Evaluate`, set status to `vulnerable` / `not_vulnerable`.”*

---

## Step 9 — Output

Each result includes:

- `rule_id`, `endpoint`, `status`
- `mutations_applied`
- `variants` (mutated path/headers)
- `evidence`

Plus summary: rules loaded vs skipped.

---

## How to explain the design in 30 seconds

> “We externalized attack signatures into YAML. The CLI loads rules and an OpenAPI spec, matches rules to endpoints by path pattern and method, then applies pluggable mutations via a registry — today `parameter_swap` and `header_inject`. Each run produces structured results with evidence. Invalid rules are skipped, not fatal. Detection is implemented but dry-run for now since we don’t hit a live API.”

---

## Common follow-up questions (short answers)

| Question | Answer |
|----------|--------|
| Why `internal/`? | App code not importable by other modules |
| Why registry not `switch`? | Open/closed — new mutation types without editing engine |
| Why clone requests? | Avoid shared mutable state across variants |
| Why soft-fail invalid YAML? | Research team files shouldn’t kill the whole scan |
| Does `*` match nested paths? | No — exactly one segment |
| What’s next? | Real HTTP execution + mark vulnerable/not_vulnerable |

If you want, I can also turn this into a short “cheat sheet” markdown file under `ai-conversation/` for the interview submission.

---

**User**

yes do it

---

**Cursor**

Created [ai-conversation/cheat-sheet.md](ai-conversation/cheat-sheet.md) with the pipeline, package layout, worked examples, design patterns, and likely Q&A.

You can skim that before explaining, or attach it with the interview AI conversation export.

---

**User**

This is the output it's generating:
@/Users/piyush_tiwari/.cursor/projects/Users-piyush-tiwari-go-src-piyush-interview/terminals/1.txt:22-226 

Explain me what this output means in simple terms? what are we printing?

---

**Cursor**

In plain terms: the tool scanned the API and printed **which attack rules applied, what fake attack requests it would send, and why it didn’t mark anything vulnerable yet**.

---

### Top summary

```text
WARNING: skipping invalid_rule.yaml ...
Loaded 2 rule(s), skipped 1 invalid file(s), scanned 7 endpoint(s), produced 4 result(s)
```

| Line | Meaning |
|------|---------|
| Warning | One YAML file is broken (no `target`) → ignored, rest continues |
| Loaded 2 | `BOLA-001` and `AUTH-BYPASS-001` are valid |
| Scanned 7 | OpenAPI has 7 endpoints (users, admin, products, etc.) |
| Produced 4 | Only **4 rule×endpoint pairs** matched (not every endpoint gets every rule) |

---

### The 4 results (human section)

Each block is: **“Rule X hit endpoint Y → here’s the attack variant(s).”**

**[1] & [2] BOLA-001 on `PUT` / `GET /users/{userId}`**  
- Rule says: try changing the user id.  
- Spec only has `{userId}`, so we use demo id `42`.  
- Variants: call `/users/43` and `/users/41` (id+1 and id−1).  
- Idea: if another user’s data comes back, it’s a BOLA bug.

**[3] & [4] AUTH-BYPASS-001 on `/admin/dashboard` and `/admin/users`**  
- Rule says: clear the `Authorization` header.  
- Variant: same path, but `Authorization` is empty.  
- Idea: if admin still returns 200, auth may be bypassable.

Endpoints like `/products` don’t appear because **no rule matched them**.

---

### What does `status: skipped` mean?

Not “safe” and not “vulnerable.”

It means: **we built the attack requests, but we didn’t call a real API**, so we can’t decide pass/fail.  
Evidence says dry-run and what *would* count as vulnerable (e.g. status 200 + body contains `"email"`).

---

### What is the JSON block?

Same 4 results in machine-readable form (for tools/CI), including:

- `rule_id`, `endpoint`, `status`
- `mutations_applied` (what the rule asked for)
- `variants` (exact mutated method/path/headers)
- `evidence` (why status is skipped / what detection would check)

---

### One-sentence takeaway

You’re printing a **security test plan for this API**: which signatures apply, which mutated requests to try, and a note that detection is pending because there’s no live HTTP response yet.

---

**User**

Write .md file in go/ folder to explain the overview of project what we have done and how to run test cases, code or any use ful information which is useful for any person need to know when they look this project feature. By reding this readme.md file, they can understand what is happening even any non technocal person or any junior engineer.

---

**Cursor**

Created [go/README.md](go/README.md). It covers:

- What the feature does in plain language  
- How to run the tool and tests  
- What the output means  
- Sample data, flow with BOLA/auth examples  
- Folder layout and design choices  
- Status meanings and intentional dry-run limits  

Aimed at both non-technical readers and junior engineers.

