# Attack Signature Rules Engine (Go)

A small command-line tool that turns **security attack patterns** into **configurable YAML rules**, then checks which rules apply to an API described in an OpenAPI file.

You do **not** need to redeploy engine code when security researchers add or change a rule — they edit YAML instead.

---

## What problem does this solve? (plain English)

Imagine a security product that tests customer APIs for common bugs (for example: “Can user A see user B’s data?”).

**Before:** Those test patterns were hard-coded in the program. Changing a test meant changing code and shipping a new build.

**After:** Tests live in YAML files called **rules**. This tool:

1. Reads the rules
2. Reads the API definition (OpenAPI / Swagger)
3. Figures out which rules apply to which API endpoints
4. Builds modified “attack” requests (called **variants**)
5. Prints a clear report of what it would test

It runs once, prints results, and exits. It is **not** a long-running web server.

---

## Quick start

### Requirements

- Go **1.23+** installed ([https://go.dev/dl/](https://go.dev/dl/))

### Run the engine

From this `go/` folder:

```bash
cd go
go run ./cmd/engine --rules ../rules --spec ../sample_specs/petstore.yaml
```

| Flag | Meaning |
|------|---------|
| `--rules` | Folder containing YAML rule files |
| `--spec` | OpenAPI YAML file describing the API |

### Run the tests

```bash
cd go
go test ./...
```

That runs unit tests for loading rules, matching paths, mutations, and detection logic.

---

## What you should see when it works

A successful run looks roughly like this:

1. **A warning** about `invalid_rule.yaml` (expected — that file is intentionally broken)
2. A summary: how many rules loaded, how many endpoints scanned, how many matches
3. A short human-readable list of results
4. The same data again as **JSON** (useful for tools / CI)

Example (shortened):

```text
WARNING: skipping ../rules/invalid_rule.yaml: ...

Loaded 2 rule(s), skipped 1 invalid file(s), scanned 7 endpoint(s), produced 4 result(s)

[1] BOLA-001 (high) on GET /users/{userId} → skipped
    variant: GET /users/43 ...
    variant: GET /users/41 ...
```

### What does each part mean?

| Output | Simple meaning |
|--------|----------------|
| **Loaded / skipped rules** | Valid YAML accepted; broken YAML ignored with a warning |
| **Scanned endpoints** | Paths found in the OpenAPI file (e.g. `GET /users/{userId}`) |
| **Result block** | One pairing: “this rule applies to this endpoint” |
| **variant** | A concrete attack request the engine generated |
| **status: skipped** | We built the attack requests, but did **not** call a live API, so we cannot say “vulnerable” or “safe” yet |
| **evidence** | Extra detail: what was generated, and what response would count as a finding |

---

## Sample data included in the repo

| Path | What it is |
|------|------------|
| `../rules/bola_users.yaml` | Rule that tries swapping a user ID (BOLA test) |
| `../rules/auth_bypass.yaml` | Rule that clears the Authorization header |
| `../rules/invalid_rule.yaml` | Broken on purpose — engine must skip it gracefully |
| `../sample_specs/petstore.yaml` | Demo API with users, admin, and products endpoints |

> Do not edit these fixture files unless you intend to change the shared test data for the whole interview repo.

---

## How the tool works (simple flow)

```text
  YAML rules                 OpenAPI spec
       │                          │
       ▼                          ▼
   Load & validate            List endpoints
       │                          │
       └──────────┬───────────────┘
                  ▼
         Match rules ↔ endpoints
                  │
                  ▼
      Create attack request variants
                  │
                  ▼
     Print report (human + JSON)
```

### Example 1 — Broken Object Level Authorization (BOLA)

Rule says: for `GET`/`PUT` on `/users/{userId}`, try user id **+1** and **−1**.

If the API still returns `200` with an `email` field for another user’s id, that suggests a serious access-control bug.

With the sample OpenAPI path `/users/{userId}`, the tool uses a demo id `42` and produces:

- `/users/43`
- `/users/41`

### Example 2 — Authorization header bypass

Rule says: for `GET /admin/*`, set the `Authorization` header to empty.

Matching sample endpoints:

- `GET /admin/dashboard` ✅
- `GET /admin/users` ✅
- Something like `/admin/dashboard/settings` would **not** match (`*` = exactly one path segment)

---

## Project structure (for engineers)

```text
go/
├── README.md                 ← you are here
├── go.mod / go.sum           ← Go module (name: interview)
├── cmd/
│   └── engine/main.go        ← CLI entrypoint (flags only)
├── internal/                 ← application code (not for other modules to import)
│   ├── domain/               ← shared types: Rule, Request, Result
│   ├── loader/               ← read & validate YAML rules
│   ├── matcher/              ← path + method matching
│   ├── mutation/             ← attack transforms (pluggable)
│   ├── detection/            ← “does this response look vulnerable?”
│   ├── engine/               ← orchestrates the pipeline
│   ├── output/               ← pretty print + JSON
│   └── config/               ← runtime options
└── pkg/
    └── specparser/           ← OpenAPI → Endpoint helper (pre-existing)
```

### Design choices worth knowing

| Choice | Why |
|--------|-----|
| Thin `main.go` | Business logic stays testable in packages |
| `internal/` packages | Clear layers; each folder has one job |
| Mutation **registry** | Easy to add a new attack type later without rewriting the engine |
| Soft-fail on bad YAML | One bad rule file should not crash the whole scan |
| Clone before mutate | Attack variants must not corrupt the original request |

Mutation types supported today:

- `parameter_swap` — change a path parameter (e.g. user id)
- `header_inject` — set/replace an HTTP header

---

## Understanding result statuses

| Status | Meaning |
|--------|---------|
| `skipped` | Dry-run: variants created; no live HTTP, so no final verdict |
| `vulnerable` | Detection matched a response (used when a response is provided) |
| `not_vulnerable` | Response checked; detection did not match |
| `error` | Something failed while applying mutations |

Detection logic **is implemented and unit-tested**. The CLI currently runs in **dry-run** mode (no network calls to a customer API).

---

## Useful commands cheat sheet

```bash
# From repo root
cd go

# Run against sample rules + sample API
go run ./cmd/engine --rules ../rules --spec ../sample_specs/petstore.yaml

# Run all unit tests
go test ./...

# Run tests for one package (example)
go test ./internal/matcher -v

# List packages in this module
go list ./...
```

---

## Who this README is for

| Reader | What to focus on |
|--------|------------------|
| Non-technical | “What problem / Quick start / What you should see” |
| Junior engineer | Whole doc + run the CLI and tests once |
| Reviewer / interviewer | Structure, soft-fail behavior, mutation registry, dry-run honesty |

---

## What’s intentionally not included (yet)

- Sending real HTTP requests to a live API
- Marking endpoints `vulnerable` / `not_vulnerable` from live responses in the CLI

Those are natural next steps: take each **variant**, call the API, pass the response into `internal/detection`, then set the result status.

---

## Related docs in the repo

- Root `README.md` — interview brief / feature request
