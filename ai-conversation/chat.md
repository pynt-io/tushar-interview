# AI Collaboration Log

This document records how I worked with an AI assistant (Claude) to build the
configurable attack-signature rule engine. It captures the sequence of decisions,
the questions I asked, and where I steered vs. where I delegated.

---

## 1. Understanding the assignment

I started by having the AI read the `README.md` and the existing repo (the provided
`spec_parser.py` / `parser.go`, the sample rules, and the petstore spec) and explain
the requirement back to me with diagrams.

Key things I confirmed up front:

- The engine is a **run-once CLI**, not a service.
- The core deliverable is **Load → Match → Mutate**. Actually **sending** requests and
  **detection** are nice-to-haves.
- One rule file (`invalid_rule.yaml`) is intentionally invalid and must be skipped
  gracefully.
- `*` in a path pattern matches **exactly one** segment.

I corrected my own initial mental model in two places (with the AI pushing back):

- We do **not** have to actually call the APIs for the must-have scope — only
  *generate* the mutated request.
- "Detection" is about whether the *endpoint is vulnerable*, not whether a rule
  "passes/fails".

## 2. Design discussion

I drove the design decisions and used the AI as a sounding board:

- **Language: Go** — for real concurrency control (goroutines + bounded pool) so we
  never overload a customer API, and for typed, testable package boundaries.
- **Strategy pattern + registry** for mutation types, so new types are additive.
- The AI proposed (and I accepted) splitting the mutation into **two orthogonal axes**:
  - `Mutator` = *what* we do to a value (parameter_swap / header_inject)
  - `Accessor` = *where* the value lives (path / query / header / body)
  This avoids a combinatorial explosion of `type × domain` strategies. A nested-JSON
  body mutation becomes a dot-path walk inside `BodyAccessor`, isolated from strategies.
- I raised the gap that **OpenAPI specs have no concrete values or request bodies** —
  `increment` needs a real number to work on. We introduced a `ValueProvider` seam
  (placeholder defaults for the MVP; spec-examples / seed-config later).
- **Concurrency placement:** I initially justified Go by concurrency, and the AI
  correctly pointed out that Load/Match/Mutate are pure in-memory steps where
  concurrency only adds bug surface. We agreed to keep the core sequential and reserve
  a **bounded worker pool for the send step only** (`--concurrency` as the rate cap).
- **Result correlation:** every mutated request is wrapped in an `AttackRequest`
  carrying `RuleID` / `Endpoint` provenance, so responses map back to their rule and
  concurrent sends stay safe.
- **Mock target:** to make detection demonstrable end-to-end, I wanted a mock server.
  The AI recommended stdlib `net/http/httptest` over a Gin service (zero deps,
  in-process, dies with the CLI, matches "runs and exits"). I agreed.
- I asked for `AttackRequest` (and the other cross-layer objects) to live in a
  dedicated **`dto` package**, keeping transfer objects free of business logic.

## 3. Documentation before code

Before writing any code I had the AI produce two design docs, which I reviewed:

- `docs/ADR.md` — 9 architecture decisions with rationale + rejected alternatives.
- `docs/LLD.md` — package layout, data model, per-component algorithms, a full
  function-level sequential flow, a modularity/SOLID review, a test plan, and an
  MVP-first build order.

## 4. Implementation

I had the AI implement the packages in the LLD's build order:

1. `dto` (Request, AttackRequest, Response, Result)
2. `rule` (model + `Validate` + `LoadRules`, skip-invalid)
3. `matcher` (method + segment/wildcard matching)
4. `mutation` (Mutator×Accessor, parameter_swap + header_inject, 4 accessors) +
   `valueprovider`
5. `engine.Run` + `report` (no-send MVP)
6. `mocktarget` + `sender` (bounded pool) + `detect` (send path)

Every package was kept independently unit-testable.

## 5. Testing

We wrote unit tests for `matcher`, `rule.Validate`, `rule.LoadRules`,
`mutation` (parameter_swap / header_inject / nested body / parseTarget), and `detect`,
plus an `engine` end-to-end test that runs the real pipeline against the mock target.

`go build`, `go vet`, and `go test ./...` all pass.

### End-to-end run on the provided test data

```
go run ./cmd/engine --rules ../rules --spec ../sample_specs/petstore.yaml --send
```

- `invalid_rule.yaml` skipped with a clear reason; run continues.
- 6 attack requests generated (BOLA parameter-swaps on `/users/{userId}` GET+PUT;
  AUTH-BYPASS header-injects on `/admin/*`).
- `/users/{userId}/orders` and `/products` correctly **not** matched (wildcard = one
  segment).
- With `--send`, all 6/6 variants flagged VULNERABLE against the mock target.

(See `output.txt` for the captured run.)

### Additional edge-case testing

I had the AI create extra rule files in a temp directory (not committed) to probe
robustness:

- Malformed YAML → skipped with a parse-error message.
- Unknown mutation type (`sql_inject`) → rejected at validation.
- A rule targeting a non-existent path → loaded but matched nothing (no spurious
  output).
- A rule targeting a **query** parameter → generated variants with **zero engine
  changes**, validating the Mutator×Accessor extensibility.
- Against `/products` the mock returns 404 → correctly reported **safe** (exercises the
  not-vulnerable detection path).

## 6. How I worked with the AI

- I made the architectural calls (language, where concurrency belongs, DTO packaging,
  MVP scope) and used the AI to pressure-test them and flag gaps.
- The AI caught two of my incorrect assumptions (must-send vs. must-generate; meaning
  of "detection") and I incorporated the corrections.
- I insisted on ADR + LLD before coding so the design was explicit and reviewable.
- I asked for edge-case testing beyond the happy path to prove robustness.

## 7. What I'd do differently with more time

- Richer `ValueProvider` sources (read OpenAPI `example`/`schema`, a seed-values config).
- Parallelize across multiple spec files (a second natural fan-out).
- Structured output (JSON) alongside the human-readable report.
- More detection conditions (headers, regex body match, response time).
- Config for the `increment` base value / range instead of a fixed placeholder.
