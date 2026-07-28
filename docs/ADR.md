# Architecture Decision Record — Configurable Attack Signature Rule Engine

**Status:** Accepted
**Date:** 2026-07-28
**Author:** Yash
**Context:** Radware code assessment — externalize hardcoded attack patterns into YAML-configurable rules.

---

## Context

Today, attack patterns are hardcoded inside the engine. Adding or modifying a signature
requires a code change and a redeploy. We want security researchers to author, modify, and
version attack signatures as **YAML rules**, with no code changes.

The engine is a **run-once CLI**: it loads rules + an OpenAPI spec, matches rules to
endpoints, mutates requests, (optionally) sends them and detects vulnerabilities, then
prints structured results and exits. It is **not** a long-running service.

This ADR records the significant decisions. The detailed component design lives in
[`LLD.md`](./LLD.md).

---

## Decision Summary

| # | Decision | Choice |
|---|----------|--------|
| 1 | Language | **Go** |
| 2 | Mutation extensibility | **Strategy pattern + registry** |
| 3 | Target addressing | **Two orthogonal axes: Mutator (what) × Accessor (where)** |
| 4 | Invalid rules | **Validate on load, skip + warn, never crash** |
| 5 | Path matching | **Segment-wise walk; `*` and `{param}` = exactly one segment** |
| 6 | Missing spec values (no body/example) | **`ValueProvider` seam; placeholder defaults for MVP** |
| 7 | Concurrency | **Sequential core; bounded worker pool only at the HTTP send step** |
| 8 | Mock target for detection | **In-process `net/http/httptest` server (not Gin)** |
| 9 | Result correlation | **`AttackRequest` carries rule/endpoint provenance end-to-end** |

---

## ADR-1: Language — Go

**Decision:** Implement in Go.

**Why:**
- First-class concurrency primitives (goroutines + channels) for the one place concurrency
  genuinely pays off — sending mutated requests to a live target under a rate cap.
- Strong static typing and a clean package model make the loader/matcher/mutator boundaries
  explicit and independently testable.
- Parser (`pkg/specparser`) is already provided in Go.

**Trade-off:** Python would be marginally faster to prototype, but Go's concurrency control
and typed interfaces better fit a security engine that must not overload customer APIs.

---

## ADR-2: Mutation extensibility — Strategy pattern + registry

**Decision:** Each mutation `type` is a `Mutator` strategy, resolved from a registry keyed by
the YAML `type` string.

**Why:** The brief requires `parameter_swap` and `header_inject` today but explicitly asks
that adding new types later be easy. A registry means a new type is "register one
implementation," never an edit to the engine's control flow.

**Rejected:** A `switch`/`if-else` on `type` in the engine — grows unboundedly and couples the
engine to every mutation kind.

---

## ADR-3: Target addressing — Mutator × Accessor (two orthogonal axes)

**Decision:** Separate **what** we do to a value (the `Mutator` strategy) from **where** the
value lives (the `Accessor` for a domain: `path` / `query` / `header` / `body`). A target
string like `body.user.address.id` is parsed into a **domain** (`body`) and a **field path**
(`user.address.id`).

**Why:** Path, query, header, and body values are all "a value at a location," but reaching
them differs (path segment vs. query key vs. header vs. nested-JSON descent). Without this
split we'd get a combinatorial explosion (`parameter_swap×path`, `parameter_swap×query`,
`parameter_swap×body`, …). With it:
- new **domain** → one new `Accessor`,
- new **strategy** → one new `Mutator`,
- they compose freely.

**Consequence:** Nested JSON body mutation reduces to a dot-path walk inside `BodyAccessor`,
isolated from strategy logic.

---

## ADR-4: Invalid rules — validate on load, skip + warn

**Decision:** Validate every rule as it loads. On failure (e.g. missing `target`), skip that
one rule, log a warning, and continue with the rest. One bad file never aborts the run.

**Why:** The repo ships an intentionally invalid rule (`invalid_rule.yaml`, no `target`). A
researcher's typo must not disable the whole engine. Errors are collected and reported, not
thrown.

---

## ADR-5: Path matching — segment walk, wildcard = exactly one segment

**Decision:** Split pattern and path on `/`; require equal segment counts; per segment, `*`
and `{param}` match any single segment, literals must match exactly.

**Why:** The brief states `*` matches **exactly one** segment (`/admin/*` matches
`/admin/dashboard` but not `/admin/dashboard/settings`). Equal-length + per-segment matching
enforces this precisely and treats OpenAPI `{param}` placeholders as single-segment wildcards.

---

## ADR-6: Missing spec values — `ValueProvider` seam

**Decision:** Introduce a `ValueProvider` abstraction that supplies concrete base values for
mutation. For the MVP it returns placeholder defaults (e.g. `{userId}` → `42`, missing body →
`{}`). Later sources (OpenAPI `example`/`schema`, a seed-values config, recorded traffic) plug
in behind the same interface.

**Why:** The OpenAPI spec provides **templates only** — no concrete IDs and no request bodies.
`increment` needs a real number; body swap needs a real payload. This is a genuine gap; naming
the seam now keeps the core untouched when richer value sources arrive.

**Assumption (flagged for PM):** MVP substitutes a default value for path params so
`increment` has something to operate on. Documented in the PR.

---

## ADR-7: Concurrency — sequential core, bounded pool only at send

**Decision:** Load → Match → Mutate run sequentially. Concurrency is introduced **only** at
the optional HTTP send step, via a bounded worker pool (buffered-channel semaphore of size
`--concurrency`).

**Why:** Load/Match/Mutate are pure, in-memory, microsecond-scale — parallelizing them adds
bug surface for zero gain. Sending is slow, blocking I/O against a **real customer API**;
that's the only place a rate cap matters, both for speed and for not overloading the target.

**Consequence:** `--concurrency N` is the safety valve controlling max in-flight requests.
A second natural fan-out (multiple spec files) is also parallelizable but is out of MVP scope.

---

## ADR-8: Mock target — in-process `httptest`, not Gin

**Decision:** For end-to-end detection, spin up an in-process `net/http/httptest` server that
returns scripted responses per route. Gin is explicitly rejected for the core.

**Why:**
- Zero new dependencies; `httptest` is stdlib.
- In-process — starts and dies with the CLI, matching "runs, produces output, exits."
- Real HTTP round-trip on a real localhost URL, so detection is genuinely exercised.
- Gin would add a dependency, a separate process/lifecycle, and contradicts the
  "not a long-running service" constraint.

**Consequence:** Detection graduates from "nice-to-have (no server to hit)" to a working
end-to-end demo. An external target may still be supplied via an optional `--target` flag.

---

## ADR-9: Result correlation — provenance on every request

**Decision:** Each mutated request is wrapped in an `AttackRequest{RuleID, RuleName, Endpoint,
Mutation, Request}`. The tag rides with the request through send and detection, so every
`Result` maps unambiguously back to the rule that produced it.

**Why:** Without provenance, responses are orphaned and results can't be attributed. Carrying
the tag inside each unit of work (rather than in shared state) also makes concurrent send
trivially safe — each goroutine owns its own `AttackRequest` and returns its own `Result`.

---

## Scope for this assessment

**Must (build):** Load+validate, Match, `parameter_swap`, `header_inject`, `AttackRequest`
provenance.
**Should (if time):** `httptest` mock + bounded-concurrent send + detection.
**Designed-for, not built:** `query`/`body` accessors, richer `ValueProvider` sources,
multi-spec fan-out, external `--target`.

Guiding principle from the brief: **a smaller solution that runs end-to-end on the test data
beats a larger one that doesn't execute.**
