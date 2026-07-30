# Rule-Based API Security Testing Engine — Design Plan

## 1. Goals & Priorities

Priority order (per requirements): **loader → matcher → parameter_swap mutation → structured result output**. Detection and actual HTTP dispatch are nice-to-haves, built as thin, swappable layers on top so they don't block the core path. Everything is designed so `header_inject` (and future mutation types) slot in without touching the loader/matcher.

Since this is a one-shot CLI (run → output → exit), there's no long-running state, no concurrency requirements beyond "nice to have," and no persistence layer. Keep it simple: in-memory structs, stdout/JSON file output.

---

## 2. Project Layout

```
rule-engine/
├── cmd/
│   └── engine/
│       └── main.go              # CLI entrypoint: parse flags, wire everything, run, exit
├── internal/
│   ├── rules/
│   │   ├── types.go              # Rule, Target, Mutation, Detection structs
│   │   ├── loader.go             # LoadRulesFromDir, YAML parsing, validation
│   │   └── loader_test.go
│   ├── spec/
│   │   ├── types.go               # Endpoint struct (mirrors parser.go's output)
│   │   └── parser.go              # existing OpenAPI parser (as given / adapted)
│   ├── matcher/
│   │   ├── matcher.go             # path_pattern <-> Endpoint.path matching, method matching
│   │   └── matcher_test.go
│   ├── mutate/
│   │   ├── mutator.go             # Mutator interface + registry
│   │   ├── parameter_swap.go      # implements Mutator
│   │   ├── header_inject.go       # implements Mutator
│   │   └── mutate_test.go
│   ├── request/
│   │   └── request.go             # AttackRequest struct (method, url, headers, body, path params)
│   ├── detect/
│   │   └── detect.go              # Detector: evaluates detection conditions against a response
│   ├── executor/
│   │   └── executor.go            # orchestrates: match -> mutate -> (send) -> detect -> Result
│   └── result/
│       └── result.go              # Result struct + JSON/console reporter
├── rules.d/                        # example rule YAML files (BOLA-001.yaml, AUTH-BYPASS-001.yaml)
├── testdata/
│   └── openapi_sample.yaml
├── go.mod
└── README.md
```

Rationale: each pipeline stage (`rules` → `spec` → `matcher` → `mutate` → `detect` → `executor` → `result`) is its own package with a narrow interface, so a security researcher's new mutation type, or a swap from "print result" to "send to a queue," touches exactly one package.

---

## 3. Core Data Types

### 3.1 Rule (`internal/rules/types.go`)

```go
type Rule struct {
    ID       string     `yaml:"rule"`
    Name     string     `yaml:"name"`
    Severity string     `yaml:"severity"`
    Target   Target     `yaml:"target"`
    Mutations []Mutation `yaml:"mutations"`
    Detection []Detection `yaml:"detection"`

    SourceFile string `yaml:"-"` // for error messages / traceability, not from YAML
}

type Target struct {
    PathPattern string   `yaml:"path_pattern"`
    Methods     []string `yaml:"methods"`
}

type Mutation struct {
    Type     string `yaml:"type"`     // "parameter_swap" | "header_inject" | future types
    Target   string `yaml:"target"`   // e.g. "path.userId", "header.Authorization"
    Strategy string `yaml:"strategy,omitempty"` // used by parameter_swap
    Value    string `yaml:"value,omitempty"`    // used by header_inject
    // NOTE: kept generic; type-specific interpretation happens in the Mutator impl.
}

type Detection struct {
    StatusCode   *int   `yaml:"status_code,omitempty"`
    BodyContains string `yaml:"body_contains,omitempty"`
}
```

**Design note on `Mutation`:** rather than a strict typed struct per mutation type, use a generic struct with common optional fields, OR (better for extensibility) parse mutations as `map[string]interface{}` / `yaml.Node` and let each `Mutator` implementation validate/extract what it needs. Recommendation: use `yaml.Node` for `mutations[].raw` deferred decoding — this avoids the core loader needing to know about every mutation type's fields as the rule format grows. Concretely:

```go
type RawMutation struct {
    Type string `yaml:"type"`
    Rest yaml.Node `yaml:",inline"` // captures all other fields for type-specific decode
}
```

This is the key extensibility hinge: adding a new mutation type = add a new Go file implementing `Mutator`, register it, and it can define its own YAML fields without touching `types.go`.

### 3.2 Endpoint (from `parser.go`, treated as given)

```go
type Endpoint struct {
    Path        string
    Method      string
    OperationID string
}
```

### 3.3 AttackRequest (`internal/request/request.go`)

Represents a request the engine has constructed (original or mutated) — never actually issued unless the send-nice-to-have is wired in.

```go
type AttackRequest struct {
    Method      string
    PathTemplate string            // e.g. "/users/{userId}"
    ResolvedPath string            // e.g. "/users/43" after mutation
    PathParams  map[string]string  // e.g. {"userId": "43"}
    QueryParams map[string]string
    Headers     map[string]string
    Body        []byte
    IsBaseline  bool               // true = original/unmutated request
    MutationApplied string        // human-readable description, e.g. "userId: 42 -> 43"
}
```

### 3.4 Result (`internal/result/result.go`)

```go
type Result struct {
    RuleID          string    `json:"rule_id"`
    RuleName        string    `json:"rule_name"`
    Severity        string    `json:"severity"`
    Endpoint        string    `json:"endpoint"`        // path template
    Method          string    `json:"method"`
    MutationSummary string    `json:"mutation_summary"`
    ResolvedPath    string    `json:"resolved_path"`
    Status          string    `json:"status"`           // "vulnerable" | "not_vulnerable" | "error" | "skipped_no_send"
    Evidence        Evidence  `json:"evidence,omitempty"`
    Error           string    `json:"error,omitempty"`
    Timestamp       time.Time `json:"timestamp"`
}

type Evidence struct {
    StatusCode int    `json:"status_code,omitempty"`
    BodySnippet string `json:"body_snippet,omitempty"` // truncated, matched substring context
    MatchedConditions []string `json:"matched_conditions,omitempty"`
}
```

Since actual sending is optional, `Status` includes `skipped_no_send` — the engine still reports that it generated a valid mutated request and pass/fail is "unknown" pending execution, rather than silently omitting the rule. This keeps output structurally consistent whether or not the HTTP-send feature is enabled.

---

## 4. Pipeline Stages

### 4.1 Loader (`internal/rules/loader.go`)

```go
func LoadRulesFromDir(dir string) ([]Rule, []LoadError, error)
```

Responsibilities:
- Walk directory (non-recursive by default, or recursive — decide via flag `--recursive`), reading `*.yaml`/`*.yml` files.
- Parse each file with `yaml.Unmarshal`. **One bad file must not kill the whole run** — collect per-file errors into `[]LoadError{File, Err}` and continue loading the rest; return the good rules plus a list of errors. `main.go` decides whether to warn-and-continue or fail-hard (default: warn and continue).
- Validate each rule after parse:
  - `rule` (ID) non-empty and unique across the loaded set (duplicate IDs → load error for that file, not a crash).
  - `target.path_pattern` non-empty.
  - `target.methods` non-empty, and each normalized to uppercase; reject unknown HTTP methods.
  - `mutations` non-empty; each mutation's `type` must be registered in the Mutator registry (unknown type → load error, rule skipped, doesn't stop other rules loading — this is exactly the "add new type later" extensibility path: unrecognized future types degrade gracefully instead of crashing old engines).
  - `detection` may be empty/absent (nice-to-have) — if empty, note the rule will never auto-flag "vulnerable" and will report `status: skipped_no_send` or `no_detection_defined`.
- Return everything as an in-memory `[]Rule`. No dependency on external DB — directory is source of truth per run.

### 4.2 Matcher (`internal/matcher/matcher.go`)

```go
func Matches(rule rules.Rule, ep spec.Endpoint) bool
func MatchAll(loadedRules []rules.Rule, endpoints []spec.Endpoint) []Match // Match{Rule, Endpoint}
```

**Method matching:** case-insensitive comparison of `ep.Method` against `rule.Target.Methods` (normalized uppercase at load time already).

**Path pattern matching — this is the trickiest part, needs precise semantics:**

Two kinds of "variable" path segments to reconcile:
1. Rule pattern segments: literal, or `*` wildcard (matches exactly one segment, no more).
2. Endpoint path segments (from OpenAPI): literal, or `{paramName}` (OpenAPI path parameter placeholder).

Matching algorithm:
```
func Matches(pattern, endpointPath string) bool {
    patternSegs := splitPath(pattern)      // split on "/", drop empty from leading/trailing slash
    endpointSegs := splitPath(endpointPath)
    if len(patternSegs) != len(endpointSegs) {
        return false
    }
    for i := range patternSegs {
        p := patternSegs[i]
        e := endpointSegs[i]
        switch {
        case p == "*":
            continue // wildcard matches any single segment, including {param}-style ones
        case isBraceParam(p) && isBraceParam(e):
            continue // both are named params e.g. rule "{userId}" vs endpoint "{userId}" -> match regardless of name
                      // (decide: match by position, not name, since researcher may use a different param name)
        case p == e:
            continue // exact literal match
        default:
            return false
        }
    }
    return true
}
```

Key edge-case decisions (explicit, since spec is ambiguous here):
- **Segment count must match exactly.** `/admin/*` (2 segments) must NOT match `/admin/dashboard/settings` (3 segments) — matches the spec's explicit example.
- **`*` matches exactly one segment**, never zero, never multiple. No `**` support in v1 (documented as a future extension point).
- **`{userId}` in the rule pattern vs `{userId}` in the endpoint path**: match structurally (both are "a parameter slot") regardless of literal name equality, since a rule author might write `/users/{id}` while the spec says `/users/{userId}` — these should still match by position/shape, not string equality. **Recommendation given the examples given (`/users/{userId}` rule matching an endpoint with the exact same `{userId}` placeholder): implement structural match (param-slot vs param-slot matches regardless of name) since it's more robust and still satisfies every example in the spec.** Document this decision clearly in code comments since it's a judgment call.
- **Trailing slash normalization**: strip trailing slashes from both pattern and endpoint path before splitting, so `/products/` and `/products` are equivalent.
- **Case sensitivity**: paths are matched case-sensitively (HTTP paths are case-sensitive by convention); methods are matched case-insensitively.
- **Empty methods list on rule** → validation error at load time (already covered above), matcher can assume non-empty.
- Return `MatchAll` as a flat list of `(Rule, Endpoint)` pairs — one rule can match multiple endpoints, one endpoint can match multiple rules (e.g., both BOLA-001 and AUTH-BYPASS-001 apply to different targets; also plausible that two BOLA-style rules both target `/users/{userId}`).

### 4.3 Mutator (`internal/mutate/mutator.go`)

Interface + registry, so adding a new mutation type is additive:

```go
type Mutator interface {
    Type() string
    // Apply takes the baseline request derived from the endpoint + rule's mutation config,
    // returns 1..N mutated AttackRequests (parameter_swap:increment produces 2, header_inject produces 1).
    Apply(baseline request.AttackRequest, m rules.RawMutation) ([]request.AttackRequest, error)
}

var registry = map[string]Mutator{}

func Register(m Mutator) { registry[m.Type()] = m }
func Get(t string) (Mutator, bool) { m, ok := registry[t]; return m, ok }
```

`init()` in `parameter_swap.go` and `header_inject.go` each call `mutate.Register(...)`.

**Baseline request construction** (happens before mutation, in the executor): from `Endpoint.Path` + `Endpoint.Method`, build an `AttackRequest` with:
- `PathTemplate = ep.Path`
- `PathParams` populated with placeholder/sample values for every `{param}` in the path (since we don't have real data — use a configurable default, e.g. `"1"` or a documented dummy value like `"42"`; or, if the spec parser exposes example values/schema in future, use those). **Edge case**: for `parameter_swap`, the *current* value matters (need something to increment). Since there's no live data, decide: baseline path param values default to a fixed seed (e.g. `1`) unless the mutation config or a `--seed-values` map overrides it. Document this clearly as a known limitation ("the engine has no live session, so parameter_swap operates on a synthetic seed ID unless configured otherwise").
- `Headers` = empty map (no auth headers by default, since no live traffic capture is in scope) — again, document as a limitation / extension point for a future "live request capture" feature.
- `Body = nil`.
- `IsBaseline = true`.

#### 4.3.1 `parameter_swap` (`internal/mutate/parameter_swap.go`)

Config fields (from `RawMutation.Rest`):
```go
type ParamSwapConfig struct {
    Target   string `yaml:"target"`   // "path.userId"
    Strategy string `yaml:"strategy"` // "increment" (only strategy required for v1)
}
```

Logic:
1. Parse `target` — must be of form `path.<paramName>`. Validate `<paramName>` exists in `baseline.PathParams` (i.e., the rule's targeted param must actually appear in the endpoint's path template) — if not, return error (e.g., rule says `path.userId` but endpoint is `/products/{productId}` — this shouldn't happen since matcher already filtered by pattern, but defensive check is cheap and catches path-pattern/param-name mismatches).
2. Look up current value in `baseline.PathParams[paramName]` — parse as integer.
   - **Edge case**: non-numeric ID (e.g., UUID). `increment` strategy is numeric-only — if the value can't be parsed as int, return a clear error/skip (`"parameter_swap increment requires numeric ID, got UUID-like value"`), do not crash the whole run. This is a good documented limitation + extension point ("future strategies: `uuid_swap`, `enum_swap`, `boundary`").
   - **Edge case**: decrementing below zero (e.g., ID = 0 → -1). Decide: allow negative values to be generated (some APIs may 500 or 400 on negative, which is itself informative) OR clamp at 0/1. **Recommendation: generate as-is (42→41, 0→-1), let detection/response decide; document that negative-ID handling is the API's problem, not the engine's** — but flag it via a `Warning` field on the AttackRequest if the value goes negative, for downstream visibility.
3. Produce two `AttackRequest` copies of baseline:
   - Variant A: `PathParams[paramName] = strconv.Itoa(id+1)`, `MutationApplied = fmt.Sprintf("%s: %d -> %d", paramName, id, id+1)`
   - Variant B: same for `id-1`.
   - Both: recompute `ResolvedPath` by substituting all `PathParams` into `PathTemplate` (e.g., replace `{userId}` with the new value; leave other params at baseline/seed values).
   - `IsBaseline = false`.
4. Return `[]AttackRequest{variantA, variantB}`, never mutate/return the original (explicitly per spec: "the original request is not modified").

#### 4.3.2 `header_inject` (`internal/mutate/header_inject.go`)

Config fields:
```go
type HeaderInjectConfig struct {
    Target string `yaml:"target"` // "header.Authorization"
    Value  string `yaml:"value"`  // "" means empty string, not "unset" — must support empty explicitly
}
```

Logic:
1. Parse `target` — must be `header.<HeaderName>`. Validate `<HeaderName>` non-empty.
2. Copy baseline headers map, set (or overwrite, case-insensitively per HTTP header semantics — normalize header name lookups, e.g. `Authorization` vs `authorization` should be treated as the same header) `HeaderName = Value`.
   - **Edge case**: header name case-insensitivity — when "replacing" an existing header, must match case-insensitively so we don't end up with both `Authorization` and `authorization` in the mutated request. Use a case-preserving-but-case-insensitive-lookup map, or canonicalize via `http.CanonicalHeaderKey`.
   - **Edge case**: `value: ""` is a valid, meaningful config (empty-string auth bypass test) — must be distinguished from "field absent" at YAML-parse time. Since `Value string` with `yaml:"value"` defaults to `""` when absent too, this is ambiguous. Fix: use `*string` for `Value` so absent vs explicitly-empty can be distinguished if that distinction ever matters (for now spec only needs empty-string support, but `*string` costs nothing and removes ambiguity); validate at load time that `value` key is present (even if empty) for `header_inject` rules.
3. Return single `AttackRequest` variant with `MutationApplied = fmt.Sprintf("header %s set to %q", headerName, value)`.

**Extensibility for future mutation types** (e.g., `body_field_swap`, `method_override`, `query_param_fuzz`): each just implements `Mutator`, self-registers, and defines its own config struct decoded from `RawMutation.Rest`. Loader validation only needs the type name to exist in the registry — no changes needed to `types.go`, `loader.go`, or `matcher.go`. This satisfies "design should make it easy to add new types."

### 4.4 Detector (`internal/detect/detect.go`) — nice-to-have, but designed cleanly

```go
func Evaluate(detections []rules.Detection, resp *SimResponse) (matched bool, evidence result.Evidence)
```

Since sending isn't required, `SimResponse` may simply not exist for most runs — detection is only evaluated when a response is actually available (from the optional HTTP-send feature). If no response, `Result.Status = "not_executed"` and evidence is empty; this is explicitly a valid, expected output state, not an error.

Detection semantics (all conditions AND'd, per spec: "matches when all its conditions are true"):
```go
type SimResponse struct {
    StatusCode int
    Body       string
}

func Evaluate(det rules.Detection, resp SimResponse) (bool, Evidence) {
    ok := true
    var matchedConds []string
    if det.StatusCode != nil {
        if resp.StatusCode == *det.StatusCode {
            matchedConds = append(matchedConds, fmt.Sprintf("status_code == %d", *det.StatusCode))
        } else {
            ok = false
        }
    }
    if det.BodyContains != "" {
        if strings.Contains(resp.Body, det.BodyContains) {
            matchedConds = append(matchedConds, fmt.Sprintf("body_contains %q", det.BodyContains))
        } else {
            ok = false
        }
    }
    return ok, Evidence{StatusCode: resp.StatusCode, BodySnippet: snippet(resp.Body, det.BodyContains), MatchedConditions: matchedConds}
}
```

- A rule may have multiple `detection` entries in a list — **decide semantics**: is it "any of the detection blocks matching = vulnerable" (OR across blocks) or "all blocks must match" (AND across blocks)? Spec shows a single detection block per example but the field is a YAML list (`detection:` as a list under the rule). **Recommendation: OR across list entries, AND within a single entry's fields** — this models "there are multiple possible vulnerable-response signatures for this rule, any one confirms it." Document this clearly since it's inferred, not explicitly stated.
- Body matching should be case-sensitive substring match by default (simplest, least surprising); consider a future `body_contains_ignore_case` as an extension, not needed now.

### 4.5 Executor (`internal/executor/executor.go`)

Orchestrates the full pipeline for one CLI run:

```go
func Run(loadedRules []rules.Rule, endpoints []spec.Endpoint, opts RunOptions) []result.Result
```

Steps:
1. `matches := matcher.MatchAll(loadedRules, endpoints)`
2. For each `(rule, endpoint)` pair:
   - Build baseline `AttackRequest` from endpoint.
   - For each `mutation` in `rule.Mutations`:
     - Look up `Mutator` by `mutation.Type` from registry.
     - If not found (shouldn't happen post-validation, but defensive): emit `Result{Status: "error", Error: "unknown mutation type"}`, continue.
     - Call `mutator.Apply(baseline, mutation)` → `[]AttackRequest`.
     - If `Apply` errors (e.g., non-numeric ID for increment): emit `Result{Status: "error", Error: err.Error()}` for that rule/endpoint/mutation, continue to next mutation/rule — **never abort the whole run** for one bad mutation.
     - For each resulting mutated request:
       - If `opts.SendRequests` (nice-to-have flag, default false): actually issue HTTP call, get real response, run `detect.Evaluate`, set `Status` to `vulnerable`/`not_vulnerable` accordingly.
       - Else: `Status = "generated_not_sent"`, still include the mutated request details (method, resolved path, headers, mutation summary) in the result so the output is useful/inspectable even without sending.
     - Append `Result` to output slice.
3. Return all results.

This ordering means **the loader+matcher+parameter_swap-generation path works and produces meaningful output even with zero network code**, satisfying the stated priority.

### 4.6 Result Reporting (`internal/result/result.go`)

- `PrintJSON(results []Result, w io.Writer) error` — pretty-printed JSON array to stdout or `--output results.json`.
- `PrintTable(results []Result, w io.Writer)` — optional human-readable summary (rule ID, endpoint, status) for quick CLI reading — nice-to-have.
- Exit code: `main.go` sets exit code 1 if any `Status == "vulnerable"` (useful for CI pipelines), 0 otherwise, non-zero for load/fatal errors distinctly (e.g., exit 2 if rules dir doesn't exist at all).

---

## 5. CLI (`cmd/engine/main.go`)

```
engine \
  --rules-dir ./rules.d \
  --spec ./openapi.yaml \
  --output results.json \
  --send=false \
  --recursive=false
```

Flow:
1. Parse flags.
2. `endpoints, err := spec.Parse(specPath)` — fatal on error (can't do anything without endpoints).
3. `loadedRules, loadErrs, err := rules.LoadRulesFromDir(rulesDir)` — fatal only if directory itself is unreadable/missing; individual bad rule files are logged as warnings to stderr and skipped.
4. `results := executor.Run(loadedRules, endpoints, opts)`.
5. `result.PrintJSON(results, outputWriter)`.
6. Exit with appropriate code.

No daemon, no server, no background goroutines required — a single synchronous pass is sufficient and matches "runs, produces output, exits." Concurrency (e.g., goroutine pool over rule×endpoint pairs) is a valid future optimization but not needed for correctness; note it as an extension point rather than building it now, to keep the first working version simple.

---

## 6. Edge Cases Summary (explicit checklist)

| Area | Edge case | Decision |
|---|---|---|
| Loader | Malformed YAML in one file | Skip file, log warning, continue loading others |
| Loader | Duplicate rule IDs across files | Reject second occurrence, log warning, keep first |
| Loader | Unknown mutation `type` | Reject that rule at load time, don't crash |
| Loader | Empty `detection` list | Allowed; rule still loads, just can't auto-classify vulnerable/not |
| Loader | Empty rules directory | Return empty rule set, not an error; engine runs, produces empty results |
| Matcher | Segment count mismatch (`/admin/*` vs 3-segment path) | No match (exact segment count required) |
| Matcher | `*` vs `{param}` positional shape mismatch | Match only compares position/shape, `*` always matches one segment regardless of what's there |
| Matcher | Rule param name differs from spec param name (`{id}` vs `{userId}`) | Match structurally by position, not by literal name (documented judgment call) |
| Matcher | Trailing slashes | Normalized away before comparison |
| Matcher | Method case (`get` vs `GET`) | Case-insensitive method match |
| Matcher | No endpoints match any rule | Empty result set, valid output, exit 0 |
| Mutator (param_swap) | Non-numeric path param (UUID) | Error result for that rule, engine continues |
| Mutator (param_swap) | Decrement below 0 | Generate as-is, flag as warning, let detection decide |
| Mutator (param_swap) | `target` references a param not present in path template | Validation error, skip that rule/mutation |
| Mutator (header_inject) | Header name case variants | Canonicalize header names before compare/replace |
| Mutator (header_inject) | Explicit empty-string value vs missing `value` key | Use `*string` to disambiguate; require key present at load time |
| Mutator (general) | Unknown/unsupported mutation type encountered mid-run | Per-mutation error result, not fatal |
| Detection | Multiple detection blocks | OR across blocks, AND within a block's fields (documented assumption) |
| Detection | No response available (send disabled) | `Status: generated_not_sent`, no evidence, not an error |
| Executor | One rule's mutation throws error | Isolated failure result, rest of run continues |
| Output | No vulnerabilities found | Still produce valid JSON with all attempted results, exit 0 |
| CLI | Rules dir missing entirely | Fatal, exit 2, clear message |
| CLI | Spec file invalid/missing | Fatal, exit 2, clear message |

---

## 7. Testing Strategy

- **Loader**: valid rule loads correctly; malformed YAML skipped gracefully; duplicate ID rejected; unknown mutation type rejected.
- **Matcher**: table-driven tests directly from the spec's own examples — `/users/{userId}` matches `GET /users/{userId}` and `PUT /users/{userId}`, not `GET /products`; `/admin/*` matches `/admin/dashboard`, not `/admin/dashboard/settings`; wildcard vs multi-segment; trailing slash normalization.
- **parameter_swap**: numeric ID 42 → produces 43 and 41 variants, original untouched, `ResolvedPath` computed correctly; non-numeric ID produces a clean error, not a panic.
- **header_inject**: existing header replaced (case-insensitive), missing header added, empty-string value handled distinctly from absent value.
- **Executor/integration**: full pipeline against the provided sample OpenAPI spec + the two example rules (BOLA-001, AUTH-BYPASS-001) — assert exact expected `Result` set (rule/endpoint pairs, mutation summaries) with `--send=false`.

---

## 8. Build Order (for the implementing model)

1. `spec` package — wrap/adapt given `parser.go`, define `Endpoint`.
2. `rules` package — types + loader + validation (get this solid first, it's foundational).
3. `matcher` package — path/method matching logic + tests against spec's explicit examples.
4. `mutate` package — `Mutator` interface/registry, then `parameter_swap`, then `header_inject`.
5. `request`/`result` packages — data carriers.
6. `executor` — wire loader → matcher → mutate → (skip send) → result.
7. `detect` — add detection evaluation (usable once/if send is added).
8. `cmd/engine/main.go` — CLI wiring, flags, JSON output, exit codes.
9. (Optional/last) actual HTTP client to send mutated requests and populate real `SimResponse`.

This order guarantees that even if implementation time runs out partway through, the most valuable, spec-required pieces (loader, matcher, parameter_swap) are complete and demonstrably working before optional pieces are attempted.