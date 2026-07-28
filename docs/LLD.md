# Low-Level Design — Configurable Attack Signature Rule Engine

**Companion to:** [`ADR.md`](./ADR.md) (records *why*; this records *how*).
**Language:** Go · **Shape:** run-once CLI.

---

## 1. High-level pipeline

```
                 rules/*.yaml ─┐
                               ├─▶ ① LOAD ─▶ ② MATCH ─▶ ③ MUTATE ─▶ ④ SEND ─▶ ⑤ DETECT ─▶ 📋 REPORT
                 spec.yaml ────┘   +validate  rule↔ep    strategy    bounded    rule vs        grouped
                                   skip bad             ×accessor    pool        response      by rule
                                   [SEQ]     [SEQ]       [SEQ]        [CONCURRENT — nice-to-have]
```

- **[SEQ]** Load / Match / Mutate — pure, in-memory, cheap.
- **[CONCURRENT]** Send — the only I/O step; bounded worker pool; detection runs on each response.
- Steps ④–⑤ are nice-to-have; the in-process mock target (§9) makes them demonstrable end-to-end.

---

## 2. Package layout

```
go/
├── cmd/engine/main.go              orchestrator: flags → wire packages → print
└── pkg/
    ├── specparser/parser.go        [PROVIDED] ParseSpec → []Endpoint
    ├── dto/                        ← pure data-transfer objects (no business logic)
    │   ├── request.go              Request struct + Clone()
    │   ├── attack.go               AttackRequest (provenance wrapper)
    │   ├── response.go             Response struct
    │   └── result.go               Result struct
    ├── rule/
    │   ├── rule.go                 Rule, Target, Mutation, Detection (config model)
    │   ├── loader.go               LoadRules(dir) ([]Rule, []LoadError)
    │   └── validate.go             (*Rule).Validate() error
    ├── matcher/
    │   └── matcher.go              Match(Rule, Endpoint) bool
    ├── mutation/
    │   ├── mutator.go              Mutator interface + mutatorRegistry + NewMutator()
    │   ├── accessor.go             Accessor interface + accessorRegistry + parseTarget()
    │   ├── builder.go              FromEndpoint(Endpoint, ValueProvider) dto.Request
    │   ├── parameter_swap.go       ParameterSwap Mutator
    │   ├── header_inject.go        HeaderInject Mutator
    │   ├── accessor_path.go        PathAccessor
    │   ├── accessor_header.go      HeaderAccessor
    │   ├── accessor_query.go       QueryAccessor      (designed-for)
    │   └── accessor_body.go        BodyAccessor       (designed-for, nested JSON)
    ├── valueprovider/
    │   └── provider.go             ValueProvider interface + DefaultProvider
    ├── engine/
    │   └── engine.go               Run(rules, endpoints, vp) []dto.AttackRequest — core loop
    ├── sender/
    │   └── sender.go               Send([]dto.AttackRequest, base, n) []dto.Response
    ├── detect/
    │   └── detect.go               Detect([]rule.Detection, dto.Response) (bool, evidence)
    │   └── correlate.go            Correlate(attacks, resps, rules) []dto.Result
    ├── report/
    │   └── report.go               PrintAttacks(), PrintResults()
    └── mocktarget/
        └── mocktarget.go           httptest.Server with scripted vulnerable/safe routes
```

> **DTO package (`pkg/dto`)** holds the four objects that cross layer boundaries — `Request`,
> `AttackRequest`, `Response`, `Result`. They are **pure data** (fields + `Clone()` only), so
> every layer (matcher→mutation→engine→sender→detect→report) depends on a shared vocabulary
> without depending on each other's *logic*. `Rule` stays in `pkg/rule` because it owns
> validation behavior (it's a config model, not a transfer object).

---

## 3. Data model

```go
// pkg/rule
type Rule struct {
    ID        string        // yaml: rule
    Name      string
    Severity  string
    Target    Target
    Mutations []Mutation
    Detection []Detection
}
type Target struct {
    PathPattern string   // "/users/{userId}"
    Methods     []string // ["GET","PUT"]  (normalized upper-case)
}
type Mutation struct {
    Type     string // "parameter_swap" | "header_inject"
    Target   string // "path.userId" | "header.Authorization" | "body.a.b"
    Strategy string // "increment" (parameter_swap only)
    Value    string // header_inject value
}
type Detection struct {
    StatusCode   int    // 0 = not set
    BodyContains string // "" = not set
}

// ── pkg/dto — pure data-transfer objects, shared vocabulary across all layers ──
type Request struct {
    Method  string
    Path    string
    Headers map[string]string
    Query   map[string]string
    Body    map[string]any     // nested JSON
}
func (r Request) Clone() Request { /* deep copy — variants must not alias */ }

type AttackRequest struct {     // provenance wrapper — carries lineage end-to-end
    RuleID   string; RuleName string
    Endpoint string          // "GET /users/{userId}"
    Mutation string          // human description, e.g. "parameter_swap increment +1"
    Request  Request
}

type Response struct {
    Status int
    Body   string
}

type Result struct {
    RuleID     string; Endpoint string
    Mutation   string
    Sent       bool
    Vulnerable bool
    Evidence   string
}
```

---

## 4. LOAD + VALIDATE (`pkg/rule`)

```
LoadRules(dir):
    files := glob(dir, "*.yaml", "*.yml")
    for f in files:
        raw, err := readFile(f)                 ─┐ collect error, continue
        rule, err := yaml.Unmarshal(raw)         │ (never abort the run)
        err := rule.Validate()                  ─┘
        if any err: loadErrors.append({f, err}); continue
        rules.append(rule)
    return rules, loadErrors
```

**Validation rules (`Validate()`):**

| Field | Requirement |
|-------|-------------|
| `ID` (rule) | non-empty |
| `Target.PathPattern` | non-empty |
| `Target.Methods` | ≥ 1, each a known HTTP method |
| `Mutations` | ≥ 1; each has a known `Type` and non-empty `Target` |
| `parameter_swap` | `Strategy` recognized (`increment`) |

`invalid_rule.yaml` fails on **missing `Target`** → skipped + warned.

---

## 5. MATCH (`pkg/matcher`)

```go
func Match(r rule.Rule, e specparser.Endpoint) bool {
    if !contains(r.Target.Methods, strings.ToUpper(e.Method)) { return false } // cheap first
    return segmentMatch(r.Target.PathPattern, e.Path)
}

func segmentMatch(pattern, path string) bool {
    p := split(pattern); q := split(path)          // trim "/", split on "/"
    if len(p) != len(q) { return false }           // ← "*"/param = EXACTLY one segment
    for i := range p {
        seg := p[i]
        if seg == "*" || isParam(seg) { continue }  // isParam: {...}
        if seg != q[i] { return false }
    }
    return true
}
```

```
/admin/*  vs  /admin/dashboard          → [admin,*] vs [admin,dashboard]         ✅ len 2==2
/admin/*  vs  /admin/dashboard/settings → [admin,*] vs [admin,dashboard,settings] ❌ len 2!=3
```

---

## 6. MUTATE — the two-axis core (`pkg/mutation`)

### 6.1 Interfaces

```go
// WHAT: transform a value into attack variants
type Mutator interface {
    Mutate(orig request.Request, acc Accessor, field string, m rule.Mutation,
           vp valueprovider.ValueProvider) ([]request.Request, error)
}

// WHERE: get/set a value at a field path within a request domain
type Accessor interface {
    Get(r request.Request, field string) (any, bool)
    Set(r *request.Request, field string, val any)   // mutates a *clone*
}

var mutatorRegistry  = map[string]Mutator{ "parameter_swap": ParameterSwap{}, "header_inject": HeaderInject{} }
var accessorRegistry = map[string]Accessor{ "path": PathAccessor{}, "header": HeaderAccessor{},
                                            "query": QueryAccessor{}, "body": BodyAccessor{} }

// "body.user.address.id" → ("body", "user.address.id")
func parseTarget(t string) (domain, field string) {
    parts := strings.SplitN(t, ".", 2)
    if len(parts) == 1 { return parts[0], "" }
    return parts[0], parts[1]
}
```

### 6.2 Dispatch (inside `engine.Run`, per matched rule+endpoint)

```
orig := request.FromEndpoint(ep)              // seed values via ValueProvider
for m in rule.Mutations:
    domain, field := parseTarget(m.Target)
    acc  := accessorRegistry[domain]          // path/query/header/body
    mut  := mutatorRegistry[m.Type]           // parameter_swap/header_inject
    if acc == nil || mut == nil: warn+skip
    variants := mut.Mutate(orig, acc, field, m, vp)
    for v in variants:
        attacks.append(AttackRequest{RuleID:r.ID, Endpoint:ep.String(),
                                     Mutation:describe(m), Request:v})
```

### 6.3 ParameterSwap

```
Mutate(orig, acc, field, m, vp):
    cur, ok := acc.Get(orig, field)
    if !ok: cur = vp.BaseValue(domain, field)   // e.g. {userId} → 42
    n := toInt(cur)
    out := []
    for delta in [+1, -1] (strategy=increment):
        v := orig.Clone()
        acc.Set(&v, field, n+delta)
        out.append(v)
    return out                                   // → /users/43, /users/41
```

### 6.4 HeaderInject

```
Mutate(orig, acc, field, m, vp):
    v := orig.Clone()
    acc.Set(&v, field, m.Value)                  // set/replace; "" allowed
    return [v]                                    // → Authorization: ""
```

### 6.5 Accessors

```
PathAccessor   field="userId"  → find "{userId}" segment; Get returns its value, Set replaces it
HeaderAccessor field="Authorization" → r.Headers[field]           (case-insensitive)
QueryAccessor  field="userId"  → r.Query[field]                    (designed-for)
BodyAccessor   field="user.address.id" → dot-path walk of r.Body:  (designed-for)
      keys := split(field, "."); descend map[string]any per key; get/set leaf
      (guard: missing key or non-map intermediate → no-op / create as configured)
```

---

## 7. ValueProvider (`pkg/valueprovider`)

```go
type ValueProvider interface { BaseValue(domain, field string) any }

type DefaultProvider struct{}                         // MVP
func (DefaultProvider) BaseValue(domain, field string) any {
    switch domain {
    case "path", "query": return 42                    // give increment something to work on
    case "body":          return map[string]any{}
    default:              return ""
    }
}
// Future: SpecExampleProvider, SeedConfigProvider, RecordedTrafficProvider — same interface.
```

---

## 8. SEND (`pkg/sender`) + DETECT (`pkg/detect`) — nice-to-have

```go
func Send(attacks []attack.AttackRequest, baseURL string, concurrency int) []Response {
    sem := make(chan struct{}, concurrency)            // bounded — the rate cap
    out := make([]Response, len(attacks))
    var wg sync.WaitGroup
    for i, a := range attacks {
        wg.Add(1); sem <- struct{}{}
        go func(i int, a attack.AttackRequest) {
            defer wg.Done(); defer func(){ <-sem }()
            out[i] = doHTTP(baseURL, a.Request)        // each goroutine owns its slot+result
        }(i, a)
    }
    wg.Wait(); return out
}
```

```go
// Detect: ALL set conditions must hold.
func Detect(ds []rule.Detection, resp Response) (bool, string) {
    for _, d := range ds {
        if d.StatusCode != 0 && resp.Status != d.StatusCode { continue }
        if d.BodyContains != "" && !strings.Contains(resp.Body, d.BodyContains) { continue }
        return true, fmt.Sprintf("status=%d body~=%q", resp.Status, d.BodyContains)
    }
    return false, ""
}
```

Provenance (`AttackRequest`) + index alignment map each `Response` back to its `Result`.

---

## 9. Mock target (`pkg/mocktarget`) — makes detection demonstrable

```go
func New() *httptest.Server {
    mux := http.NewServeMux()
    mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(200)
        w.Write([]byte(`{"id":43,"email":"victim@example.com"}`)) // → BOLA-001 fires
    })
    mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
        if r.Header.Get("Authorization") == "" { w.WriteHeader(200) } // → AUTH-BYPASS fires
        else { w.WriteHeader(403) }
    })
    return httptest.NewServer(mux)   // srv.URL → baseURL for Send
}
```

In-process, no deps, dies with the CLI. Optional `--target <url>` overrides it with a real host.

---

## 10. Orchestrator (`cmd/engine/main.go`)

```
main():
    flags: --rules (req), --spec (req), --send (bool), --target (str), --concurrency (int=5)
    endpoints, err := specparser.ParseSpec(spec)             ; fatal on err
    rules, loadErrs := rule.LoadRules(rulesDir)
    for e in loadErrs: log.Printf("skip rule: %v", e)        ; continue-anyway
    attacks := engine.Run(rules, endpoints, valueprovider.DefaultProvider{})
    if !send:
        report.PrintAttacks(attacks)                          ; return   // MVP path
    base := target or mocktarget.New().URL
    resps   := sender.Send(attacks, base, concurrency)
    results := detect.Correlate(attacks, resps, rules)
    report.PrintResults(results)                              // grouped by RuleID
```

---

## 11. Expected run (petstore)

```
$ go run ./cmd/engine --rules ../../rules --spec ../../sample_specs/petstore.yaml

Loaded 2 rules (skipped 1 invalid: BAD-001 — missing target)

BOLA-001  Broken Object Level Authorization  [high]
  match GET /users/{userId}
    parameter_swap increment  → GET /users/43
    parameter_swap increment  → GET /users/41
  match PUT /users/{userId}
    parameter_swap increment  → PUT /users/43
    parameter_swap increment  → PUT /users/41

AUTH-BYPASS-001  Authorization Header Bypass  [critical]
  match GET /admin/dashboard
    header_inject Authorization=""  → GET /admin/dashboard (Authorization: "")
  match GET /admin/users
    header_inject Authorization=""  → GET /admin/users (Authorization: "")

# with --send:
BOLA-001     GET /users/{userId}   VULNERABLE  (status=200 body~="email")
AUTH-BYPASS-001 GET /admin/dashboard VULNERABLE (status=200)
```

---

## 12. Test plan

| Unit | Cases |
|------|-------|
| `matcher` | exact, method mismatch, `{param}`, `*` one-segment, `*` reject multi-segment, `/products` no-match |
| `rule.Validate` | valid rule passes; `invalid_rule.yaml` (missing target) rejected |
| `loader` | 3 files → 2 loaded + 1 error; malformed YAML handled |
| `ParameterSwap` | `/users/42` → `43` & `41`; original untouched |
| `HeaderInject` | adds when absent; replaces when present; empty value allowed |
| `BodyAccessor` | nested get/set `a.b.c`; missing intermediate guarded |
| `Detect` | all-conditions-AND; status-only; status+body |
| e2e | run against petstore + mock target → expected vulnerable results |

---

## 13. Sequential flow — every function, in call order

```
main()                                                         [cmd/engine]
│
├─ flag.Parse()                                                 rulesDir, specPath, send, target, concurrency
│
├─ specparser.ParseSpec(specPath) → []Endpoint                 [PROVIDED]   (fatal on err)
│
├─ rule.LoadRules(rulesDir) → ([]Rule, []LoadError)            [rule/loader.go]
│    └─ for each *.yaml:
│         ├─ os.ReadFile(f)
│         ├─ yaml.Unmarshal(raw, &Rule)
│         └─ (*Rule).Validate() → error                        [rule/validate.go]
│              ├─ checks ID, Target.PathPattern, Methods, Mutations
│              └─ invalid → append LoadError, skip (never abort)
│    └─ report loadErrors (log "skip rule: …")
│
├─ vp := valueprovider.DefaultProvider{}                       [valueprovider/provider.go]
│
├─ engine.Run(rules, endpoints, vp) → []dto.AttackRequest      [engine/engine.go]   ◀── CORE LOOP
│    └─ for r in rules:
│         └─ for ep in endpoints:
│              ├─ matcher.Match(r, ep) → bool                  [matcher/matcher.go]
│              │    ├─ contains(r.Target.Methods, ep.Method)   method check (cheap first)
│              │    └─ segmentMatch(pattern, path) → bool      split → len-check → per-seg
│              │         └─ isParam(seg) / seg=="*" / literal==
│              ├─ (no match → continue)
│              ├─ orig := mutation.FromEndpoint(ep, vp) → dto.Request   [mutation/builder.go]
│              │    └─ vp.BaseValue(domain, field) fills path placeholders
│              └─ for m in r.Mutations:
│                   ├─ domain, field := mutation.parseTarget(m.Target)  [mutation/accessor.go]
│                   ├─ acc := mutation.accessorRegistry[domain]         Accessor
│                   ├─ mut := mutation.mutatorRegistry[m.Type]          Mutator
│                   ├─ (nil acc|mut → warn + skip)
│                   ├─ variants := mut.Mutate(orig, acc, field, m, vp)  [mutator impl]
│                   │    ├─ ParameterSwap.Mutate:                       [parameter_swap.go]
│                   │    │    ├─ acc.Get(orig, field) → cur             [accessor_path.go]
│                   │    │    ├─ (miss → vp.BaseValue)
│                   │    │    └─ for delta in {+1,-1}:
│                   │    │         ├─ v := orig.Clone()                 [dto/request.go]
│                   │    │         └─ acc.Set(&v, field, cur+delta)     [accessor_path.go]
│                   │    └─ HeaderInject.Mutate:                        [header_inject.go]
│                   │         ├─ v := orig.Clone()
│                   │         └─ acc.Set(&v, field, m.Value)            [accessor_header.go]
│                   └─ for v in variants:
│                        └─ append dto.AttackRequest{RuleID, Endpoint,  ◀── PROVENANCE tag
│                                    Mutation:describe(m), Request:v}
│
├─ IF !send:                                                    ── MVP PATH ──
│    └─ report.PrintAttacks(attacks)                           [report/report.go]  → EXIT
│
└─ ELSE (nice-to-have path):
     ├─ base := target  OR  mocktarget.New().URL                [mocktarget/mocktarget.go]
     │                        └─ httptest.NewServer(mux)         scripted /users/, /admin/
     ├─ resps := sender.Send(attacks, base, concurrency) → []dto.Response   [sender/sender.go]
     │    └─ sem := make(chan struct{}, concurrency)             bounded pool
     │         └─ per attack goroutine: doHTTP(base, a.Request) → dto.Response
     ├─ results := detect.Correlate(attacks, resps, rules) → []dto.Result   [detect/correlate.go]
     │    └─ per (attack[i], resp[i]):
     │         └─ detect.Detect(rule.Detection, resp) → (bool, evidence)     [detect/detect.go]
     │              └─ ALL set conditions must hold (status, body_contains)
     └─ report.PrintResults(results)                            [report/report.go]  → EXIT
```

**Dependency direction (acyclic):**

```
   cmd/engine ──▶ engine ──▶ matcher
                    │  └────▶ mutation ──▶ valueprovider
                    │                └───▶ dto
                    ├──▶ rule (also used by detect, matcher)
                    ├──▶ sender ──▶ dto
                    ├──▶ detect ──▶ dto, rule
                    ├──▶ report ──▶ dto
                    └──▶ mocktarget
   everything ──▶ dto            (leaf: dto imports nothing internal)
   everything ──▶ specparser     (leaf: provided)
```

`dto` and `specparser` are **leaves** (import no internal package); `cmd/engine` is the only
**root**. No cycles.

---

## 14. Modularity review

**Cohesion — each package has one reason to change:**

| Package | Single responsibility | Changes when… |
|---------|----------------------|---------------|
| `dto` | shared data shapes | a field is added to a transfer object |
| `rule` | rule config model + validation | the rule schema changes |
| `matcher` | rule↔endpoint matching | matching semantics change (e.g. `**`) |
| `mutation` | generating attack variants | a new mutation type/domain is added |
| `valueprovider` | supplying base values | a new value source is added |
| `engine` | orchestrating the core loop | pipeline wiring changes |
| `sender` | HTTP I/O + concurrency | transport/rate policy changes |
| `detect` | response→verdict | detection conditions change |
| `report` | output formatting | output format changes |
| `mocktarget` | test double | mock scenarios change |

**Coupling — low, via interfaces + DTOs:**
- Layers share the `dto` vocabulary but never each other's logic → swapping an implementation
  (e.g. a real `SpecExampleProvider`) touches one package.
- `Mutator` and `Accessor` interfaces mean `engine` depends on *abstractions*, not concrete
  mutation types → **Open/Closed**: new type = new file + one registry line, engine untouched.
- `ValueProvider` interface isolates the "missing spec value" gap behind one seam.

**SOLID scorecard:**

| Principle | How it's honored |
|-----------|------------------|
| **S**RP | one package = one responsibility (table above) |
| **O**CP | registries make mutation types/accessors/value-sources additive, not invasive |
| **L**SP | all `Mutator`s, `Accessor`s, `ValueProvider`s are interchangeable behind their interface |
| **I**SP | tiny focused interfaces (`Mutator`: 1 method, `Accessor`: 2, `ValueProvider`: 1) |
| **D**IP | `engine` depends on interfaces + `dto`, not on concrete strategies or transports |

**Testability:** every package is unit-testable in isolation — `matcher` needs no I/O,
mutation strategies take plain `dto.Request`, `sender` is the only package touching the
network (and even that is exercised via the in-process `mocktarget`).

**Known trade-offs / weak spots (honest):**
- `mutation` package is the densest — mitigated by one-file-per-strategy/accessor split.
- `dto` as a shared package is a mild "hub"; acceptable because it's pure data (no logic to
  couple to) and keeps the graph acyclic. Alternative (per-layer DTOs) was rejected as
  over-engineering for this scope.
- Package granularity (10 packages) is generous for a 1.5h task — deliberate, to make the
  extensibility story concrete; could collapse `detect`+`report` if time-pressed.

---

## 15. Build order (MVP-first)

1. `dto` structs (Request, AttackRequest, Response, Result) + `Clone`.
2. `rule` structs + `Validate` + `loader`  → prove skip-invalid.
3. `matcher` + tests                        → prove path/method/wildcard.
4. `mutation` (builder, parameter_swap, header_inject; path+header accessors) + `valueprovider`.
5. `engine.Run` + `report` (no-send)        → **end-to-end on petstore (MVP done).**
6. `mocktarget` + `sender` + `detect`       → end-to-end with detection (nice-to-have).
7. Stretch: query/body accessors, multi-spec fan-out, `--target`.
