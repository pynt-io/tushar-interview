## Part 1: Code Assessment

**Duration:** 1.5 hours
**Format:** AI-Assisted Pair Programming

---

## Welcome

In this interview, you'll implement a core component of an API security testing engine. You'll work with an **AI assistant of your choice** (Claude, ChatGPT, Copilot - whatever you're comfortable with).

We're interested in:

- How you collaborate with the AI - what you ask it vs. what you do yourself
- How you review and iterate on output
- The quality of your design and code

You can ask the interviewer clarifying questions at any time,  treat them as your PM.

---

## Your Environment

- **Language:** Python or Go - your choice
- **AI Assistant:** Use whichever tool you prefer.

## Setup

Clone this repo and create your branch:

```jsx
git clone <repo-url>
cd <repo-name>
git checkout -b solution/<your-name>
```

---

## The Scenario

Radware's engine container runs automated security tests against customer APIs. Today, attack patterns are hardcoded in the engine. We want to **externalize these patterns into configurable rules** so that our security research team can add, modify, and version attack signatures without deploying new engine code.

> Your job is to build the core of this rule engine.
>

---

## Feature Request: Configurable Attack Signature Rules

We want to externalize our attack patterns into a rule format that security researchers can author without writing code. Here's what we need:

1. **Rules are defined in YAML files.** Each rule describes one attack test.
2. A rule specifies: **which API endpoints it targets** (by path pattern and HTTP method), **how to mutate the original request** (headers, query params, body), and **what response pattern indicates a vulnerability** was found.
3. The engine **loads all rules from a directory**, matches them against a given API endpoint, and executes the matching rules.
4. Each rule execution should produce a **structured result**: rule ID, target endpoint, pass/fail, evidence.

## The Rule Format

Below are the two mutation types your engine needs to support: `parameter_swap` and `header_inject`. Implement these two types - you don't need to invent others, but your design should make it easy to add new types in the future.

`parameter_swap` - Replaces a path parameter with modified values

This rule says: *"For any endpoint matching `/users/{userId}` on GET or PUT, try swapping the user ID (e.g., change 42 to 43). If the API still returns 200 with an email field in the body, it's likely vulnerable to Broken Object Level Authorization."*

```yaml
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
```

**How `parameter_swap` works:** Given an endpoint `/users/42`, the `increment` strategy produces two attack variants: one with `/users/43` and one with `/users/41`. The original request is not modified.

`header_inject` - Sets or replaces an HTTP header

```yaml
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
```

**How `header_inject` works:** Takes the original request and creates a variant with the specified header set to the given value. If the header already exists, it's replaced.

### Detection (what "vulnerability found" means)

The `detection` section describes what response pattern indicates the endpoint is vulnerable. A detection matches when **all** its conditions are true:

- `status_code` — the HTTP response status code equals this value
- `body_contains` — the response body contains this string

If a rule has `status_code: 200` and `body_contains: "email"`, it only triggers when both are true.

---

## API Endpoints Input

The repo includes a **ready-to-use OpenAPI parser** (`spec_parser.py` , `parser.go`) that reads a spec file and returns typed `Endpoint` objects.

Each `Endpoint` has `.path` (e.g., `"/users/{userId}"`), `.method` (e.g., `"GET"`), and an optional `.operation_id`. You can use this parser as-is or modify it if needed.

Your engine matches rules against these endpoints. For example, the rule targeting `/users/{userId}` with methods `[GET, PUT]` should match both `GET /users/{userId}` and `PUT /users/{userId}`, but not `GET /products`.

A `*` wildcard in a rule pattern matches **exactly one** path segment: `/admin/*` matches `/admin/dashboard` but NOT `/admin/dashboard/settings`.

### What We Need

Given a directory of YAML rule files and an API endpoint, the engine should:

1. Load the rules
2. Figure out which rules apply to the endpoint
3. Modify the request according to the rule's mutations
4. Determine if the response indicates a vulnerability

> The interviewer is your PM - ask them questions if anything is unclear.
>

**Expected usage:**

```
python main.py --rules ./rules --spec ./sample_specs/petstore.yaml
```

> **It’s not a long-running service.** It runs, produces output, and exits.
>

---

## Test Data

The `rules/` directory in this repo contains sample YAML files you can use to test your implementation. One of them is intentionally invalid - your engine should handle that gracefully.

The `sample_specs/` directory contains an OpenAPI spec you can use.

**You can (and should) run your tool against this test data before submitting** to verify it works

---

## What to Prioritize

We'd rather see a code **that runs end-to-end on the test data** with fewer features, than more code that doesn't execute. If you're running low on time, cut scope - don't leave broken code.

Specifically:

- A working loader + matcher + at least `parameter_swap` is more valuable than a non-working full implementation
- Your mutations handling must generate a mutated request, but don't need to actually send them (that's nice-to-have)
- The detection logic is a nice-to-have, not a must-have

---

## **When You're Done**

Commit your work, push, and open a PR.

**In your PR description, include:**

- How to run your tool (the command)
- Anything you'd do differently with more time

## Working with AI

Use your AI assistant however you normally would — we want to see your real workflow.

At the end of the session, export your AI conversation as a text or markdown file and add it to the repo:

```
ai-conversation/
└── chat.md
```

We review this as part of the interview - it helps us understand how you approach and collaborate with AI.

---

## Notes

- The interviewer is your PM. Ask them anything you'd ask a PM in real life.
- Commit as you go — we like to see how your thinking evolved.
- Existing files in the repo (rules, specs) are inputs — don't modify them.

Good luck! 🚀
