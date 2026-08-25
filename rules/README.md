# API Security Rule Engine - Rules Directory

This directory contains YAML rule files for the API security testing engine.

## Rule Structure

Each rule file follows this structure:

```yaml
rule_id: UNIQUE_RULE_ID
name: Human-readable rule name
description: What this rule checks for
severity: HIGH|MEDIUM|LOW|INFO|CRITICAL

# Matching criteria - which endpoints this rule applies to
match:
  path_patterns:
    - "/pattern/*"
    - "/specific/path"
  methods:
    - GET
    - POST

# Request mutations - how to modify the request for testing
mutations:
  - type: replace_header
    header: "Header-Name"
    value: "test_value"
  - type: replace_path_param
    param: "paramName"
    value: "test_value"

# Response analysis - how to detect vulnerabilities
response_checks:
  - type: status_code
    operator: "=="|"<="|">="|"!="
    expected: 200
    vulnerability: "VULNERABILITY_TYPE"
    message: "Description of the vulnerability"
```

## Supported Features

### Matching Criteria
- `path_patterns`: List of glob patterns to match endpoint paths
- `methods`: List of HTTP methods to match (GET, POST, PUT, DELETE, PATCH)

### Mutation Types
- `replace_header`: Replace an existing header value
- `add_header`: Add a new header
- `replace_path_param`: Replace a path parameter value

### Response Check Types
- `status_code`: Check HTTP status code
  - Operators: `==`, `!=`, `<=`, `>=`
- `body_contains`: Check if response body contains/doesn't contain text
  - Operators: `contains`, `not_contains`

## Example Rules

### Admin Endpoint Check
Detects exposed admin endpoints that should be protected with authentication.

### IDOR Check
Tests for Insecure Direct Object Reference vulnerabilities by manipulating user IDs.

### Public Endpoint Check
Verifies public endpoints are accessible and respond correctly.

## Usage

Run the rule engine with:

```bash
python python/main.py --rules ./rules --spec ./sample_specs/petstore.yaml
```

## Adding New Rules

1. Create a new `.yaml` file in this directory
2. Follow the rule structure above
3. Test your rule with the sample spec
4. The engine will automatically load all `.yaml` files from this directory