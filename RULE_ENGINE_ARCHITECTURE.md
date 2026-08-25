# API Security Rule Engine - Architecture Documentation

## Overview

This is a Python-based rule engine for API security testing that loads YAML rules, matches them to OpenAPI endpoints, applies request mutations, and analyzes responses for vulnerabilities. The engine is designed for extensibility and testability, with comprehensive unit tests covering all functionality.

## Architecture

### Components

1. **spec_parser.py** - OpenAPI spec parser
   - Parses OpenAPI 3.x YAML files
   - Returns Endpoint objects (path, method, operation_id)

2. **rule_engine.py** - Core rule engine
   - Rule class: Represents a security rule loaded from YAML
   - Vulnerability class: Represents a detected vulnerability
   - RuleEngine class: Main engine for loading and applying rules
   - Supports external response injection for testing

3. **main.py** - CLI entry point
   - Command-line interface for running the engine
   - Integrates spec parser and rule engine
   - Supports optional predefined responses for testing

4. **test_rule_engine.py** - Comprehensive unit test suite
   - 38 unit tests covering all rule engine functionality
   - Tests rule matching, mutation application, response analysis
   - Tests all three provided rules (admin, IDOR, public endpoint)
   - Integration tests for complete workflow
   - Edge case testing

5. **rules/** - YAML rule files
   - Contains security rules in YAML format
   - Each rule defines matching criteria, mutations, and response checks

6. **sample_specs/test_responses.yaml** - Test response data
   - Predefined responses for testing the rule engine
   - Maps endpoint paths to response objects

## Rule File Structure

```yaml
rule_id: UNIQUE_ID
name: Rule Name
description: What this rule checks
severity: HIGH|MEDIUM|LOW|INFO|CRITICAL

match:
  path_patterns:
    - "/admin/*"
  methods:
    - GET
    - POST

mutations:
  - type: replace_header
    header: "X-Auth-Token"
    value: "invalid_token"

response_checks:
  - type: status_code
    operator: "!="
    expected: 401
    vulnerability: "ADMIN_ENDPOINT_EXPOSED"
    message: "Admin endpoint accessible without valid authentication"
```

## Features

### Rule Matching
- Pattern matching on endpoint paths (glob patterns)
- HTTP method filtering
- Multiple patterns per rule

### Request Mutations
- Header replacement/addition
- Path parameter manipulation
- Extensible mutation types

### Response Analysis
- Status code checking (==, !=, <=, >=)
- Body content analysis (contains, not_contains)
- Multiple checks per rule
- Configurable vulnerability types and messages

## Usage

### Basic Usage
```bash
python python/main.py --rules ./rules --spec ./sample_specs/petstore.yaml
```

### Installation
```bash
pip install -r python/requirements.txt
```

## Example Rules Included

1. **admin_endpoint_check.yaml** - Detects exposed admin endpoints
2. **idor_check.yaml** - Tests for IDOR vulnerabilities
3. **public_endpoint_check.yaml** - Verifies public endpoint availability

## Output Format

The engine provides:
- Real-time progress updates during evaluation
- Formatted vulnerability results with severity levels
- Exit codes (0 for no vulnerabilities, 1 for findings)
- Detailed per-rule and per-endpoint reporting

## Extensibility

### Adding New Rules
1. Create a new YAML file in the `rules/` directory
2. Define matching criteria, mutations, and response checks
3. The engine automatically loads all `.yaml` files

### Adding New Mutation Types
Extend the `_apply_mutations` method in `rule_engine.py`

### Adding New Response Check Types
Extend the `_analyze_response` method in `rule_engine.py`

### Real HTTP Requests
Replace the `_generate_mock_response` method with actual HTTP client calls to test real APIs

## Testing

### Unit Tests
The engine includes a comprehensive unit test suite with 38 tests covering:

- **Rule Matching Tests**: Path pattern matching, method filtering, wildcard patterns
- **Mutation Tests**: Header replacement/addition, path parameter manipulation
- **Response Analysis Tests**: Status code checks, body content analysis
- **Rule-Specific Tests**: Admin endpoint, IDOR, and public endpoint rules
- **Integration Tests**: Complete workflow with multiple endpoints and rules
- **Edge Case Tests**: Empty mutations, empty response checks, multiple patterns

Run unit tests:
```bash
cd python
python3 -m pytest test_rule_engine.py -v
```

### Integration Testing with Predefined Responses
The engine supports predefined responses for testing without making actual HTTP requests:

```bash
python python/main.py --rules ./rules --spec ./sample_specs/petstore.yaml --responses ./sample_specs/test_responses.yaml
```

### Real API Testing
To test with real APIs, you can extend the engine to make actual HTTP requests by:
1. Adding HTTP client functionality to make real requests
2. Configure target API base URL
3. Add authentication/authorization headers as needed
4. Replace the response injection with actual HTTP responses

## Exit Codes

- `0` - No vulnerabilities found
- `1` - Vulnerabilities detected or error occurred

## Future Enhancements

- Real HTTP request execution
- Configuration file support
- Output formats (JSON, XML, HTML)
- Rule dependency management
- Performance optimizations for large specs
- Rule validation and testing framework