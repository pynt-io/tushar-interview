# Rule Engine Unit Tests

This directory contains comprehensive unit tests for the API Security Rule Engine.

## Test Structure

The test suite is organized into the following test classes:

### TestRuleMatching
Tests the rule matching logic:
- Path pattern matching (admin paths, user paths, wildcards)
- HTTP method filtering
- Case sensitivity
- Multiple pattern support
- Negative matching (wrong paths/methods)

### TestMutationApplication
Tests request mutation application:
- Header replacement mutations
- Header addition mutations
- Path parameter replacement
- Multiple mutations on same header
- Request structure preservation

### TestResponseAnalysis
Tests response analysis and vulnerability detection:
- Status code checks (==, !=, <=, >=)
- Body content analysis (contains, not_contains)
- Vulnerability object properties
- Multiple response checks per rule

### TestAdminEndpointRule
Tests the admin endpoint specific rule:
- Admin endpoint matching
- Non-admin endpoint filtering
- Admin-specific mutations
- Response analysis for admin endpoints

### TestIDORRule
Tests the IDOR (Insecure Direct Object Reference) rule:
- IDOR endpoint matching
- Non-IDOR endpoint filtering
- IDOR-specific mutations
- Response analysis for IDOR detection

### TestPublicEndpointRule
Tests the public endpoint rule:
- Public endpoint matching
- Non-public endpoint filtering
- Public endpoint mutations

### TestRuleEngineIntegration
Integration tests for the complete workflow:
- Multiple rules applied to single endpoint
- No matching rules scenario
- Multiple endpoints evaluation
- Severity level verification

### TestEdgeCases
Tests edge cases and error conditions:
- Empty mutations
- Empty response checks
- Wildcard path patterns
- Multiple path patterns

## Running Tests

### Run all tests
```bash
cd python
python3 -m pytest test_rule_engine.py -v
```

### Run specific test class
```bash
python3 -m pytest test_rule_engine.py::TestRuleMatching -v
```

### Run specific test
```bash
python3 -m pytest test_rule_engine.py::TestRuleMatching::test_matches_path_pattern_admin -v
```

### Run with coverage
```bash
python3 -m pytest test_rule_engine.py --cov=. --cov-report=html
```

## Test Coverage

The test suite provides comprehensive coverage of:
- ✅ Rule matching logic (7 tests)
- ✅ Mutation application (5 tests)
- ✅ Response analysis (6 tests)
- ✅ Admin endpoint rule (4 tests)
- ✅ IDOR rule (4 tests)
- ✅ Public endpoint rule (3 tests)
- ✅ Integration tests (4 tests)
- ✅ Edge cases (5 tests)

**Total: 38 tests**

## Test Data

Tests use actual rule files from the `../rules/` directory:
- `admin_endpoint_check.yaml`
- `idor_check.yaml`
- `public_endpoint_check.yaml`

This ensures tests validate against the actual rule structure used in production.

## Key Testing Features

1. **No External Dependencies**: Tests don't require actual HTTP requests
2. **Real Rule Files**: Tests use actual YAML rule files for authenticity
3. **Comprehensive Coverage**: All rule engine functionality is tested
4. **Isolated Tests**: Each test is independent and can run alone
5. **Clear Naming**: Test names clearly describe what they test

## Design Decisions

### Response Injection
The updated rule engine supports response injection rather than using mock responses internally. This allows:
- Clean separation of concerns
- Easier testing with predefined responses
- Support for both testing and real HTTP scenarios
- Better testability and maintainability

### Test Organization
Tests are organized by functionality rather than by rule, making it easier to:
- Find specific test cases
- Understand test coverage
- Add new tests for new features
- Maintain the test suite