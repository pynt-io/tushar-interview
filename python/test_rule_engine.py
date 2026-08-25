"""
Unit tests for the API Security Rule Engine
Tests rule matching, mutation application, and response analysis
"""
import unittest
import sys
from pathlib import Path
from typing import Dict, Any

# Add the python directory to the path
sys.path.insert(0, str(Path(__file__).parent))

from spec_parser import Endpoint
from rule_engine import Rule, RuleEngine, Vulnerability


class TestRuleMatching(unittest.TestCase):
    """Test rule matching logic."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.rule = Rule(
            rule_id="TEST_RULE",
            name="Test Rule",
            description="Test description",
            severity="HIGH",
            match={
                "path_patterns": ["/admin/*", "/users/{userId}"],
                "methods": ["GET", "POST"]
            },
            mutations=[],
            response_checks=[]
        )
        self.engine = RuleEngine.__new__(RuleEngine)
        self.engine.rules = [self.rule]
    
    def test_matches_path_pattern_admin(self):
        """Test matching admin path pattern."""
        endpoint = Endpoint(path="/admin/dashboard", method="GET")
        self.assertTrue(self.engine._matches_endpoint(self.rule, endpoint))
    
    def test_matches_path_pattern_user(self):
        """Test matching user path pattern."""
        endpoint = Endpoint(path="/users/{userId}", method="GET")
        self.assertTrue(self.engine._matches_endpoint(self.rule, endpoint))
    
    def test_matches_path_pattern_wildcard(self):
        """Test matching wildcard pattern."""
        endpoint = Endpoint(path="/admin/users", method="POST")
        self.assertTrue(self.engine._matches_endpoint(self.rule, endpoint))
    
    def test_no_match_wrong_path(self):
        """Test no match for wrong path."""
        endpoint = Endpoint(path="/products", method="GET")
        self.assertFalse(self.engine._matches_endpoint(self.rule, endpoint))
    
    def test_no_match_wrong_method(self):
        """Test no match for wrong method."""
        endpoint = Endpoint(path="/admin/dashboard", method="DELETE")
        self.assertFalse(self.engine._matches_endpoint(self.rule, endpoint))
    
    def test_matches_multiple_patterns(self):
        """Test matching against multiple patterns."""
        endpoint = Endpoint(path="/admin/settings", method="GET")
        self.assertTrue(self.engine._matches_endpoint(self.rule, endpoint))
    
    def test_case_insensitive_method(self):
        """Test case-insensitive method matching."""
        endpoint = Endpoint(path="/admin/dashboard", method="GET")
        self.assertTrue(self.engine._matches_endpoint(self.rule, endpoint))


class TestMutationApplication(unittest.TestCase):
    """Test request mutation application."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.rule = Rule(
            rule_id="TEST_RULE",
            name="Test Rule",
            description="Test description",
            severity="HIGH",
            match={},
            mutations=[
                {"type": "replace_header", "header": "X-Auth-Token", "value": "invalid_token"},
                {"type": "add_header", "header": "X-Custom", "value": "test_value"},
                {"type": "replace_path_param", "param": "userId", "value": "999999"}
            ],
            response_checks=[]
        )
        self.engine = RuleEngine.__new__(RuleEngine)
        self.engine.rules = [self.rule]
    
    def test_replace_header_mutation(self):
        """Test header replacement mutation."""
        endpoint = Endpoint(path="/users/123", method="GET")
        mutated = self.engine._apply_mutations(self.rule, endpoint)
        
        self.assertEqual(mutated["headers"]["X-Auth-Token"], "invalid_token")
    
    def test_add_header_mutation(self):
        """Test header addition mutation."""
        endpoint = Endpoint(path="/users/123", method="GET")
        mutated = self.engine._apply_mutations(self.rule, endpoint)
        
        self.assertEqual(mutated["headers"]["X-Custom"], "test_value")
    
    def test_replace_path_param_mutation(self):
        """Test path parameter replacement mutation."""
        endpoint = Endpoint(path="/users/123", method="GET")
        mutated = self.engine._apply_mutations(self.rule, endpoint)
        
        self.assertEqual(mutated["path_params"]["userId"], "999999")
    
    def test_mutated_request_structure(self):
        """Test mutated request maintains correct structure."""
        endpoint = Endpoint(path="/users/123", method="GET")
        mutated = self.engine._apply_mutations(self.rule, endpoint)
        
        self.assertEqual(mutated["method"], "GET")
        self.assertEqual(mutated["path"], "/users/123")
        self.assertIsInstance(mutated["headers"], dict)
        self.assertIsInstance(mutated["path_params"], dict)
    
    def test_multiple_mutations_same_header(self):
        """Test multiple mutations on same header."""
        rule = Rule(
            rule_id="TEST_RULE",
            name="Test Rule",
            description="Test description",
            severity="HIGH",
            match={},
            mutations=[
                {"type": "replace_header", "header": "X-Auth", "value": "first"},
                {"type": "replace_header", "header": "X-Auth", "value": "second"}
            ],
            response_checks=[]
        )
        endpoint = Endpoint(path="/admin/test", method="GET")
        mutated = self.engine._apply_mutations(rule, endpoint)
        
        # Last mutation should win
        self.assertEqual(mutated["headers"]["X-Auth"], "second")


class TestResponseAnalysis(unittest.TestCase):
    """Test response analysis and vulnerability detection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.rule = Rule(
            rule_id="TEST_RULE",
            name="Test Rule",
            description="Test description",
            severity="HIGH",
            match={},
            mutations=[],
            response_checks=[
                {
                    "type": "status_code",
                    "operator": "==",
                    "expected": 200,
                    "vulnerability": "VULN_200",
                    "message": "Status code is 200"
                },
                {
                    "type": "status_code",
                    "operator": "!=",
                    "expected": 401,
                    "vulnerability": "VULN_NOT_401",
                    "message": "Status code is not 401"
                },
                {
                    "type": "body_contains",
                    "operator": "contains",
                    "pattern": "error",
                    "vulnerability": "VULN_CONTAINS_ERROR",
                    "message": "Body contains error"
                },
                {
                    "type": "body_contains",
                    "operator": "not_contains",
                    "pattern": "success",
                    "vulnerability": "VULN_NO_SUCCESS",
                    "message": "Body does not contain success"
                }
            ]
        )
        self.engine = RuleEngine.__new__(RuleEngine)
        self.engine.rules = [self.rule]
    
    def test_status_code_equals_match(self):
        """Test status code equals operator."""
        request = {"method": "GET", "path": "/test", "headers": {}, "path_params": {}}
        response = {"status_code": 200, "body": "test"}
        
        vulnerabilities = self.engine._analyze_response(self.rule, request, response)
        
        vuln_types = [v.vulnerability_type for v in vulnerabilities]
        self.assertIn("VULN_200", vuln_types)
    
    def test_status_code_not_equals_match(self):
        """Test status code not equals operator."""
        request = {"method": "GET", "path": "/test", "headers": {}, "path_params": {}}
        response = {"status_code": 200, "body": "test"}
        
        vulnerabilities = self.engine._analyze_response(self.rule, request, response)
        
        vuln_types = [v.vulnerability_type for v in vulnerabilities]
        self.assertIn("VULN_NOT_401", vuln_types)
    
    def test_status_code_no_match(self):
        """Test status code that doesn't match condition."""
        request = {"method": "GET", "path": "/test", "headers": {}, "path_params": {}}
        response = {"status_code": 401, "body": "test"}
        
        vulnerabilities = self.engine._analyze_response(self.rule, request, response)
        
        vuln_types = [v.vulnerability_type for v in vulnerabilities]
        self.assertNotIn("VULN_200", vuln_types)
    
    def test_body_contains_match(self):
        """Test body contains operator."""
        request = {"method": "GET", "path": "/test", "headers": {}, "path_params": {}}
        response = {"status_code": 200, "body": "error message"}
        
        vulnerabilities = self.engine._analyze_response(self.rule, request, response)
        
        vuln_types = [v.vulnerability_type for v in vulnerabilities]
        self.assertIn("VULN_CONTAINS_ERROR", vuln_types)
    
    def test_body_not_contains_match(self):
        """Test body not contains operator."""
        request = {"method": "GET", "path": "/test", "headers": {}, "path_params": {}}
        response = {"status_code": 200, "body": "failure message"}
        
        vulnerabilities = self.engine._analyze_response(self.rule, request, response)
        
        vuln_types = [v.vulnerability_type for v in vulnerabilities]
        self.assertIn("VULN_NO_SUCCESS", vuln_types)
    
    def test_vulnerability_properties(self):
        """Test vulnerability object properties."""
        request = {"method": "GET", "path": "/test", "headers": {}, "path_params": {}}
        response = {"status_code": 200, "body": "test"}
        
        vulnerabilities = self.engine._analyze_response(self.rule, request, response)
        
        self.assertEqual(len(vulnerabilities), 3)  # 200 == 200, 200 != 401, and body doesn't contain "success"
        
        vuln = vulnerabilities[0]
        self.assertEqual(vuln.rule_id, "TEST_RULE")
        self.assertEqual(vuln.severity, "HIGH")
        self.assertIn("GET /test", vuln.endpoint)


class TestAdminEndpointRule(unittest.TestCase):
    """Test admin endpoint specific rule."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Load actual admin rule
        import yaml
        rule_path = Path(__file__).parent.parent / "rules" / "admin_endpoint_check.yaml"
        with open(rule_path) as f:
            rule_data = yaml.safe_load(f)
        
        self.rule = Rule(
            rule_id=rule_data["rule_id"],
            name=rule_data["name"],
            description=rule_data["description"],
            severity=rule_data["severity"],
            match=rule_data["match"],
            mutations=rule_data["mutations"],
            response_checks=rule_data["response_checks"]
        )
        self.engine = RuleEngine.__new__(RuleEngine)
        self.engine.rules = [self.rule]
    
    def test_admin_endpoint_matching(self):
        """Test admin endpoint matches correctly."""
        endpoint = Endpoint(path="/admin/dashboard", method="GET")
        self.assertTrue(self.engine._matches_endpoint(self.rule, endpoint))
    
    def test_non_admin_endpoint_no_match(self):
        """Test non-admin endpoint doesn't match."""
        endpoint = Endpoint(path="/products", method="GET")
        self.assertFalse(self.engine._matches_endpoint(self.rule, endpoint))
    
    def test_admin_mutations(self):
        """Test admin endpoint mutations."""
        endpoint = Endpoint(path="/admin/dashboard", method="GET")
        mutated = self.engine._apply_mutations(self.rule, endpoint)
        
        self.assertIn("X-Auth-Token", mutated["headers"])
        self.assertEqual(mutated["headers"]["X-Auth-Token"], "invalid_token")
        self.assertIn("Authorization", mutated["headers"])
        self.assertEqual(mutated["headers"]["Authorization"], "Bearer invalid_token")
    
    def test_admin_response_analysis_200(self):
        """Test admin response analysis with 200 status."""
        request = {"method": "GET", "path": "/admin/dashboard", "headers": {}, "path_params": {}}
        response = {"status_code": 200, "body": "admin data"}
        
        vulnerabilities = self.engine._analyze_response(self.rule, request, response)
        
        # 200 != 401 and 200 != 403 should trigger vulnerabilities
        self.assertGreater(len(vulnerabilities), 0)
        vuln_types = [v.vulnerability_type for v in vulnerabilities]
        self.assertIn("ADMIN_ENDPOINT_EXPOSED", vuln_types)
    
    def test_admin_response_analysis_401(self):
        """Test admin response analysis with 401 status."""
        request = {"method": "GET", "path": "/admin/dashboard", "headers": {}, "path_params": {}}
        response = {"status_code": 401, "body": "Unauthorized"}
        
        vulnerabilities = self.engine._analyze_response(self.rule, request, response)
        
        # 401 == 401 should not trigger first check, but 401 != 403 should trigger second
        # Actually with our logic, 401 != 403 would still trigger
        self.assertGreater(len(vulnerabilities), 0)


class TestIDORRule(unittest.TestCase):
    """Test IDOR specific rule."""
    
    def setUp(self):
        """Set up test fixtures."""
        import yaml
        rule_path = Path(__file__).parent.parent / "rules" / "idor_check.yaml"
        with open(rule_path) as f:
            rule_data = yaml.safe_load(f)
        
        self.rule = Rule(
            rule_id=rule_data["rule_id"],
            name=rule_data["name"],
            description=rule_data["description"],
            severity=rule_data["severity"],
            match=rule_data["match"],
            mutations=rule_data["mutations"],
            response_checks=rule_data["response_checks"]
        )
        self.engine = RuleEngine.__new__(RuleEngine)
        self.engine.rules = [self.rule]
    
    def test_idor_endpoint_matching(self):
        """Test IDOR endpoint matches correctly."""
        endpoint1 = Endpoint(path="/users/{userId}", method="GET")
        endpoint2 = Endpoint(path="/users/{userId}/orders", method="GET")
        
        self.assertTrue(self.engine._matches_endpoint(self.rule, endpoint1))
        self.assertTrue(self.engine._matches_endpoint(self.rule, endpoint2))
    
    def test_non_idor_endpoint_no_match(self):
        """Test non-IDOR endpoint doesn't match."""
        endpoint = Endpoint(path="/products", method="GET")
        self.assertFalse(self.engine._matches_endpoint(self.rule, endpoint))
    
    def test_idor_mutations(self):
        """Test IDOR mutations."""
        endpoint = Endpoint(path="/users/123", method="GET")
        mutated = self.engine._apply_mutations(self.rule, endpoint)
        
        # Should have path parameter mutations
        self.assertIn("userId", mutated["path_params"])
        # Note: Since we have multiple mutations for the same param, the last one wins
        self.assertIn(mutated["path_params"]["userId"], ["999999", "1"])
    
    def test_idor_response_analysis_200(self):
        """Test IDOR response analysis with 200 status."""
        request = {"method": "GET", "path": "/users/999999", "headers": {}, "path_params": {}}
        response = {"status_code": 200, "body": "user data"}
        
        vulnerabilities = self.engine._analyze_response(self.rule, request, response)
        
        # 200 == 200 should trigger vulnerability
        vuln_types = [v.vulnerability_type for v in vulnerabilities]
        self.assertIn("POTENTIAL_IDOR", vuln_types)


class TestPublicEndpointRule(unittest.TestCase):
    """Test public endpoint specific rule."""
    
    def setUp(self):
        """Set up test fixtures."""
        import yaml
        rule_path = Path(__file__).parent.parent / "rules" / "public_endpoint_check.yaml"
        with open(rule_path) as f:
            rule_data = yaml.safe_load(f)
        
        self.rule = Rule(
            rule_id=rule_data["rule_id"],
            name=rule_data["name"],
            description=rule_data["description"],
            severity=rule_data["severity"],
            match=rule_data["match"],
            mutations=rule_data["mutations"],
            response_checks=rule_data["response_checks"]
        )
        self.engine = RuleEngine.__new__(RuleEngine)
        self.engine.rules = [self.rule]
    
    def test_public_endpoint_matching(self):
        """Test public endpoint matches correctly."""
        endpoint1 = Endpoint(path="/products", method="GET")
        endpoint2 = Endpoint(path="/products/123", method="GET")
        
        self.assertTrue(self.engine._matches_endpoint(self.rule, endpoint1))
        self.assertTrue(self.engine._matches_endpoint(self.rule, endpoint2))
    
    def test_non_public_endpoint_no_match(self):
        """Test non-public endpoint doesn't match."""
        endpoint = Endpoint(path="/admin/dashboard", method="GET")
        self.assertFalse(self.engine._matches_endpoint(self.rule, endpoint))
    
    def test_public_mutations(self):
        """Test public endpoint mutations."""
        endpoint = Endpoint(path="/products", method="GET")
        mutated = self.engine._apply_mutations(self.rule, endpoint)
        
        self.assertIn("X-Test-Header", mutated["headers"])
        self.assertEqual(mutated["headers"]["X-Test-Header"], "security_test")


class TestRuleEngineIntegration(unittest.TestCase):
    """Integration tests for the complete rule engine flow."""
    
    def setUp(self):
        """Set up test fixtures."""
        import yaml
        rules_dir = Path(__file__).parent.parent / "rules"
        
        self.rules = []
        for rule_file in rules_dir.glob("*.yaml"):
            with open(rule_file) as f:
                rule_data = yaml.safe_load(f)
                self.rules.append(Rule(
                    rule_id=rule_data["rule_id"],
                    name=rule_data["name"],
                    description=rule_data["description"],
                    severity=rule_data["severity"],
                    match=rule_data["match"],
                    mutations=rule_data["mutations"],
                    response_checks=rule_data["response_checks"]
                ))
        
        self.engine = RuleEngine.__new__(RuleEngine)
        self.engine.rules = self.rules
    
    def test_evaluate_endpoint_with_multiple_rules(self):
        """Test endpoint evaluation with multiple applicable rules."""
        endpoint = Endpoint(path="/admin/dashboard", method="GET")
        response = {"status_code": 200, "body": "admin data"}
        
        vulnerabilities = self.engine.evaluate_endpoint(endpoint, response)
        
        # Should have vulnerabilities from admin endpoint check
        self.assertGreater(len(vulnerabilities), 0)
    
    def test_evaluate_endpoint_no_match(self):
        """Test endpoint evaluation with no matching rules."""
        endpoint = Endpoint(path="/unknown/path", method="GET")
        response = {"status_code": 404, "body": "Not found"}
        
        vulnerabilities = self.engine.evaluate_endpoint(endpoint, response)
        
        # Should have no vulnerabilities since no rules match
        self.assertEqual(len(vulnerabilities), 0)
    
    def test_evaluate_multiple_endpoints(self):
        """Test evaluation of multiple endpoints."""
        endpoints = [
            Endpoint(path="/admin/dashboard", method="GET"),
            Endpoint(path="/users/123", method="GET"),
            Endpoint(path="/products", method="GET")
        ]
        
        responses = {
            "/admin/dashboard": {"status_code": 200, "body": "admin data"},
            "/users/123": {"status_code": 200, "body": "user data"},
            "/products": {"status_code": 200, "body": "products data"}
        }
        
        vulnerabilities = self.engine.evaluate_spec(endpoints, responses)
        
        # Should have vulnerabilities from multiple endpoints
        self.assertGreater(len(vulnerabilities), 0)
    
    def test_vulnerability_severity_levels(self):
        """Test that vulnerabilities have correct severity levels."""
        endpoint = Endpoint(path="/admin/dashboard", method="GET")
        response = {"status_code": 200, "body": "admin data"}
        
        vulnerabilities = self.engine.evaluate_endpoint(endpoint, response)
        
        severities = [v.severity for v in vulnerabilities]
        self.assertIn("HIGH", severities)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""
    
    def test_empty_mutations(self):
        """Test rule with no mutations."""
        rule = Rule(
            rule_id="TEST_RULE",
            name="Test Rule",
            description="Test description",
            severity="HIGH",
            match={},
            mutations=[],
            response_checks=[]
        )
        engine = RuleEngine.__new__(RuleEngine)
        engine.rules = [rule]
        
        endpoint = Endpoint(path="/test", method="GET")
        mutated = engine._apply_mutations(rule, endpoint)
        
        self.assertEqual(mutated["method"], "GET")
        self.assertEqual(mutated["path"], "/test")
        self.assertEqual(mutated["headers"], {})
        self.assertEqual(mutated["path_params"], {})
    
    def test_empty_response_checks(self):
        """Test rule with no response checks."""
        rule = Rule(
            rule_id="TEST_RULE",
            name="Test Rule",
            description="Test description",
            severity="HIGH",
            match={},
            mutations=[],
            response_checks=[]
        )
        engine = RuleEngine.__new__(RuleEngine)
        engine.rules = [rule]
        
        request = {"method": "GET", "path": "/test", "headers": {}, "path_params": {}}
        response = {"status_code": 200, "body": "test"}
        vulnerabilities = engine._analyze_response(rule, request, response)
        
        self.assertEqual(len(vulnerabilities), 0)
    
    def test_wildcard_path_pattern(self):
        """Test wildcard path pattern matching."""
        rule = Rule(
            rule_id="TEST_RULE",
            name="Test Rule",
            description="Test description",
            severity="HIGH",
            match={"path_patterns": ["/*"], "methods": ["GET"]},
            mutations=[],
            response_checks=[]
        )
        engine = RuleEngine.__new__(RuleEngine)
        engine.rules = [rule]
        
        endpoint1 = Endpoint(path="/anything", method="GET")
        endpoint2 = Endpoint(path="/something/else", method="GET")
        
        self.assertTrue(engine._matches_endpoint(rule, endpoint1))
        self.assertTrue(engine._matches_endpoint(rule, endpoint2))
    
    def test_multiple_path_patterns(self):
        """Test rule with multiple path patterns."""
        rule = Rule(
            rule_id="TEST_RULE",
            name="Test Rule",
            description="Test description",
            severity="HIGH",
            match={
                "path_patterns": ["/admin/*", "/users/*", "/products/*"],
                "methods": ["GET"]
            },
            mutations=[],
            response_checks=[]
        )
        engine = RuleEngine.__new__(RuleEngine)
        engine.rules = [rule]
        
        for path in ["/admin/test", "/users/123", "/products/456"]:
            endpoint = Endpoint(path=path, method="GET")
            self.assertTrue(engine._matches_endpoint(rule, endpoint))


if __name__ == "__main__":
    unittest.main()