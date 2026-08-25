"""
Rule Engine for API Security Testing
Loads YAML rules, matches them to endpoints, applies mutations, and analyzes responses.
"""
import yaml
import fnmatch
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from pathlib import Path
from spec_parser import Endpoint


@dataclass
class Rule:
    """A security rule loaded from YAML."""
    rule_id: str
    name: str
    description: str
    severity: str
    match: Dict[str, Any]
    mutations: List[Dict[str, Any]]
    response_checks: List[Dict[str, Any]]


@dataclass
class Vulnerability:
    """A detected vulnerability."""
    rule_id: str
    vulnerability_type: str
    message: str
    severity: str
    endpoint: str


class RuleEngine:
    """Engine for loading and applying security rules to API endpoints."""
    
    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.rules: List[Rule] = []
        self._load_rules()
    
    def _load_rules(self):
        """Load all YAML rule files from the rules directory."""
        if not self.rules_dir.exists():
            raise FileNotFoundError(f"Rules directory not found: {self.rules_dir}")
        
        for rule_file in self.rules_dir.glob("*.yaml"):
            with open(rule_file) as f:
                rule_data = yaml.safe_load(f)
                self.rules.append(Rule(
                    rule_id=rule_data.get("rule_id"),
                    name=rule_data.get("name"),
                    description=rule_data.get("description"),
                    severity=rule_data.get("severity"),
                    match=rule_data.get("match", {}),
                    mutations=rule_data.get("mutations", []),
                    response_checks=rule_data.get("response_checks", [])
                ))
        
        print(f"Loaded {len(self.rules)} rules from {self.rules_dir}")
    
    def _matches_endpoint(self, rule: Rule, endpoint: Endpoint) -> bool:
        """Check if a rule matches an endpoint."""
        match_criteria = rule.match
        
        # Check method match
        if "methods" in match_criteria:
            methods = [m.upper() for m in match_criteria["methods"]]
            if endpoint.method not in methods:
                return False
        
        # Check path pattern match
        if "path_patterns" in match_criteria:
            patterns = match_criteria["path_patterns"]
            matched = False
            for pattern in patterns:
                if fnmatch.fnmatch(endpoint.path, pattern):
                    matched = True
                    break
            if not matched:
                return False
        
        return True
    
    def _apply_mutations(self, rule: Rule, endpoint: Endpoint) -> Dict[str, Any]:
        """Apply mutations to an endpoint request."""
        mutated_request = {
            "method": endpoint.method,
            "path": endpoint.path,
            "headers": {},
            "path_params": {}
        }
        
        for mutation in rule.mutations:
            mutation_type = mutation.get("type")
            
            if mutation_type == "replace_header":
                header = mutation.get("header")
                value = mutation.get("value")
                mutated_request["headers"][header] = value
            
            elif mutation_type == "add_header":
                header = mutation.get("header")
                value = mutation.get("value")
                mutated_request["headers"][header] = value
            
            elif mutation_type == "replace_path_param":
                param = mutation.get("param")
                value = mutation.get("value")
                mutated_request["path_params"][param] = value
        
        return mutated_request
    
    def _analyze_response(self, rule: Rule, mutated_request: Dict[str, Any], response: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze a response to detect vulnerabilities."""
        vulnerabilities = []
        
        for check in rule.response_checks:
            check_type = check.get("type")
            operator = check.get("operator")
            expected = check.get("expected")
            
            is_vulnerable = False
            
            if check_type == "status_code":
                status_code = response.get("status_code")
                if operator == "==" and status_code == expected:
                    is_vulnerable = True
                elif operator == "!=" and status_code != expected:
                    is_vulnerable = True
                elif operator == "<=" and status_code <= expected:
                    is_vulnerable = True
                elif operator == ">=" and status_code >= expected:
                    is_vulnerable = True
            
            elif check_type == "body_contains":
                body = response.get("body", "")
                pattern = check.get("pattern", "")
                if operator == "contains" and pattern in body:
                    is_vulnerable = True
                elif operator == "not_contains" and pattern not in body:
                    is_vulnerable = True
            
            if is_vulnerable:
                vuln_type = check.get("vulnerability", "UNKNOWN")
                message = check.get("message", "No message provided")
                
                vulnerabilities.append(Vulnerability(
                    rule_id=rule.rule_id,
                    vulnerability_type=vuln_type,
                    message=message,
                    severity=rule.severity,
                    endpoint=f"{mutated_request['method']} {mutated_request['path']}"
                ))
        
        return vulnerabilities
    
    def evaluate_endpoint(self, endpoint: Endpoint, response: Optional[Dict[str, Any]] = None) -> List[Vulnerability]:
        """Evaluate a single endpoint against all applicable rules.
        
        Args:
            endpoint: The endpoint to evaluate
            response: Optional response dict with 'status_code' and 'body' keys.
                      If not provided, the method will only apply mutations and return
                      the mutated requests without vulnerability analysis.
        
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        for rule in self.rules:
            if self._matches_endpoint(rule, endpoint):
                print(f"  Applying rule: {rule.rule_id} to {endpoint.method} {endpoint.path}")
                
                # Apply mutations
                mutated_request = self._apply_mutations(rule, endpoint)
                
                # Analyze response if provided
                if response is not None:
                    rule_vulnerabilities = self._analyze_response(rule, mutated_request, response)
                    vulnerabilities.extend(rule_vulnerabilities)
        
        return vulnerabilities
    
    def evaluate_spec(self, endpoints: List[Endpoint], responses: Optional[Dict[str, Dict[str, Any]]] = None) -> List[Vulnerability]:
        """Evaluate all endpoints from a spec against applicable rules.
        
        Args:
            endpoints: List of endpoints to evaluate
            responses: Optional dict mapping endpoint paths to response dicts.
                      If not provided, the method will only apply mutations without
                      vulnerability analysis.
        
        Returns:
            List of vulnerabilities found
        """
        all_vulnerabilities = []
        
        print(f"\nEvaluating {len(endpoints)} endpoints against {len(self.rules)} rules...")
        
        for endpoint in endpoints:
            print(f"\nEvaluating endpoint: {endpoint.method} {endpoint.path}")
            
            # Get response for this endpoint if provided
            response = None
            if responses is not None:
                response = responses.get(endpoint.path)
            
            endpoint_vulns = self.evaluate_endpoint(endpoint, response)
            all_vulnerabilities.extend(endpoint_vulns)
        
        return all_vulnerabilities
    
    def print_results(self, vulnerabilities: List[Vulnerability]):
        """Print vulnerability results in a formatted way."""
        print("\n" + "="*60)
        print("SECURITY ASSESSMENT RESULTS")
        print("="*60)
        
        if not vulnerabilities:
            print("✓ No vulnerabilities detected")
            return
        
        print(f"\nFound {len(vulnerabilities)} potential vulnerabilities:\n")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{i}. [{vuln.severity}] {vuln.vulnerability_type}")
            print(f"   Rule: {vuln.rule_id}")
            print(f"   Endpoint: {vuln.endpoint}")
            print(f"   Message: {vuln.message}")
            print()
