#!/usr/bin/env python3
"""
Main entry point for the API Security Rule Engine

Usage:
    python main.py --rules ./rules --spec ./sample_specs/petstore.yaml
"""
import argparse
import sys
import yaml
from pathlib import Path

# Add the python directory to the path to import local modules
sys.path.insert(0, str(Path(__file__).parent))

from spec_parser import parse_spec
from rule_engine import RuleEngine


def main():
    parser = argparse.ArgumentParser(
        description="API Security Rule Engine - Evaluate API endpoints against security rules"
    )
    parser.add_argument(
        "--rules",
        required=True,
        help="Path to directory containing YAML rule files"
    )
    parser.add_argument(
        "--spec",
        required=True,
        help="Path to OpenAPI spec YAML file"
    )
    parser.add_argument(
        "--responses",
        required=False,
        help="Path to YAML file containing predefined responses for testing"
    )
    
    args = parser.parse_args()
    
    try:
        # Parse the OpenAPI spec
        print(f"Parsing OpenAPI spec: {args.spec}")
        endpoints = parse_spec(args.spec)
        print(f"Found {len(endpoints)} endpoints in spec\n")
        
        # Load predefined responses if provided
        responses = None
        if args.responses:
            print(f"Loading predefined responses from: {args.responses}")
            with open(args.responses) as f:
                responses = yaml.safe_load(f)
            print(f"Loaded {len(responses)} predefined responses\n")
        
        # Initialize the rule engine
        print(f"Loading rules from: {args.rules}")
        engine = RuleEngine(args.rules)
        
        # Evaluate all endpoints
        vulnerabilities = engine.evaluate_spec(endpoints, responses)
        
        # Print results
        engine.print_results(vulnerabilities)
        
        # Exit with appropriate code
        if vulnerabilities:
            print(f"\n⚠ Security assessment completed with {len(vulnerabilities)} findings")
            sys.exit(1)
        else:
            print("\n✓ Security assessment completed - no vulnerabilities found")
            sys.exit(0)
            
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()