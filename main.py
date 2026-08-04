import argparse
import yaml

from rule_engine import load_rules, rule_match_endpoint

def main():
    parser = argparse.ArgumentParser("Configurable rule engine")
    parser.add_argument("--rules", required=True, help="Rules dir file")
    parser.add_argument("--spec", required=True, help="OpenAPI spec file")
    args = parser.parse_args()

    # get the endpoints from the openapi file
    endpoints_file = args.spec
    with open(endpoints_file) as f:
        spec = yaml.safe_load(f)

    endpoints = []
    for route, operations in spec.get("paths", {}).items():
            for method, details in operations.items():
                if method.lower() not in {
                    "get", "put",
                }:
                    continue

                endpoints.append({
                    "method": method.upper(),
                    "path": route,
                    "operation_id": details.get("operationId"),
                    "summary": details.get("summary"),
                })

    # load the rules
    rules_dir = args.rules
    rules, errors = load_rules(rules_dir)
    if errors:
        print("Skipping the invalid rule file", errors)

    for endpoint in endpoints:
        for rule in rules:
            if not rule_match_endpoint(rule, endpoint):
                continue
            else:
                print(rule, endpoint)

if __name__ == "__main__":
    main()

