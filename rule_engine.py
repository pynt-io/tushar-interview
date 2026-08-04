from pathlib import Path
import yaml

def load_rules(rules_dir):
    rules = []
    errors = []
    for rule_file in Path(rules_dir).glob("*.yaml"):
        try:
            with open(rule_file) as f:
                rule = yaml.safe_load(f)
            validate_rule(rule)
            rules.append(rule)
        except Exception as e:
            errors.append(f"{rule_file.name}: {e}")
    return rules, errors

def validate_rule(rule):
    if not isinstance(rule, dict):
        raise ValueError("Not a dict")

    for key_names in ("rule","name", "severity", "target", "mutations"):
        if key_names not in rule:
            raise ValueError("Not a valid rule, missing key: " + key_names)

    if "path_pattern" not in rule["target"]:
        raise ValueError("path_patten should be present in target")

    if "methods" not in rule["target"]:
        raise ValueError("methods should be present in target")

def rule_match_endpoint(rule, endpoint):
    target = rule["target"]
    if endpoint["method"].upper() not in target["methods"]:
        return False

    # need to match the path btw target path_pattern and endpoint path
    return path_matches(target["path_pattern"], endpoint["path"])

def split_path(path):
    return [path_part for path_part in path.strip('/').split('/') if path_part]

def is_path_param(path):
    return True if path.startswith("{") and path.endswith("}") else False

def path_matches(rule_path, endpoint_path):
    rule_paths = split_path(rule_path)
    endpoint_paths = split_path(endpoint_path)

    if len(rule_paths) != len(endpoint_paths):
        return False

    for rule_part, endpoint_part in zip(rule_paths, endpoint_paths):
        if rule_part == '*':
            continue

        if is_path_param(rule_part):
            continue

        if rule_part != endpoint_part:
            return False
    return True



