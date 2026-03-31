import argparse
import importlib
import inspect
from pathlib import Path

from spec_parser import parse_spec
from rules.rules import Rules


def load_rule_objects():
    rule_objects = []
    rules_package_dir = Path(__file__).parent / "rules"

    for module_path in sorted(rules_package_dir.glob("*.py")):
        if module_path.stem in {"__init__", "rules", "endpoint"}:
            continue

        module = importlib.import_module(f"rules.{module_path.stem}")
        for _, class_obj in inspect.getmembers(module, inspect.isclass):
            if class_obj.__module__ != module.__name__:
                continue
            if issubclass(class_obj, Rules) and class_obj is not Rules:
                print(f"Loaded rule class: {class_obj.__name__}")
                rule_objects.append(class_obj())

    return rule_objects


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, help="Path to the OpenAPI spec file")
    parser.add_argument("--rules", required=True, help="Path to the rules directory")
    args = parser.parse_args()

    rules_dir = Path(args.rules)
    if not rules_dir.is_dir():
        raise NotADirectoryError(f"Rules directory not found: {args.rules}")

    endpoints = parse_spec(args.spec)
    rule_objects = load_rule_objects()

    for endpoint in endpoints:
        print(f"Parsed endpoint: {endpoint.method} {endpoint.path}")
        for rule_object in rule_objects:
            rule_object.run_rule(endpoint)
            break
        break


if __name__ == "__main__":
    main()
