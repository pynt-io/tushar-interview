import argparse
import importlib
import inspect
from pathlib import Path

from spec_parser import parse_spec
from rules.rules import Rules


def load_rule_objects(rules_dir):
    rule_objects = []
    rule_files = sorted(path for path in rules_dir.iterdir() if path.is_file())

    for rule_file in rule_files:
        if rule_file.suffix != ".yaml":
            continue

        try:
            module = importlib.import_module(f"rules.{rule_file.stem}")
        except ModuleNotFoundError:
            print(f"No Python rule module found for: {rule_file.stem}")
            continue

        for _, class_obj in inspect.getmembers(module, inspect.isclass):
            if class_obj.__module__ != module.__name__:
                continue
            if issubclass(class_obj, Rules) and class_obj is not Rules:
                print(f"Loaded rule class: {class_obj.__name__}")
                rule_objects.append(class_obj(rule_file))

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
    rule_objects = load_rule_objects(rules_dir)

    for endpoint in endpoints:
        print(f"Parsed endpoint: {endpoint.method} {endpoint.path}")
        for rule_object in rule_objects:
            rule_object.run_rule(endpoint)


if __name__ == "__main__":
    main()
