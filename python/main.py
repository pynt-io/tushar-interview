import argparse
from pathlib import Path
from util import spec_parser, rule_parser

def execute():
    parser = argparse.ArgumentParser(description="Parse api doc and rule engine directory")
    parser.add_argument('--rules', type=str, help='Path to rule files directory')
    parser.add_argument('--spec', type=str, help='Path to api spec document')

    args = parser.parse_args()
    rule_dir = args.rules
    api_spec = args.spec

    endpoints = spec_parser.parse_spec(api_spec)

    yaml_files = list(Path(rule_dir).glob('*.yaml'))
    final_result = []
    for rule_file in yaml_files:
        try:
            result = rule_parser.parse_rules(rule_file, endpoints)
            final_result.append(result)
        except Exception as e:
            continue
        return final_result

if __name__ == "__main__":
    print(execute())