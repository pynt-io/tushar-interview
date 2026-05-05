import yaml
from pathlib import Path
import re

import requests

def execute_parameter_swap(methods:list, url:str, target:str, strategy:str, endpoints):
    for method in methods:
        target = re.search(r'path\.(.*?)$', target, re.S).group(1)
        if strategy == 'increament':
            target_endpoint = endpoints.path

        if method == 'GET':
            response = requests.get(target_endpoint)
    pass

def execute_header_inject():
    pass

def parse_rules(rule_file_path:str):
    RULE_FORMAT_MAPPER = {
        'parameter_swap' : execute_parameter_swap,
        'header_inject' : execute_header_inject
    }
    path = Path(rule_file_path)
    if not path.exists():
        raise FileNotFoundError(f"Spec file not found: {rule_file_path}")
    with open(path) as f:
        rule = yaml.safe_load(f)
    if isinstance(rule['mutations'], list):
        test_rules = rule['mutations'][0]
    target = rule['target']['path_pattern']
    methods = list(rule['target']['methods'])
    # print(methods[1])
    RULE_FORMAT_MAPPER[test_rules['type']]()

    
parse_rules('rules\\bola_users.yaml')