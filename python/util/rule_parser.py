import yaml
from pathlib import Path
import re
import logging
from dataclasses import dataclass
from typing import Literal

from api_invoker import invoke_api

@dataclass
class Result():
    rule_id: str
    target_endpoint: str
    result: Literal['pass','fail']
    evidence: str

def get_endpoint_method(endpoints, target, method):
    for endpoint in endpoints:
        if endpoint.path == target and method == endpoint.method:
            return endpoint.path, endpoint.method
    return '', ''

def process_response(response, detection, rule_id, target):
    if 'body_contains' in detection:
        if detection['status_code'] == response.status_code and detection['body_contains'] in response.body:
            final_data = Result(
                rule_id=rule_id,
                target_endpoint=target,
                result='fail',
                evidence=str(response.body)
            )
        else:
            final_data = Result(
                rule_id=rule_id,
                target_endpoint=target,
                result='pass',
                evidence=str(response.body)
            )
    else:
        if detection['status_code'] == response.status_code:
            final_data = Result(
                rule_id=rule_id,
                target_endpoint=target,
                result='fail',
                evidence=str(response.status_code)
            )
        else:
            final_data = Result(
                rule_id=rule_id,
                target_endpoint=target,
                result='pass',
                evidence=str(response.status_code)
            )
    return final_data

def execute_parameter_swap(target:str, methods:list, endpoints:list, mutation:dict, detection:list, rule_id:str):
    params = {
        'userId' : 1
    }
    result = []
    for method in methods:
        api_endpoint, api_method = get_endpoint_method(endpoints, target, method)
        if not api_endpoint and api_method:
            logging.warning('Endpoint and method not present in the API Spec')
            return
        target = re.search(r'path\.(.*?)$', target, re.S).group(1)
        trigger_endpoint = api_endpoint
        if mutation['strategy'] == 'increament':
            trigger_endpoint = api_endpoint.replace(target, str(params[target]+1))
        response = invoke_api(trigger_endpoint, method, None, None)
        re = process_response(response, detection, rule_id, target)
        result.append(re)
    return result


def execute_header_inject():
    pass

def parse_rules(rule_file_path:Path, endpoints):
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
    if isinstance(rule['detection'], list):
        detection = rule['detection'][0]
    if not 'target' in rule.keys():
        return 'Invalid rule file'
    if not 'path_pattern' in rule['target'].keys() or not 'methods' in rule['target'].keys():
        return 'Invalid rule file'
    target = rule['target']['path_pattern']
    methods = list(rule['target']['methods'])
    return RULE_FORMAT_MAPPER[test_rules['type']](target, methods, endpoints, test_rules, detection, rule['rule'])