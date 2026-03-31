import yaml
import re
from .rules import Rules


class AuthByPass(Rules):
    def __init__(self, yaml_path):
        with open(yaml_path, 'r') as f:
            self.data = yaml.safe_load(f)

    def get_pattern(self):
        return self.data['target']['path_pattern']

    def get_applicable_method(self):
        return self.data['target']['methods']


    def _is_rule_applicable(self, endpoint, headers=None):
        input_path = endpoint.path
        input_method = endpoint.method

        pattern = re.escape(self.get_pattern()).replace(r'\*', r'.*')
        match = re.match(pattern, input_path)

        if match and input_method in self.get_applicable_method():
            return True

        return False


    def _transform(self, endpoint, headers=None):
        if self._is_rule_applicable(endpoint, headers):
            new_headers = headers.copy() if headers else {}
            new_headers["Authorization"] = ""

            return True, endpoint, new_headers

        return False, endpoint, headers


    def _apply(self, endpoint, headers=None):
        print(f"Applying AuthByPass rule to endpoint: {endpoint.method} {endpoint.path}")
