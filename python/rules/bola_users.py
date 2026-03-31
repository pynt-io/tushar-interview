import yaml
import os
import re
from .endpoint import Endpoint
from .rules import Rules


class BolaUser(Rules):
    def __init__(self):
        yaml_path = os.path.join(os.path.dirname(__file__), '../../rules/bola_users.yaml')
        with open(yaml_path, 'r') as file:
            self.data = yaml.safe_load(file)

    def get_pattern(self):
        return self.data['target']['path_pattern']


    def get_applicable_method(self):
        return self.data['target']['methods']


    def _is_rule_applicable(self, endpoint, headers=None):
        input_path = endpoint.path
        input_method = endpoint.method
        
        pattern = re.escape(self.get_pattern()).replace(r'\{userId\}', r'(\w+)').replace(r'\*', r'.*')
        match = re.match(pattern, input_path)
        if match and input_method in self.get_applicable_method():
            return True

        return False


    def _transform(self, endpoint, headers=None):
        if self._is_rule_applicable(endpoint, headers):
            userId = re.match(re.escape(self.get_pattern()).replace(r'\{userId\}', r'(\w+)'), endpoint.path).group(1)
            userId = int(userId) + 1
            new_path = self.get_pattern().replace("{userId}", str(userId))

            new_endpoint = Endpoint(
                path=new_path,
                method=endpoint.method,
                operation_id=endpoint.operation_id
            )

            return True, new_endpoint, headers

        return False, endpoint, headers


    def _apply(self, endpoint, headers=None):
        print(f"Applying BolaUser rule to endpoint: {endpoint.method} {endpoint.path}")
