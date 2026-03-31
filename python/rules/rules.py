from abc import ABC, abstractmethod
from .endpoint import Endpoint

class Rules(ABC):
    @abstractmethod
    def get_pattern(self):
        pass

    @abstractmethod
    def get_applicable_method(self):
        pass

    @abstractmethod
    def _is_rule_applicable(self, endpoint):
        pass

    @abstractmethod
    def _transform(self, endpoint, headers=None):
        pass

    @abstractmethod
    def _apply(self, endpoint, headers=None):
        pass

    def run_rule(self, endpoint, headers=None):
        is_applicable, new_endpoint, new_headers = self._transform(endpoint, headers)
        if is_applicable:
            self._apply(new_endpoint, new_headers)
