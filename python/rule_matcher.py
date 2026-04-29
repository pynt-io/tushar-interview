"""
Rule matcher — decides which rules apply to a given API endpoint.

Path-pattern matching rules (from the spec):
  - {param}  matches exactly one path segment (any value).
  - *        matches exactly one path segment (wildcard).
  - Literal  segments must match case-sensitively.
  - Segment count must be equal (no greedy / recursive matching).

Examples:
  /users/{userId}  matches  /users/42        ✓
  /admin/*         matches  /admin/dashboard ✓
  /admin/*         does NOT match /admin/dashboard/settings  ✗ (different depth)
"""
import re

from models import Rule
from spec_parser import Endpoint


def _build_regex(path_pattern: str) -> re.Pattern:
    """Compile a path pattern into a full-match regex."""
    segments = path_pattern.strip("/").split("/")
    parts = []
    for seg in segments:
        if (seg.startswith("{") and seg.endswith("}")) or seg == "*":
            parts.append(r"[^/]+")
        else:
            parts.append(re.escape(seg))
    return re.compile(r"^/" + r"/".join(parts) + r"$")


def matches_rule(rule: Rule, endpoint: Endpoint) -> bool:
    """Return True when the endpoint path AND method both match the rule's target."""
    if endpoint.method.upper() not in rule.target.methods:
        return False
    return bool(_build_regex(rule.target.path_pattern).match(endpoint.path))


def find_matching_rules(rules: list[Rule], endpoint: Endpoint) -> list[Rule]:
    """Return every rule whose target matches the given endpoint."""
    return [r for r in rules if matches_rule(r, endpoint)]
