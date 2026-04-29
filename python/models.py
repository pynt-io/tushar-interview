"""
Shared data models for the Radware API Security Rule Engine.
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Mutation:
    """Describes a single request mutation to apply."""
    type: str                       # "parameter_swap" | "header_inject"
    target: str                     # "path.userId" | "header.Authorization"
    strategy: Optional[str] = None  # "increment" (for parameter_swap)
    value: Optional[str] = None     # header value (for header_inject)


@dataclass
class DetectionCriteria:
    """
    Conditions that together indicate a vulnerability was found.
    All specified conditions must be true simultaneously (AND logic).
    """
    status_code: Optional[int] = None
    body_contains: Optional[str] = None


@dataclass
class RuleTarget:
    """Defines which endpoints a rule applies to."""
    path_pattern: str   # e.g., "/users/{userId}" or "/admin/*"
    methods: list[str]  # e.g., ["GET", "PUT"]


@dataclass
class Rule:
    """A complete attack-signature rule loaded from a YAML file."""
    rule_id: str
    name: str
    severity: str
    target: RuleTarget
    mutations: list[Mutation]
    detection: list[DetectionCriteria]


@dataclass
class MutatedRequest:
    """A single mutated variant of an HTTP request."""
    method: str
    path: str
    headers: dict[str, str]
    original_path: str
    mutation_type: str
    description: str


@dataclass
class RuleMatchResult:
    """Result of matching and applying one rule against one endpoint."""
    rule: Rule
    endpoint_method: str
    endpoint_path: str
    mutated_requests: list[MutatedRequest]
