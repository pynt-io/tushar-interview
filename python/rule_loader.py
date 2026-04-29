"""
Rule loader — reads YAML rule files from a directory, validates each one,
and returns a list of valid Rule objects. Invalid files are skipped gracefully.
"""
import logging
import yaml
from pathlib import Path

from models import DetectionCriteria, Mutation, Rule, RuleTarget

logger = logging.getLogger(__name__)

# Fields that every valid rule MUST contain
_REQUIRED_RULE_FIELDS = ("rule", "name", "severity", "target")
_REQUIRED_TARGET_FIELDS = ("path_pattern", "methods")


def load_rules(rules_dir: str) -> tuple[list[Rule], list[str]]:
    """
    Load all YAML rule files from a directory.

    Args:
        rules_dir: Path to directory containing .yaml / .yml rule files.

    Returns:
        (valid_rules, error_messages) tuple.
        valid_rules  — list of successfully parsed Rule objects.
        error_messages — human-readable description for each skipped file.

    Raises:
        FileNotFoundError: if rules_dir does not exist.
    """
    rules: list[Rule] = []
    errors: list[str] = []

    rules_path = Path(rules_dir)
    if not rules_path.exists():
        raise FileNotFoundError(f"Rules directory not found: {rules_dir}")

    yaml_files = sorted(
        rules_path.glob("*.yaml"), key=lambda p: p.name
    ) + sorted(rules_path.glob("*.yml"), key=lambda p: p.name)

    if not yaml_files:
        logger.warning("No YAML rule files found in %s", rules_dir)
        return rules, errors

    for yaml_file in yaml_files:
        try:
            rule = _parse_rule_file(yaml_file)
            rules.append(rule)
            logger.info("Loaded rule %-20s  ← %s", rule.rule_id, yaml_file.name)
        except (ValueError, KeyError, TypeError) as exc:
            msg = f"Skipping '{yaml_file.name}': {exc}"
            errors.append(msg)
            logger.warning(msg)

    return rules, errors


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_rule_file(path: Path) -> Rule:
    """Parse one YAML file into a Rule.  Raises ValueError on any problem."""
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        raise ValueError("File is empty or not a YAML mapping")

    # ── top-level required fields ──────────────────────────────────────────
    for field in _REQUIRED_RULE_FIELDS:
        if not data.get(field):
            raise ValueError(f"Missing required field: '{field}'")

    # ── target sub-object ──────────────────────────────────────────────────
    target_data = data["target"]
    if not isinstance(target_data, dict):
        raise ValueError("'target' must be a mapping")

    for field in _REQUIRED_TARGET_FIELDS:
        if not target_data.get(field):
            raise ValueError(f"Missing required field: 'target.{field}'")

    target = RuleTarget(
        path_pattern=target_data["path_pattern"],
        methods=[str(m).upper() for m in target_data["methods"]],
    )

    # ── mutations (optional list) ──────────────────────────────────────────
    mutations: list[Mutation] = []
    for m in data.get("mutations") or []:
        if not isinstance(m, dict):
            raise ValueError("Each mutation entry must be a mapping")
        if not m.get("type"):
            raise ValueError("Mutation entry missing required field 'type'")
        if not m.get("target"):
            raise ValueError("Mutation entry missing required field 'target'")
        mutations.append(
            Mutation(
                type=m["type"],
                target=m["target"],
                strategy=m.get("strategy"),
                value=m.get("value"),
            )
        )

    # ── detection (optional list) ──────────────────────────────────────────
    detection: list[DetectionCriteria] = []
    for d in data.get("detection") or []:
        if not isinstance(d, dict):
            raise ValueError("Each detection entry must be a mapping")
        detection.append(
            DetectionCriteria(
                status_code=d.get("status_code"),
                body_contains=d.get("body_contains"),
            )
        )

    return Rule(
        rule_id=str(data["rule"]),
        name=str(data["name"]),
        severity=str(data["severity"]),
        target=target,
        mutations=mutations,
        detection=detection,
    )
