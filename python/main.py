"""
Radware API Security Rule Engine  —  CLI entry point.

Usage:
    python main.py --rules ./rules --spec ./sample_specs/petstore.yaml
"""
import argparse
import logging
import sys
from pathlib import Path

from models import RuleMatchResult
from mutation_engine import generate_mutations
from result_reporter import print_report
from rule_loader import load_rules
from rule_matcher import find_matching_rules
from spec_parser import parse_spec

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)-8s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

# Directory where main.py lives — used to resolve relative CLI paths
_SCRIPT_DIR = Path(__file__).parent.resolve()


def _resolve(user_path: str) -> Path:
    """
    Resolve a CLI-supplied path robustly:
      1. If it is absolute → use as-is.
      2. If it exists relative to CWD → use that.
      3. Otherwise fall back to resolving relative to the script directory.

    This means `./rules` works whether you run:
        python main.py ...                    (from inside python/)
        python python/main.py ...             (from the parent folder)
        python D:/full/path/main.py ...       (from anywhere)
    """
    p = Path(user_path)
    if p.is_absolute():
        return p
    cwd_path = Path.cwd() / p
    if cwd_path.exists():
        return cwd_path.resolve()
    return (_SCRIPT_DIR / p).resolve()


def run_engine(rules_dir: str, spec_path: str) -> None:
    # ── 1. Parse OpenAPI spec ───────────────────────────────────────────
    logger.info("Parsing spec: %s", spec_path)
    endpoints = parse_spec(spec_path)
    logger.info("Found %d endpoint(s)", len(endpoints))

    # ── 2. Load rules ───────────────────────────────────────────────────
    logger.info("Loading rules from: %s", rules_dir)
    rules, errors = load_rules(rules_dir)
    logger.info(
        "Loaded %d valid rule(s); %d file(s) skipped",
        len(rules), len(errors),
    )

    # ── 3. Match rules → endpoints, then generate mutations ─────────────
    results: list[RuleMatchResult] = []

    for endpoint in endpoints:
        matching = find_matching_rules(rules, endpoint)
        for rule in matching:
            mutated = generate_mutations(rule, endpoint)
            results.append(
                RuleMatchResult(
                    rule=rule,
                    endpoint_method=endpoint.method,
                    endpoint_path=endpoint.path,
                    mutated_requests=mutated,
                )
            )

    # ── 4. Report ───────────────────────────────────────────────────────
    print_report(results, errors, total_endpoints=len(endpoints))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Radware API Security Rule Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --rules ./rules --spec ./sample_specs/petstore.yaml\n"
            "  python main.py --rules rules   --spec sample_specs/petstore.yaml\n"
        ),
    )
    p.add_argument(
        "--rules",
        required=True,
        metavar="DIR",
        help="Directory containing YAML rule files",
    )
    p.add_argument(
        "--spec",
        required=True,
        metavar="FILE",
        help="Path to an OpenAPI 3.x YAML spec file",
    )
    return p


def main() -> None:
    args = _build_parser().parse_args()

    rules_path = _resolve(args.rules)
    spec_path  = _resolve(args.spec)

    logger.info("Resolved rules dir : %s", rules_path)
    logger.info("Resolved spec file : %s", spec_path)

    if not rules_path.exists():
        logger.error("Rules directory not found: %s", rules_path)
        sys.exit(1)
    if not spec_path.exists():
        logger.error("Spec file not found: %s", spec_path)
        sys.exit(1)

    run_engine(str(rules_path), str(spec_path))


if __name__ == "__main__":
    main()
