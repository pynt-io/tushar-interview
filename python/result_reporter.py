"""
Result reporter — formats and prints the engine output to stdout.
"""
from models import DetectionCriteria, RuleMatchResult

_SEVERITY_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}
_WIDTH = 65


def print_report(
    results: list[RuleMatchResult],
    errors: list[str],
    total_endpoints: int,
) -> None:
    """Print a human-readable summary of all matched rules and mutations."""

    # ── summary header ──────────────────────────────────────────────────
    print("\n" + "=" * _WIDTH)
    print("  RADWARE API SECURITY RULE ENGINE  —  RESULTS")
    print("=" * _WIDTH)
    print(f"\n  Endpoints scanned   : {total_endpoints}")

    matched_count    = sum(1 for r in results if r.mutated_requests)
    mutations_total  = sum(len(r.mutated_requests) for r in results)
    print(f"  Rules matched       : {matched_count}")
    print(f"  Mutations generated : {mutations_total}")

    # ── skipped / invalid rules ─────────────────────────────────────────
    if errors:
        print(f"\n  ⚠️  Skipped {len(errors)} invalid rule file(s):")
        for err in errors:
            print(f"     • {err}")

    if not results:
        print("\n  No rules matched any endpoints.\n")
        return

    # ── per-result detail ───────────────────────────────────────────────
    print("\n" + "-" * _WIDTH)

    for result in results:
        icon = _SEVERITY_ICON.get(result.rule.severity.lower(), "⚪")
        print(f"\n{icon}  [{result.rule.rule_id}]  {result.rule.name}")
        print(f"     Severity  : {result.rule.severity.upper()}")
        print(f"     Endpoint  : {result.endpoint_method} {result.endpoint_path}")
        print(f"     Mutations : {len(result.mutated_requests)}")

        for i, req in enumerate(result.mutated_requests, start=1):
            print(f"\n     ── Variant {i}  ({req.mutation_type})")
            print(f"        Method  : {req.method}")
            print(f"        Path    : {req.path}")
            if req.headers:
                for k, v in req.headers.items():
                    print(f"        Header  : {k}: {v!r}")
            print(f"        Note    : {req.description}")

        if result.rule.detection:
            print(f"\n     ── Detection criteria (all must match to flag as VULNERABLE):")
            for criteria in result.rule.detection:
                parts = _format_criteria(criteria)
                print(f"        ✓  {parts}")

    print("\n" + "=" * _WIDTH + "\n")


def _format_criteria(c: DetectionCriteria) -> str:
    parts = []
    if c.status_code is not None:
        parts.append(f"status_code == {c.status_code}")
    if c.body_contains:
        parts.append(f"body contains {c.body_contains!r}")
    return "  AND  ".join(parts) if parts else "(no criteria)"
