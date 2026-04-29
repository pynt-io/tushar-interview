"""
Mutation engine — generates mutated HTTP request variants from a rule + endpoint.

Supported mutation types
  parameter_swap  — replaces a path parameter using a strategy.
                    Currently supported strategy: "increment" (id±1).
  header_inject   — sets (or overwrites) a request header to a given value.

The engine is intentionally open/closed: add a new mutation type by registering
a handler function in _MUTATION_HANDLERS at module load time.
"""
import logging
import re
from typing import Callable

from models import Mutation, MutatedRequest, Rule
from spec_parser import Endpoint

logger = logging.getLogger(__name__)

# Type alias for a mutation handler function
MutationHandler = Callable[[Mutation, Endpoint], list[MutatedRequest]]

# Handler registry — maps mutation type string → handler function
_MUTATION_HANDLERS: dict[str, MutationHandler] = {}


def register_handler(mutation_type: str):
    """Decorator to register a handler for a mutation type."""
    def decorator(fn: MutationHandler) -> MutationHandler:
        _MUTATION_HANDLERS[mutation_type] = fn
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Core entry point
# ---------------------------------------------------------------------------

def generate_mutations(rule: Rule, endpoint: Endpoint) -> list[MutatedRequest]:
    """
    For every mutation in the rule, generate all mutated request variants.
    Unknown mutation types are logged and skipped (forward-compatibility).
    """
    results: list[MutatedRequest] = []
    for mutation in rule.mutations:
        handler = _MUTATION_HANDLERS.get(mutation.type)
        if handler is None:
            logger.warning(
                "Rule %s: unknown mutation type '%s' — skipping",
                rule.rule_id, mutation.type,
            )
            continue
        results.extend(handler(mutation, endpoint))
    return results


# ---------------------------------------------------------------------------
# Mutation handlers
# ---------------------------------------------------------------------------

@register_handler("parameter_swap")
def _handle_parameter_swap(mutation: Mutation, endpoint: Endpoint) -> list[MutatedRequest]:
    """
    Replaces a named path parameter with variant values.

    strategy=increment → produces two variants: sample_id+1 and sample_id-1.
    We use 42 as the representative sample value for demonstration; in a real
    engine this would be populated from actual session/request data.
    """
    # "path.userId"  →  "userId"
    param_name = mutation.target.split(".", 1)[-1]
    results: list[MutatedRequest] = []

    if mutation.strategy == "increment":
        sample_id = 42
        for variant_id in (sample_id + 1, sample_id - 1):
            mutated_path = re.sub(
                r"\{" + re.escape(param_name) + r"\}",
                str(variant_id),
                endpoint.path,
            )
            results.append(
                MutatedRequest(
                    method=endpoint.method,
                    path=mutated_path,
                    headers={},
                    original_path=endpoint.path,
                    mutation_type="parameter_swap",
                    description=(
                        f"Swapped '{param_name}' → {variant_id} "
                        f"(increment from sample id={sample_id})"
                    ),
                )
            )
    else:
        logger.warning("parameter_swap: unsupported strategy '%s'", mutation.strategy)

    return results


@register_handler("header_inject")
def _handle_header_inject(mutation: Mutation, endpoint: Endpoint) -> list[MutatedRequest]:
    """
    Sets (or replaces) the named HTTP header with the rule-specified value.

    "header.Authorization"  →  header name "Authorization"
    """
    header_name = mutation.target.split(".", 1)[-1]
    injected_value = mutation.value if mutation.value is not None else ""

    return [
        MutatedRequest(
            method=endpoint.method,
            path=endpoint.path,
            headers={header_name: injected_value},
            original_path=endpoint.path,
            mutation_type="header_inject",
            description=f"Set header '{header_name}' = {injected_value!r}",
        )
    ]
