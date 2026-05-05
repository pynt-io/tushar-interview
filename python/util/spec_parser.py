"""
OpenAPI spec parser — provided as part of the interview setup.
Parses an OpenAPI 3.x YAML file and returns a list of Endpoint objects.

You can use this as-is or modify it if needed.
"""
import yaml
from dataclasses import dataclass
from typing import Optional
from pathlib import Path


@dataclass
class Endpoint:
    """A single API endpoint from the OpenAPI spec."""
    path: str          # e.g., "/users/{userId}"
    method: str        # e.g., "GET"
    operation_id: Optional[str] = None


def parse_spec(spec_path: str) -> list[Endpoint]:
    """
    Parse an OpenAPI 3.x spec and return a list of Endpoints.

    Args:
        spec_path: Path to the YAML spec file

    Returns:
        List of Endpoint objects

    Example:
        endpoints = parse_spec("./sample_specs/petstore.yaml")
        for ep in endpoints:
            print(f"{ep.method} {ep.path}")
        # GET /users/{userId}
        # PUT /users/{userId}
        # GET /users/{userId}/orders
        # GET /admin/dashboard
        # ...
    """
    path = Path(spec_path)
    if not path.exists():
        raise FileNotFoundError(f"Spec file not found: {spec_path}")

    with open(path) as f:
        spec = yaml.safe_load(f)

    if not spec or "paths" not in spec:
        return []

    http_methods = {"get", "put", "post", "delete", "patch"}
    endpoints = []

    for path_template, methods in spec["paths"].items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method.lower() not in http_methods:
                continue
            operation_id = None
            if isinstance(details, dict):
                operation_id = details.get("operationId")
            endpoints.append(Endpoint(
                path=path_template,
                method=method.upper(),
                operation_id=operation_id,
            ))

    return endpoints
