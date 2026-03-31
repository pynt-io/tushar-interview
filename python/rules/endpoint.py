from dataclasses import dataclass
from typing import Optional


@dataclass
class Endpoint:
    """A single API endpoint from the OpenAPI spec."""
    path: str          # e.g., "/users/{userId}"
    method: str        # e.g., "GET"
    operation_id: Optional[str] = None
