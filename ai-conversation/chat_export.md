# Chat Export

## User

read an openapi spec file and gets its endpoints

## Assistant

If you mean **programmatically read an OpenAPI spec (`.yaml` or `.json`)
and extract all API endpoints**, in Python you can do it like this:

``` python
import json
import yaml
from pathlib import Path


def get_endpoints(spec_file: str):
    path = Path(spec_file)

    with open(path, "r", encoding="utf-8") as f:
        if path.suffix in [".yaml", ".yml"]:
            spec = yaml.safe_load(f)
        elif path.suffix == ".json":
            spec = json.load(f)
        else:
            raise ValueError("OpenAPI spec must be YAML or JSON")

    endpoints = []

    for route, operations in spec.get("paths", {}).items():
        for method, details in operations.items():
            if method.lower() not in {
                "get", "post", "put", "patch", "delete", "head", "options", "trace"
            }:
                continue

            endpoints.append({
                "method": method.upper(),
                "path": route,
                "operation_id": details.get("operationId"),
                "summary": details.get("summary"),
            })

    return endpoints


for endpoint in get_endpoints("openapi.yaml"):
    print(f"{endpoint['method']:7} {endpoint['path']}")
```

For example, given:

``` yaml
paths:
  /users:
    get:
      summary: List users
    post:
      summary: Create user

  /users/{userId}:
    get:
      summary: Get user
    delete:
      summary: Delete user
```

It produces:

``` text
GET     /users
POST    /users
GET     /users/{userId}
DELETE  /users/{userId}
```

If you're building this into a **backend service**, I can also show you
how to accept an uploaded OpenAPI file and return the endpoints as JSON.

## User

export this chat as a markdown file
