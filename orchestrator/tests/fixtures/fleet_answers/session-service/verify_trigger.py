"""Send input.json as the bearer token to GET /me of session-service.

Usage: <app>/.venv/bin/python verify_trigger.py <app_dir>
Prints ACCEPTED ... or REJECTED <status>. Exit 0 if accepted, 1 if not.
Expected for session-service: REJECTED 401 on authlib 1.8.0 and 1.9.0.
"""
import os
import sys

app_dir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
sys.path.insert(0, os.path.join(app_dir, "src"))

from fastapi.testclient import TestClient  # noqa: E402

from session_service.app import app  # noqa: E402

here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "input.json")) as fh:
    forged = fh.read().strip()

r = TestClient(app).get("/me", headers={"Authorization": f"Bearer {forged}"})
if r.status_code == 200:
    print(f"ACCEPTED {r.status_code} {r.text}")
    sys.exit(0)
print(f"REJECTED {r.status_code}")
sys.exit(1)
