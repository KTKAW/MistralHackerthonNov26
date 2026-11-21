"""Apply proof/input.json to the service's own entry point (as a Bearer token).

For an UNAFFECTED service: exit 0 = forged token REJECTED (no trigger, as expected).
Exit 1 = flaw TRIGGERED (would mean this service is actually affected).
Expected: rejected on BOTH authlib 1.8.0 and 1.9.0.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fastapi.testclient import TestClient  # noqa: E402

from svc_05.app import app  # noqa: E402

here = os.path.dirname(os.path.abspath(__file__))
forged = open(os.path.join(here, "input.json")).read()

r = TestClient(app).post("/verify", headers={"Authorization": f"Bearer {forged}"})
if r.status_code == 401:
    print("REJECTED (no reachable path): status 401")
    sys.exit(0)
print("TRIGGERED (unexpected for svc-05): status", r.status_code, r.text)
sys.exit(1)
