"""Apply proof/input.json to the service's own entry point (as the webhook body).

Exit 0 = flaw TRIGGERED (forged webhook accepted). Exit 1 = rejected.
Expected: TRIGGERED on authlib 1.8.0, rejected on authlib 1.9.0.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fastapi.testclient import TestClient  # noqa: E402

from svc_03.app import app  # noqa: E402

here = os.path.dirname(os.path.abspath(__file__))
forged = json.load(open(os.path.join(here, "input.json")))

r = TestClient(app).post("/hooks/payment", json=forged)
if r.status_code == 200:
    print("TRIGGERED: forged webhook accepted ->", r.json())
    sys.exit(0)
print("REJECTED: status", r.status_code)
sys.exit(1)
