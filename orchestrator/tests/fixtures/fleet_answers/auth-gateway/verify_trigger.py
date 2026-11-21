"""Send the forged token in input.json to auth-gateway's /introspect entry point.

Usage:  <app>/.venv/bin/python verify_trigger.py <app_dir>

Prints one line and sets the exit code:
  ACCEPTED ...   exit 0  -> the forged token was accepted
  REJECTED <n>   exit 1  -> the forged token was rejected (HTTP <n>)
"""
import json
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
sys.path.insert(0, os.path.join(app_dir, "src"))

from fastapi.testclient import TestClient  # noqa: E402

from auth_gateway.app import app  # noqa: E402

token = open(os.path.join(here, "input.json")).read().strip()

resp = TestClient(app).post("/introspect", json={"token": token})
if resp.status_code == 200:
    print("ACCEPTED", json.dumps(resp.json()))
    sys.exit(0)
print("REJECTED", resp.status_code)
sys.exit(1)
