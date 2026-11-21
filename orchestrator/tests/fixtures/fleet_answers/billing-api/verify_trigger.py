"""Send the forged token in input.json to billing-api's entry point.

Usage:
    <app>/.venv/bin/python verify_trigger.py <app_dir>

Prints one line and exits 0 if the forged token was ACCEPTED (flaw triggered),
1 if it was REJECTED.
"""
import json
import os
import sys


def main() -> int:
    app_dir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    sys.path.insert(0, os.path.join(app_dir, "src"))

    from fastapi.testclient import TestClient
    from billing_api.app import app

    here = os.path.dirname(os.path.abspath(__file__))
    forged = open(os.path.join(here, "input.json")).read()

    r = TestClient(app).post(
        "/charge",
        json={"amount": 1, "description": "verify"},
        headers={"Authorization": f"Bearer {forged}"},
    )
    if r.status_code in (200, 201):
        print("ACCEPTED: forged token accepted ->", json.dumps(r.json()))
        return 0
    print("REJECTED", r.status_code)
    return 1


if __name__ == "__main__":
    sys.exit(main())
