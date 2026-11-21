"""Apply the forged token in input.json to profile-api's entry point.

Usage:
    python verify_trigger.py <app_dir> [--setting-on]

Puts <app_dir>/src on sys.path, sets or clears PROFILE_ACCEPT_JSON_TOKENS
before importing the app, then sends the forged token as the bearer value at
GET /profile through FastAPI's TestClient.

Prints one line and exits 0 if the forged token was accepted, 1 otherwise.
"""
import importlib
import json
import os
import sys


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    setting_on = "--setting-on" in sys.argv[1:]
    if not args:
        print("usage: verify_trigger.py <app_dir> [--setting-on]")
        return 2
    app_dir = os.path.abspath(args[0])

    if setting_on:
        os.environ["PROFILE_ACCEPT_JSON_TOKENS"] = "1"
    else:
        os.environ.pop("PROFILE_ACCEPT_JSON_TOKENS", None)

    sys.path.insert(0, os.path.join(app_dir, "src"))
    app_module = importlib.import_module("profile_api.app")

    from fastapi.testclient import TestClient

    here = os.path.dirname(os.path.abspath(__file__))
    forged = open(os.path.join(here, "input.json")).read()

    client = TestClient(app_module.app)
    r = client.get("/profile", headers={"Authorization": f"Bearer {forged}"})
    if r.status_code == 200:
        print("ACCEPTED:", json.dumps(r.json()))
        return 0
    print("REJECTED", r.status_code)
    return 1


if __name__ == "__main__":
    sys.exit(main())
