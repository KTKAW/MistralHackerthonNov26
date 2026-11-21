"""Probe whether a deeply nested CSS selector overflows the parser.

Usage:
    <app>/.venv/bin/python verify_trigger.py <app_dir>

Posts a depth-330 nested-pseudo selector to POST /extract through Starlette's
TestClient. Prints exactly one line and sets the exit code:

    TRIGGERED RecursionError   -> exit 0   (a RecursionError came out of the app)
    NOT TRIGGERED <status>     -> exit 1   (the app answered normally)
"""

import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("NOT TRIGGERED usage", flush=True)
        return 1

    app_dir = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(app_dir / "src"))

    from fastapi.testclient import TestClient
    from html_extractor.app import app

    client = TestClient(app)

    depth = 330
    selector = ":is(" * depth + "p" + ")" * depth
    payload = {"html": "<p>hi</p>", "selector": selector, "attribute": None}

    try:
        response = client.post("/extract", json=payload)
    except RecursionError:
        print("TRIGGERED RecursionError", flush=True)
        return 0

    # If the app instead surfaced the overflow as a 500, count it as triggered.
    if response.status_code == 500:
        print("TRIGGERED RecursionError", flush=True)
        return 0

    print(f"NOT TRIGGERED {response.status_code}", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
