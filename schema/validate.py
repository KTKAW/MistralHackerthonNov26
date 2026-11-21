#!/usr/bin/env python3
"""Validate a verdict.json against schema/verdict.schema.json.

Usage: python schema/validate.py path/to/verdict.json
Exit 0 = valid, 1 = invalid (errors printed to stdout).
"""
import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    sys.exit("missing dependency — run: uv add jsonschema   (or: pip install jsonschema)")

SCHEMA = Path(__file__).parent / "verdict.schema.json"


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    schema = json.loads(SCHEMA.read_text())
    data = json.loads(Path(sys.argv[1]).read_text())
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        for e in errors:
            loc = "/".join(map(str, e.path)) or "<root>"
            print(f"INVALID at {loc}: {e.message}")
        return 1
    print(f"OK: {sys.argv[1]} is a valid verdict.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
