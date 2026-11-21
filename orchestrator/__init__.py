"""The orchestrator. Its modules are run from the repository root.

The run contract lives in the package `vulnerability_agent` under src/ (see docs/contract.md).
This puts src/ on the import path, so `python -m orchestrator.workflow` and `python -m web.app`
find it without the project having to be installed.
"""
import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
