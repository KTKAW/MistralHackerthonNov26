#!/usr/bin/env python3
"""Render the Mermaid diagrams in the pages to images in diagrams/. Needs the Mermaid CLI, `mmdc`.

Usage:
  python3 tools/diagrams.py

The Mermaid block in a page is the source: agents read it as text. The image beside it is what
people see, because GitHub's built-in view of a large diagram is cramped. Run this after changing
a block. Images are named <page>-<n>.png, in the order the blocks appear in the page.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGES = ["system.md", "concepts/cra-reporting-clock.md"]
BLOCK = re.compile(r"```mermaid\n(.*?)```", re.S)


def render(source: Path, target: Path) -> bool:
    """mmdc sometimes fails on its first start, so try twice."""
    command = ["mmdc", "-i", str(source), "-o", str(target), "-b", "white", "-s", "2", "-w", "1600"]
    for _ in range(2):
        target.unlink(missing_ok=True)
        subprocess.run(command, capture_output=True, text=True)
        if target.exists():
            return True
    return False


def main() -> int:
    if not shutil.which("mmdc"):
        print("mmdc not found: install the Mermaid CLI (@mermaid-js/mermaid-cli)", file=sys.stderr)
        return 1
    out = ROOT / "diagrams"
    out.mkdir(exist_ok=True)
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name in PAGES:
            blocks = BLOCK.findall((ROOT / name).read_text(encoding="utf-8"))
            for number, block in enumerate(blocks, start=1):
                source = Path(tmp) / f"{Path(name).stem}-{number}.mmd"
                source.write_text(block, encoding="utf-8")
                target = out / f"{Path(name).stem}-{number}.png"
                if render(source, target):
                    print(f"wrote {target.relative_to(ROOT)}")
                else:
                    print(f"FAILED {name}, diagram {number}", file=sys.stderr)
                    failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
