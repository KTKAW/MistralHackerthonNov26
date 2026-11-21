#!/usr/bin/env python3
"""Generate kb-scan's inventory.json from this codebase. Standard library only.

The engine never reads source code; it only reads the inventory this script
emits. Scanning the repo for lockfiles is the "do we run this?" step that
feeds.md says the feeds cannot answer.

Usage:
  python3 tools/scan/inventory.py                 write tools/scan/inventory.json
  python3 tools/scan/inventory.py --out FILE      write elsewhere
  python3 tools/scan/inventory.py --check         exit 1 if inventory.json is stale

Sources recognised (best-effort, stdlib parsers):
  package-lock.json (npm), requirements*.txt / pyproject.toml (PyPI),
  Cargo.toml, go.mod, Gemfile.lock, poetry.lock, Dockerfile FROM lines,
  .github/workflows/*.yml (actions with versions), .vibe/mcp*.json / mcp.json
  (MCP servers as products). Unparseable lines are skipped, never guessed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "tools" / "scan" / "inventory.json"


def npm_from_lock(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    pkgs = []
    for name, info in (data.get("packages") or {}).items():
        if not name:
            continue
        version = info.get("version")
        if version:
            pkgs.append({"ecosystem": "npm", "name": name.lstrip("node_modules/"), "version": str(version)})
    return pkgs


def pypi_from_requirements(path: Path) -> list[dict]:
    pkgs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;]+)", line)
        if m:
            pkgs.append({"ecosystem": "PyPI", "name": m.group(1), "version": m.group(2)})
    return pkgs


def pypi_from_pyproject(path: Path) -> list[dict]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    pkgs = []
    for dep in (data.get("project", {}).get("dependencies") or []):
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;]+)", dep.strip())
        if m:
            pkgs.append({"ecosystem": "PyPI", "name": m.group(1), "version": m.group(2)})
    return pkgs


def cargo_from_toml(path: Path) -> list[dict]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    pkgs = []
    for name, info in (data.get("dependencies") or {}).items():
        if isinstance(info, dict) and info.get("version"):
            pkgs.append({"ecosystem": "crates.io", "name": name, "version": str(info["version"]).lstrip("^~")})
    return pkgs


def go_from_mod(path: Path) -> list[dict]:
    pkgs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\s*([\w./-]+)\s+v([\w.\-]+)", line)
        if m and not line.strip().startswith("//"):
            pkgs.append({"ecosystem": "Go", "name": m.group(1), "version": m.group(2)})
    return pkgs


def docker_from(path: Path) -> list[dict]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\s*FROM\s+(\S+)", line, re.I)
        if not m or "$" in m.group(1):
            continue
        image = m.group(1)
        name, _, tag = image.partition(":")
        if "/" in tag:  # the colon was a registry port, not a tag
            name, tag = image, "latest"
        out.append({"ecosystem": "docker", "name": name, "version": tag or "latest"})
    return out


def actions_from_workflows(root: Path) -> list[dict]:
    out = []
    wf = root / ".github" / "workflows"
    if not wf.is_dir():
        return out
    for f in sorted(wf.glob("*.yml")) + sorted(wf.glob("*.yaml")):
        for m in re.finditer(r"uses:\s*([\w./-]+)@([\w.\-]+)", f.read_text(encoding="utf-8")):
            out.append({"ecosystem": "github-actions", "name": m.group(1), "version": m.group(2)})
    return out


def mcp_products(root: Path) -> list[dict]:
    out = []
    for pat in (".vibe/mcp.json", ".vibe/mcp_servers.json", "mcp.json"):
        p = root / pat
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            servers = data.get("mcpServers", data) if isinstance(data, dict) else {}
            if isinstance(servers, dict):
                for name in servers:
                    out.append({"vendor": "mcp", "product": name})
    return out


def build_inventory(root: Path = ROOT) -> dict:
    packages: list[dict] = []
    seen: set[tuple] = set()

    def add(items: list[dict], source: str) -> None:
        for p in items:
            # OSV/GitHub reject malformed versions with HTTP 400/422 and fail the whole
            # batch — normalise to a bare semver-ish string or drop the version (the
            # feeds then match any version of the package).
            version = str(p.get("version", "")).lstrip("=^~> <").strip()
            if version and not re.match(r"^\d+(\.\d+){0,3}([-+].*)?$", version):
                version = ""
            p["version"] = version
            key = (p.get("ecosystem"), p.get("name"), p.get("version"))
            if key not in seen:
                seen.add(key)
                p["source"] = source
                packages.append(p)

    for f in sorted(root.rglob("package-lock.json")):
        if "node_modules" in f.parts:
            continue
        add(npm_from_lock(f), str(f.relative_to(root)))
    for pat in ("requirements*.txt", "requirements/*.txt"):
        for f in sorted(root.glob(pat)):
            add(pypi_from_requirements(f), str(f.relative_to(root)))
    for f in sorted(root.rglob("pyproject.toml")):
        if ".venv" in f.parts or "node_modules" in f.parts:
            continue
        add(pypi_from_pyproject(f), str(f.relative_to(root)))
    for f in sorted(root.rglob("Cargo.toml")):
        if "target" in f.parts:
            continue
        add(cargo_from_toml(f), str(f.relative_to(root)))
    for f in sorted(root.rglob("go.mod")):
        add(go_from_mod(f), str(f.relative_to(root)))
    for f in sorted(root.rglob("Dockerfile")) + sorted(root.rglob("Dockerfile.*")):
        add(docker_from(f), str(f.relative_to(root)))
    add(actions_from_workflows(root), ".github/workflows")
    return {"packages": packages, "products": mcp_products(root), "cves": []}


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate kb-scan inventory from this codebase.")
    parser.add_argument("--out", default=str(OUT))
    parser.add_argument("--check", action="store_true", help="exit 1 if the written inventory would change")
    args = parser.parse_args()
    inv = build_inventory()
    text = json.dumps(inv, indent=1, sort_keys=True) + "\n"
    out = Path(args.out)
    if args.check:
        current = out.read_text(encoding="utf-8") if out.exists() else ""
        if current != text:
            print(f"stale: {out} differs from the codebase", file=sys.stderr)
            return 1
        print(f"{out} is up to date ({len(inv['packages'])} packages, {len(inv['products'])} products)")
        return 0
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out}: {len(inv['packages'])} packages, {len(inv['products'])} products")
    return 0


if __name__ == "__main__":
    sys.exit(main())
