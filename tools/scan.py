#!/usr/bin/env python3
"""Python plug for the kb-scan engine: build/locate the binary, run it, render its reports. Standard library only.

Usage:
  python3 tools/scan.py scan   [--config FILE] [--inventory FILE] [--out report.json]
  python3 tools/scan.py sync   [--repo DIR] [--out sync.json]
  python3 tools/scan.py loop   [--config FILE] [--interval SECS] [--max-runs N]
  python3 tools/scan.py report --json REPORT [--out advisories/scan-latest.md] [--watch SECS]
  python3 tools/scan.py selftest
  python3 tools/scan.py feeds

The binary is resolved in order: $KB_SCAN_BIN, then tools/scan/target/x86_64-unknown-linux-musl/release/kb-scan,
then `cargo build --release --target x86_64-unknown-linux-musl` (needs export PATH=$HOME/.cargo/bin:$PATH).
Without cargo the wrapper exits 2 with install instructions. See tools/scan/ORCHESTRATION.md for the pinned CLI
and JSON schemas. The engine only reports; a person acts on what it finds. Run tools/lint.py --sync afterwards.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN_DIR = ROOT / "tools" / "scan"
DEFAULT_BIN = SCAN_DIR / "target" / "x86_64-unknown-linux-musl" / "release" / "kb-scan"
DEFAULT_REPORT_OUT = ROOT / "advisories" / "scan-latest.md"
TARGET = "x86_64-unknown-linux-musl"

TIER_NAMES = {
    1: "Tier 1 — malware",
    2: "Tier 2 — in KEV and in the inventory",
    3: "Tier 3 — high/critical or EPSS at or above the threshold",
    4: "Tier 4 — the rest",
}


def clean(value: object) -> str:
    """Feed text is data. Collapse whitespace and drop square brackets so it cannot form markdown links."""
    return " ".join(str(value).replace("[", "(").replace("]", ")").split())


# ---------------------------------------------------------------- binary resolution


def cargo_path() -> str | None:
    found = shutil.which("cargo")
    if found:
        return found
    candidate = Path.home() / ".cargo" / "bin" / "cargo"
    return str(candidate) if candidate.exists() else None


def rustup_instructions() -> str:
    return (
        "kb-scan needs the Rust toolchain to build the engine binary.\n"
        "Install it with rustup (https://rustup.rs):\n"
        "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y\n"
        "  export PATH=$HOME/.cargo/bin:$PATH\n"
        "  rustup target add x86_64-unknown-linux-musl\n"
        "Then re-run this command, or point $KB_SCAN_BIN at an existing kb-scan binary."
    )


def resolve_binary() -> Path:
    """$KB_SCAN_BIN, then the built binary, then build it with cargo. Exit 2 when that is impossible."""
    env_bin = os.environ.get("KB_SCAN_BIN")
    if env_bin:
        path = Path(env_bin)
        if not path.exists():
            print(f"KB_SCAN_BIN points at a file that does not exist: {env_bin}", file=sys.stderr)
            sys.exit(2)
        return path
    if DEFAULT_BIN.exists():
        return DEFAULT_BIN
    cargo = cargo_path()
    if not cargo:
        print(rustup_instructions(), file=sys.stderr)
        sys.exit(2)
    env = dict(os.environ)
    env["PATH"] = f"{Path.home() / '.cargo' / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    print(f"building kb-scan with {cargo} build --release --target {TARGET} ...", file=sys.stderr)
    build = subprocess.run(
        [cargo, "build", "--release", "--target", TARGET],
        cwd=SCAN_DIR, env=env, capture_output=True, text=True,
    )
    if build.returncode != 0 or not DEFAULT_BIN.exists():
        tail = (build.stderr or build.stdout or "").strip().splitlines()[-10:]
        print("cargo build failed:", file=sys.stderr)
        for line in tail:
            print(f"  {line}", file=sys.stderr)
        print(f"expected the binary at {DEFAULT_BIN.relative_to(ROOT)}", file=sys.stderr)
        sys.exit(2)
    return DEFAULT_BIN


def default_config() -> str | None:
    for name in ("config.json", "config.example.json"):
        path = SCAN_DIR / name
        if path.exists():
            return str(path)
    return None


def default_inventory() -> str | None:
    for name in ("inventory.json", "inventory.example.json"):
        path = SCAN_DIR / name
        if path.exists():
            return str(path)
    return None


# ---------------------------------------------------------------- engine subcommands


def run_engine(argv: list[str], stream: bool = False) -> int:
    """Run the engine. stdout carries only JSON; progress lines go to stderr. Exit codes: 0 ok, 2 usage, 3 feed/git, 4 lock."""
    binary = resolve_binary()
    command = [str(binary), *argv]
    if stream:
        return subprocess.run(command).returncode
    result = subprocess.run(command, capture_output=True, text=True)
    if result.stderr:
        sys.stderr.write(result.stderr)
    if result.stdout:
        sys.stdout.write(result.stdout if result.stdout.endswith("\n") else result.stdout + "\n")
    return result.returncode


def cmd_scan(args: argparse.Namespace) -> int:
    argv = ["scan"]
    config = args.config or default_config()
    inventory = args.inventory or default_inventory()
    if config:
        argv += ["--config", config]
    if inventory:
        argv += ["--inventory", inventory]
    if args.out:
        argv += ["--out", args.out]
        print(f"report will be written to {args.out}", file=sys.stderr)
        return run_engine(argv, stream=True)
    if args.pretty:
        argv += ["--pretty"]
    return run_engine(argv)


def cmd_sync(args: argparse.Namespace) -> int:
    argv = ["sync", "--repo", args.repo]
    if args.out:
        argv += ["--out", args.out]
        print(f"sync report will be written to {args.out}", file=sys.stderr)
        return run_engine(argv, stream=True)
    return run_engine(argv)


def cmd_loop(args: argparse.Namespace) -> int:
    argv = ["watch"]
    config = args.config or default_config()
    if config:
        argv += ["--config", config]
    if args.interval is not None:
        argv += ["--interval", str(args.interval)]
    if args.max_runs is not None:
        argv += ["--max-runs", str(args.max_runs)]
    print("streaming kb-scan watch mode; stop with Ctrl-C", file=sys.stderr)
    return run_engine(argv, stream=True)


def cmd_feeds(args: argparse.Namespace) -> int:
    return run_engine(["feeds"])


# ---------------------------------------------------------------- report rendering


def playbook_link(name: object) -> str:
    """Link the playbook when it exists in playbooks/; otherwise show the name as plain code."""
    slug = clean(name)
    if slug and (ROOT / "playbooks" / f"{slug}.md").exists():
        return f"[{slug}](../playbooks/{slug}.md)"
    return f"`{slug}`"


def render_report(report: dict, source_path: str, today: dt.date) -> str:
    """Render a kb-scan-report/1 JSON document as a lint-safe feed-snapshot page."""
    if report.get("schema") != "kb-scan-report/1":
        raise ValueError(f"not a kb-scan-report/1 document (schema: {report.get('schema')!r})")
    generated_at = clean(report.get("generated_at", ""))
    fetched = generated_at[:10] if len(generated_at) >= 10 else today.isoformat()
    try:
        dt.date.fromisoformat(fetched)
    except ValueError:
        fetched = today.isoformat()
    engine = report.get("engine", {})
    stats = report.get("stats", {})
    feeds = report.get("feeds", [])
    findings = sorted(report.get("findings", []), key=lambda f: (f.get("tier", 9), clean(f.get("id", ""))))

    lines = [
        "---",
        "type: feed-snapshot",
        'title: "kb-scan: continuous scanner report"',
        "feed: kb-scan-report/1",
        f"fetched: {fetched}",
        "generated: true",
        "---",
        "",
        "# kb-scan: continuous scanner report",
        "",
        f"Generated by `python3 tools/scan.py report --json {clean(source_path)}` from a `kb-scan-report/1` report written by "
        f"kb-scan {clean(engine.get('version', 'unknown'))} (static musl build: {clean(engine.get('static_musl', ''))}) "
        f"at {generated_at or 'an unknown time'}. Do not edit by hand.",
        "",
        "This page is a snapshot of one scan pass. For a live answer, run the scanner yourself — see [Feeds](../feeds.md). "
        "The scanner only reports; a person acts on what it finds. Findings follow the order of triage in "
        "[Feeds](../feeds.md): malware first, then exploited vulnerabilities in the inventory, then severity and EPSS, then the rest.",
        "",
        "## Feeds",
        "",
    ]
    for feed in feeds:
        status = clean(feed.get("status", ""))
        detail = f" — {clean(feed.get('detail', ''))}" if feed.get("detail") else ""
        entries = f" ({feed['entries']} entries)" if feed.get("entries") is not None else ""
        lines.append(f"- {clean(feed.get('name', ''))}: {status}{entries}{detail}")
    lines += [
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines += ["No findings in this pass.", ""]
    current_tier = None
    for finding in findings:
        tier = finding.get("tier", 4)
        if tier != current_tier:
            current_tier = tier
            lines += [f"### {TIER_NAMES.get(tier, f'Tier {tier}')}", ""]
        title_bits = [clean(finding.get("id", "unknown"))]
        target = clean(finding.get("package") or finding.get("product") or finding.get("cve") or "")
        if target:
            title_bits.append(target)
        lines.append(f"#### {' — '.join(title_bits)}")
        lines.append("")
        facts = [f"**Kind:** {clean(finding.get('kind', ''))}", f"**Source:** {clean(finding.get('source', ''))}"]
        if finding.get("cve"):
            facts.append(f"**CVE:** {clean(finding.get('cve'))}")
        if finding.get("epss") is not None:
            facts.append(f"**EPSS:** {clean(finding.get('epss'))}")
        if finding.get("kev_date_added"):
            facts.append(f"**KEV date added:** {clean(finding.get('kev_date_added'))}")
        lines.append("- " + " · ".join(facts))
        lines.append(f"- **Summary:** {clean(finding.get('summary', ''))}")
        if finding.get("playbook"):
            lines.append(f"- **Playbook:** {playbook_link(finding.get('playbook'))}")
        lines.append("")
    errors = stats.get("errors", [])
    lines += [
        "## Stats",
        "",
        f"- Packages in the inventory: {stats.get('packages', 0)} · CVEs watched: {stats.get('cves', 0)} · "
        f"findings: {stats.get('findings', len(findings))} · errors: {len(errors)}",
        "",
    ]
    for error in errors:
        lines.append(f"- Error: {clean(error)}")
    if errors:
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def cmd_report(args: argparse.Namespace) -> int:
    source = Path(args.json)
    try:
        report = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"could not read the report: {error}", file=sys.stderr)
        return 2
    try:
        rendered = render_report(report, args.json, dt.date.today())
    except ValueError as error:
        print(f"could not render the report: {error}", file=sys.stderr)
        return 2

    def render_once() -> None:
        write_atomic(Path(args.out), rendered)
        print(f"wrote {Path(args.out).relative_to(ROOT) if Path(args.out).is_relative_to(ROOT) else args.out}")

    if not args.watch:
        render_once()
        return 0
    last_mtime = None
    print(f"watching {args.json} for changes every {args.watch}s; stop with Ctrl-C", file=sys.stderr)
    try:
        while True:
            mtime = source.stat().st_mtime
            if mtime != last_mtime:
                last_mtime = mtime
                try:
                    report = json.loads(source.read_text(encoding="utf-8"))
                    rendered = render_report(report, args.json, dt.date.today())
                except (OSError, ValueError) as error:
                    print(f"could not re-read the report: {error}", file=sys.stderr)
                else:
                    render_once()
            time.sleep(args.watch)
    except KeyboardInterrupt:
        return 0


# ---------------------------------------------------------------- selftest


def cmd_selftest(args: argparse.Namespace) -> int:
    failures = []

    def check(name: str, ok: bool) -> None:
        print(f"{'ok' if ok else 'FAIL'}  {name}")
        if not ok:
            failures.append(name)

    check("clean() drops square brackets and collapses whitespace", clean(" [GHSA-1]  a\nb ") == "(GHSA-1) a b")

    sample = {
        "schema": "kb-scan-report/1",
        "generated_at": "2026-11-21T12:00:00Z",
        "engine": {"name": "kb-scan", "version": "0.1.0", "static_musl": True},
        "feeds": [
            {"name": "kev", "status": "ok", "entries": 1790},
            {"name": "osv", "status": "error", "detail": "boom [x]"},
        ],
        "findings": [
            {
                "tier": 1, "kind": "malware", "id": "MAL-2026-0001", "package": "npm evil-pkg",
                "summary": "drops [a] payload", "source": "github", "playbook": "malicious-dependency",
            },
            {
                "tier": 2, "kind": "kev", "id": "CVE-2021-44228", "cve": "CVE-2021-44228",
                "summary": "log4shell", "source": "kev", "epss": 0.97, "kev_date_added": "2021-12-10",
                "playbook": "exploited-vulnerability",
            },
        ],
        "stats": {"packages": 3, "cves": 1, "findings": 2, "errors": ["osv: boom [x]"]},
    }
    rendered = render_report(sample, "tools/scan/out/latest.json", dt.date(2026, 11, 21))
    check("render produces feed-snapshot frontmatter", "type: feed-snapshot" in rendered and "generated: true" in rendered)
    check("render sanitises feed text", "drops (a) payload" in rendered and "boom (x)" in rendered)
    check("render links ../feeds.md and existing playbooks", "[Feeds](../feeds.md)" in rendered
          and "[malicious-dependency](../playbooks/malicious-dependency.md)" in rendered)
    check("render refuses other schemas", isinstance(_try_render({"schema": "nope"}), ValueError))

    stub = Path(tempfile.mkdtemp()) / "kb-scan-stub"
    stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    stub.chmod(0o755)
    old = os.environ.get("KB_SCAN_BIN")
    os.environ["KB_SCAN_BIN"] = str(stub)
    try:
        check("KB_SCAN_BIN wins binary resolution", resolve_binary() == stub)
    finally:
        if old is None:
            del os.environ["KB_SCAN_BIN"]
        else:
            os.environ["KB_SCAN_BIN"] = old

    try:
        binary = resolve_binary()
    except SystemExit as exit_info:
        check("binary resolves or exits 2 with instructions", exit_info.code == 2)
        binary = None
    if binary is not None:
        result = subprocess.run([str(binary), "self-test"], capture_output=True, text=True)
        check("kb-scan self-test exits 0", result.returncode == 0)

    if failures:
        print(f"selftest failed: {len(failures)} check(s)", file=sys.stderr)
        return 1
    print("selftest ok")
    return 0


def _try_render(report: dict) -> object:
    try:
        render_report(report, "selftest", dt.date(2026, 11, 21))
        return None
    except ValueError as error:
        return error


# ---------------------------------------------------------------- main


def main() -> int:
    parser = argparse.ArgumentParser(description="Python plug for the kb-scan engine (see tools/scan/ORCHESTRATION.md).")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="one scan pass against the feeds; report JSON on stdout")
    scan.add_argument("--config", help="config file (default: tools/scan/config.json, else config.example.json)")
    scan.add_argument("--inventory", help="inventory file (default: tools/scan/inventory.json, else inventory.example.json)")
    scan.add_argument("--out", help="write the report JSON to this file instead of stdout")
    scan.add_argument("--pretty", action="store_true", help="pretty-print the report JSON")
    scan.set_defaults(func=cmd_scan)

    sync = sub.add_parser("sync", help="one git poll of the remote; sync report JSON on stdout")
    sync.add_argument("--repo", default=str(ROOT), help="repository to poll (default: this checkout)")
    sync.add_argument("--out", help="write the sync report JSON to this file instead of stdout")
    sync.set_defaults(func=cmd_sync)

    loop = sub.add_parser("loop", help="stream the engine's watch mode (sync then scan, forever or --max-runs times)")
    loop.add_argument("--config", help="config file (default: tools/scan/config.json, else config.example.json)")
    loop.add_argument("--interval", type=int, help="seconds between cycles")
    loop.add_argument("--max-runs", type=int, help="stop after this many cycles")
    loop.set_defaults(func=cmd_loop)

    report = sub.add_parser("report", help="render a kb-scan-report/1 JSON into a lint-safe snapshot page")
    report.add_argument("--json", required=True, help="the kb-scan-report/1 JSON file to render")
    report.add_argument("--out", default=str(DEFAULT_REPORT_OUT), help="page to write (default: advisories/scan-latest.md)")
    report.add_argument("--watch", type=int, metavar="SECS", help="re-render whenever the JSON file changes, polling every SECS")
    report.set_defaults(func=cmd_report)

    selftest = sub.add_parser("selftest", help="check the wrapper itself, and the engine binary when it is available")
    selftest.set_defaults(func=cmd_selftest)

    feeds = sub.add_parser("feeds", help="list the engine's feed endpoints and host allowlist")
    feeds.set_defaults(func=cmd_feeds)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
