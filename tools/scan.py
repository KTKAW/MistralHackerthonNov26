#!/usr/bin/env python3
"""Python plug for the kb-scan engine: build/locate the binary, run it sandboxed, render its reports. Standard library only.

Usage:
  python3 tools/scan.py scan   [--config FILE] [--inventory FILE] [--out report.json] [--allow-unsandboxed]
  python3 tools/scan.py sync   [--repo DIR] [--out sync.json] [--allow-unsandboxed]
  python3 tools/scan.py loop   [--config FILE] [--interval SECS] [--max-runs N] [--allow-unsandboxed]
  python3 tools/scan.py swarm  [--config FILE] [--interval SECS] [--max-runs N] [--allow-unsandboxed]
  python3 tools/scan.py report --json REPORT [--out advisories/scan-latest.md] [--watch SECS]
  python3 tools/scan.py brief  --json REPORT [--sync-json sync.json] [--out brief.txt] [--speak]
  python3 tools/scan.py audio-loop --json REPORT [--sync-json sync.json] [--interval 60] [--once] [--listen]
  python3 tools/scan.py query ENDPOINT [--port 8787] [--tier N] [--token-env KB_SCAN_QUERY_TOKEN] [--speak]
  python3 tools/scan.py selftest
  python3 tools/scan.py feeds

Sandboxing is mandatory for anything that touches the network (scan, sync, loop, swarm): when bwrap is on PATH
(shutil.which('bwrap')), every such engine invocation is wrapped in the tested bubblewrap shape from
tools/scan/bwrap.example.sh — repo read-only, only the out dir (and a --out file's directory) writable, /usr and
/etc read-only with the usrmerge symlinks, /proc and /dev, cwd=repo, env scrubbed, engine argv after `--`.
The shape may be overridden by a top-level "sandbox_cmd" array in the config file ("{repo}"/"{out}" are
substituted; the wrapper strips that wrapper-only key before handing the config to the strict engine parser).
If bwrap is MISSING, network-touching subcommands fail closed: exit 2 with a clear message, unless
--allow-unsandboxed is passed, which prints a loud warning (local debugging only, never in production).
report, selftest and feeds touch no network and may run unsandboxed.

`brief` renders a deterministic, spoken-style brief of at most 90 words from a kb-scan-report/1 (top verified
tier 1/2 findings, any sync attention lines, then the standing closer). `--speak` posts the brief to Mistral's
speech API (voxtral-tts) with MISTRAL_API_KEY from the environment only — the key is never printed, logged or
stored — writes tools/scan/out/brief.wav and plays it when a player exists; without the key it exits 2.

`audio-loop` polls the report file's mtime and, on change, speaks one short alert per NEW verified tier<=2
finding or new sync attention line (debounced by id+status in tools/scan/out/audio-loop-state.json, also
appended to tools/scan/out/audio-loop.log). `--once` does a single check; `--listen` runs a voice query loop
(voxtral-realtime transcription; speaks the current brief when the question mentions threat/scan/brief/new).
Tests can set KB_SCAN_SPEAK_STUB to a script that receives the spoken text on stdin instead of calling the API.

`query` reads the live loopback API of a running `kb-scan serve` (health|latest|sync|findings|brief): it GETs
http://127.0.0.1:<port>/<endpoint> (findings also takes ?tier=N via --tier), prints the body, exits 3 on a
non-200 status, and sends `Authorization: Bearer` from the env var named by --token-env (default
KB_SCAN_QUERY_TOKEN when set) without ever printing the token. `--speak` speaks the /brief body, or one alert
per finding, via the same speak() helper.

The binary is resolved in order: $KB_SCAN_BIN, then tools/scan/target/x86_64-unknown-linux-musl/release/kb-scan,
then `cargo build --release --target x86_64-unknown-linux-musl` (needs export PATH=$HOME/.cargo/bin:$PATH).
Without cargo the wrapper exits 2 with install instructions. See tools/scan/ORCHESTRATION.md for the pinned CLI
and JSON schemas. The engine only reports; a person acts on what it finds. Run tools/lint.py --sync afterwards.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import http.server
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN_DIR = ROOT / "tools" / "scan"
DEFAULT_BIN = SCAN_DIR / "target" / "x86_64-unknown-linux-musl" / "release" / "kb-scan"
DEFAULT_REPORT_OUT = ROOT / "advisories" / "scan-latest.md"
TARGET = "x86_64-unknown-linux-musl"

# The tested bwrap shape from tools/scan/bwrap.example.sh (bubblewrap 0.11.1, 2026-11-21). "{repo}" and "{out}"
# are substituted by the wrapper; the env is scrubbed and only PATH is passed through.
BWRAP_TEMPLATE = [
    "bwrap",
    "--clearenv", "--setenv", "PATH", "/usr/bin:/bin",
    "--ro-bind", "/usr", "/usr",
    "--symlink", "usr/bin", "/bin",
    "--symlink", "usr/lib", "/lib",
    "--symlink", "usr/lib64", "/lib64",
    "--ro-bind", "/etc", "/etc",
    "--proc", "/proc",
    "--dev", "/dev",
    "--ro-bind", "{repo}", "{repo}",
    "--bind", "{out}", "{out}",
    "--chdir", "{repo}",
]

# Top-level config keys the wrapper consumes itself; stripped before the config is handed to the engine,
# whose parser is strict (unknown keys are an error).
WRAPPER_ONLY_CONFIG_KEYS = {"sandbox_cmd"}

TIER_NAMES = {
    1: "Tier 1 — malware",
    2: "Tier 2 — in KEV and in the inventory",
    3: "Tier 3 — high/critical or EPSS at or above the threshold",
    4: "Tier 4 — the rest",
}

# Voice briefings (see ORCHESTRATION.md "Voice briefings"). The key lives only in the environment.
SPEECH_URL = "https://api.mistral.ai/v1/audio/speech"
SPEECH_MODEL = "voxtral-tts"
TRANSCRIBE_URL = "https://api.mistral.ai/v1/audio/transcriptions"
TRANSCRIBE_MODEL = "voxtral-realtime"
SPEECH_TIMEOUT_SECS = 60
MAX_SPEECH_BYTES = 25 * 1024 * 1024
AUDIO_PLAYERS = ("aplay", "ffplay", "paplay", "pw-play")
AUDIO_RECORDERS = ("arecord", "ffmpeg")
BRIEF_MAX_WORDS = 90
BRIEF_CLOSER = "A person approves before anything is sent."
ALERT_MAX_WORDS = 40
QUESTION_WORDS = ("threat", "scan", "brief", "new")
# Local query API (kb-scan serve): loopback only, read-only GET endpoints.
QUERY_ENDPOINTS = ("health", "latest", "sync", "findings", "brief")
QUERY_DEFAULT_PORT = 8787
QUERY_TIMEOUT_SECS = 30
QUERY_DEFAULT_TOKEN_ENV = "KB_SCAN_QUERY_TOKEN"
# audio-loop state and log; module-level so tests can point them at a temp dir.
AUDIO_STATE_FILE = SCAN_DIR / "out" / "audio-loop-state.json"
AUDIO_LOG_FILE = SCAN_DIR / "out" / "audio-loop.log"


def clean(value: object) -> str:
    """Feed text is data. Collapse whitespace, drop square brackets so it cannot form markdown
    links, and HTML-escape < > & so injected markup cannot survive into a rendered page."""
    return (
        " ".join(str(value).replace("[", "(").replace("]", ")").split())
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


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


def read_config_json(path: str | None) -> dict:
    """The wrapper's own view of the config file; unreadable or non-object means no wrapper-only settings."""
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def engine_config_path(path: str | None) -> str | None:
    """The config path to hand to the engine: a copy without wrapper-only keys when those are present."""
    if not path:
        return None
    data = read_config_json(path)
    if not any(key in data for key in WRAPPER_ONLY_CONFIG_KEYS):
        return path
    sanitized = {key: value for key, value in data.items() if key not in WRAPPER_ONLY_CONFIG_KEYS}
    out_dir = SCAN_DIR / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    stripped = out_dir / "config-for-engine.json"
    stripped.write_text(json.dumps(sanitized, indent=2) + "\n", encoding="utf-8")
    return str(stripped)


def sandbox_template(config_path: str | None) -> list[str]:
    """The sandbox argv prefix: the config's top-level sandbox_cmd when set, else the tested bwrap shape."""
    cmd = read_config_json(config_path).get("sandbox_cmd")
    if isinstance(cmd, list) and cmd and all(isinstance(item, str) for item in cmd):
        return cmd
    return list(BWRAP_TEMPLATE)


def out_dir_for(config_path: str | None) -> Path:
    value = read_config_json(config_path).get("out_dir")
    path = Path(value) if isinstance(value, str) and value else SCAN_DIR / "out"
    return path if path.is_absolute() else ROOT / path


# ---------------------------------------------------------------- sandboxing


def sandbox_command(
    binary: Path,
    engine_argv: list[str],
    config: str | None,
    out_file: str | None,
    allow_unsandboxed: bool,
) -> list[str] | None:
    """Wrap the engine invocation in the sandbox. Returns None (after printing why) when refusing to run unsandboxed."""
    template = sandbox_template(config)
    sandbox_bin = shutil.which(template[0])
    if sandbox_bin is None:
        if allow_unsandboxed:
            print(
                f"WARNING: --allow-unsandboxed: running `kb-scan {engine_argv[0]}` WITHOUT a sandbox. "
                "Local debugging only; never in production.",
                file=sys.stderr,
            )
            return [str(binary), *engine_argv]
        print(
            f"refusing to run `kb-scan {engine_argv[0]}` without a sandbox: {template[0]!r} not found on PATH. "
            "Network-touching subcommands fail closed.",
            file=sys.stderr,
        )
        print("Install bubblewrap (e.g. `apt install bubblewrap`) or pass --allow-unsandboxed for local debugging only.", file=sys.stderr)
        return None
    repo = str(ROOT)
    extra_writable: list[Path] = []
    if out_file:
        given = Path(out_file)
        extra_writable.append((given if given.is_absolute() else ROOT / given).parent)
    writable = [out_dir_for(config), *extra_writable]
    for directory in writable:
        directory.mkdir(parents=True, exist_ok=True)
    command = [sandbox_bin]
    for token in template[1:]:
        command.append(token.replace("{repo}", repo).replace("{out}", str(writable[0])))
    for directory in extra_writable:
        command += ["--bind", str(directory), str(directory)]
    command += ["--", str(binary), *engine_argv]
    print(f"running kb-scan under {template[0]} (repo read-only, only the out dir writable)", file=sys.stderr)
    return command


# ---------------------------------------------------------------- engine subcommands


def run_engine(
    argv: list[str],
    stream: bool = False,
    network: bool = False,
    allow_unsandboxed: bool = False,
    config: str | None = None,
    out_file: str | None = None,
) -> int:
    """Run the engine, sandboxed when it touches the network. stdout carries only JSON; progress goes to stderr.

    Exit codes: 0 ok, 2 usage/config/sandbox refusal, 3 feed/git error, 4 lock held."""
    binary = resolve_binary()
    command = [str(binary), *argv]
    if network:
        command = sandbox_command(binary, argv, config, out_file, allow_unsandboxed)
        if command is None:
            return 2
    if stream:
        return subprocess.run(command).returncode
    result = subprocess.run(command, capture_output=True, text=True)
    if result.stderr:
        sys.stderr.write(result.stderr)
    if result.stdout:
        sys.stdout.write(result.stdout if result.stdout.endswith("\n") else result.stdout + "\n")
    return result.returncode


def cmd_scan(args: argparse.Namespace) -> int:
    config = args.config or default_config()
    inventory = args.inventory or default_inventory()
    argv = ["scan"]
    engine_config = engine_config_path(config)
    if engine_config:
        argv += ["--config", engine_config]
    if inventory:
        argv += ["--inventory", inventory]
    if args.pretty:
        argv += ["--pretty"]
    if args.out:
        argv += ["--out", args.out]
    return run_engine(
        argv, stream=bool(args.out), network=True,
        allow_unsandboxed=args.allow_unsandboxed, config=config, out_file=args.out,
    )


def cmd_sync(args: argparse.Namespace) -> int:
    argv = ["sync", "--repo", args.repo]
    if args.out:
        argv += ["--out", args.out]
    return run_engine(
        argv, stream=bool(args.out), network=True,
        allow_unsandboxed=args.allow_unsandboxed, out_file=args.out,
    )


def cmd_loop(args: argparse.Namespace) -> int:
    config = args.config or default_config()
    argv = ["watch"]
    engine_config = engine_config_path(config)
    if engine_config:
        argv += ["--config", engine_config]
    if args.interval is not None:
        argv += ["--interval", str(args.interval)]
    if args.max_runs is not None:
        argv += ["--max-runs", str(args.max_runs)]
    print("streaming kb-scan watch mode; stop with Ctrl-C", file=sys.stderr)
    return run_engine(argv, stream=True, network=True, allow_unsandboxed=args.allow_unsandboxed, config=config)


def cmd_swarm(args: argparse.Namespace) -> int:
    config = args.config or default_config()
    argv = ["swarm"]
    engine_config = engine_config_path(config)
    if engine_config:
        argv += ["--config", engine_config]
    if args.interval is not None:
        argv += ["--interval", str(args.interval)]
    if args.max_runs is not None:
        argv += ["--max-runs", str(args.max_runs)]
    if args.out_dir:
        argv += ["--out-dir", args.out_dir]
    print("streaming kb-scan swarm mode; stop with Ctrl-C", file=sys.stderr)
    return run_engine(argv, stream=True, network=True, allow_unsandboxed=args.allow_unsandboxed, config=config)


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


# ---------------------------------------------------------------- voice brief


def _verified(finding: dict) -> bool:
    """Feed-confirmed findings carry no status; unverified/unconfirmed leads sort after them."""
    return str(finding.get("status", "confirmed")).lower() not in ("unverified", "unconfirmed")


def _finding_line(finding: dict) -> str:
    """One spoken line: id, one-line what-it-is, what we run, patch target if known. All feed text via clean()."""
    what = clean(finding.get("summary", ""))
    first_sentence = re.split(r"(?<=[.!?])\s+", what, maxsplit=1)[0] if what else ""
    runs = clean(finding.get("package") or finding.get("product") or finding.get("cve") or "")
    patch = next(
        (clean(finding[key]) for key in ("fixed_in", "patched_in", "patch_target", "patch") if finding.get(key)),
        "",
    )
    line = f"{clean(finding.get('id', 'unknown'))}: {first_sentence}".rstrip(" .") + "."
    if runs:
        line = f"{line[:-1]} — we run {runs}."
    if patch:
        line = f"{line[:-1]}; patch {patch}."
    return line


def render_brief(report: dict, sync_report: dict | None = None) -> str:
    """Render a deterministic spoken-style brief of at most BRIEF_MAX_WORDS words from a kb-scan-report/1."""
    if report.get("schema") != "kb-scan-report/1":
        raise ValueError(f"not a kb-scan-report/1 document (schema: {report.get('schema')!r})")
    # Top verified tier 1/2 findings only (unverified/unconfirmed leads excluded) — matches serve.rs.
    top = [f for f in report.get("findings", []) if f.get("tier") in (1, 2) and _verified(f)]
    top.sort(key=lambda f: (f.get("tier", 9), clean(f.get("id", ""))))
    header = f"Scan brief {clean(report.get('generated_at', ''))[:10] or 'undated'}."
    body = [_finding_line(f) for f in top]
    if sync_report is not None:
        body += [f"{clean(line)}." for line in sync_report.get("attention", []) if str(line).strip()]
    budget = BRIEF_MAX_WORDS - len(BRIEF_CLOSER.split())
    words = len(header.split())
    kept: list[str] = []
    for line in body:
        count = len(line.split())
        if words + count > budget:
            break
        kept.append(line)
        words += count
    return "\n".join([header, *kept, BRIEF_CLOSER]) + "\n"


def speak(text: str) -> int:
    """Speak a short text: via $KB_SCAN_SPEAK_STUB when set (tests), else POST to Mistral speech and play the wav.

    MISTRAL_API_KEY comes from the environment only and is never printed, logged or stored."""
    stub = os.environ.get("KB_SCAN_SPEAK_STUB")
    if stub:
        result = subprocess.run([stub], input=text.encode("utf-8") + b"\n", capture_output=True)
        if result.returncode != 0:
            print(f"speak stub failed: {result.stderr.decode('utf-8', 'replace').strip()}", file=sys.stderr)
            return 3
        return 0
    api_key = os.environ.get("MISTRAL_API_KEY")
    if not api_key:
        print("set your own MISTRAL_API_KEY to use --speak", file=sys.stderr)
        return 2
    payload = json.dumps({"model": SPEECH_MODEL, "input": text, "response_format": "wav"}).encode("utf-8")
    request = urllib.request.Request(
        SPEECH_URL,
        data=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    out = SCAN_DIR / "out" / "brief.wav"
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(request, timeout=SPEECH_TIMEOUT_SECS) as response:
            fd, tmp = tempfile.mkstemp(dir=out.parent, prefix="brief.", suffix=".wav.tmp")
            total = 0
            try:
                with os.fdopen(fd, "wb") as handle:
                    while True:
                        chunk = response.read(65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > MAX_SPEECH_BYTES:
                            raise ValueError(f"speech response is over {MAX_SPEECH_BYTES} bytes")
                        handle.write(chunk)
                os.replace(tmp, out)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
    except (OSError, ValueError) as error:
        print(f"speech request failed: {error}", file=sys.stderr)
        return 3
    player = next((name for name in AUDIO_PLAYERS if shutil.which(name)), None)
    if player is None:
        print(f"no audio player found ({'/'.join(AUDIO_PLAYERS)}); wav written to {out}")
        return 0
    argv = [player]
    if player == "ffplay":
        argv += ["-nodisp", "-autoexit"]
    argv.append(str(out))
    print(f"playing {out} with {player}", file=sys.stderr)
    return subprocess.run(argv).returncode


def cmd_brief(args: argparse.Namespace) -> int:
    try:
        report = json.loads(Path(args.json).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"could not read the report: {error}", file=sys.stderr)
        return 2
    sync_report = None
    if args.sync_json:
        try:
            sync_report = json.loads(Path(args.sync_json).read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            print(f"could not read the sync report: {error}", file=sys.stderr)
            return 2
    try:
        brief = render_brief(report, sync_report)
    except ValueError as error:
        print(f"could not render the brief: {error}", file=sys.stderr)
        return 2
    sys.stdout.write(brief)
    if args.out:
        write_atomic(Path(args.out), brief)
        print(f"wrote {Path(args.out).relative_to(ROOT) if Path(args.out).is_relative_to(ROOT) else args.out}")
    if args.speak:
        return speak(brief)
    return 0


# ---------------------------------------------------------------- audio loop


def _alert_line(finding: dict) -> str:
    """One short alert utterance (<= ALERT_MAX_WORDS words) for a new verified tier<=2 finding."""
    what = clean(finding.get("summary", ""))
    sentence = re.split(r"(?<=[.!?])\s+", what, maxsplit=1)[0] if what else ""
    runs = clean(finding.get("package") or finding.get("product") or finding.get("cve") or "")
    patch = next(
        (clean(finding[key]) for key in ("fixed_in", "patched_in", "patch_target", "patch") if finding.get(key)),
        "",
    )
    tail = f" — we run {runs}" if runs else ""
    tail += f"; patch {patch}" if patch else ""
    line = f"New verified threat: {clean(finding.get('id', 'unknown'))} — {sentence}{tail}."
    words = line.split()
    if len(words) > ALERT_MAX_WORDS:
        line = " ".join(words[: ALERT_MAX_WORDS - 1]) + " ..."
    return line


def new_alerts(state: dict, report: dict, sync_report: dict | None) -> list[tuple[str, str]]:
    """(state key, alert text) for findings/attention lines not yet spoken. Feed text is data: clean()ed."""
    alerts: list[tuple[str, str]] = []
    for finding in report.get("findings", []):
        if finding.get("tier") not in (1, 2) or not _verified(finding):
            continue
        key = f"finding:{clean(finding.get('id', ''))}|{clean(finding.get('status', 'confirmed'))}"
        if key not in state["spoken"]:
            alerts.append((key, _alert_line(finding)))
    for line in (sync_report or {}).get("attention", []):
        text = clean(line)
        if not text:
            continue
        key = f"attention:{text}"
        if key not in state["spoken"]:
            alerts.append((key, f"New sync attention: {text}."))
    return alerts


def load_state() -> dict:
    try:
        data = json.loads(AUDIO_STATE_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("spoken"), dict):
            return data
    except (OSError, ValueError):
        pass
    return {"spoken": {}}


def save_state(state: dict) -> None:
    write_atomic(AUDIO_STATE_FILE, json.dumps(state, indent=1, sort_keys=True) + "\n")


def append_log(lines: list[str]) -> None:
    """Append alert lines to the audio-loop log; read-modify-rename so the write stays atomic."""
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    existing = AUDIO_LOG_FILE.read_text(encoding="utf-8") if AUDIO_LOG_FILE.exists() else ""
    write_atomic(AUDIO_LOG_FILE, existing + "".join(f"[{stamp}] {line}\n" for line in lines))


def check_once(report_path: Path, sync_path: Path | None, state: dict) -> int:
    """One poll: diff the report against the state, speak and log each new alert. Returns an exit code."""
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"could not read the report: {error}", file=sys.stderr)
        return 2
    sync_report = None
    if sync_path is not None:
        try:
            sync_report = json.loads(sync_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            print(f"could not read the sync report: {error}", file=sys.stderr)
            return 2
    spoken: list[str] = []
    for key, text in new_alerts(state, report, sync_report):
        if speak(text) != 0:
            break
        state["spoken"][key] = True
        spoken.append(text)
    if spoken:
        save_state(state)
        append_log(spoken)
        print(f"spoke {len(spoken)} alert(s); state saved to {AUDIO_STATE_FILE}", file=sys.stderr)
    return 0


def transcribe(wav_path: Path) -> str:
    """POST a wav to Mistral's transcription endpoint (voxtral-realtime). The key never leaves the header."""
    api_key = os.environ.get("MISTRAL_API_KEY")
    if not api_key:
        print("set your own MISTRAL_API_KEY to use --speak", file=sys.stderr)
        raise SystemExit(2)
    boundary = "kbscan-boundary"
    audio = wav_path.read_bytes()
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n{TRANSCRIBE_MODEL}\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"query.wav\"\r\n"
        f"Content-Type: audio/wav\r\n\r\n"
    ).encode("utf-8") + audio + f"\r\n--{boundary}--\r\n".encode("utf-8")
    request = urllib.request.Request(
        TRANSCRIBE_URL,
        data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=SPEECH_TIMEOUT_SECS) as response:
        data = json.loads(response.read(MAX_SPEECH_BYTES))
    return str(data.get("text", ""))


def record_query(seconds: int = 5) -> Path:
    """Record one utterance from the default mic with the first available recorder."""
    arecord = shutil.which("arecord")
    ffmpeg = shutil.which("ffmpeg")
    out = Path(tempfile.mkstemp(prefix="query.", suffix=".wav")[1])
    if arecord:
        subprocess.run([arecord, "-q", "-f", "cd", "-d", str(seconds), str(out)], check=True)
    elif ffmpeg:
        subprocess.run([ffmpeg, "-y", "-loglevel", "error", "-f", "alsa", "-i", "default", "-t", str(seconds), str(out)], check=True)
    else:
        out.unlink(missing_ok=True)
        print("no recorder found: install alsa-utils (arecord) or ffmpeg, or python3 -m pip install sounddevice", file=sys.stderr)
        raise SystemExit(2)
    return out


def cmd_audio_loop(args: argparse.Namespace) -> int:
    report_path = Path(args.json)
    sync_path = Path(args.sync_json) if args.sync_json else None
    if not os.environ.get("KB_SCAN_SPEAK_STUB") and not os.environ.get("MISTRAL_API_KEY"):
        print("set your own MISTRAL_API_KEY to use --speak", file=sys.stderr)
        return 2
    state = load_state()

    if args.listen:
        while True:
            try:
                wav = record_query()
                transcript = transcribe(wav).lower()
                wav.unlink(missing_ok=True)
                if any(word in transcript for word in QUESTION_WORDS):
                    report = json.loads(report_path.read_text(encoding="utf-8"))
                    sync = json.loads(sync_path.read_text(encoding="utf-8")) if sync_path else None
                    speak(render_brief(report, sync))
                time.sleep(args.interval)
            except SystemExit:
                raise
            except Exception as error:  # any STT/record failure: log and keep listening, never crash
                append_log([f"listen error: {error}"])
                time.sleep(args.interval)

    if args.once:
        return check_once(report_path, sync_path, state)
    last_mtime = None
    print(f"audio-loop: polling {args.json} every {args.interval}s; stop with Ctrl-C", file=sys.stderr)
    try:
        while True:
            try:
                mtime = report_path.stat().st_mtime
            except OSError:
                mtime = None
            if mtime != last_mtime:
                last_mtime = mtime
                code = check_once(report_path, sync_path, state)
                if code != 0:
                    return code
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


# ---------------------------------------------------------------- query (kb-scan serve)


def cmd_query(args: argparse.Namespace) -> int:
    """GET http://127.0.0.1:<port>/<endpoint> from a running `kb-scan serve` and print the body.

    The bearer token is read from the named env var and sent as Authorization only — never printed.
    Non-200 responses exit 3 with the status."""
    url = f"http://127.0.0.1:{args.port}/{args.endpoint}"
    if args.endpoint == "findings" and args.tier is not None:
        url += f"?tier={args.tier}"
    headers = {}
    token_env = args.token_env or QUERY_DEFAULT_TOKEN_ENV
    token = os.environ.get(token_env)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif args.token_env:
        print(f"environment variable {args.token_env} is not set", file=sys.stderr)
        return 2
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=QUERY_TIMEOUT_SECS) as response:
            body = response.read(MAX_SPEECH_BYTES).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        print(f"query failed: HTTP {error.code} for {url}", file=sys.stderr)
        return 3
    except OSError as error:
        print(f"query failed: {error}", file=sys.stderr)
        return 3
    sys.stdout.write(body if body.endswith("\n") else body + "\n")
    if not args.speak:
        return 0
    if args.endpoint == "brief":
        return speak(body)
    if args.endpoint == "findings":
        try:
            data = json.loads(body)
        except ValueError as error:
            print(f"could not parse the findings response: {error}", file=sys.stderr)
            return 2
        findings = data if isinstance(data, list) else data.get("findings", [])
        for finding in findings:
            code = speak(_alert_line(finding))
            if code != 0:
                return code
        return 0
    return speak(f"kb-scan {args.endpoint}: ok.")


# ---------------------------------------------------------------- selftest


def cmd_selftest(args: argparse.Namespace) -> int:
    global AUDIO_STATE_FILE, AUDIO_LOG_FILE
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

    brief_sample = {
        "schema": "kb-scan-report/1",
        "generated_at": "2026-11-21T13:23:01Z",
        "findings": [
            {"tier": 2, "kind": "kev", "id": "CVE-2021-44228", "cve": "CVE-2021-44228",
             "summary": "Log4Shell [RCE] in Apache Log4j. Second sentence.", "product": "Apache Log4j",
             "fixed_in": "2.17.1", "playbook": "exploited-vulnerability"},
            {"tier": 1, "kind": "malware", "id": "MAL-2026-0001", "summary": "Poisoned release.",
             "package": "npm evil-pkg", "status": "confirmed", "playbook": "malicious-dependency"},
            {"tier": 2, "kind": "kev", "id": "CVE-2020-0001", "summary": "Old flaw.", "product": "Exchange Server",
             "status": "unverified", "fixed_in": "CU 23", "playbook": "exploited-vulnerability"},
            {"tier": 1, "kind": "malware", "id": "MAL-2026-0002", "summary": "Unconfirmed lead.",
             "package": "npm other-pkg", "status": "unconfirmed", "playbook": "malicious-dependency"},
        ],
        "stats": {"packages": 3, "cves": 1, "findings": 4, "errors": []},
    }
    brief = render_brief(brief_sample, {"attention": ["new branch [x] appeared"]})
    check("brief stays within 90 words and ends with the closer",
          len(brief.split()) <= 90 and brief.rstrip("\n").endswith(BRIEF_CLOSER))
    check("brief sanitises feed text and keeps one line per verified finding",
          "(RCE)" in brief and "(x)" in brief and brief.count("we run") == 2)
    check("brief orders by tier, verified findings only",
          brief.index("MAL-2026-0001") < brief.index("CVE-2021-44228"))
    check("brief excludes unverified/unconfirmed findings",
          "CVE-2020-0001" not in brief and "MAL-2026-0002" not in brief)
    check("brief names the patch target when known", "patch 2.17.1" in brief)
    check("brief is deterministic", brief == render_brief(brief_sample, {"attention": ["new branch [x] appeared"]}))
    try:
        render_brief({"schema": "nope"})
        check("brief refuses other schemas", False)
    except ValueError:
        check("brief refuses other schemas", True)

    loop_report = {
        "schema": "kb-scan-report/1",
        "generated_at": "2026-11-21T14:00:00Z",
        "findings": [
            {"tier": 1, "kind": "malware", "id": "MAL-2026-0009", "summary": "Poisoned release of a package we run.",
             "package": "npm evil-pkg", "playbook": "malicious-dependency"},
            {"tier": 2, "kind": "kev", "id": "CVE-2021-44228", "summary": "Log4Shell remote code execution.",
             "product": "Apache Log4j", "fixed_in": "2.17.1", "playbook": "exploited-vulnerability"},
            {"tier": 2, "kind": "kev", "id": "CVE-2020-0001", "summary": "Unverified lead.", "status": "unverified"},
        ],
        "stats": {},
    }
    state: dict = {"spoken": {}}
    alerts = new_alerts(state, loop_report, {"attention": ["new branch [x] appeared"]})
    texts = [text for _, text in alerts]
    check("audio-loop alerts on new verified tier<=2 findings and attention, skipping unverified",
          len(alerts) == 3 and any(t.startswith("New verified threat: MAL-2026-0009") for t in texts)
          and any(t.startswith("New sync attention: new branch (x) appeared.") for t in texts)
          and all("CVE-2020-0001" not in t for t in texts))
    check("audio-loop alert is one short utterance (<= 40 words)",
          all(len(t.split()) <= 40 for t in texts))
    for key, _ in alerts:
        state["spoken"][key] = True
    check("audio-loop never re-speaks the same finding id+status (state debounce)",
          new_alerts(state, loop_report, {"attention": ["new branch [x] appeared"]}) == [])

    tmpdir = Path(tempfile.mkdtemp())
    stub_log = tmpdir / "speak-stub.log"
    stub = tmpdir / "speak-stub"
    stub.write_text(f"#!/bin/sh\ncat >> {stub_log}\n", encoding="utf-8")
    stub.chmod(0o755)
    report_file = tmpdir / "report.json"
    report_file.write_text(json.dumps(loop_report), encoding="utf-8")
    old_state, old_log = AUDIO_STATE_FILE, AUDIO_LOG_FILE
    old_stub, old_key = os.environ.get("KB_SCAN_SPEAK_STUB"), os.environ.get("MISTRAL_API_KEY")
    AUDIO_STATE_FILE, AUDIO_LOG_FILE = tmpdir / "state.json", tmpdir / "loop.log"
    os.environ["KB_SCAN_SPEAK_STUB"] = str(stub)
    try:
        rc = cmd_audio_loop(argparse.Namespace(json=str(report_file), sync_json=None, interval=60, once=True, listen=False))
        check("audio-loop --once speaks via KB_SCAN_SPEAK_STUB and logs atomically",
              rc == 0 and stub_log.exists() and "New verified threat: MAL-2026-0009" in stub_log.read_text(encoding="utf-8")
              and AUDIO_LOG_FILE.exists())
        del os.environ["KB_SCAN_SPEAK_STUB"]
        os.environ.pop("MISTRAL_API_KEY", None)
        rc = cmd_audio_loop(argparse.Namespace(json=str(report_file), sync_json=None, interval=60, once=True, listen=False))
        check("audio-loop without key or stub exits 2", rc == 2)
    finally:
        AUDIO_STATE_FILE, AUDIO_LOG_FILE = old_state, old_log
        if old_stub is None:
            os.environ.pop("KB_SCAN_SPEAK_STUB", None)
        else:
            os.environ["KB_SCAN_SPEAK_STUB"] = old_stub
        if old_key is None:
            os.environ.pop("MISTRAL_API_KEY", None)
        else:
            os.environ["MISTRAL_API_KEY"] = old_key

    canned_brief = "Scan brief 2026-11-21.\nA person approves before anything is sent.\n"
    query_finding = {"tier": 2, "kind": "kev", "id": "CVE-2021-44228",
                     "summary": "Log4Shell remote code execution.", "product": "Apache Log4j"}
    seen: list[tuple[str, str | None]] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen.append((self.path, self.headers.get("Authorization")))
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/health":
                body = json.dumps({"status": "ok"}).encode("utf-8")
                ctype = "application/json"
            elif parsed.path == "/findings":
                tier = urllib.parse.parse_qs(parsed.query).get("tier", [None])[0]
                body = json.dumps({"tier": tier, "findings": [query_finding]}).encode("utf-8")
                ctype = "application/json"
            elif parsed.path == "/brief":
                body = canned_brief.encode("utf-8")
                ctype = "text/plain"
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    query_port = server.server_address[1]
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cmd_query(argparse.Namespace(endpoint="health", port=query_port, tier=None, token_env=None, speak=False))
        check("query prints the endpoint body", rc == 0 and json.loads(buf.getvalue()) == {"status": "ok"})

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cmd_query(argparse.Namespace(endpoint="findings", port=query_port, tier=2, token_env=None, speak=False))
        check("query findings passes ?tier=N through",
              rc == 0 and any(path == "/findings?tier=2" for path, _ in seen) and '"tier": "2"' in buf.getvalue())

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cmd_query(argparse.Namespace(endpoint="sync", port=query_port, tier=None, token_env=None, speak=False))
        check("query exits 3 on a non-200 response", rc == 3)

        os.environ["KB_SCAN_TEST_QUERY_TOKEN"] = "test-token-abc123"
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cmd_query(argparse.Namespace(endpoint="health", port=query_port, tier=None,
                                                 token_env="KB_SCAN_TEST_QUERY_TOKEN", speak=False))
            check("query sends the bearer token from --token-env and never prints it",
                  rc == 0 and any(auth == "Bearer test-token-abc123" for _, auth in seen)
                  and "test-token-abc123" not in buf.getvalue())
        finally:
            del os.environ["KB_SCAN_TEST_QUERY_TOKEN"]

        stub_log2 = tmpdir / "speak-stub2.log"
        stub2 = tmpdir / "speak-stub2"
        stub2.write_text(f"#!/bin/sh\ncat >> {stub_log2}\n", encoding="utf-8")
        stub2.chmod(0o755)
        old_stub2 = os.environ.get("KB_SCAN_SPEAK_STUB")
        os.environ["KB_SCAN_SPEAK_STUB"] = str(stub2)
        try:
            rc = cmd_query(argparse.Namespace(endpoint="brief", port=query_port, tier=None, token_env=None, speak=True))
            check("query --speak speaks the /brief body via the stub",
                  rc == 0 and canned_brief in stub_log2.read_text(encoding="utf-8"))
        finally:
            if old_stub2 is None:
                os.environ.pop("KB_SCAN_SPEAK_STUB", None)
            else:
                os.environ["KB_SCAN_SPEAK_STUB"] = old_stub2
    finally:
        server.shutdown()

    stub = Path(tempfile.mkdtemp()) / "kb-scan-stub"
    stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    stub.chmod(0o755)
    old = os.environ.get("KB_SCAN_BIN")
    os.environ["KB_SCAN_BIN"] = str(stub)
    try:
        check("KB_SCAN_BIN wins binary resolution", resolve_binary() == stub)
        wrapped = sandbox_command(stub, ["scan"], None, None, allow_unsandboxed=False)
        if shutil.which(BWRAP_TEMPLATE[0]):
            check("sandbox wraps the engine: bwrap ... -- <bin> scan",
                  wrapped is not None and wrapped[0] == shutil.which("bwrap")
                  and "--" in wrapped and wrapped[wrapped.index("--") + 1 :] == [str(stub), "scan"])
        else:
            check("missing bwrap fails closed without the flag", wrapped is None)
            check("missing bwrap runs with --allow-unsandboxed",
                  sandbox_command(stub, ["scan"], None, None, allow_unsandboxed=True) == [str(stub), "scan"])
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

    scan = sub.add_parser("scan", help="one scan pass against the feeds; report JSON on stdout (sandboxed, fail-closed)")
    scan.add_argument("--config", help="config file (default: tools/scan/config.json, else config.example.json)")
    scan.add_argument("--inventory", help="inventory file (default: tools/scan/inventory.json, else inventory.example.json)")
    scan.add_argument("--out", help="write the report JSON to this file instead of stdout")
    scan.add_argument("--pretty", action="store_true", help="pretty-print the report JSON")
    scan.add_argument("--allow-unsandboxed", action="store_true",
                      help="run without the bwrap sandbox (local debugging only; never in production)")
    scan.set_defaults(func=cmd_scan)

    sync = sub.add_parser("sync", help="one git poll of the remote; sync report JSON on stdout (sandboxed, fail-closed)")
    sync.add_argument("--repo", default=str(ROOT), help="repository to poll (default: this checkout)")
    sync.add_argument("--out", help="write the sync report JSON to this file instead of stdout")
    sync.add_argument("--allow-unsandboxed", action="store_true",
                      help="run without the bwrap sandbox (local debugging only; never in production)")
    sync.set_defaults(func=cmd_sync)

    loop = sub.add_parser("loop", help="stream the engine's watch mode (sandboxed, fail-closed)")
    loop.add_argument("--config", help="config file (default: tools/scan/config.json, else config.example.json)")
    loop.add_argument("--interval", type=int, help="seconds between cycles")
    loop.add_argument("--max-runs", type=int, help="stop after this many cycles")
    loop.add_argument("--allow-unsandboxed", action="store_true",
                      help="run without the bwrap sandbox (local debugging only; never in production)")
    loop.set_defaults(func=cmd_loop)

    swarm = sub.add_parser("swarm", help="stream the engine's swarm mode (sandboxed, fail-closed)")
    swarm.add_argument("--config", help="config file (default: tools/scan/config.json, else config.example.json)")
    swarm.add_argument("--interval", type=int, help="seconds between cycles")
    swarm.add_argument("--max-runs", type=int, help="stop after this many cycles")
    swarm.add_argument("--out-dir", help="where the swarm writes its reports")
    swarm.add_argument("--allow-unsandboxed", action="store_true",
                       help="run without the bwrap sandbox (local debugging only; never in production)")
    swarm.set_defaults(func=cmd_swarm)

    report = sub.add_parser("report", help="render a kb-scan-report/1 JSON into a lint-safe snapshot page (no network)")
    report.add_argument("--json", required=True, help="the kb-scan-report/1 JSON file to render")
    report.add_argument("--out", default=str(DEFAULT_REPORT_OUT), help="page to write (default: advisories/scan-latest.md)")
    report.add_argument("--watch", type=int, metavar="SECS", help="re-render whenever the JSON file changes, polling every SECS")
    report.set_defaults(func=cmd_report)

    brief = sub.add_parser("brief", help="render a spoken-style brief (<= 90 words) from a kb-scan-report/1; no network unless --speak")
    brief.add_argument("--json", required=True, help="the kb-scan-report/1 JSON file to read")
    brief.add_argument("--sync-json", help="a kb-scan-sync/1 JSON file whose attention[] lines are read into the brief")
    brief.add_argument("--out", help="also write the brief to this file (atomic)")
    brief.add_argument("--speak", action="store_true", help="post the brief to Mistral speech (voxtral-tts) and play the wav; needs MISTRAL_API_KEY")
    brief.set_defaults(func=cmd_brief)

    audio_loop = sub.add_parser("audio-loop", help="poll a report and speak an alert for each new verified tier<=2 finding or sync attention line")
    audio_loop.add_argument("--json", required=True, help="the kb-scan-report/1 JSON file to poll")
    audio_loop.add_argument("--sync-json", help="a kb-scan-sync/1 JSON file whose attention[] lines are also alerted on")
    audio_loop.add_argument("--interval", type=int, default=60, help="seconds between polls (default 60)")
    audio_loop.add_argument("--once", action="store_true", help="do a single check and exit (for tests/cron)")
    audio_loop.add_argument("--listen", action="store_true", help="voice query loop: transcribe mic input and speak the brief on question words")
    audio_loop.set_defaults(func=cmd_audio_loop)

    query = sub.add_parser("query", help="GET a read-only endpoint from a running `kb-scan serve` and print the body")
    query.add_argument("endpoint", choices=sorted(QUERY_ENDPOINTS), help="one of health, latest, sync, findings, brief")
    query.add_argument("--port", type=int, default=QUERY_DEFAULT_PORT, help=f"serve port (default {QUERY_DEFAULT_PORT})")
    query.add_argument("--tier", type=int, help="for findings: pass ?tier=N")
    query.add_argument("--token-env", help=f"env var holding the bearer token (default {QUERY_DEFAULT_TOKEN_ENV} when set)")
    query.add_argument("--speak", action="store_true", help="speak the /brief body, or one alert per finding")
    query.set_defaults(func=cmd_query)

    selftest = sub.add_parser("selftest", help="check the wrapper itself, and the engine binary when it is available")
    selftest.set_defaults(func=cmd_selftest)

    feeds = sub.add_parser("feeds", help="list the engine's feed endpoints and host allowlist (no network)")
    feeds.set_defaults(func=cmd_feeds)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
