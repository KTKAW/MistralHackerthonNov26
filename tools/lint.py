#!/usr/bin/env python3
"""Checks and generated parts for the security knowledge base. Standard library only.

Usage:
  python3 tools/lint.py
      Check everything. Exit 1 on errors.
  python3 tools/lint.py --sync
      Also rewrite the generated parts: the source and advisory lists in index.md, and manifest.json.
  python3 tools/lint.py --sync --log "ingest | Title of the source"
      Sync, check and, if there are no errors, append a dated entry to log.md that lists the
      files changed since the last commit. Operations: init, ingest, lint, refresh, edit.

Errors:
  - a relative markdown link points at a file that does not exist
  - a page in sources/, concepts/, playbooks/ or advisories/ lacks required frontmatter, has a
    value outside the allowed set, or is not listed in index.md
  - two source notes share a URL
  - a concept, playbook or advisory links to no source note
  - a bullet under "What to do" on a concept page cites no source note
  - a numbered step in a playbook neither cites a source note nor carries the (baseline) tag
  - an advisory names a playbook that does not exist
  - a citation label ends with a date that differs from the note's `published` value

Warnings:
  - a figure on a cited line that is not in any source note the line cites
  - a source note that no page uses
  - a glossary term that does not appear on the page its entry links to
  - a page not reviewed for --stale-days days, or a feed snapshot older than --snapshot-days days
  - generated parts that are out of date (run with --sync)
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent

# folder -> page types allowed in it
FOLDERS = {
    "sources": {"source"},
    "concepts": {"concept"},
    "playbooks": {"playbook"},
    "advisories": {"advisory", "feed-snapshot"},
}
REQUIRED = {
    "source": ["type", "title", "publisher", "url", "published", "ingested", "kind", "read"],
    "concept": ["type", "title", "updated", "reviewed", "status"],
    "playbook": ["type", "title", "signals", "severity", "updated", "reviewed"],
    "advisory": ["type", "title", "date", "kind", "exploited", "fix_status", "affects", "playbook", "updated"],
    "feed-snapshot": ["type", "title", "feed", "fetched"],
}
ALLOWED = {
    ("source", "kind"): {"article", "report", "paper", "docs", "guidance", "feed", "research-report"},
    ("source", "read"): {"full", "partial", "via-report", "via-snippet"},
    ("concept", "status"): {"settled", "evolving", "contested"},
    ("playbook", "severity"): {"critical", "high", "medium", "low"},
    ("advisory", "kind"): {"incident", "campaign", "research", "vulnerability"},
    ("advisory", "exploited"): {"in-the-wild", "demonstrated", "unknown"},
    ("advisory", "fix_status"): {"fixed", "mitigation-only", "unknown"},
}
FULL_DATE_FIELDS = ["ingested", "updated", "reviewed", "fetched"]
OPERATIONS = {"init", "ingest", "lint", "refresh", "edit"}
BASELINE = "*(baseline)*"
MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1)}

LINK = re.compile(r"(?<!!)\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
LINK_FULL = re.compile(r"!?\[[^\]]*\]\([^)]*\)")
SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.I)
FENCE = re.compile(r"```.*?```", re.S)
INLINE_CODE = re.compile(r"`[^`\n]*`")
PARTIAL_DATE = re.compile(r"^\d{4}(-\d{2}(-\d{2})?)?$")
PAGE_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*\.md$")
BULLET = re.compile(r"^\s*[-*]\s+")
STEP = re.compile(r"^\s*\d+\.\s+")
LIST_ITEM = re.compile(r"^\s*(?:[-*]|\d+\.)\s+")
LABEL_TAIL = re.compile(r"^(?:(\d{1,2}) )?(?:(" + "|".join(MONTHS) + r") )?(\d{4})$")
GLOSSARY_ENTRY = re.compile(r"^- \*\*(.+?)\*\* — .*\]\(([^)#]+)(?:#[^)]*)?\)\s*$")
NUMBER = re.compile(r"(?<![\w.^@])\d+(?:\.\d+)?")
MARKERS = {
    "sources": ("<!-- sources:start -->", "<!-- sources:end -->"),
    "advisories": ("<!-- advisories:start -->", "<!-- advisories:end -->"),
}

Pages = dict  # Path -> (frontmatter fields, body)


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, path: Path, message: str) -> None:
        self.errors.append(f"ERROR {rel(path)}: {message}")

    def warn(self, path: Path, message: str) -> None:
        self.warnings.append(f"WARN  {rel(path)}: {message}")


# ---------------------------------------------------------------- helpers


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def strip_digit_commas(text: str) -> str:
    """Write 2,500 as 2500 so figures compare regardless of thousands separators."""
    return re.sub(r"(?<=\d),(?=\d{3})", "", text)


def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[`*_]", "", text.lower()))


def markdown_files() -> list[Path]:
    """Pages of the knowledge base: markdown at the top level and in the typed folders. Other folders are not ours."""
    found = sorted(ROOT.glob("*.md"))
    for folder in sorted(FOLDERS):
        found.extend(sorted((ROOT / folder).glob("*.md")))
    return found


def split_frontmatter(text: str) -> tuple[dict[str, object], str]:
    """Return (fields, body). Understands `key: value` and `key: [a, b]` only, so list items hold no commas."""
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---", 4)
    if end == -1:
        return {}, text
    fields: dict[str, object] = {}
    for line in text[4:end].splitlines():
        if not line.strip() or line.lstrip().startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        value = value.strip()
        if value.startswith("[") and value.endswith("]"):
            fields[key.strip()] = [v.strip().strip("\"'") for v in value[1:-1].split(",") if v.strip()]
        elif len(value) >= 2 and value[0] == value[-1] == '"':
            fields[key.strip()] = value[1:-1].replace('\\"', '"')
        else:
            fields[key.strip()] = value.strip("'")
    return fields, text[end + 4 :]


def links_in(path: Path, text: str) -> list[tuple[str, Path]]:
    """(label, resolved target) for every relative link in a piece of markdown."""
    found = []
    for label, raw in LINK.findall(text):
        if SCHEME.match(raw) or raw.startswith("#"):
            continue
        target = unquote(raw.split("#", 1)[0].split("?", 1)[0])
        if target:
            found.append((label, (path.parent / target).resolve()))
    return found


def prose_links(path: Path, body: str) -> list[tuple[str, Path]]:
    """Links in a page, ignoring anything inside code."""
    return links_in(path, INLINE_CODE.sub("", FENCE.sub("", body)))


def full_date(value: object) -> dt.date | None:
    try:
        return dt.date.fromisoformat(str(value)) if len(str(value)) == 10 else None
    except ValueError:
        return None


def label_matches(label: str, published: str) -> bool:
    """A citation reads [Short title, Mon YYYY], [Short title, YYYY] or [Short title, undated]."""
    tail = label.rsplit(",", 1)[-1].strip() if "," in label else ""
    if published == "undated":
        return tail == "undated"
    match = LABEL_TAIL.match(tail)
    if not match:
        return False
    day, month, year = match.groups()
    parts = published.split("-")
    if int(year) != int(parts[0]):
        return False
    if len(parts) >= 2 and (not month or MONTHS[month] != int(parts[1])):
        return False
    if len(parts) == 1 and month:
        return False
    return not day or (len(parts) == 3 and int(day) == int(parts[2]))


# ---------------------------------------------------------------- checks


def check_frontmatter(report: Report, pages: Pages, by_folder: dict[str, set[Path]]) -> None:
    seen_urls: dict[str, Path] = {}
    for folder, types in FOLDERS.items():
        for path in sorted(by_folder[folder]):
            fields = pages[path][0]
            kind = str(fields.get("type", ""))
            if kind not in types:
                report.error(path, f"`type` must be one of {sorted(types)} in {folder}/")
                continue
            if not PAGE_NAME.match(path.name):
                report.error(path, "filename must be kebab-case")
            for key in REQUIRED[kind]:
                if key not in fields:
                    report.error(path, f"missing frontmatter field `{key}`")
            for (page_type, key), allowed in ALLOWED.items():
                if page_type == kind and key in fields and fields[key] not in allowed:
                    report.error(path, f"`{key}` must be one of {sorted(allowed)}")
            for key in FULL_DATE_FIELDS:
                if key in fields and full_date(fields[key]) is None:
                    report.error(path, f"`{key}` must be a real YYYY-MM-DD date, got '{fields[key]}'")
            if kind == "source":
                published = str(fields.get("published", ""))
                if published != "undated" and not PARTIAL_DATE.match(published):
                    report.error(path, "`published` must be YYYY, YYYY-MM, YYYY-MM-DD or `undated`")
                url = str(fields.get("url", ""))
                if url != "none" and not url.startswith("http"):
                    report.error(path, "`url` must be a web address, or `none` for a local document")
                elif url in seen_urls:
                    report.error(path, f"same `url` as {rel(seen_urls[url])}")
                elif url != "none":
                    seen_urls[url] = path
            if kind == "advisory":
                if not PARTIAL_DATE.match(str(fields.get("date", ""))):
                    report.error(path, "`date` must be YYYY, YYYY-MM or YYYY-MM-DD")
                playbook = ROOT / "playbooks" / f"{fields.get('playbook', '')}.md"
                if playbook not in pages:
                    report.error(path, f"`playbook` names a page that does not exist: {rel(playbook)}")
            if kind == "playbook" and not fields.get("signals"):
                report.error(path, "`signals` must list at least one way this incident shows up")


def check_citations(report: Report, pages: Pages, links: dict, sources: set[Path], concepts: set[Path], playbooks: set[Path], advisories: set[Path]) -> None:
    for path in sorted(concepts | playbooks | advisories):
        if not any(target in sources for _, target in links.get(path, [])):
            report.error(path, "links to no source note; every claim needs a source")
    for path in sorted(concepts):
        section = ""
        for line in pages[path][1].splitlines():
            if line.startswith("## "):
                section = line[3:].strip().lower()
            elif section.startswith("what to do") and BULLET.match(line) and not line.rstrip().endswith(":"):
                if not any(target in sources for _, target in links_in(path, line)):
                    report.error(path, f"bullet under 'What to do' cites no source note: {BULLET.sub('', line)[:60]}")
    for path in sorted(playbooks):
        for line in FENCE.sub("", pages[path][1]).splitlines():
            if STEP.match(line) and BASELINE not in line and not any(t in sources for _, t in links_in(path, line)):
                report.error(path, f"step cites no source note and is not tagged {BASELINE}: {STEP.sub('', line)[:60]}")


def check_labels(report: Report, pages: Pages, links: dict, sources: set[Path], cited_pages: list[Path]) -> None:
    for path in cited_pages:
        for label, target in links.get(path, []):
            if target in sources:
                published = str(pages[target][0].get("published", ""))
                if not label_matches(label, published):
                    report.error(path, f"citation '{label}' must end with the note's date ({published}), written like 'Short title, Mon YYYY'")


def check_numbers(report: Report, pages: Pages, sources: set[Path], cited_pages: list[Path]) -> None:
    """A figure on a cited line must appear in one of the source notes that line cites."""
    source_text = {s: strip_digit_commas(s.read_text(encoding="utf-8")) for s in sources}
    for path in cited_pages:
        for line in pages[path][1].splitlines():
            cited = [target for _, target in links_in(path, line) if target in source_text]
            if not cited:
                continue
            prose = strip_digit_commas(LIST_ITEM.sub("", INLINE_CODE.sub("", LINK_FULL.sub("", line))))
            for number in sorted(set(NUMBER.findall(prose))):
                pattern = re.compile(r"(?<![\d.])" + re.escape(number) + r"(?!\d)")
                if not any(pattern.search(source_text[s]) for s in cited):
                    report.warn(path, f"number {number} is not in the source notes cited on its line: {prose.strip()[:70]}")


def check_usage(report: Report, links: dict, sources: set[Path], cited_pages: list[Path]) -> None:
    used = {target for path in cited_pages for _, target in links.get(path, [])}
    for path in sorted(sources - used):
        report.warn(path, "no page uses this source")


def check_glossary(report: Report, pages: Pages) -> None:
    """Every term must appear by name on the page its entry points to."""
    glossary = ROOT / "glossary.md"
    if glossary not in pages:
        report.error(glossary, "glossary.md is missing")
        return
    for line in pages[glossary][1].splitlines():
        entry = GLOSSARY_ENTRY.match(line)
        if not entry:
            continue
        target = (ROOT / entry.group(2)).resolve()
        if target not in pages:
            continue  # already reported as a broken link
        page_text = normalise(pages[target][1])
        names = [n for n in re.split(r"\s*/\s*|,\s*|\s*\(|\)", entry.group(1)) if n.strip()]
        if not any(normalise(name) in page_text for name in names):
            report.warn(glossary, f"term '{entry.group(1)}' does not appear on {rel(target)}")


def check_freshness(report: Report, pages: Pages, reviewed_pages: set[Path], snapshots: set[Path], today: dt.date, stale_days: int, snapshot_days: int) -> None:
    for path in sorted(reviewed_pages):
        reviewed = full_date(pages[path][0].get("reviewed", ""))
        if reviewed and (today - reviewed).days > stale_days:
            report.warn(path, f"not reviewed for {(today - reviewed).days} days; re-read it against newer sources, then set `reviewed:`")
    for path in sorted(snapshots):
        fetched = full_date(pages[path][0].get("fetched", ""))
        if fetched and (today - fetched).days > snapshot_days:
            report.warn(path, f"snapshot is {(today - fetched).days} days old; refresh it with the tool named on the page")


# ---------------------------------------------------------------- generated parts


def clean_title(fields: dict[str, object], path: Path) -> str:
    return str(fields.get("title", path.stem)).replace("[", "(").replace("]", ")")


def sources_block(sources: set[Path], pages: Pages) -> str:
    """Source notes for index.md, newest first, undated last."""
    def key(path: Path) -> tuple[int, str, str]:
        published = str(pages[path][0].get("published", ""))
        return (0 if published == "undated" else 1, published, path.name)
    lines = []
    for path in sorted(sources, key=key, reverse=True):
        fields = pages[path][0]
        lines.append(f"- {fields.get('published', '')} · [{clean_title(fields, path)}](sources/{path.name}) · {fields.get('publisher', '')} · read: {fields.get('read', '')}")
    return "\n".join(lines)


def advisories_block(advisories: set[Path], pages: Pages) -> str:
    lines = []
    for path in sorted(advisories, key=lambda p: (str(pages[p][0].get("date", "")), p.name), reverse=True):
        fields = pages[path][0]
        lines.append(
            f"- {fields.get('date', '')} · [{clean_title(fields, path)}](advisories/{path.name}) · {fields.get('kind', '')}, "
            f"{fields.get('exploited', '')} · playbook: [{fields.get('playbook', '')}](playbooks/{fields.get('playbook', '')}.md)"
        )
    return "\n".join(lines)


def sync_index(report: Report, pages: Pages, links: dict, blocks: dict[str, str], listed_pages: set[Path], sync: bool) -> None:
    """The lists between the markers are generated. The rest of index.md is written by hand."""
    index = ROOT / "index.md"
    if index not in pages:
        report.error(index, "index.md is missing")
        return
    text = original = index.read_text(encoding="utf-8")
    for name, wanted in blocks.items():
        start, end = MARKERS[name]
        if start not in text or end not in text:
            report.error(index, f"missing the {start} / {end} markers")
            continue
        head, rest = text.split(start, 1)
        current, tail = rest.split(end, 1)
        if current != "\n" + wanted + "\n":
            if sync:
                text = head + start + "\n" + wanted + "\n" + end + tail
            else:
                report.warn(index, f"the {name} list is out of date; run `python3 tools/lint.py --sync`")
    if text != original:
        index.write_text(text, encoding="utf-8")
        pages[index] = split_frontmatter(text)
        links[index] = prose_links(index, pages[index][1])
    listed = {target for _, target in links.get(index, [])}
    for path in sorted(listed_pages - listed):
        report.error(path, "not listed in index.md")


def sync_manifest(report: Report, pages: Pages, sync: bool) -> None:
    """manifest.json: every typed page with its frontmatter, for agents that route in code."""
    entries = [{"path": rel(path), **fields} for path, (fields, _) in sorted(pages.items()) if fields.get("type")]
    wanted = json.dumps({"generated_by": "python3 tools/lint.py --sync", "pages": entries}, indent=1, ensure_ascii=False) + "\n"
    manifest = ROOT / "manifest.json"
    current = manifest.read_text(encoding="utf-8") if manifest.exists() else ""
    if current == wanted:
        return
    if sync:
        manifest.write_text(wanted, encoding="utf-8")
    else:
        report.warn(manifest, "out of date; run `python3 tools/lint.py --sync`")


def run_checks(args: argparse.Namespace, today: dt.date) -> tuple[Report, str]:
    report = Report()
    pages: Pages = {}
    links: dict[Path, list[tuple[str, Path]]] = {}
    for path in markdown_files():
        pages[path] = split_frontmatter(path.read_text(encoding="utf-8"))
        links[path] = prose_links(path, pages[path][1])
        for _, target in links[path]:
            if not target.exists():
                report.error(path, f"broken link to {os.path.relpath(target, ROOT)}")

    by_folder = {name: {p for p in pages if p.parent == ROOT / name} for name in FOLDERS}
    sources, concepts, playbooks = by_folder["sources"], by_folder["concepts"], by_folder["playbooks"]
    advisories = {p for p in by_folder["advisories"] if pages[p][0].get("type") == "advisory"}
    snapshots = by_folder["advisories"] - advisories
    cited_pages = sorted(concepts | playbooks | advisories | ({ROOT / "overview.md", ROOT / "feeds.md"} & set(pages)))

    check_frontmatter(report, pages, by_folder)
    check_citations(report, pages, links, sources, concepts, playbooks, advisories)
    check_labels(report, pages, links, sources, cited_pages)
    check_numbers(report, pages, sources, cited_pages)
    check_usage(report, links, sources, cited_pages)
    check_glossary(report, pages)
    check_freshness(report, pages, concepts | playbooks, snapshots, today, args.stale_days, args.snapshot_days)
    blocks = {"sources": sources_block(sources, pages), "advisories": advisories_block(advisories, pages)}
    sync_index(report, pages, links, blocks, set().union(*by_folder.values()), args.sync)
    sync_manifest(report, pages, args.sync)

    summary = (
        f"{len(sources)} sources, {len(concepts)} concepts, {len(playbooks)} playbooks, {len(advisories)} advisories, "
        f"{len(snapshots)} feed snapshots: {len(report.errors)} errors, {len(report.warnings)} warnings"
    )
    return report, summary


# ---------------------------------------------------------------- bookkeeping


def changed_files() -> list[str]:
    """Files changed since the last commit, or nothing if this is not a git checkout."""
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    paths = [line[3:].split(" -> ")[-1].strip().strip('"') for line in out.splitlines()]
    ours = set(FOLDERS) | {"tools"}
    return sorted(p for p in paths if p and p != "log.md" and ("/" not in p or p.split("/", 1)[0] in ours))


def append_log(operation: str, title: str, today: dt.date) -> None:
    groups: dict[str, list[str]] = {}
    for path in changed_files():
        groups.setdefault(path.split("/", 1)[0] if "/" in path else "", []).append(path)
    lines = []
    for head in sorted(groups):
        if head and len(groups[head]) > 8:
            lines.append(f"- {head}/ ({len(groups[head])} files)")
        else:
            lines.extend(f"- {path}" for path in groups[head])
    log = ROOT / "log.md"
    existing = log.read_text(encoding="utf-8") if log.exists() else "# Log\n"
    entry = f"\n## [{today.isoformat()}] {operation} | {title}\n"
    if lines:
        entry += "\n" + "\n".join(lines) + "\n"
    log.write_text(existing.rstrip("\n") + "\n" + entry, encoding="utf-8")
    print(f"logged: [{today.isoformat()}] {operation} | {title}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Lint the security knowledge base.")
    parser.add_argument("--sync", action="store_true", help="rewrite the generated lists in index.md and manifest.json")
    parser.add_argument("--log", metavar='"OPERATION | TITLE"', help="append an entry to log.md if there are no errors")
    parser.add_argument("--stale-days", type=int, default=120, help="flag concepts and playbooks not reviewed for this long (default 120)")
    parser.add_argument("--snapshot-days", type=int, default=7, help="flag feed snapshots older than this (default 7)")
    args = parser.parse_args()

    entry = None
    if args.log is not None:
        entry = re.match(r"^\s*([a-z]+)\s*\|\s*(\S.*?)\s*$", args.log)
        if not entry or entry.group(1) not in OPERATIONS:
            parser.error(f'--log takes "OPERATION | TITLE" with one of: {", ".join(sorted(OPERATIONS))}')

    today = dt.date.today()
    report, summary = run_checks(args, today)
    for line in report.errors + report.warnings:
        print(line)
    print(summary)
    if entry and report.errors:
        print("log entry not written: fix the errors and run again")
    elif entry:
        append_log(entry.group(1), entry.group(2), today)
    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())
