# Security knowledge base

A wiki on cybersecurity and patches for people and small teams, written to be read by an incident-response agent. Every claim links to a dated source note that says how the source was read. It lives on the `knowledge` branch, apart from the code.

## What it is for

1. **Responding.** Go from "this just happened" to the right runbook in one read.
2. **Patching.** Know where live patch data comes from, how to ask for it, and what to patch first.
3. **A shared vocabulary.** When a person and an agent say "Rule of Two", "read level" or "baseline step", they mean the same thing.

## Where to start

| If you want | Open |
|---|---|
| The runbook for what just happened | "By signal" in [index.md](index.md) |
| The system this serves, with diagrams | [system.md](system.md) |
| The big picture in five minutes | [overview.md](overview.md) |
| Live patch data and how to query it | [feeds.md](feeds.md) |
| What a term means here | [glossary.md](glossary.md) |
| The rules for agents | [AGENTS.md](AGENTS.md) |

## How an agent uses it

**With file access.** Clone the branch and read `AGENTS.md`, then `index.md`.

```bash
git clone --branch knowledge --single-branch https://github.com/KTKAW/MistralHackerthonNov26 knowledge
```

**Over HTTP.** Every page is plain markdown at a stable address. Start from the index, or from the manifest if the agent routes in code:

```
https://raw.githubusercontent.com/KTKAW/MistralHackerthonNov26/knowledge/index.md
https://raw.githubusercontent.com/KTKAW/MistralHackerthonNov26/knowledge/manifest.json
```

`manifest.json` lists every page with its type and frontmatter. A playbook carries `signals`, the ways its incident shows up. An advisory carries `affects`, tags to match against an inventory, and `playbook`, the runbook to follow. Two tools are enough for an agent: one that reads the manifest and one that reads a page by path.

**During an incident** the agent follows the section "Responding to an incident" in `AGENTS.md`. In short: evidence is untrusted input, the agent proposes and a person acts, and it never handles the value of a secret.

## How it is organised

```
AGENTS.md      rules for agents that read or write here (CLAUDE.md imports it)
index.md       routing by signal and by decision, then every page in one line
manifest.json  every page with its frontmatter, generated
system.md      the tool this serves: pipeline, diagrams, verdict file
overview.md    the threat picture, what works, thin evidence, gaps
glossary.md    the shared vocabulary
playbooks/     one runbook per kind of incident
concepts/      one page per idea or control, every claim linked to a source note
advisories/    incidents, campaigns, research findings, vulnerabilities; feed snapshots
feeds.md       live patch and advisory feeds, with tested queries
sources/       one note per source: our summary, the link, the read level
raw/           local full-text captures (gitignored)
log.md         what was added and changed, and when
watchlist.md   publishers to re-check and open leads
diagrams/      images drawn from the Mermaid blocks in the pages, generated
tools/         lint.py, kev.py, scan.py and diagrams.py, standard library only
tools/scan/    the kb-scan engine (Rust, static musl binary), config and inventory examples, ORCHESTRATION.md
```

This is the LLM wiki pattern: sources, a wiki that agents own, and a schema file that tells them how to maintain it.

## What is in it

Seeded on 21 November 2026 from one research report on cybersecurity for people and small teams. The team's system design was ingested the same day, with the European Commission's page on CRA reporting and the advisory for the flaw the tool was tested on. In all: 43 source notes, 11 concept pages, 8 playbooks and 12 advisory records, plus a generated snapshot of the vulnerabilities CISA added to its exploited list in the previous 14 days.

## What to keep in mind

- **Most of it is second-hand.** Six sources were read directly: the research report, the team's two design documents, the Commission's page on CRA reporting, one advisory record and the CISA feed. Every other source note is marked `via-report` or `via-snippet`, and none of those originals has been re-read. Check a figure against its original before you rely on it.
- **Some runbook steps have no source yet.** They are standard practice and are tagged *(baseline)*.
- **A model wrote this**, from a report that a model helped to write.
- **UK only** where it names phone numbers and reporting services.
- **It dates quickly.** Patch data goes stale in a day, which is why the agent is told to ask the feeds.
- **Summaries, not copies.** The sources are other people's work. Each note is a short summary in our own words with a link.

## Checks

```bash
python3 tools/lint.py
```

It fails on broken links, missing frontmatter, a "What to do" bullet with no source, a playbook step with neither a source nor the *(baseline)* tag, and a citation whose date differs from its note. It warns when a figure on a cited line is not in the note it cites, and when a feed snapshot is more than 7 days old. Add `--sync` to regenerate the lists in `index.md` and `manifest.json`, and `--log "ingest | Title"` to append the `log.md` entry.

```bash
python3 tools/kev.py
```

Refreshes the snapshot of exploited vulnerabilities from CISA's feed.

```bash
python3 tools/scan.py scan --inventory tools/scan/inventory.example.json
```

Runs one pass of the kb-scan engine (built on demand with cargo) against the live feeds and prints a `kb-scan-report/1`. `python3 tools/scan.py loop` runs it continuously, `python3 tools/scan.py sync` polls the git remote for new branches and commits, `python3 tools/scan.py report --json <report>` renders the newest report into [advisories/scan-latest.md](advisories/scan-latest.md), and `python3 tools/scan.py selftest` checks the wrapper. Network-touching subcommands run inside `bwrap` when it is installed and fail closed (exit 2) without it. `python3 tools/scan.py brief --json <report>` prints a short spoken-style summary of the top findings (`--speak` reads it aloud via Mistral speech). `python3 tools/scan.py audio-loop --json <report> [--once]` speaks an alert whenever a new verified finding appears. `python3 tools/scan.py query latest` (or `health`/`sync`/`findings`/`brief`) prints what a running `kb-scan serve` answers on loopback.
