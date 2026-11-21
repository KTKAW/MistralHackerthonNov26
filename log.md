# Log

Append-only, newest at the bottom. Every entry starts with `## [YYYY-MM-DD] operation | title`, so `grep "^## \[" log.md | tail` shows recent activity. Operations: `init`, `ingest`, `lint`, `refresh`, `edit`.

Entries are written by `python3 tools/lint.py --sync --log "operation | title"`, which lists the files changed since the last commit. Add a line of explanation under an entry by hand when the title is not enough.

## [2026-11-21] init | Knowledge base created and seeded

- .gitignore
- AGENTS.md
- CLAUDE.md
- README.md
- feeds.md
- glossary.md
- index.md
- manifest.json
- overview.md
- watchlist.md
- advisories/ (12 files)
- concepts/ (9 files)
- playbooks/account-phish.md
- playbooks/agent-hijack.md
- playbooks/exploited-vulnerability.md
- playbooks/leaked-secret.md
- playbooks/malicious-dependency.md
- playbooks/pasted-command.md
- playbooks/payment-or-voice-scam.md
- sources/ (39 files)
- tools/kev.py
- tools/lint.py

Structure, schema (`AGENTS.md`), `tools/lint.py` and `tools/kev.py`.

- Seeded from one research report dated 2026-11-21, read in full: 39 source notes, 9 concept pages, 7 playbooks, 11 advisory records, the glossary and the overview.
- Read levels: 2 notes read directly (the report, and CISA's feed in part), 9 `via-report`, 28 `via-snippet`. No original behind the report was re-read.
- `advisories/kev-recent.md` generated from CISA KEV catalog version 2026.11.20: 21 entries added in the previous 14 days.
- Every address and query in `feeds.md` was tried on this date and answered as described.
- `tools/lint.py --sync` passes with no errors and no warnings. A planted wrong date and wrong figure were both caught before being removed.

## [2026-11-21] ingest | System design from the docs/system-design branch

- AGENTS.md
- README.md
- feeds.md
- glossary.md
- index.md
- manifest.json
- overview.md
- system.md
- watchlist.md
- advisories/2026-10-authlib-cve-2026-96760.md
- concepts/cra-reporting-clock.md
- concepts/patching-and-exploit-speed.md
- concepts/reachability-and-proof.md
- playbooks/advisory-fleet-triage.md
- playbooks/exploited-vulnerability.md
- sources/european-commission-cra-reporting.md
- sources/osv-authlib-ghsa-6v38-4h7w-rj9h.md
- sources/team-project-brief.md
- sources/team-system-design.md
- tools/lint.py

The team's project brief and architecture page, read in full at commit `c0211d4` of `docs/system-design`.

- New: `system.md` with two diagrams (the system with the knowledge base attached; one worker's run), the concept pages on reachability and proof and on the CRA reporting clock (with a third diagram), the playbook for fleet triage, and an advisory record for CVE-2026-96760.
- Four source notes, all read directly: the brief, the design, the European Commission's page on CRA reporting (read by a reader agent, one pass), and the advisory's record in OSV.
- The diagrams were rendered locally with Mermaid 10.6.1 and looked at before this entry was written.
- Found while checking the test flaw against the feeds: OSV lists 8 advisories for Authlib 1.8.0, and 2 of them are fixed only in 1.9.1; the flaw is not in CISA's catalog at version 2026.11.20. Both are recorded on `system.md` and in the advisory.
- The links from the knowledge base into the system are a proposal by this knowledge base. They are not in the team's design.

## [2026-11-21] edit | Diagram images beside the Mermaid sources

- AGENTS.md
- README.md
- system.md
- concepts/cra-reporting-clock.md
- diagrams/cra-reporting-clock-1.png
- diagrams/system-1.png
- diagrams/system-2.png
- tools/diagrams.py
- tools/lint.py

GitHub draws the Mermaid blocks, but its built-in view of the large system diagram is cramped. Each diagram is now also an image in `diagrams/`, drawn by `tools/diagrams.py`, with the Mermaid source kept in the page under it. The lint fails when an embedded image is missing.

## [2026-11-21] edit | Rust scan-engine swarm (tools/scan) with tools/scan.py wrapper, containerisation, vendored skills

- .gitignore
- AGENTS.md
- README.md
- feeds.md
- index.md
- manifest.json
- advisories/scan-latest.md
- tools/ (29 files)

## [2026-11-21] edit | Explorer/verifier orchestration in kb-scan swarm (agent.rs, explore.rs, verify.rs, triage.json handoff)

- tools/ (15 files)
