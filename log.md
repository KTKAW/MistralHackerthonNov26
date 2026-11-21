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
