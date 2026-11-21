# Prior art: polling loops for vulnerability/feed monitoring (searched 2026-11-21 via connector_web_search)

Read as leads, not facts (via-snippet level): titles/snippets from Brave search results.

## KEV/feed watchers (closest analogues to kb-scan's scan loop)
- joshuaburnie/kev-monitor — Cloudflare Worker + cron, polls KEV, keeps a "seen set" in KV (~1,250 entries, ~14 bytes/CVE), 6 h poll interval keeps detection lag < half a day; watchlist vendor match + NVD per-CVE for CVSS (KEV has no scores); alerts to Telegram/Slack. https://github.com/joshuaburnie/kev-monitor
- n0ts0cial/intel-cisa-feed — GitHub Actions workflow on a schedule, enriches KEV with NVD, writes daily reports. https://github.com/n0ts0cial/intel-cisa-feed
- hahwul/kev.cr, Zasnit1/kev-watcher — KEV watchers with vendor watchlists. https://github.com/hahwul/kev.cr , https://github.com/Zasnit1/kev-watcher
- sazabi/cve.now and openctemio/vulnfeed — merged, normalised feeds (CVE + GHSA + OSV + KEV + EPSS) for agents; supports merging feeds into one report. https://cve.now/ , https://github.com/openctemio/vulnfeed
- Fazmin/cve-intel — local CVE triage tool combining 4 sources into risk scores. https://github.com/Fazmin/cve-intel
- Apify "CVE Monitor: NVD, CISA KEV and EPSS" — hosted poller. https://apify.com/nightwave-owner/vulnerability-monitor-nvd-kev-epss

## Scanners run in loops
- google/osv-scanner (Go) + GitHub Action — lockfile scanning in CI; our engine is the continuous, host-side analogue using OSV querybatch. https://google.github.io/osv-scanner/
- Dependabot — PR-based remediation triggered by advisory feeds.

## EPSS
- FIRST EPSS recomputes daily; tools list at https://www.first.org/epss/epss_tools ; rune_epss is a Rust client crate (we hand-roll instead: zero-dep rule). https://docs.rs/rune-epss/

## Git drift polling (kb-scan's sync loop)
- Efficient remote-branch change detection: `git fetch` then compare remote-tracking refs (`git rev-list --left-right --count`, `git ls-remote`) — Super User answer. https://superuser.com/questions/1530233/
- explainx.ai "Branch Sync Loop" — agent-loop pattern for keeping branches in sync. https://explainx.ai/loops/branch-sync-loop

## Design lessons adopted into kb-scan (tools/scan/ORCHESTRATION.md)
1. Poll interval vs detection lag: configurable interval (default 3600 s); KEV cadence makes 6 h acceptable for digests, but exploited-in-the-wild matching wants < 1 h.
2. Seen-set / dedup: timestamped reports + latest.json act as the seen set; new-only attention is derived by diffing consecutive reports.
3. Watchlist matching: inventory products/packages play the role of kev-monitor's vendor watchlist.
4. Enrichment from a second source: KEV lacks CVSS; we enrich matched CVEs with EPSS (and optionally NVD).
5. Two run modes: in-process loop (our `watch`) or platform cron (GitHub Actions / harness `/loop` cron) — both supported; engine writes JSON either way.
6. Alerting = reports + `attention[]` in the sync report; a human acts (AGENTS.md rule).
