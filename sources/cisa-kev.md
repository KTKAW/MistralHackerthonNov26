---
type: source
title: "CISA Known Exploited Vulnerabilities Catalog"
publisher: "US Cybersecurity and Infrastructure Security Agency"
url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
published: undated
ingested: 2026-11-21
kind: feed
read: partial
---

# CISA Known Exploited Vulnerabilities Catalog

**In one line:** The list of vulnerabilities that CISA has evidence are being exploited, each with a date by which US federal agencies must act.

## What it says

- Each entry names a CVE, the vendor and product, a short description, the required action, the date it was added and a due date. It also says whether the flaw is known to be used in ransomware campaigns.
- On 21 November 2026 the catalog was at version 2026.11.20 and held 1790 entries.
- Newer entries also say whether CISA asks for forensic triage of the affected systems.
- The entries added most recently are copied into [the snapshot page](../advisories/kev-recent.md) by `tools/kev.py`.

## Caveats

- A living feed, so it has no publication date. Only its machine-readable feed was read, and only the fields above.
- Due dates bind US federal agencies. For everyone else they measure urgency.
