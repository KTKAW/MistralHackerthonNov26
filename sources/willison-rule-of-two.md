---
type: source
title: "Simon Willison on Meta's Agents Rule of Two"
publisher: "Simon Willison's Weblog"
url: https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/
published: 2025-11-02
ingested: 2026-11-21
kind: article
read: via-snippet
---

# Simon Willison on Meta's Agents Rule of Two

**In one line:** Until prompt injection can be detected reliably, an agent session should combine at most two of three risky properties.

## What it says

- The Agents Rule of Two, from a Meta paper of October 2025: a session should have at most two of (1) untrusted input, (2) access to private data or sensitive systems, and (3) the ability to change state or communicate externally.
- A session that needs all three gets a human approval step.
- It builds on Willison's lethal trifecta.

## Caveats

- Not read for this knowledge base. These points come from the [research report of 21 November 2026](research-report-2026-11.md), which took them from search results without reading the page in full. Treat them as leads until someone reads the original.
- Publication date taken from the page address.
