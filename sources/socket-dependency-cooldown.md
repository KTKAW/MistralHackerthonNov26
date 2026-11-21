---
type: source
title: "Socket glossary: dependency cooldown"
publisher: "Socket"
url: https://socket.dev/glossary/dependency-cooldown
published: undated
ingested: 2026-11-21
kind: docs
read: via-snippet
---

# Socket glossary: dependency cooldown

**In one line:** Waiting a day before installing a new release avoids most malicious packages, because they are usually removed within hours.

## What it says

- pnpm 11 defaults to a 24-hour minimum release age. npm needs `min-release-age` set by hand.
- Add `ignore-scripts`, or pnpm's build allow-list, so that install scripts do not run.
- Most malicious releases are pulled within hours, so a waiting period breaks the chain a worm depends on.
- Socket's caveat: a cooldown is a clock, not a detector.

## Caveats

- Not read for this knowledge base. These points come from the [research report of 21 November 2026](research-report-2026-11.md), which took them from search results without reading the page in full. Treat them as leads until someone reads the original.
- Setting names and defaults change between package-manager versions. Check the package manager's own documentation.
