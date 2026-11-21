---
type: source
title: "Claude Code documentation: sandboxing"
publisher: "Anthropic"
url: https://docs.claude.com/en/docs/claude-code/sandboxing
published: undated
ingested: 2026-11-21
kind: docs
read: via-snippet
---

# Claude Code documentation: sandboxing

**In one line:** A sandbox for a coding agent needs two walls, one around the filesystem and one around the network.

## What it says

- Claude Code's sandbox isolates both the filesystem and the network. Without the network wall, a hijacked agent can still send your SSH keys out.

## Caveats

- Not read for this knowledge base. These points come from the [research report of 21 November 2026](research-report-2026-11.md), which took them from search results without reading the page in full. Treat them as leads until someone reads the original.
- Product documentation, which changes without notice.
