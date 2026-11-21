---
type: source
title: "Automate security reviews with Claude Code"
publisher: "Anthropic"
url: https://www.anthropic.com/news/automate-security-reviews-with-claude-code
published: undated
ingested: 2026-11-21
kind: article
read: via-snippet
---

# Automate security reviews with Claude Code

**In one line:** A model can review your own code for security bugs before commit, and its CI version must be kept away from untrusted pull requests.

## What it says

- `/security-review` in Claude Code checks a repository before you commit. It is included in the Pro and Max plans, according to [Claude Help](https://support.claude.com/en/articles/11932705-automated-security-reviews-in-claude-code).
- Anthropic says the pull-request action caught a remote code execution bug and an SSRF in its own code before merge.
- The [GitHub Action's repository](https://github.com/anthropics/claude-code-security-review) says it is "not hardened against prompt injection" and is for trusted PRs only.

## Caveats

- Not read for this knowledge base. These points come from the [research report of 21 November 2026](research-report-2026-11.md), which took them from search results without reading the page in full. Treat them as leads until someone reads the original.
- A vendor describing its own product.
