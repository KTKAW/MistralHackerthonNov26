---
type: advisory
title: "Zenity hijacks five AI browsers"
date: 2026-08
kind: research
exploited: demonstrated
fix_status: unknown
affects: [ai-browsers, claude-in-chrome, gemini-in-chrome, comet, chatgpt-atlas, copilot-edge]
ids: []
playbook: agent-hijack
updated: 2026-11-21
---

# Zenity hijacks five AI browsers

**In one line:** Ordinary content was enough to turn five AI browser agents against their users.

## What happened

- In August 2026 Zenity showed that Claude in Chrome, Gemini in Chrome, Comet, ChatGPT Atlas and Copilot Edge can be turned against their users by ordinary content. [Zenity AI browser hijacks, 2026](../sources/notebookcheck-zenity-ai-browsers.md)
- No prompt-injection filter has held up: every AI browser that researchers tested at Black Hat 2026 proved vulnerable. [Research report, Nov 2026](../sources/research-report-2026-11.md)

## What to do

- Do not let a browser agent act inside your main mailbox, GitHub or cloud console. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Keep any one session to at most two of: untrusted input, private data, outbound action. [Rule of Two, Nov 2025](../sources/willison-rule-of-two.md)

## If it touched you

Follow [An agent did something it was not asked to do](../playbooks/agent-hijack.md).

## Not recorded here

- Whether a vendor fix has shipped. The sources say what happened; `fix_status` stays `unknown` until someone reads the originals.
- Identifiers such as CVE or GHSA numbers.
