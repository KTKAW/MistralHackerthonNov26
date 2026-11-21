---
type: advisory
title: "ClickFix lures dressed as AI-tool install guides"
date: 2026-09
kind: campaign
exploited: in-the-wild
fix_status: unknown
affects: [terminal, claude-code, notebooklm, search-ads, shared-ai-chats]
ids: []
playbook: pasted-command
updated: 2026-11-21
---

# ClickFix lures dressed as AI-tool install guides

**In one line:** Fake install guides for AI tools, reached through ads and shared chats, tell people to paste a malicious command.

## What happened

- ClickFix is a fake error or CAPTCHA that tells the visitor to paste a command into a terminal. It averaged 52% of Push Security's detections through Q2 2026 and reached 67% in August. [State of ClickFix, Sep 2026](../sources/push-security-state-of-clickfix.md)
- Four in five were reached from search results. [State of ClickFix, Sep 2026](../sources/push-security-state-of-clickfix.md)
- Push saw fake install guides for Claude Code and NotebookLM promoted by ads, and malicious install steps hosted in shared Claude.ai and ChatGPT conversations. [State of ClickFix, Sep 2026](../sources/push-security-state-of-clickfix.md)

## What to do

- Never paste a command from a web page, ad or shared chat into a terminal or Run box. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Install AI tools only from the vendor's own documentation. [Research report, Nov 2026](../sources/research-report-2026-11.md)

## If it touched you

Follow [Someone pasted a command from a web page](../playbooks/pasted-command.md).

## Not recorded here

- Whether a vendor fix has shipped. The sources say what happened; `fix_status` stays `unknown` until someone reads the originals.
- Identifiers such as CVE or GHSA numbers.
