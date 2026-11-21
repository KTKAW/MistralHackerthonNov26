---
type: concept
title: "ClickFix and pasted commands"
updated: 2026-11-21
reviewed: 2026-11-21
status: evolving
---

# ClickFix and pasted commands

**Definition:** *ClickFix* is a lure in which a fake error message or fake CAPTCHA tells the visitor to paste a command into a terminal or the Windows Run box. The victim runs the attacker's code themselves, so nothing has to be exploited. [State of ClickFix, Sep 2026](../sources/push-security-state-of-clickfix.md)

## Why it matters

It is the fastest-growing trick in the 2026 record. It averaged 52% of Push Security's detections through Q2 2026 and reached 67% in August. [State of ClickFix, Sep 2026](../sources/push-security-state-of-clickfix.md) It fits the wider pattern: money and access are still lost mostly to persuasion, where the victim pays, pastes or logs in themselves. [Research report, Nov 2026](../sources/research-report-2026-11.md)

AI tools are now the bait. Push saw fake install guides for Claude Code and NotebookLM promoted by ads, and malicious install steps hosted in shared Claude.ai and ChatGPT conversations. [State of ClickFix, Sep 2026](../sources/push-security-state-of-clickfix.md)

## What to do

- Never paste a command from a web page, ad or shared chat into a terminal or Run box. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Install AI tools only from the vendor's own documentation. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Do not trust a page because a search engine led you to it. Four in five ClickFix pages were reached from search results. [State of ClickFix, Sep 2026](../sources/push-security-state-of-clickfix.md)
- Read a shared AI conversation as a web page written by a stranger. Malicious install steps have been hosted in shared Claude.ai and ChatGPT chats. [State of ClickFix, Sep 2026](../sources/push-security-state-of-clickfix.md)

## When it happens

A pasted command is an incident, not a slip to tidy up. Follow [Someone pasted a command from a web page](../playbooks/pasted-command.md). The recorded campaign is [ClickFix lures dressed as AI-tool install guides](../advisories/2026-09-clickfix-ai-tool-lures.md).

## Evidence

- 52% of detections on average through Q2 2026, 67% in August, four in five reached from search. [State of ClickFix, Sep 2026](../sources/push-security-state-of-clickfix.md)
- These are one vendor's detections, so they describe what that vendor's customers met.

## Open problems

This knowledge base has no source yet on what ClickFix commands do once they run. The playbook's assumption that saved passwords, sessions and keys are taken is baseline practice, marked as such there.

## Related

[Social engineering and verification](social-engineering-and-verification.md) · [Secrets and AI keys](secrets-and-ai-keys.md) · [Supply chain and dependency cooldown](supply-chain-and-dependency-cooldown.md)
