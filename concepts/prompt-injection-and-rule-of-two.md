---
type: concept
title: "Prompt injection and the Rule of Two"
updated: 2026-11-21
reviewed: 2026-11-21
status: evolving
---

# Prompt injection and the Rule of Two

**Definition:** *Prompt injection* is text that an agent reads as data and then follows as instructions. The *Agents Rule of Two* limits the damage: a session should have at most two of three *legs*, which are (1) untrusted input, (2) access to private data or sensitive systems, and (3) the ability to change state or communicate externally. [Rule of Two, Nov 2025](../sources/willison-rule-of-two.md) It builds on the *lethal trifecta*. [Rule of Two, Nov 2025](../sources/willison-rule-of-two.md)

## Why it matters

Prompt injection is still unsolved, so the defence that holds is architectural: limit what any single agent session can combine. [Research report, Nov 2026](../sources/research-report-2026-11.md) No filter has held up. Every AI browser that researchers tested at Black Hat 2026 proved vulnerable. [Research report, Nov 2026](../sources/research-report-2026-11.md)

The record from 2026:

- Five AI browsers were turned against their users by ordinary content. [Zenity AI browser hijacks, 2026](../sources/notebookcheck-zenity-ai-browsers.md)
- Six AI browsers leaked sensitive data in tests. [BioShocking, 2026](../sources/techrepublic-bioshocking.md)
- Text in GitHub repositories redirected three CI agents into leaking credentials. [OWASP Q2 round-up, Jul 2026](../sources/owasp-genai-exploit-roundup-2026-q2.md)
- One malicious issue title led to a supply-chain compromise of a coding agent. [CSA Clinejection note, 2026](../sources/csa-clinejection-note.md)

## What to do

- Give a session at most two of the three legs. A session that needs all three gets a human approval step. [Rule of Two, Nov 2025](../sources/willison-rule-of-two.md)
- Count legs per session, not per agent. Tag every grant as untrusted input, private data or secrets, or outbound action, and refuse a session that would hold all three without explicit approval. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Treat as untrusted input: issue titles, repository text, web pages, email, shared chats, and an agent's own description of what it needs. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Do not let a browser agent act inside your main mailbox, GitHub or cloud console. Whatever the agent is logged into is in scope. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Give CI agents that read public issues no secrets in reach, and run AI review in CI only on trusted pull requests. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Keep a person's review on every write to the memory or record that steers later sessions. An injected agent can rewrite it. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Adopt slowly: start with low-risk tasks, and prioritise resilience over productivity. [Five Eyes agentic AI guidance, Apr 2026](../sources/five-eyes-agentic-ai-guidance.md)

## For an incident-response agent

This knowledge base's reading: an agent that investigates an incident holds the first leg by definition. The phishing email, the malicious page and the hijacked transcript are all untrusted input, and one of them has already worked once. So while it reads evidence it should hold no secrets and take no outbound action without a person's approval. The rules are in [AGENTS.md](../AGENTS.md), under "Responding to an incident".

## When it happens

Follow [An agent did something it was not asked to do](../playbooks/agent-hijack.md).

## Open problems

- No mainstream agent harness has adopted the published injection-resistant design patterns. [Sophos on the lethal trifecta, undated](../sources/sophos-lethal-trifecta.md)
- Methods for evaluating the security of agentic systems are still evolving. [Five Eyes agentic AI guidance, Apr 2026](../sources/five-eyes-agentic-ai-guidance.md)

## Related

[Agent containment](agent-containment.md) · [Secrets and AI keys](secrets-and-ai-keys.md) · [Supply chain and dependency cooldown](supply-chain-and-dependency-cooldown.md)
