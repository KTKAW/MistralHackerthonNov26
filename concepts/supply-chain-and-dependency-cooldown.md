---
type: concept
title: "Supply chain and dependency cooldown"
updated: 2026-11-21
reviewed: 2026-11-21
status: evolving
---

# Supply chain and dependency cooldown

**Definition:** A *supply-chain attack* reaches you through something you install: a package, an agent skill, an MCP server. A *dependency cooldown* is a rule that a release must have been public for a set time before you install it. An *install script* is code a package runs on your machine at install time.

## Why it matters

48% of breaches involve a third party, up 60%. [Verizon DBIR, May 2026](../sources/verizon-dbir-2026.md) Developer machines are a prime target. [Research report, Nov 2026](../sources/research-report-2026-11.md) In August 2026 a worm pushed more than 2,200 malicious versions of 440 npm packages in under four hours, stole npm, GitHub and cloud tokens, and planted Claude and VS Code config files for persistence. [npm worm, 2026](../sources/securityweek-npm-worm-2026-08.md)

The same thing happens one layer up, in what agents install. Koi documented 341 malicious skills on OpenClaw's ClawHub marketplace, and five slipped past VirusTotal screening. [Unit 42 on OpenClaw, 2026](../sources/unit42-openclaw-supply-chain.md) A cloned Oura Ring MCP server was used to deliver malware. [UpGuard MCP incidents, undated](../sources/upguard-mcp-incidents.md)

## What to do

- Set a cooldown of 24 hours or longer. pnpm 11 defaults to a 24-hour minimum release age; npm needs `min-release-age` set by hand. [Socket on cooldowns, undated](../sources/socket-dependency-cooldown.md)
- Switch install scripts off, with `ignore-scripts` or pnpm's build allow-list. [Socket on cooldowns, undated](../sources/socket-dependency-cooldown.md)
- Do not mistake the cooldown for detection. It is a clock, not a detector: it works because most malicious releases are pulled within hours. [Socket on cooldowns, undated](../sources/socket-dependency-cooldown.md)
- Handle skills and MCP servers as dependencies: pin versions, read the tool descriptions, prefer first-party ones, and install MCP servers from the original author only. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Keep long-lived secrets off developer machines: one scoped key per agent, and no shared `.env` file. [Research report, Nov 2026](../sources/research-report-2026-11.md)

## When it happens

Follow [A malicious package was installed](../playbooks/malicious-dependency.md). For a skill or MCP server, follow [An agent did something it was not asked to do](../playbooks/agent-hijack.md). Recorded cases: [August 2026 npm worm](../advisories/2026-08-npm-worm.md), [Malicious skills on ClawHub](../advisories/2026-02-clawhub-malicious-skills.md), [Cloned Oura Ring MCP server](../advisories/2026-02-cloned-oura-mcp-server.md), [Clinejection](../advisories/2026-02-clinejection.md).

## Evidence

- One malicious GitHub issue title chained four flaws into a supply-chain compromise of the Cline coding agent. [CSA Clinejection note, 2026](../sources/csa-clinejection-note.md)
- OWASP lists agentic supply chain as ASI04 in its top 10 for agentic applications. [OWASP agentic top 10, undated](../sources/owasp-agentic-top-10-2026.md)

## Open problems

This knowledge base's reading: a cooldown does nothing against a bad release that stays up longer than the waiting period, or against a package that was malicious from its first version. Checking installed versions against the malware advisories in [Feeds](../feeds.md) covers part of that gap.

## Related

[Secrets and AI keys](secrets-and-ai-keys.md) · [Agent containment](agent-containment.md) · [Patching and exploit speed](patching-and-exploit-speed.md)
