---
type: concept
title: "Agent containment"
updated: 2026-11-21
reviewed: 2026-11-21
status: evolving
---

# Agent containment

**Definition:** Limits on what an agent can reach, whatever it decides to do. A *sandbox* is two walls, one around the filesystem and one around the network. A *scoped token* is a credential that can do one job. A *grant log* records which agent used which permission, on what, and when.

## Why it matters

The [Rule of Two](prompt-injection-and-rule-of-two.md) says what a session may combine. Containment is what makes that true in practice, and what caps the damage when an injection gets through. The tools agents load are part of the problem: in April 2026 a design flaw in MCP's STDIO transport was estimated to expose about 200,000 instances. [CSA MCP note, May 2026](../sources/csa-mcp-security-note.md)

## What to do

- Sandbox coding agents with both walls. Without the network wall, a hijacked agent can still send your SSH keys out. [Claude Code sandboxing docs, undated](../sources/claude-code-sandboxing-docs.md)
- Open the network wall only to an allow-list, such as package registries and GitHub. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Give each agent, skill and MCP server its own scoped token. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Grant from your own policy. An agent's description of what it needs is input written by the agent, so read it as untrusted. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Treat a local MCP server as a path to command execution, and install MCP servers from the original author only. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Serve any interface that an agent supplies from a separate origin, under a strict content policy, with no tokens in reach. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Log every use of a grant: which agent, which grant, on what, when. It is cheap now and the only way to reconstruct an incident later. [Research report, Nov 2026](../sources/research-report-2026-11.md)

## When it happens

Follow [An agent did something it was not asked to do](../playbooks/agent-hijack.md). Recorded cases: [MCP STDIO design flaw](../advisories/2026-04-mcp-stdio-flaw.md), [Cloned Oura Ring MCP server](../advisories/2026-02-cloned-oura-mcp-server.md), [Comment and Control](../advisories/2026-04-comment-and-control.md).

## Evidence

- A cloned Oura Ring MCP server was used to deliver malware. [UpGuard MCP incidents, undated](../sources/upguard-mcp-incidents.md)
- The Claude Code security review action says of itself that it is "not hardened against prompt injection" and is for trusted PRs only. [Claude Code security review, undated](../sources/anthropic-security-review.md)

## Open problems

The sources here describe containment for coding agents and browser agents. There is nothing yet on containing an agent that must act during an incident, where speed argues for more access. This knowledge base's position is in [AGENTS.md](../AGENTS.md): the agent proposes and a person acts.

## Related

[Prompt injection and the Rule of Two](prompt-injection-and-rule-of-two.md) · [Secrets and AI keys](secrets-and-ai-keys.md) · [Supply chain and dependency cooldown](supply-chain-and-dependency-cooldown.md)
