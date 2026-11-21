---
type: advisory
title: "Malicious skills on OpenClaw's ClawHub marketplace"
date: 2026-02
kind: incident
exploited: in-the-wild
fix_status: unknown
affects: [agent-skills, openclaw, clawhub, macos]
ids: []
playbook: agent-hijack
updated: 2026-11-21
---

# Malicious skills on OpenClaw's ClawHub marketplace

**In one line:** Hundreds of malicious agent skills were published to a public marketplace, and some passed its malware screening.

## What happened

- Between February and September 2026, Koi documented 341 malicious skills on ClawHub, the skill marketplace of OpenClaw. [Unit 42 on OpenClaw, 2026](../sources/unit42-openclaw-supply-chain.md)
- Unit 42 found five that slipped past VirusTotal screening. Some dropped macOS infostealers. [Unit 42 on OpenClaw, 2026](../sources/unit42-openclaw-supply-chain.md)

## What to do

- Treat a skill as code that runs with your permissions, and expect screening to miss some. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Handle skills and MCP servers as dependencies: pin versions, read the tool descriptions, prefer first-party ones, and give each its own scoped token. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- OWASP lists agentic supply chain as ASI04. [OWASP agentic top 10, undated](../sources/owasp-agentic-top-10-2026.md)

## If it touched you

Follow [An agent did something it was not asked to do](../playbooks/agent-hijack.md).

## Not recorded here

- Whether a vendor fix has shipped. The sources say what happened; `fix_status` stays `unknown` until someone reads the originals.
- Identifiers such as CVE or GHSA numbers.
