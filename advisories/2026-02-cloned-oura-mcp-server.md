---
type: advisory
title: "Cloned Oura Ring MCP server delivers malware"
date: 2026-02
kind: incident
exploited: in-the-wild
fix_status: unknown
affects: [mcp, oura-ring-mcp-server]
ids: []
playbook: agent-hijack
updated: 2026-11-21
---

# Cloned Oura Ring MCP server delivers malware

**In one line:** A copy of a legitimate MCP server was used to deliver malware.

## What happened

- In February 2026 a cloned Oura Ring MCP server was used to deliver malware. [UpGuard MCP incidents, undated](../sources/upguard-mcp-incidents.md)

## What to do

- Install MCP servers from the original author only. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Pin the version, read the tool descriptions, and give the server its own scoped token. [Research report, Nov 2026](../sources/research-report-2026-11.md)

## If it touched you

Follow [An agent did something it was not asked to do](../playbooks/agent-hijack.md).

## Not recorded here

- Whether a vendor fix has shipped. The sources say what happened; `fix_status` stays `unknown` until someone reads the originals.
- Identifiers such as CVE or GHSA numbers.
