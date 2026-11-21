---
type: advisory
title: "MCP STDIO design flaw"
date: 2026-04
kind: vulnerability
exploited: unknown
fix_status: unknown
affects: [mcp, mcp-stdio-servers]
ids: []
playbook: agent-hijack
updated: 2026-11-21
---

# MCP STDIO design flaw

**In one line:** A design flaw in how local MCP servers are started was estimated to expose about 200,000 installations.

## What happened

- In April 2026 OX Security disclosed a design flaw in MCP's STDIO transport, estimated to expose about 200,000 instances. [CSA MCP note, May 2026](../sources/csa-mcp-security-note.md)

## What to do

- Treat a local MCP server as a path to command execution on your machine. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Install MCP servers from the original author only, and pin their versions. [Research report, Nov 2026](../sources/research-report-2026-11.md)

## If it touched you

Follow [An agent did something it was not asked to do](../playbooks/agent-hijack.md).

## Not recorded here

- Whether a vendor fix has shipped. The sources say what happened; `fix_status` stays `unknown` until someone reads the originals.
- Identifiers such as CVE or GHSA numbers.
