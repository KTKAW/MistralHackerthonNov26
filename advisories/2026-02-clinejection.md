---
type: advisory
title: "Clinejection: a GitHub issue title compromises a coding agent"
date: 2026-02
kind: incident
exploited: in-the-wild
fix_status: unknown
affects: [coding-agents, cline, github-issues, github-actions]
ids: []
playbook: agent-hijack
updated: 2026-11-21
---

# Clinejection: a GitHub issue title compromises a coding agent

**In one line:** One malicious issue title led to a supply-chain compromise of the Cline coding agent.

## What happened

- "Clinejection", February 2026: one malicious GitHub issue title chained four flaws into a supply-chain compromise of the Cline coding agent. [CSA Clinejection note, 2026](../sources/csa-clinejection-note.md)

## What to do

- Treat issue titles, and any other text an outsider can write into a repository, as untrusted input. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Keep secrets out of reach of any CI agent that reads them. [Research report, Nov 2026](../sources/research-report-2026-11.md)

## If it touched you

Follow [An agent did something it was not asked to do](../playbooks/agent-hijack.md).

## Not recorded here

- Whether a vendor fix has shipped. The sources say what happened; `fix_status` stays `unknown` until someone reads the originals.
- Identifiers such as CVE or GHSA numbers.
