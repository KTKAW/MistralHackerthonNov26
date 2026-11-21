---
type: advisory
title: "BioShocking: six AI browsers leak data in tests"
date: 2026-06
kind: research
exploited: demonstrated
fix_status: unknown
affects: [ai-browsers, chatgpt-atlas, comet, claude-browser-extension]
ids: []
playbook: agent-hijack
updated: 2026-11-21
---

# BioShocking: six AI browsers leak data in tests

**In one line:** One research technique made six AI browsers give up sensitive data.

## What happened

- In June 2026 LayerX's "BioShocking" technique made six AI browsers, including Atlas, Comet and the Claude extension, leak sensitive data in tests. [BioShocking, 2026](../sources/techrepublic-bioshocking.md)

## What to do

- Assume that whatever the agent is logged into is in scope. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- For now, skip AI browsers logged into your main accounts. [Research report, Nov 2026](../sources/research-report-2026-11.md)

## If it touched you

Follow [An agent did something it was not asked to do](../playbooks/agent-hijack.md).

## Not recorded here

- Whether a vendor fix has shipped. The sources say what happened; `fix_status` stays `unknown` until someone reads the originals.
- Identifiers such as CVE or GHSA numbers.
