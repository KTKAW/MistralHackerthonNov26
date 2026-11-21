---
type: advisory
title: "Comment and Control: repository text steers CI review agents"
date: 2026-04
kind: research
exploited: demonstrated
fix_status: unknown
affects: [github-actions, ci-secrets, claude-code-security-review, gemini-cli-action, copilot-agent]
ids: []
playbook: agent-hijack
updated: 2026-11-21
---

# Comment and Control: repository text steers CI review agents

**In one line:** Text in a repository redirected three CI agents into leaking credentials.

## What happened

- "Comment and Control", a research demo from April 2026: text in GitHub repositories redirected Claude Code Security Review, Gemini CLI Action and Copilot Agent into leaking credentials. [OWASP Q2 round-up, Jul 2026](../sources/owasp-genai-exploit-roundup-2026-q2.md)

## What to do

- Give CI agents that read public issues or pull requests no secrets in reach. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Run AI review in CI only on trusted pull requests, in jobs with no deploy or publish tokens. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Note that the Claude Code security review action says of itself that it is not hardened against prompt injection and is for trusted PRs only. [Claude Code security review, undated](../sources/anthropic-security-review.md)

## If it touched you

Follow [An agent did something it was not asked to do](../playbooks/agent-hijack.md).

## Not recorded here

- Whether a vendor fix has shipped. The sources say what happened; `fix_status` stays `unknown` until someone reads the originals.
- Identifiers such as CVE or GHSA numbers.
