---
type: advisory
title: "August 2026 npm worm"
date: 2026-08
kind: incident
exploited: in-the-wild
fix_status: unknown
affects: [npm, npm-tokens, github-tokens, cloud-tokens, claude-code-config, vscode-config]
ids: []
playbook: malicious-dependency
updated: 2026-11-21
---

# August 2026 npm worm

**In one line:** A self-spreading npm attack published more than 2,200 malicious package versions in under four hours and stole developer tokens.

## What happened

- In August 2026 a worm pushed more than 2,200 malicious versions of 440 npm packages in under four hours. [npm worm, 2026](../sources/securityweek-npm-worm-2026-08.md)
- It stole npm, GitHub and cloud tokens from the machines it ran on. [npm worm, 2026](../sources/securityweek-npm-worm-2026-08.md)
- It planted Claude and VS Code config files so that it would keep running. [npm worm, 2026](../sources/securityweek-npm-worm-2026-08.md)

## What to do

- Set a dependency cooldown. pnpm 11 waits 24 hours by default; npm needs `min-release-age` set by hand. Most malicious releases are pulled within hours. [Socket on cooldowns, undated](../sources/socket-dependency-cooldown.md)
- Stop install scripts from running, with `ignore-scripts` or pnpm's build allow-list. [Socket on cooldowns, undated](../sources/socket-dependency-cooldown.md)
- Do not count on the cooldown to catch anything: it is a clock, not a detector. [Socket on cooldowns, undated](../sources/socket-dependency-cooldown.md)
- Look for Claude and VS Code config files you did not write. [npm worm, 2026](../sources/securityweek-npm-worm-2026-08.md)

## If it touched you

Follow [A malicious package was installed](../playbooks/malicious-dependency.md).

## Not recorded here

- Whether a vendor fix has shipped. The sources say what happened; `fix_status` stays `unknown` until someone reads the originals.
- Identifiers such as CVE or GHSA numbers.
