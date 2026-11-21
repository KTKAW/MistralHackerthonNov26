---
type: concept
title: "Secrets and AI keys"
updated: 2026-11-21
reviewed: 2026-11-21
status: evolving
---

# Secrets and AI keys

**Definition:** A *secret* is anything that lets its holder act as you: an API key, a token, a session, a password. *Rotation* replaces a secret with a new one and makes the old one useless. AI keys and agent tokens are production credentials. [Research report, Nov 2026](../sources/research-report-2026-11.md)

## Why it matters

- AI keys are loot. One group used a victim's stolen AI keys to attack about 30 AI companies, and fake "cheap Claude" resellers harvested logins. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md)
- Attackers look for secrets at scale. They ran TruffleHog over 1.8m Android apps to find hardcoded ones. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md)
- Stolen tokens are used fast. One group pulled more than 2,100 Azure AD token sets from more than 40 tenants in about 34 hours. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md)
- Developer machines hold many of them. The August 2026 npm worm stole npm, GitHub and cloud tokens. [npm worm, 2026](../sources/securityweek-npm-worm-2026-08.md)

## What to do

- Hunt for your own exposed keys and rotate them first. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md)
- Give each agent one scoped key, with a spend cap, rotation and monitoring for use from odd locations. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Do not share one `.env` file between agents. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Sweep repositories, dotfiles, `.env` files and images for exposed keys on a schedule, then have a person rotate what is found. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Make sure the agent that does the sweep holds none of the keys it finds and has no outbound access. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Buy AI access only from official channels. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Keep deploy and publish tokens out of any CI job that runs an AI review. [Research report, Nov 2026](../sources/research-report-2026-11.md)

## When it happens

Follow [A key or token is exposed](../playbooks/leaked-secret.md). The recorded campaign is [Stolen AI keys, bulk token theft and fake Claude resellers](../advisories/2026-09-stolen-ai-keys-and-fake-resellers.md).

## Where the evidence is thin

The figures above are reported by a model maker about misuse of its own models. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md)

## Open problems

This knowledge base's reading: rotation only helps if you can list where a key is used, and a shared key cannot be rotated without breaking everything that uses it. One key per agent is what makes rotation a single step during an incident.

## Related

[Agent containment](agent-containment.md) · [Supply chain and dependency cooldown](supply-chain-and-dependency-cooldown.md) · [Phishing-resistant sign-in](phishing-resistant-sign-in.md)
