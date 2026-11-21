---
type: advisory
title: "Stolen AI keys, bulk token theft and fake Claude resellers"
date: 2026-09
kind: campaign
exploited: in-the-wild
fix_status: unknown
affects: [ai-api-keys, azure-ad-tokens, claude-accounts, android-apps, hardcoded-secrets]
ids: []
playbook: leaked-secret
updated: 2026-11-21
---

# Stolen AI keys, bulk token theft and fake Claude resellers

**In one line:** Keys and tokens are stolen in bulk and reused at once, and AI keys are now among the things worth stealing.

## What happened

- One group pulled more than 2,100 Azure AD token sets from more than 40 tenants in about 34 hours. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md)
- Another group used a victim's stolen AI keys to attack about 30 AI companies. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md)
- Fake "cheap Claude" resellers harvested logins. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md)
- Attackers ran TruffleHog over 1.8m Android apps to find hardcoded secrets. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md)

## What to do

- Hunt for your own exposed keys and rotate them first. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md)
- Give each agent one scoped key, with a spend cap, rotation and monitoring for use from odd locations. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Buy AI access only from official channels. [Research report, Nov 2026](../sources/research-report-2026-11.md)

## If it touched you

Follow [A key or token is exposed](../playbooks/leaked-secret.md).

## Not recorded here

- Whether a vendor fix has shipped. The sources say what happened; `fix_status` stays `unknown` until someone reads the originals.
- Identifiers such as CVE or GHSA numbers.
