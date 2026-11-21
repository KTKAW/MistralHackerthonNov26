---
type: advisory
title: "Device-code phishing against cloud email"
date: 2026-09
kind: campaign
exploited: in-the-wild
fix_status: unknown
affects: [cloud-email, device-code-sign-in, identity-provider]
ids: []
playbook: account-phish
updated: 2026-11-21
---

# Device-code phishing against cloud email

**In one line:** Attackers get into cloud mailboxes by talking people into approving a device-code sign-in.

## What happened

- Anthropic's September 2026 report saw device-code phishing used against cloud email. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md)
- Phishing was the way in for 23% of the intrusions Microsoft's incident responders investigated, up from 7% a year earlier. [Microsoft MDDR, Oct 2026](../sources/microsoft-digital-defense-report-2026.md)

## What to do

- Use passkeys or hardware keys on email, GitHub, cloud and bank. One-time codes can be phished. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Restrict device-code sign-in where your identity provider allows it. [Research report, Nov 2026](../sources/research-report-2026-11.md)

## If it touched you

Follow [An account may be taken over](../playbooks/account-phish.md).

## Not recorded here

- Whether a vendor fix has shipped. The sources say what happened; `fix_status` stays `unknown` until someone reads the originals.
- Identifiers such as CVE or GHSA numbers.
