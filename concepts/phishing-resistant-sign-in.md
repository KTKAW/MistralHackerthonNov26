---
type: concept
title: "Phishing-resistant sign-in"
updated: 2026-11-21
reviewed: 2026-11-21
status: settled
---

# Phishing-resistant sign-in

**Definition:** A way of signing in that a person cannot hand to an attacker by mistake: a *passkey* or a *hardware security key*. One-time codes are not phishing-resistant, because they can be phished like a password. [Research report, Nov 2026](../sources/research-report-2026-11.md) *Device-code phishing* gets round a sign-in page altogether: the victim is talked into approving a sign-in that the attacker started.

## Why it matters

Microsoft names identity as the primary control plane. Phishing was the way in for 23% of the intrusions its incident responders investigated, up from 7% a year earlier. [Microsoft MDDR, Oct 2026](../sources/microsoft-digital-defense-report-2026.md) Device-code phishing has been used against cloud email. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md) Tokens are taken in bulk and quickly: one group pulled more than 2,100 Azure AD token sets from more than 40 tenants in about 34 hours. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md) Meanwhile only 47% of UK businesses use two-factor authentication at all. [UK breaches survey, Apr 2026](../sources/dsit-cyber-security-breaches-survey-2025-26.md)

## What to do

- Put passkeys or hardware keys on email, GitHub, cloud, the domain registrar and the bank. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Use a password manager for everything, and passkeys wherever they are offered. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Restrict device-code sign-in where your identity provider allows it. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Lean on controls that do not depend on any single patch, such as MFA and logging. [Glasswing update, May 2026](../sources/anthropic-glasswing-update.md)

## When it happens

Follow [An account may be taken over](../playbooks/account-phish.md). The recorded campaign is [Device-code phishing against cloud email](../advisories/2026-09-device-code-phishing-cloud-email.md).

## Evidence

- More than a third of successful sign-ins now use a passkey. [FIDO Passkey Index, Oct 2026](../sources/fido-passkey-index-2026.md)

## Open problems

This knowledge base's reading: a passkey protects the sign-in, not the session that follows. The Azure AD case above took tokens, not passwords. There is no source here yet on protecting sessions after sign-in, and the playbook's steps for it are baseline practice.

## Related

[Social engineering and verification](social-engineering-and-verification.md) · [Secrets and AI keys](secrets-and-ai-keys.md)
