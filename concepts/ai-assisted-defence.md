---
type: concept
title: "AI-assisted defence"
updated: 2026-11-21
reviewed: 2026-11-21
status: evolving
---

# AI-assisted defence

**Definition:** Using a model on the defender's side. It works best as a second pair of eyes that points to a verification step, not as the judge. [Research report, Nov 2026](../sources/research-report-2026-11.md) The *verification route* is the answer to ask for: how to confirm something through a channel you already trust.

## Why it matters

Protection at personal and small-team scale comes from a few hard boundaries, not from an AI that watches everything. [Research report, Nov 2026](../sources/research-report-2026-11.md) Four uses of AI have evidence behind them at this scale, and each has a failure mode that the same sources describe.

## What to do

- **Screen calls and texts on the device.** Android Scam Detection flags scam speech patterns in calls and scam texts from non-contacts. [Android scam detection, undated](../sources/google-android-scam-detection.md) Call Screening in iOS 26 makes unknown callers state who they are. [Apple call screening, Oct 2025](../sources/apple-call-screening.md)
- **Ask for a second opinion on a suspicious message.** Paste it and ask for the verification route, not a verdict. A model can be fooled about the message itself; asking for the route keeps the final check on a channel you control. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- **Review your own code.** `/security-review` in Claude Code checks a repository before you commit. [Claude Code security review, undated](../sources/anthropic-security-review.md)
- **Keep AI review in CI away from untrusted input.** Run it only on trusted pull requests, in jobs with no deploy or publish tokens. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- **Run the attacker's scan on yourself.** A scheduled agent sweeps repositories, dotfiles, `.env` files and images for exposed keys, and a person rotates them. The scanning agent must not hold the keys it finds or have outbound access. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- **Do not build your own AI security operations centre at this size.** A small team usually lacks the logs and hours. The AI triage built into a managed detection service, or into your email and identity platform, is where those hours pay back. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- **Read the original.** Do not act on an AI summary of email from strangers. Hidden text can steer the summary. [Gemini summary hijack, undated](../sources/bleepingcomputer-gemini-summaries.md)

## Evidence

- In one study Claude 3.5 Sonnet caught well above 90% of phishing with few false alarms. [Heiding et al., Dec 2024](../sources/heiding-llm-phishing-study.md)
- A 2026 study on 2,000 emails found that chatbots scored them inconsistently. [SANS email study, 2026](../sources/sans-llm-email-classification.md)
- Anthropic says its pull-request action caught a remote code execution bug and an SSRF in its own code before merge. [Claude Code security review, undated](../sources/anthropic-security-review.md)
- Google says it flags more than 5m suspected scam calls and texts a month. [Android scam detection, undated](../sources/google-android-scam-detection.md)

## Where the evidence is thin

- The scam-checker result rests on a small study of 101 participants. [Heiding et al., Dec 2024](../sources/heiding-llm-phishing-study.md)
- No large real-world test of consumers using AI as a scam checker exists yet. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- The product claims come from the vendors themselves. [Claude Code security review, undated](../sources/anthropic-security-review.md) [Android scam detection, undated](../sources/google-android-scam-detection.md)

## Related

[Social engineering and verification](social-engineering-and-verification.md) · [Prompt injection and the Rule of Two](prompt-injection-and-rule-of-two.md) · [Secrets and AI keys](secrets-and-ai-keys.md)
