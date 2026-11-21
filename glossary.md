---
type: reference
title: "Glossary"
---

# Glossary

The shared vocabulary. Use these terms as defined here, in conversation and in this repository. If a person or a source uses a term differently, say so and reconcile it.

One line per term. The linked page has the detail and the sources.

## A–F

- **159** — UK short number that connects you to your own bank's fraud team. [Social engineering and verification](concepts/social-engineering-and-verification.md)
- **7726** — UK number to which scam texts are forwarded. [An account may be taken over](playbooks/account-phish.md)
- **Advisory** — A record of something that happened or was disclosed, what it affects, and which playbook to follow. [Index](index.md)
- **APP fraud (authorised push payment fraud)** — The victim is persuaded to send the money themselves. [Social engineering and verification](concepts/social-engineering-and-verification.md)
- **Baseline step** — A playbook step that is standard practice but has no source note here yet. Tagged *(baseline)*. [AGENTS.md](AGENTS.md)
- **BEC (business email compromise)** — Fraud run through a real or imitated business mailbox, typically a request to pay or to change bank details. [An account may be taken over](playbooks/account-phish.md)
- **Cifas Protective Registration** — A paid UK service that makes lenders take extra care with credit applications in your name. [An account may be taken over](playbooks/account-phish.md)
- **ClickFix** — A fake error or CAPTCHA that tells the visitor to paste a command into a terminal. [ClickFix and pasted commands](concepts/clickfix.md)
- **CVE** — The public identifier of one vulnerability. [Feeds](feeds.md)
- **Cyber Essentials** — The UK government's baseline certification for organisations. [Cyber Security Breaches Survey 2025/26](sources/dsit-cyber-security-breaches-survey-2025-26.md)
- **Dependency cooldown** — A rule that a release must have been public for a set time before you install it. [Supply chain and dependency cooldown](concepts/supply-chain-and-dependency-cooldown.md)
- **Device-code phishing** — Talking a victim into approving a sign-in that the attacker started. [Phishing-resistant sign-in](concepts/phishing-resistant-sign-in.md)
- **EPSS** — A score from 0 to 1 for how likely a CVE is to be exploited soon. [Feeds](feeds.md)

## G–P

- **GHSA** — The identifier of an entry in the GitHub Advisory Database. [Feeds](feeds.md)
- **Grant log** — A record of which agent used which permission, on what, and when. [Agent containment](concepts/agent-containment.md)
- **Infostealer** — Malware that copies saved passwords, sessions and keys from a machine. [Malicious skills on ClawHub](advisories/2026-02-clawhub-malicious-skills.md)
- **Install script** — Code that a package runs on your machine at install time. [Supply chain and dependency cooldown](concepts/supply-chain-and-dependency-cooldown.md)
- **KEV (Known Exploited Vulnerabilities)** — CISA's catalog of vulnerabilities with evidence of exploitation. [Feeds](feeds.md)
- **Leg** — One of the three properties the Rule of Two counts: untrusted input, private data, outbound action. [Prompt injection and the Rule of Two](concepts/prompt-injection-and-rule-of-two.md)
- **Lethal trifecta** — All three legs in one agent. The idea the Rule of Two builds on. [Prompt injection and the Rule of Two](concepts/prompt-injection-and-rule-of-two.md)
- **MAL-** — The prefix of the identifier OSV gives a malicious package. [Feeds](feeds.md)
- **MCP server** — A program that gives an agent tools. A local one is a path to command execution. [Agent containment](concepts/agent-containment.md)
- **OSV** — An open database of vulnerabilities and malicious packages, queried by package and version. [Feeds](feeds.md)
- **Out-of-band verification** — Confirming a request through a channel you already hold, never one supplied in the request. [Social engineering and verification](concepts/social-engineering-and-verification.md)
- **Passkey** — A sign-in credential that cannot be typed into a fake page. [Phishing-resistant sign-in](concepts/phishing-resistant-sign-in.md)
- **Patch latency** — How long you take to apply a fix once it exists. [Patching and exploit speed](concepts/patching-and-exploit-speed.md)
- **Prompt injection** — Text an agent reads as data and then follows as instructions. [Prompt injection and the Rule of Two](concepts/prompt-injection-and-rule-of-two.md)

## R–W

- **Read level** — How a source was read for this knowledge base: `full`, `partial`, `via-report` or `via-snippet`. [AGENTS.md](AGENTS.md)
- **Report Fraud** — The UK service for reporting fraud and cyber crime. It replaced Action Fraud. [An account may be taken over](playbooks/account-phish.md)
- **Rotation** — Replacing a secret with a new one and making the old one useless. [Secrets and AI keys](concepts/secrets-and-ai-keys.md)
- **Rule of Two (Agents Rule of Two)** — A session holds at most two of the three legs; all three needs a person's approval. [Prompt injection and the Rule of Two](concepts/prompt-injection-and-rule-of-two.md)
- **Safe word** — A word agreed in advance that a caller must know. [Social engineering and verification](concepts/social-engineering-and-verification.md)
- **Sandbox** — Two walls around an agent, one for the filesystem and one for the network. [Agent containment](concepts/agent-containment.md)
- **Scoped token** — A credential that can do one job. [Agent containment](concepts/agent-containment.md)
- **Secret** — Anything that lets its holder act as you. [Secrets and AI keys](concepts/secrets-and-ai-keys.md)
- **Skill (agent skill)** — A package of instructions and code that an agent loads. It runs with your permissions. [Supply chain and dependency cooldown](concepts/supply-chain-and-dependency-cooldown.md)
- **Snapshot** — A generated copy of recent feed entries, kept for when the feed cannot be reached. [Feeds](feeds.md)
- **Supply-chain attack** — An attack that reaches you through something you install. [Supply chain and dependency cooldown](concepts/supply-chain-and-dependency-cooldown.md)
- **Untrusted input** — Any text that someone outside could have written: web pages, email, issues, repository text, another agent's output. [Prompt injection and the Rule of Two](concepts/prompt-injection-and-rule-of-two.md)
- **Verification route** — How to confirm a request through a channel you already trust. What to ask a model for, instead of a verdict. [AI-assisted defence](concepts/ai-assisted-defence.md)
- **Weaponisation time** — The gap between a flaw becoming known and a working exploit existing. [Patching and exploit speed](concepts/patching-and-exploit-speed.md)
