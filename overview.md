---
type: reference
title: "Overview: the threat picture in late 2026"
updated: 2026-11-21
---

# Overview

What the sources say, on one page. Apart from the section on the team's own system, everything here comes from one research report and the pages it cites, so read "Where the evidence is thin" and "Gaps" before leaning on it.

## The system this serves

The team's tool takes one security advisory, sends an agent into each repository, and returns a verdict per repository with a test as proof. It ends with a draft of the 24-hour regulatory early warning, which a person approves. [Project brief, Nov 2026](sources/team-project-brief.md) The design, its diagrams and the places where this knowledge base plugs in are on [System](system.md). The pages closest to it are [Reachability and proof](concepts/reachability-and-proof.md), [The CRA reporting clock](concepts/cra-reporting-clock.md) and the playbook [An advisory names a library our repositories use](playbooks/advisory-fleet-triage.md).

## The picture

- For people and small teams, money is still lost mostly to persuasion: victims pay, paste or log in themselves. [Research report, Nov 2026](sources/research-report-2026-11.md)
- What changed is speed. Known bugs become working exploits in well below 24 hours. [Microsoft MDDR, Oct 2026](sources/microsoft-digital-defense-report-2026.md) Exploiting vulnerabilities has overtaken stolen credentials as the top way into organisations. [Verizon DBIR, May 2026](sources/verizon-dbir-2026.md)
- AI mostly makes old attacks faster and more convincing, and adds one new attack surface: your own agents. [Research report, Nov 2026](sources/research-report-2026-11.md)
- Most incidents are cheap. In the UK survey the median cost of the most disruptive incident was £0. [UK breaches survey, Apr 2026](sources/dsit-cyber-security-breaches-survey-2025-26.md) The damage sits in the tail, so the controls aim at the few catastrophic paths rather than at every alert. [Research report, Nov 2026](sources/research-report-2026-11.md)

## Numbers

| Signal | Number | Source |
|---|---|---|
| Top way into organisations | Vulnerability exploitation, 31% of breaches; first time in 19 years above stolen credentials | [Verizon DBIR, May 2026](sources/verizon-dbir-2026.md) |
| Third parties | 48% of breaches involve a third party, up 60% | [Verizon DBIR, May 2026](sources/verizon-dbir-2026.md) |
| Exploit speed | Median discovery-to-exploit "well below 24 hours"; enterprises take 30–60 days to patch critical external flaws | [Microsoft MDDR, Oct 2026](sources/microsoft-digital-defense-report-2026.md) |
| Phishing as the way in | 23% of intrusions Microsoft's responders investigated, up from 7% a year earlier | [Microsoft MDDR, Oct 2026](sources/microsoft-digital-defense-report-2026.md) |
| US reported losses | $20.9bn in 2025, up 26%; 1,008,597 complaints; investment fraud $8.6bn; BEC about $3bn | [SecurityWeek on FBI IC3, 2026](sources/securityweek-fbi-ic3-2025.md) |
| UK payment fraud | £1.28bn in 2025, up 4%; APP fraud £576.4m, up 19%; 66% of APP cases start online, 17% by phone with 28% of losses | [UK Finance fraud report, 2026](sources/uk-finance-annual-fraud-report-2026.md) |
| UK businesses | 43% identified a breach or attack; phishing in 38%; only 47% use two-factor authentication | [UK breaches survey, Apr 2026](sources/dsit-cyber-security-breaches-survey-2025-26.md) |

## Four patterns

1. **Lures moved off email.** Text and voice succeed 40% more often than email phishing. [Verizon DBIR, May 2026](sources/verizon-dbir-2026.md) See [Social engineering and verification](concepts/social-engineering-and-verification.md).
2. **ClickFix is the fastest-growing trick.** It averaged 52% of one vendor's detections through Q2 2026 and reached 67% in August. [State of ClickFix, Sep 2026](sources/push-security-state-of-clickfix.md) See [ClickFix and pasted commands](concepts/clickfix.md).
3. **AI tools are the bait.** Fake install guides for Claude Code and NotebookLM are promoted by ads. [State of ClickFix, Sep 2026](sources/push-security-state-of-clickfix.md)
4. **Developer machines are a prime target.** The August 2026 npm worm pushed more than 2,200 malicious versions of 440 packages in under four hours. [npm worm, 2026](sources/securityweek-npm-worm-2026-08.md) See [Supply chain and dependency cooldown](concepts/supply-chain-and-dependency-cooldown.md).

## AI on the attacker's side

- **Better lures.** AI-automated phishing reached a 54% click-through rate against 12% for standard phishing. [AI phishing click rates, Oct 2025](sources/register-ai-phishing-click-rates.md)
- **Cloned voices.** A 3-second clip gave an 85% voice match in McAfee's tests. [Fortune on voice cloning, Oct 2026](sources/fortune-voice-cloning-safe-word.md)
- **One operator at the scale of a team.** A majority of the operations Anthropic disrupted were enabled by AI, and one hacktivist compromised 14 of 42 tracked targets alone. [Anthropic threat report, Sep 2026](sources/anthropic-threat-intelligence-2026-09.md) Being too small to target is weaker cover, because targeting is cheap. [Research report, Nov 2026](sources/research-report-2026-11.md)
- **Keys as loot.** Stolen AI keys were used to attack about 30 AI companies. [Anthropic threat report, Sep 2026](sources/anthropic-threat-intelligence-2026-09.md) See [Secrets and AI keys](concepts/secrets-and-ai-keys.md).
- **Machine-found bugs.** About 50 partners found more than 10,000 high or critical bugs in a month. [Glasswing update, May 2026](sources/anthropic-glasswing-update.md) See [Patching and exploit speed](concepts/patching-and-exploit-speed.md).
- **Autonomy is arriving, not yet the norm.** Frontier models took over an emulated enterprise domain in a 32-step chain with no defenders present, but most campaigns Microsoft sees are still manually driven. [Microsoft MDDR, Oct 2026](sources/microsoft-digital-defense-report-2026.md)
- **A sense of scale.** The FBI counted more than 22,000 AI-related complaints and $893m in losses for 2025. [FBI AI complaints, 2026](sources/helpnet-fbi-ai-complaints.md) That is about 4% of reported losses: AI is an amplifier on top of ordinary fraud, not yet its own category. [Research report, Nov 2026](sources/research-report-2026-11.md)

## Your own agents are attack surface

Prompt injection is still unsolved, so the defence that holds is architectural: limit what any single agent session can combine. [Research report, Nov 2026](sources/research-report-2026-11.md) The five national cyber agencies, including the UK's, advise adopting agentic AI slowly, starting with low-risk tasks. [Five Eyes agentic AI guidance, Apr 2026](sources/five-eyes-agentic-ai-guidance.md) The working rule is the Rule of Two: at most two of untrusted input, private data and outbound action in one session. [Rule of Two, Nov 2025](sources/willison-rule-of-two.md) See [Prompt injection and the Rule of Two](concepts/prompt-injection-and-rule-of-two.md) and [Agent containment](concepts/agent-containment.md). The incident record is under "Advisories" in the [index](index.md).

## What works

The research report's ten picks, each with the page that covers it. [Research report, Nov 2026](sources/research-report-2026-11.md)

| For | Control | Page |
|---|---|---|
| People | Passkeys or a hardware key on email, GitHub, cloud and bank | [Phishing-resistant sign-in](concepts/phishing-resistant-sign-in.md) |
| People | Automatic updates everywhere | [Patching and exploit speed](concepts/patching-and-exploit-speed.md) |
| People | Never paste a command from a page, ad or shared chat | [ClickFix and pasted commands](concepts/clickfix.md) |
| People | A safe word, and "hang up, call back" for anything about money | [Social engineering and verification](concepts/social-engineering-and-verification.md) |
| People | AI as a second opinion that names the verification route | [AI-assisted defence](concepts/ai-assisted-defence.md) |
| Agents and code | No session with untrusted input, private data and outbound action at once | [Prompt injection and the Rule of Two](concepts/prompt-injection-and-rule-of-two.md) |
| Agents and code | Sandbox coding agents with filesystem and network walls | [Agent containment](concepts/agent-containment.md) |
| Agents and code | One scoped, capped, rotated key per agent | [Secrets and AI keys](concepts/secrets-and-ai-keys.md) |
| Agents and code | A dependency cooldown, with install scripts off | [Supply chain and dependency cooldown](concepts/supply-chain-and-dependency-cooldown.md) |
| Agents and code | AI security review of your own code; in CI only on trusted PRs | [AI-assisted defence](concepts/ai-assisted-defence.md) |

**A baseline a team can show to others:** the NCSC's free Cyber Action Toolkit first, then Cyber Essentials. [NCSC Cyber Action Toolkit, undated](sources/ncsc-cyber-action-toolkit.md) Only 5% of UK businesses hold Cyber Essentials, and 12% of small ones. [UK breaches survey, Apr 2026](sources/dsit-cyber-security-breaches-survey-2025-26.md)

**Skip for now:** AI browsers logged into your main accounts, discounted third-party AI resellers, and building your own AI security operations centre. [Research report, Nov 2026](sources/research-report-2026-11.md)

## Where the evidence is thin

- Deepfake figures come from vendors that sell protection. [Research report, Nov 2026](sources/research-report-2026-11.md)
- The AI-misuse and Glasswing figures are reported by the model maker. [Research report, Nov 2026](sources/research-report-2026-11.md)
- Surveys count only what was noticed or reported. [Research report, Nov 2026](sources/research-report-2026-11.md)
- The results on AI as a scam checker rest on small studies. [Research report, Nov 2026](sources/research-report-2026-11.md)
- No prompt-injection filter has held up, so architecture, not detection, carries the weight for now. [Research report, Nov 2026](sources/research-report-2026-11.md)
- The periods differ between reports. Compare trends, not exact numbers. [Research report, Nov 2026](sources/research-report-2026-11.md)
- Who gains more from AI bug-finding is open. [Research report, Nov 2026](sources/research-report-2026-11.md)

## Gaps in this knowledge base

- **Second-hand sources.** Six notes were read directly: the research report, the team's two design documents, the Commission's page on CRA reporting, one advisory record and the KEV feed. Every other note is `via-report` or `via-snippet`.
- **Baseline steps.** Many playbook steps are standard practice with no source note behind them yet. They are tagged *(baseline)*.
- **Fix status.** No curated advisory says whether a vendor fix shipped.
- **UK only** for phone numbers and reporting routes.
- **Not covered:** ransomware response, lost or stolen devices, cloud misconfiguration, and legal duties beyond the CRA's reporting deadlines.
- **The system's evidence is small.** Two runs on one flaw, reported by the team that built it.
- **One selection.** The seed is one report's choice of sources, and it leans on reports from Anthropic and Microsoft.
