---
type: concept
title: "Social engineering and verification"
updated: 2026-11-21
reviewed: 2026-11-21
status: evolving
---

# Social engineering and verification

**Definition:** *Social engineering* persuades a person to pay, paste or log in. *Out-of-band verification* answers it: confirm the request through a channel you already hold, never one supplied in the request. A *safe word* is the same idea for voices: a word agreed in advance that a caller must know.

## Why it matters

- **Lures moved off email.** Social engineering by text and voice succeeds 40% more often than email phishing. [Verizon DBIR, May 2026](../sources/verizon-dbir-2026.md) In the UK, 17% of APP fraud cases start by phone, and those carry 28% of losses. [UK Finance fraud report, 2026](../sources/uk-finance-annual-fraud-report-2026.md)
- **The prose is no longer a tell.** AI-automated phishing reached a 54% click-through rate against 12% for standard phishing. [AI phishing click rates, Oct 2025](../sources/register-ai-phishing-click-rates.md) Spotting bad grammar no longer works: verify the channel, not the prose. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- **Voices can be cloned.** A 3-second clip gave an 85% voice match in McAfee's tests. [Fortune on voice cloning, Oct 2026](../sources/fortune-voice-cloning-safe-word.md) 31% of consumers say they received a deepfake voice call in the past 12 months. [Hiya voice fraud survey, undated](../sources/hiya-ai-voice-fraud.md) A familiar voice is no longer proof of identity. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- **The sums are large.** Losses reported to the FBI were $20.9bn in 2025, with business email compromise at about $3bn. [SecurityWeek on FBI IC3, 2026](../sources/securityweek-fbi-ic3-2025.md) UK payment fraud was £1.28bn in 2025, of which APP fraud was £576.4m. [UK Finance fraud report, 2026](../sources/uk-finance-annual-fraud-report-2026.md)

## What to do

**People**

- Agree a safe word with family and close friends. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- For anything about money, hang up and call back on a saved number. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- In the UK, dial 159 to reach your own bank's fraud team. It covers banks with more than 99% of UK current accounts. [MoneyWeek on 159, undated](../sources/moneyweek-159.md)
- Call from a different phone if you can. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Turn on screening on the phone itself. Android Scam Detection flags scam speech patterns in calls and scam texts from non-contacts; in the UK the call detection is off by default. [Android scam detection, undated](../sources/google-android-scam-detection.md) Call Screening in iOS 26 makes unknown callers state who they are. [Apple call screening, Oct 2025](../sources/apple-call-screening.md)
- Know the limit of screening: it cannot stop you calling a scammer back, and an unknown caller is not always spam. [Research report, Nov 2026](../sources/research-report-2026-11.md)

**Teams**

- Confirm new or changed bank details by calling a number you already hold, and have a second person approve. [Research report, Nov 2026](../sources/research-report-2026-11.md)

**AI as a second opinion**

- Ask a model for the verification route, not a verdict: how would I confirm this is genuine, without contacting anyone in the message, through a channel I already trust? A model can be fooled about the message itself. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Do not let an AI summary be your only view of email from strangers. Hidden text in an email can steer the summary. [Gemini summary hijack, undated](../sources/bleepingcomputer-gemini-summaries.md)

## When it happens

Money asked for or sent: [A call or message asks for money](../playbooks/payment-or-voice-scam.md). A password or code given away: [An account may be taken over](../playbooks/account-phish.md).

## Evidence

- In one study Claude 3.5 Sonnet caught well above 90% of phishing with few false alarms. The study had 101 participants. [Heiding et al., Dec 2024](../sources/heiding-llm-phishing-study.md)
- A 2026 study on 2,000 emails found that chatbots scored them inconsistently. [SANS email study, 2026](../sources/sans-llm-email-classification.md)
- Google says it flags more than 5m suspected scam calls and texts a month. [Android scam detection, undated](../sources/google-android-scam-detection.md)

## Where the evidence is thin

- The voice-clone figures come from companies that sell protection. Read them as direction, not size. [Fortune on voice cloning, Oct 2026](../sources/fortune-voice-cloning-safe-word.md) [Hiya voice fraud survey, undated](../sources/hiya-ai-voice-fraud.md)
- No large real-world test of consumers using AI as a scam checker exists yet. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- The phone numbers and services here are for the UK. Other countries are not covered.

## Related

[ClickFix and pasted commands](clickfix.md) · [Phishing-resistant sign-in](phishing-resistant-sign-in.md) · [AI-assisted defence](ai-assisted-defence.md)
