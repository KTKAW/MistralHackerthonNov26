---
type: playbook
title: "A call or message asks for money"
signals: ["caller says they are the bank or the police or a relative in trouble", "request to move money to a safe account", "supplier sends new bank details", "urgent payment request by phone or text", "money already sent to a scammer"]
severity: high
updated: 2026-11-21
reviewed: 2026-11-21
---

# A call or message asks for money

**Use when:** a call, voice message or text asks for money, bank details or codes, or presses for speed; or money has already been sent. See [Social engineering and verification](../concepts/social-engineering-and-verification.md).

**Assume until disproved:** the caller is not who they say. A familiar voice proves nothing: a 3-second clip gave an 85% voice match in McAfee's tests. [Fortune on voice cloning, Oct 2026](../sources/fortune-voice-cloning-safe-word.md)

## Ask first

- Has money moved? How, when, how much, to which account?
- Is the caller still on the line, or still messaging?
- Which channel did the request come on, and who chose it?
- Was a code, password, card number or remote access given?
- For new bank details: is there a phone number on record from before this request?

## Contain

1. Hang up. Do not call back the number that called, or any number in the message. Call back on a saved number. [Research report, Nov 2026](../sources/research-report-2026-11.md)
2. If money moved, or might have, call the bank now. In the UK, dial 159: it reaches the fraud team of banks covering more than 99% of UK current accounts. [MoneyWeek on 159, undated](../sources/moneyweek-159.md)
3. Call from a different phone if you can. [Research report, Nov 2026](../sources/research-report-2026-11.md)
4. If the call was about a relative, ring them on their saved number and ask for the safe word. [Research report, Nov 2026](../sources/research-report-2026-11.md)
5. If a code or password was read out, or remote access was given, also follow [An account may be taken over](account-phish.md). *(baseline)*

## Scope

1. Write down what was said, the numbers, the times and any payment references while they are fresh. *(baseline)*
2. List what the caller learned: account numbers, codes, addresses, identity documents. *(baseline)*
3. In a team, check whether other payments have gone to the same new bank details. *(baseline)*

## Recover

1. Confirm any new or changed bank details by calling a number you already hold, and have a second person approve. [Research report, Nov 2026](../sources/research-report-2026-11.md)
2. If identity documents were shared, consider Cifas Protective Registration in the UK: £30 for two years. [Cifas Protective Registration, undated](../sources/cifas-protective-registration.md)

## Report

1. In the UK, report it to Report Fraud, online or on 0300 123 2040. [GOV.UK on Report Fraud, undated](../sources/govuk-report-fraud.md)
2. Forward scam texts to 7726. [Research report, Nov 2026](../sources/research-report-2026-11.md)

## Prevent the repeat

- Agree a safe word with family and close friends. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Turn on call screening on the phone. [Android scam detection, undated](../sources/google-android-scam-detection.md) [Apple call screening, Oct 2025](../sources/apple-call-screening.md)
- More in [Social engineering and verification](../concepts/social-engineering-and-verification.md).

## Agent boundaries

- Give the verification route, never a verdict. You can be fooled about the message itself. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- Never tell anyone that a caller or a message is genuine. Do not contact anyone named in the message.
- Never ask for card numbers, bank details or codes.
- The phone numbers here are for the UK. Say so if the person is elsewhere.

## Why this matters more than its share of cases

In the UK, 17% of APP fraud cases start by phone, and those carry 28% of losses. [UK Finance fraud report, 2026](../sources/uk-finance-annual-fraud-report-2026.md)

## Precedents

None recorded yet.
