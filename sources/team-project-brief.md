---
type: source
title: "24-hour vulnerability response with Le Chonk: project brief"
publisher: "Project team"
url: https://github.com/KTKAW/MistralHackerthonNov26/blob/docs/system-design/PROJECT.md
published: 2026-11-21
ingested: 2026-11-21
kind: design-doc
read: full
---

# 24-hour vulnerability response with Le Chonk: project brief

**In one line:** The team's brief for its hackathon project: take a security advisory, send one agent into each repository, return a verdict per repository with a test as proof, and draft the 24-hour regulatory report for a person to approve.

## What it says

**The problem**

- When a library has a serious vulnerability, a company must answer one question fast: which of our products are actually affected?
- Listing which repositories include the library takes minutes. Working out which ones use the vulnerable part in a way an outside caller can reach takes engineers days.
- The legal clock, as the brief gives it: the EU Cyber Resilience Act's reporting duty has applied since 11 September 2026. Early warning within 24 hours of becoming aware of an actively exploited vulnerability in the product, a fuller notification within 72 hours, and a final report within 14 days of a corrective measure being available. Reports go through ENISA's Single Reporting Platform. The duty falls on manufacturers and covers products already on the market.
- The brief says these details come from law-firm summaries and the Commission's page, and tells the reader to check Regulation (EU) 2024/2847, Article 14, before quoting them.

**How the tool works**

- Six steps in one workflow: read the advisory; fan out with one agent per repository; decide and prove; fix and re-verify; check every claim with a gate that has no model in it; draft the report and wait for a person's approval.
- Each agent traces whether the flawed code can be reached with input an outside caller controls. If it can, the agent writes a test that sends a forged or malicious input through the service's own entry point. If it cannot, it states why, citing the code path.
- After the fix, the proof test must pass and the existing tests must still pass.
- Four verdicts: not affected, with the reason; affected and proven, with a failing test; affected, proven and fixed, with the test now passing; needs a human, when a run times out or a claim fails the gate.
- A wrong "not affected" is the dangerous failure. The tool says "no reachable path found", never "safe".

**What was tested on 21 November 2026**

- Model `mistral-large-4-0` driving Vibe 3.1.3 in headless mode inside an operating-system sandbox. The flaw was CVE-2026-96760, a signature-check bypass in Authlib before 1.9.0, published on 27 October 2026. The fleet was three small services pinned to Authlib 1.8.0: two affected, one not. The correct verdicts were known beforehand and the results were re-checked independently.
- One agent for the whole fleet: verdicts correct 3 of 3, 2 min 34 s, 20 steps, $0.07, 23 of 23 shell commands sandboxed.
- One agent per service, in parallel: verdicts correct 3 of 3, 2 min 39 s for all three against 5 min 6 s one after another, 16, 15 and 18 steps, $0.16, 47 of 47 shell commands sandboxed. No refusals and no rate-limit errors in either run.
- It found a route the advisory does not mention: one service calls a general-purpose function that forwards to the flawed one. The agent found it by reading the installed library's source. A text search for the flawed function finds one affected service; the agent found two.
- Web tools were off, and the agent was given only the advisory's title and first paragraph.
- Re-run against the vulnerable version, the proof tests fail; on the fixed version all three test suites pass. No existing test or application file was changed, and the installed library matched a clean copy.
- Agents also reported other bugs as follow-ups.
- The orchestrator checks: 10 activities in parallel, each a 3 s subprocess, finished in 3.2 s against 30 s one after another; a run paused until an approve signal arrived; a run resumed after its worker was killed, about 2 minutes later.

**Behaviour to design around**

- Without a rule, the agent upgrades too much: in the single-agent run it upgraded the unaffected service.
- The prompt therefore carries three rules: change nothing when the flaw is not reachable; never delete or weaken a test; never edit the installed library. The gate checks them.
- Each activity gets one attempt, because a retry would run on a half-changed work copy.
- Per-service agents cost about twice as much, because each reads the library source itself.
- "Not affected" is the slowest verdict: the unaffected service took 159 s.
- The worker sends logs and traces to Mistral by default. `OTEL_ENABLED=false` turns that off.
- File tools bypass the shell sandbox, so a second hook is needed to restrict their paths. Vibe passes its `.env` contents to shell commands unless the wrapper scrubs the environment.
- The model API key was kept in a `.env` file inside the Vibe home folder, which must never be committed.

**Scope rules**

- Run proof tests only against the team's own code, in an isolated environment. Use only publicly known flaws.
- Proof inputs must be harmless: create an empty marker file, or get a forged request accepted.
- Post nothing to third-party issue trackers automatically.

**What already exists**

- Reachability by code analysis: Semgrep, Snyk and Endor Labs. Agents that open fix pull requests: Snyk, Endor Labs, ZeroPath and Kilo.
- The team's claimed differences: proof by running code, running on your own infrastructure with an open-weight model, and a deliverable that includes the regulatory report.

## Caveats

- Read in full. It is the team's account of its own tests, not an outside evaluation.
- Its own limits: two runs on one flaw, so no measure of how often the verdicts are right; the flaw is logically simple; the model's training cutoff is not stated, so the flaw may not have been new to it; the prompt said the work was authorised and sandboxed; the gate was run by hand; three agents at once, not ten.
- What it says about the law, about Mistral's products and about competitors is second-hand here. Its claim that no existing tool produces a working test rests on one search of mostly vendor pages, which it calls a lead, not a fact.
- A design document on another branch of this repository. It will change; this note describes commit `c0211d4`.
