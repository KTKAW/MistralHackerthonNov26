---
type: concept
title: "Reachability and proof"
updated: 2026-11-21
reviewed: 2026-11-21
status: evolving
---

# Reachability and proof

**Definition:** A repository is *affected* by a vulnerability in a library only if the flawed code is *reachable*: an outside caller can get input to it through the service's own *entry point*. A *proof test* shows that by running code: it sends such input through the entry point, fails on the vulnerable version and passes on the fixed one. A *verdict* is the answer for one repository. A *gate* is a check with no model in it that re-runs every claim before a verdict is shown. [System design, Nov 2026](../sources/team-system-design.md)

## Why it matters

- Listing which repositories include a vulnerable library takes minutes. Working out which ones use the vulnerable part in a way an outside caller can reach takes engineers days. [Project brief, Nov 2026](../sources/team-project-brief.md)
- There is not that much time. The median time from a flaw's discovery to a working exploit is well below 24 hours. [Microsoft MDDR, Oct 2026](../sources/microsoft-digital-defense-report-2026.md) For a manufacturer, the early warning on an actively exploited vulnerability is due within 24 hours of becoming aware. [Commission on CRA reporting, Sep 2026](../sources/european-commission-cra-reporting.md)
- A text search is not enough. In the team's test, a search for the flawed function finds one affected service, and the agent found two: one service calls a general-purpose function that forwards to the flawed one. [Project brief, Nov 2026](../sources/team-project-brief.md)
- A wrong "not affected" is the dangerous failure. [Project brief, Nov 2026](../sources/team-project-brief.md)

## What to do

**Decide**

- Trace from the service's entry point to the flawed function, and ask whether an outside caller controls the input along the way. [System design, Nov 2026](../sources/team-system-design.md)
- Read the installed library's source, not only the advisory. That is how the route the advisory does not mention was found. [Project brief, Nov 2026](../sources/team-project-brief.md)
- Give one of four verdicts: not affected, affected and proven, affected proven and fixed, or needs a human. [System design, Nov 2026](../sources/team-system-design.md)
- Word "not affected" as "no reachable path found", never as "safe", and show the code path followed up to where the trail stops. [System design, Nov 2026](../sources/team-system-design.md)

**Prove**

- Prove "affected" with a test that goes through the service's entry point and fails on the vulnerable version. [System design, Nov 2026](../sources/team-system-design.md)
- Keep proof inputs harmless: create an empty marker file, or get a forged request accepted. [Project brief, Nov 2026](../sources/team-project-brief.md)
- Run proof tests only against your own code, in an isolated environment, and only for publicly known flaws. [Project brief, Nov 2026](../sources/team-project-brief.md)

**Fix**

- After the fix, the proof test must pass and the existing tests must still pass. [Project brief, Nov 2026](../sources/team-project-brief.md)
- Change nothing in a repository found not affected. Without that rule the agent upgraded an unaffected service. [Project brief, Nov 2026](../sources/team-project-brief.md)
- Never delete or weaken a test, and never edit the installed library. [Project brief, Nov 2026](../sources/team-project-brief.md)
- Give each agent one attempt on a fresh work copy. A retry would run on a half-changed copy. [Project brief, Nov 2026](../sources/team-project-brief.md)

**Check every claim without a model**

- Re-run each proof on the vulnerable and on the fixed version. The gate's four rules: the proof fails on the vulnerable version; it passes on the fixed version; the test count never drops; there is no diff in a "not affected" repository. [System design, Nov 2026](../sources/team-system-design.md)
- Turn any claim that fails the gate into "needs a human". Let the gate change a verdict to that and to nothing else. [System design, Nov 2026](../sources/team-system-design.md)
- Show a verdict only after the gate has run, so that an unchecked claim never appears as a result. [System design, Nov 2026](../sources/team-system-design.md)

## When it happens

Follow [An advisory names a library our repositories use](../playbooks/advisory-fleet-triage.md). The system that automates it is on the [System](../system.md) page. The recorded case is [Authlib accepts a JWS with no signatures](../advisories/2026-10-authlib-cve-2026-96760.md).

## Evidence

- One agent per service, in parallel: verdicts correct 3 of 3, in 2 min 39 s for all three, for $0.16, with 47 of 47 shell commands sandboxed. [Project brief, Nov 2026](../sources/team-project-brief.md)
- One agent for the whole fleet: verdicts correct 3 of 3, in 2 min 34 s, for $0.07. [Project brief, Nov 2026](../sources/team-project-brief.md)
- Re-run against the vulnerable version, the proof tests fail; on the fixed version all three test suites pass. No existing test or application file was changed. [Project brief, Nov 2026](../sources/team-project-brief.md)
- "Not affected" was the slowest verdict: the unaffected service took 159 s. [Project brief, Nov 2026](../sources/team-project-brief.md)

## Where the evidence is thin

- Two runs on one flaw, in a fleet of three small services. There is no measure of how often the verdicts are right. [Project brief, Nov 2026](../sources/team-project-brief.md)
- The flaw is logically simple. A memory-corruption bug or a multi-step chain will be much harder. [Project brief, Nov 2026](../sources/team-project-brief.md)
- The model's training cutoff is not stated, so the flaw may not have been new to it. [Project brief, Nov 2026](../sources/team-project-brief.md)
- The gate was run by hand. It is not code yet. [System design, Nov 2026](../sources/team-system-design.md)
- All of it is the team's account of its own tests.

## Open problems

- The team's claim that no existing tool produces a working test rests on one search of mostly vendor pages. The brief calls it a lead, not a fact. [Project brief, Nov 2026](../sources/team-project-brief.md)
- This knowledge base's reading: a proof test shows that one route is reachable. It does not show that no other route exists, so "affected and fixed" is a claim about the routes that were found.

## Related

[Patching and exploit speed](patching-and-exploit-speed.md) · [The CRA reporting clock](cra-reporting-clock.md) · [Agent containment](agent-containment.md) · [Prompt injection and the Rule of Two](prompt-injection-and-rule-of-two.md)
