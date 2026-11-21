---
type: source
title: "le-chonk system design"
publisher: "Project team"
url: https://github.com/KTKAW/MistralHackerthonNov26/blob/docs/system-design/docs/architecture.html
published: 2026-11-21
ingested: 2026-11-21
kind: design-doc
read: full
---

# le-chonk system design

**In one line:** One advisory goes in; one agent per repository decides whether the flaw can be reached, proves it with a test and fixes it; a gate with no model re-checks every claim; out come a verdict per repository and a draft of the 24-hour early warning.

## What it says

**The run**

- The orchestrator is a Mistral Workflows workflow. Mistral hosts the coordinator, which keeps the run's history. The team's worker process connects out to it and runs every step on the team's own machine.
- A run starts when someone pastes an advisory into a web page, which starts the workflow and the 24-hour clock.
- Read advisory: one model call returns the library, the affected versions and the flawed function as `advisory.json`.
- Triage: one activity per repository, all at once. In the test, three ran in parallel, started within 0.1 s of each other and finished in 159 s, against 306 s one after another. Ten at once has not been tried.
- Each activity works on a fresh copy of its repository with its own virtual environment, starts a headless Vibe process there, sends a heartbeat every 10 seconds and gets one attempt.
- When Vibe exits, the activity returns the agent's `verdict.json` and Vibe's `export.json`, which holds tokens, cost and outcome.

**What one worker does**

- Five stages: read the advisory facts and the installed library's source; trace from the entry point to the flawed function; prove with a test through the entry point that fails on the vulnerable version; fix by upgrade or patch from the local wheelhouse; re-verify that the proof now passes and the old tests still pass.
- If the flaw is not reachable by outside input, the verdict is "not affected", always worded "no reachable path found" and never "safe", with the code path followed up to the point where the trail stops.
- If no fix passes, the tile stays at "affected and proven". "Needs a human" can come from any stage: the proof never failed, a gate rule broke, or time or budget ran out.
- The prompt carries three rules, each written after something an agent did in an earlier run: change nothing in a repository found not affected, never delete or weaken a test, never edit the installed library.

**The sandbox**

- Each Vibe process talks to the model itself, outside the sandbox. Everything it does to the machine through the shell goes through a hook that rewrites the command to run through a wrapper. The wrapper removes the environment and runs the command under the operating system's sandbox.
- The sandbox profile blocks the network, blocks writes outside the work area and temporary folders, and makes a secrets folder unreadable. In the test, all 47 shell commands from the three agents ran inside it.
- File tools are not covered by that hook. A second, path-checking hook is still to be written: it must deny writes outside the work copy and reads of `.env` and of secrets.
- Web tools are turned off by name. Packages come only from a local wheelhouse that holds the vulnerable and the fixed versions.
- Tested on macOS only. Linux needs a different sandbox tool.

**The gate**

- The gate has no model. It re-runs each proof on the vulnerable and on the fixed version through the same sandbox. Its four rules: the proof fails on the vulnerable version; the proof passes on the fixed version; the test count never drops; there is no diff in a "not affected" repository.
- A claim that fails the gate becomes "needs a human". The gate can change a verdict to that and to nothing else.
- The grid shows a tile only after the gate has run, so an unchecked claim never appears as a result.
- The gate is not code yet. In the test its checks were run by hand, and all passed.

**The report**

- The report step fills an early-warning template using only verdicts that passed the gate. It makes no model call.
- The workflow then pauses until a person sends an approve signal, with a 24-hour timeout. That person submits the report to ENISA. The tool never sends anything.

**The verdict file**

- One `verdict.json` per repository. The agent writes its own fields and the orchestrator adds the rest.
- Fields: `repo` and `advisory` (orchestrator); `verdict`, one of `not_affected`, `affected_proven`, `affected_fixed`, `needs_human` (agent, then gate); `reason`; `path`, a list of file, line and note from the entry point to the flawed function or to where the trail stops; `proof`, a list of test IDs with their expected result on each version; `fix`; `suite`, the passed and failed test counts before and after; `follow_ups`; `gate`, the result of each gate rule (orchestrator); `usage`, copied from Vibe's export (orchestrator).

**In production**

- The same design inside a company's own cloud account or data centre, on a private network with no internet by default.
- Only three things cross the boundary: new advisories come in through allow-listed egress; model calls go out only if the company chooses Mistral's API; the early warning leaves only when a person submits it.
- A feed watcher starts a run for every new advisory. The orchestrator uses a dependency inventory to pick only the repositories that include the library, and clones them itself with read-only credentials.
- Each job runs in a container sandbox that covers the file tools too. It holds no credentials and reaches only a package mirror and a model gateway.
- Verdicts, proofs and report drafts go to an evidence store the company cannot silently change, because the 72-hour and 14-day reports and any audit rely on them.
- Fixes go out as draft pull requests on the company's own git host, after the gate.

**Not decided or not tested**

- How many agents at once; the path hook; whether the heartbeat shortens recovery after a crash; the gate as code; which real open-source project joins the demo fleet.

## Caveats

- Read in full, including the labels inside its three diagrams. This note describes commit `c0211d4`.
- Built against designed: the core path ran on 21 November 2026, with three agents in parallel inside one workflow. The web page, the gate and the report are designed and not built.
- The production section is a design that was not tested. Its hardware sizing is the team's own estimate.
- A design document on another branch of this repository, by the team that builds the tool.
