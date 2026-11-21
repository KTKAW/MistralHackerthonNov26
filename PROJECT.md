# 24-hour vulnerability response with Le Chonk

Our project for the "Le Chonk in London" Mistral Vibe hackathon, Saturday 21 November 2026.

This document is for the team building the project and for anyone judging it. It assumes no prior context. The system design, with diagrams, is in [docs/architecture.html](docs/architecture.html).

## The idea in one paragraph

When a serious vulnerability is announced in a library, a company has to answer one question quickly: which of our products are actually affected? We build a tool that takes a security advisory, sends one Le Chonk agent into each of the company's repositories, and returns a verdict per repository with proof. For an affected repository, the proof is a test that triggers the flaw through the service's own entry point, fails before the fix and passes after it. For an unaffected one, it is the reason, pointing at the code. The run ends with a draft of the regulatory early-warning report, which a person approves.

## The pitch

> In December 2021, engineers spent the holidays answering one question about Log4Shell: are we affected, and where? Since September 2026, EU law gives manufacturers 24 hours to report an actively exploited vulnerability in their products. We give Le Chonk the advisory and it answers that question for every repository, with a test that proves each answer, on your own infrastructure.

The line that separates this from a dependency-update bot, taken from our own test run:

> A search for the vulnerable function finds one affected service. Le Chonk found two, proved both, and explained why the third is safe.

## Why this problem

### The legal clock

The EU Cyber Resilience Act's reporting duty has applied since 11 September 2026.

| Step | Deadline |
| --- | --- |
| Early warning | Within 24 hours of becoming aware of an actively exploited vulnerability in the product |
| Fuller notification | Within 72 hours |
| Final report | Within 14 days of a corrective measure being available |

- Reports go through ENISA's Single Reporting Platform.
- The duty falls on manufacturers and covers products already on the market.
- These details come from law-firm summaries and the European Commission's page (see Sources). Check the regulation text (Regulation (EU) 2024/2847, Article 14) before quoting it on a slide.

### The hard part is knowing

Listing which repositories include a vulnerable library takes minutes. Working out which ones use the vulnerable part in a way an outside caller can reach takes engineers days.

### It matches what Mistral is selling

Mistral's cybersecurity page (mistral.ai/industry/cybersecurity) is headed "Sovereign AI for cybersecurity". Its first two use cases are:

- "Move from a suspected flaw to a tested fix", including reproducing findings "in authorized test environments".
- "Validate reachable attack paths and prioritize fixes based on exploitability".

The Large 4 launch post describes Mistral's own demo: an agent that reads vulnerability reports, reproduces the flaw in an isolated sandbox, and iterates on a patch "until a canary exploit no longer works".

Mistral's pages do not mention any regulation. The 24-hour deadline is the customer argument we add.

## How it works

The whole run is one Mistral Workflows workflow. Mistral hosts the coordinator; our worker process runs every step on our own machine.

1. **Read the advisory.** Extract the library, the affected versions and the flawed function.
2. **Fan out.** One agent per repository, all in parallel. Each agent is one workflow activity that runs Vibe in headless mode inside a sandbox.
3. **Decide and prove.** Each agent traces whether the flawed code can be reached with input an outside caller controls. If it can, the agent writes a test that sends a forged or malicious input through the service's own entry point. If it cannot, the agent states why, citing the code path.
4. **Fix and re-verify.** The agent upgrades or patches. The proof test must now pass, and the existing tests must still pass.
5. **Check every claim.** A gate with no model in it re-runs each proof on the vulnerable and the fixed version before a verdict is shown.
6. **Draft the report and wait.** Collect the affected products, the evidence, and a draft of the 24-hour early warning. The workflow pauses until a person approves it.

Every repository ends in one of four verdicts:

- **Not affected,** with the reason. The tool says "no reachable path found", never "safe".
- **Affected and proven,** with a failing test.
- **Affected, proven and fixed,** with the test now passing.
- **Needs a human,** when a run times out or a claim fails the gate.

## What we have tested

All of this ran on 21 November 2026, with Le Chonk (`mistral-large-4-0`) driving Vibe 3.1.3 in headless mode inside an operating-system sandbox. The flaw is CVE-2026-96760, a signature-check bypass in Authlib before 1.9.0, published on 27 October 2026. The test fleet is three small services pinned to Authlib 1.8.0: two affected, one not. The correct verdicts were known before the model saw the task, and its results were re-checked independently afterwards.

### Mistral Workflows as the orchestrator

All four checks passed, using only the Python SDK (`mistralai-workflows` 3.20.0).

| Check | Result |
| --- | --- |
| Hello-world from the docs | Returned its greeting in 2.2 s |
| 10 activities in parallel, each a 3 s local subprocess | All started within 0.1 s and finished in 3.2 s, against 30 s one after another |
| Pause for approval, then send an "approve" signal | Stayed `RUNNING` until the signal, then completed |
| Kill the worker mid-run, start a new one | The run resumed and completed, about 2 minutes later |

### Le Chonk inside a workflow

| | One agent for the whole fleet | One agent per service, in parallel |
| --- | --- | --- |
| Verdicts correct | 3 of 3 | 3 of 3 |
| Refusals | None | None |
| Time | 2 min 34 s | 2 min 39 s for all three (5 min 6 s one after another) |
| Steps | 20 | 16, 15 and 18 |
| Cost | $0.07 | $0.16 |
| Shell commands sandboxed | 23 of 23 | 47 of 47 |
| Rate-limit errors | None | None |

What the runs showed:

- **It found a route the advisory does not mention.** One service calls a general-purpose function that forwards to the flawed one. Le Chonk found this by reading the installed library's source.
- **It did not look the answer up.** Web tools were switched off, and it was given only the advisory's title and first paragraph.
- **Its proof tests hold up.** Re-run against the real affected version, they fail. On the fixed version, all three test suites pass.
- **Nothing was tampered with.** No existing test or application file changed, and the installed library matches a clean copy.
- **Agents write a usable verdict file.** In the parallel run, all three wrote a valid `verdict.json` with every requested field.
- **It reported other bugs as follow-ups,** such as a malformed request crashing a service instead of being cleanly rejected.
- **The parallel design works.** Three Vibe processes ran at once inside one workflow, and each activity returned Vibe's outcome, cost and the agent's verdict.

### Behaviour to design around

- **Without a rule, it upgrades too much.** In the single-agent run it upgraded the unaffected service, although it was only asked whether it would. In the parallel run the prompt said to change nothing when the flaw is not reachable, and the agent obeyed.
- **The prompt carries two more rules:** never delete or weaken a test, and never edit the installed library. The gate checks both.
- **Crash recovery waits for the activity's timeout.** A heartbeat should shorten that. It is in the test code, but its effect on a crash is unconfirmed.
- **Retries need a fresh work copy.** A retry on a half-changed copy would be wrong, so each activity gets one attempt.
- **Per-service agents cost about twice as much,** because each one reads the library source itself.
- **"Not affected" is the slowest verdict.** The unaffected service took 159 s, longer than the two affected ones together.
- **The worker sends logs and traces to Mistral by default.** `OTEL_ENABLED=false` turns that off.

### Limits of the evidence

- **Two runs on one flaw.** We have no measure of how often it gets this right.
- **The flaw is logically simple.** A memory-corruption bug or a multi-step chain will be much harder.
- **Training data.** Mistral does not state a training cutoff, so we cannot prove the October 2026 flaw was unknown to the model.
- **The prompt said the work was authorised and sandboxed.** A vaguer request may be treated differently.
- **The gate was run by hand.** Its checks all passed, but it is not code yet.
- **Three agents at once, not ten.** Rate limits at demo scale are unmeasured.

## What is left to build

| Part | Work |
| --- | --- |
| Demo fleet | Eight to ten small services, with a mix of affected, unaffected and hidden-route cases. Verify by hand that every flaw triggers on the demo machine before any agent sees it |
| Per-repository agent | The prompt, the rules, the sandbox, and the verdict format. A second hook is needed to restrict the file tools |
| Workflow and gate | The full pipeline as one workflow: read the advisory, fan out, run the gate as code, pause for approval |
| Grid | A web page that starts a run and shows one tile per repository, live |
| Report and pitch | The early-warning draft, the timer, the slides and the three-minute story |

Agree the verdict format before splitting up, since the agent, the grid and the report all depend on it. The current draft is in [docs/architecture.html](docs/architecture.html).

## The demo

1. Paste a real advisory into the tool.
2. A grid of repositories fills in live with the verdicts.
3. Open an "affected" tile: show the forged request being accepted, then the proof test failing.
4. Show the fix, and the same test passing.
5. Open a "not affected" tile and read the reason.
6. Approve the drafted early warning, with a timer showing minutes used against the 24 hours.

Aim for at least one repository where the flaw is reachable by a route a text search would miss. That tile is the centre of the demo.

## Bonus track: Mistral Workflows and Agents

- **Workflows is the orchestrator.** It gives us the parallel fan-out, a run that survives a crash, the pause for a person's approval, and a live timeline in Studio. All of these are tested above.
- **Agents is a candidate for the advisory reader.** The Agents SDK (`mistralai-agents`) can return the advisory facts as a typed result. Not tried yet.
- **The per-repository agent stays on Vibe,** because that is where all our evidence is.

## Risks

- **Preparing the fleet is real work.** A published flaw does not always trigger on the demo machine, so every sample must be verified by hand first.
- **A wrong "not affected" is the dangerous failure.** The tool must say "no reachable path found", never "safe".
- **Judges may have seen similar.** Mistral shows a single-report version of this, and commercial tools check reachability (see below). Our difference has to be visible in the demo: the whole fleet, proof by running code, and the regulatory report.
- **A staged fleet looks staged.** Include at least one real open-source project if time allows.
- **Workflows is in public preview.** Mistral says its API can still change. If it misbehaves, fall back to a plain Python orchestrator.
- **Guardrails may change.** Mistral says it is still adjusting them.

## Scope rules

- Run proof tests only against our own code, in an isolated environment.
- Use only publicly known flaws.
- Proof inputs must be harmless: create an empty marker file, or get a forged request accepted.
- Do not post anything to third-party issue trackers automatically.

## What already exists

Reachability analysis and automated fixes are a crowded commercial market.

- **Reachability by code analysis:** Semgrep, Snyk and Endor Labs.
- **Agents that open fix pull requests:** Snyk, Endor Labs, ZeroPath and Kilo.

Three things set this project apart:

- **Proof by running code.** One search found no tool that produces a working test demonstrating the flaw. That search covered mostly vendor pages, so treat it as a lead, not a fact.
- **It runs on your own infrastructure with an open-weight model.** A map of unpatched vulnerabilities is among the most sensitive data a company holds.
- **The deliverable includes the regulatory report,** not only a patch.

## Technical setup

The test code is not in this repository yet. Its paths are hard-coded to one machine, so it needs tidying before it is added.

### Voxtral Voice Input (NEW!)

The project now supports **voice input for security advisories** using Mistral's Voxtral speech-to-text model. This allows security engineers to dictate advisories instead of typing them, saving valuable time during the 24-hour response window.

**Features:**
- Dictate advisories directly via browser microphone
- Upload audio files for transcription (WAV, MP3, OGG, etc.)
- API-based transcription using Mistral's hosted service
- Local inference option for offline/private use (Apple Silicon with MLX)

**Setup:**
```bash
# For API-based transcription (recommended for hackathon)
export MISTRAL_API_KEY="your-api-key"
pip install httpx pyaudio

# For local inference (optional, requires ~8-10GB model weights)
pip install mlx-voxtral mlx
```

**Usage:**
1. Open http://localhost:8000
2. Click the "🎤 Voice" button
3. Click the microphone and start dictating
4. Review the transcription
5. Start the run!

See [voxtral/README.md](voxtral/README.md) for detailed documentation.

### Components

| Piece | Notes |
| --- | --- |
| Vibe 3.1.3, isolated install | With its own home folder, selected with the `VIBE_HOME` environment variable, so the normal `~/.vibe` is untouched |
| Sandbox hook | A `pre_tool` hook that rewrites every shell command to run through the wrapper |
| Sandbox wrapper | Runs the command under the macOS sandbox with a scrubbed environment |
| Sandbox profile | No network; writes only inside the work area and temporary folders |
| Offline packages | Fixed versions downloaded beforehand into a local folder, because the sandbox has no network |
| Workflows worker | A Python process that registers the workflow and runs one activity per repository |
| Per-service prompt | Carries the rules and the `verdict.json` format |

### The Vibe command each activity runs

```sh
VIBE_HOME=<vibe-home> vibe \
  --workdir <work-copy> --trust \
  --prompt-file <prompt> \
  --model mistral-large-4-0 \
  --output text --output-dir <out> \
  --max-turns 80 --max-price 3 --time-limit 560 \
  --disabled-tools connector_web_search_web_search \
  --disabled-tools connector_web_search_open_url \
  --auto-approve
```

`--output-dir` writes an `export.json` with token usage, cost and outcome, which the activity returns to the workflow.

### Things learned about Vibe

- **A hook can sandbox shell commands without changing Vibe.** Background commands are covered too.
- **The allowlist sees the rewritten command.** The wrapper's path must be added to `[tools.bash] allowlist` in Vibe's config, or every command asks for approval.
- **File tools bypass the shell sandbox.** `read_file`, `write_file` and `edit` are not wrapped. A second hook is needed to restrict their paths.
- **Web tools have longer names than expected.** To disable them, use `connector_web_search_web_search` and `connector_web_search_open_url`.
- **Vibe passes its `.env` contents to shell commands.** The wrapper's scrubbed environment stops that.
- **Vibe stops cleanly on SIGTERM** and still writes its `export.json`.
- **Only macOS was tested.** Linux would need `bwrap` in place of the macOS sandbox.

### Things learned about Workflows

- **No CLI is needed.** `uv add mistralai-workflows` and a Python worker are enough.
- **Start a worker** with `MISTRAL_API_KEY` and `DEPLOYMENT_NAME` set, calling `workflows.run_worker([...])`. Workflows register themselves when it starts.
- **Parallel activities work with plain `asyncio.gather`.** The worker's default limit is 100 activities at once.
- **An activity can run any local program,** which is how it starts Vibe inside our sandbox.
- **For a long activity,** set `start_to_close_timeout`, `heartbeat_timeout` and `retry_policy_max_attempts=1`, and call `workflows.activity_heartbeat(...)` while Vibe runs.

### Model access and the API key

- The tests used a pay-as-you-go Mistral API key, kept in a `.env` file inside the Vibe home folder.
- **Never commit that `.env` file.** Add it to `.gitignore` before any code lands here.
- Pricing at the time: $0.70 per million input tokens, $0.07 cached, $2.10 output.

## Open questions

- What rate limits apply to Large 4 at the venue?
- What must be submitted: repository, video, slides, live demo? How long is the demo slot?
- What are the judging criteria?

## Sources

- [Luma: Le Chonk in London, Mistral Vibe Hackathon](https://luma.com/le-chonk-in-london)
- [Mistral: Cybersecurity](https://mistral.ai/industry/cybersecurity/)
- [Mistral: Large 4 (Le Chonk) is now open weight](https://mistral.ai/news/mistral-large-4-oss/)
- [Mistral: Sovereign AI](https://mistral.ai/sovereign-ai/)
- [Mistral docs: Workflows](https://docs.mistral.ai/studio/workflows/overview)
- [Mistral docs: Agents](https://docs.mistral.ai/studio/agents/overview)
- [European Commission: CRA reporting](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting)
- [Freshfields: CRA reporting obligations take effect on 11 September 2026](https://www.freshfields.com/en/our-thinking/blogs/technology-quotient/cyber-resilience-act-reporting-obligations-take-effect-on-11-september-2026-102nzmk)
- [Irish NCSC: EU Cyber Resilience Act](https://ncsc.gov.ie/cra/)
- [Heuking: new CRA reporting obligations](https://www.heuking.de/en/news-events/newsletter-articles/detail/cyber-resilience-act-diese-neuen-meldepflichten-kommen-auf-betroffene-unternehmen-ab-september-zu.html)
- [GitHub Advisory Database](https://github.com/advisories), for CVE-2026-96760 (Authlib)
- [Semgrep Supply Chain](https://try.semgrep.dev/supply-chain/)
- [Endor Labs: AI vulnerability remediation](https://www.endorlabs.com/learn/ai-vulnerability-remediation)
- [Snyk: VulnBump](https://snyk.io/blog/vulnbump/)
- [ZeroPath: reachability and exploitability triage](https://zeropath.com/blog/reachability-exploitability-triage)
- [Kilo: why most dependency alerts don't matter](https://blog.kilo.ai/p/why-most-dependency-alerts-dont-matter)
