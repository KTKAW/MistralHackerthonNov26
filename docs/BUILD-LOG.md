# Build log

## Track C: orchestrator, gate, report, web (21 November 2026)

Built against the pinned contracts in `docs/COORDINATION.md` and `mistralai-workflows` 3.20.0.
Track A was not merged when this was written, so the per-repository worker is a stand-in.
The fleet is five apps in their own repositories, fetched into a gitignored folder: see
`docs/FLEET.md`. It ran end to end on Mistral's hosted Workflows on 21 November, with that
stand-in (step C6).

### What is here

| File | What it is |
|---|---|
| `orchestrator/workflow.py` | The `le_chonk_run` workflow, its six activities and the worker entrypoint |
| `orchestrator/steps.py` | The steps as plain functions. Both orchestrators call these |
| `orchestrator/advisory.py` | The advisory reader: one model call, and a strict check of the answer |
| `orchestrator/gate.py` | `gate(run_id, verdicts, *, runs_root, wheelhouse)`. No model |
| `orchestrator/report.py` | `render_early_warning(run_id, gated_verdicts, *, runs_root)`. No model call |
| `orchestrator/local.py` | Step C8: the same run in plain Python, for when Workflows misbehaves |
| `orchestrator/stub_agent.py` | A stand-in for track A's `run_repo`. It reads answers from `orchestrator/stub_answers.json` |
| `orchestrator/fleet.json`, `orchestrator/fetch_fleet.py` | The five demo apps, pinned by commit, and the script that fetches them |
| `docs/FLEET.md` | The fleet: how to get it, the wheelhouse, the ground truth |
| `orchestrator/pull_request.py` | Opens a draft pull request with a fix the gate has verified. Off unless `LE_CHONK_PULL_REQUESTS=draft` |
| `orchestrator/events.py` | A run's event log, `runs/<run>/events.jsonl`: every step as it happens |
| `web/app.py`, `web/page.html` | The page on `:8000`: the grid, the live activity stream and the inspector |
| `pyproject.toml`, `uv.lock` | Dependencies. `uv sync` installs them |

### How to run it

The worker. It refuses to start without the three variables. `DEPLOYMENT_NAME` is any name you
choose: it becomes the task queue the worker listens on, and the web server must use the same one.

```sh
MISTRAL_API_KEY=... DEPLOYMENT_NAME=... OTEL_ENABLED=false uv run python -m orchestrator.workflow
```

The web page, in a second terminal, sharing the same `runs/` folder:

```sh
MISTRAL_API_KEY=... DEPLOYMENT_NAME=... uv run python -m web.app
```

Without Mistral Workflows at all (step C8), one process:

```sh
LE_CHONK_ORCHESTRATOR=local MISTRAL_API_KEY=... uv run python -m web.app
```

Until track A is merged, add the stand-in worker to whichever process runs the activities:

```sh
LE_CHONK_RUN_REPO=orchestrator.stub_agent:run_repo LE_CHONK_ALLOW_UNSANDBOXED=1
```

To have the run propose each verified fix as a draft pull request, add this to the process that
runs the activities. That machine needs `git` and `gh` signed in with push access to the apps:

```sh
LE_CHONK_PULL_REQUESTS=draft
```

`LE_CHONK_ADVISORY_JSON=orchestrator/tests/fixtures/advisory.json` skips the model call, so a
run needs no key. Other settings are in `orchestrator/config.py`.

The tests need the fleet and a wheelhouse, which are not in this repository:

```sh
uv run python -m orchestrator.fetch_fleet     # the five apps, into runs/_fleet
# build wheelhouse/ as docs/FLEET.md says, then:
uv run pytest
```

### What was checked, and how

- **84 tests pass** (`uv run pytest`, about 140 s), on the eleven-app fleet.
- **It ran on Mistral's hosted Workflows with the five-app fleet**, 21 November: the model read
  the advisory, the five activities started within 234 ms, and 21 s after the start the run was
  waiting for approval with five tiles: `auth-gateway` and `billing-api` affected, proven and
  fixed; `session-service` and `token-signer` no reachable path found; `profile-api` needs a
  human. The gate's re-runs were real; the verdicts came from the stand-in.
- **Earlier the same day it ran on the hosted service with track B's eight-service fleet**
  (step C6). The measurements in this item, in the crash item and in the fallback item below
  were taken on that fleet. Deployment `le-chonk-track-c`, worker on a laptop:
  - The worker connected to Mistral's scheduler and registered `le_chonk_run` and its six
    activities.
  - A run started from the page (`execute_workflow` through the `mistralai` client). The page
    showed `RUNNING`, then `COMPLETED` after approval.
  - `mistral-large-4-0` read the advisory in 3 to 30 s and returned the four facts. An advisory
    with an instruction added for "automated triage" produced the same four facts.
  - The eight repository activities started within 170 ms of each other. With a 4 s stand-in,
    all eight were through the gate 15 s after triage began.
  - The `approve` signal sent from the page ended the pause. The run's result and the `state`
    query both came back through the client.
  - A failed step shows up: before the fix below, the advisory call was refused, the run ended
    `FAILED` on Mistral and the page showed the reason.
- **Crash and resume, measured.** All eight triage activities were in flight when the worker
  got `kill -9`. A new worker was started straight away.
  - The run stayed `RUNNING` on Mistral. Intake and the advisory read were not repeated: no
    second model call, and `advisory.json` was not rewritten.
  - 56 s after the kill, all eight in-flight activities failed on the 60 s heartbeat timeout.
    So the heartbeat does shorten recovery: it is the heartbeat timeout, not the 900 s activity
    timeout.
  - Because triage has one attempt, those eight became `needs_human`, and the run went on to
    the gate, the report and the approval pause on the new worker. **A crash does not lose the
    run, but it sends every repository that was in flight to a person.** See decision 14.
- **The workflow class itself runs.** `orchestrator/tests/test_workflow.py` runs `LeChonkRun`
  inside the SDK's workflow sandbox on Temporal's local test server, through the SDK's own
  `create_test_worker`. Three repositories fan out and start within a second of each other. The
  run stays `RUNNING` until `approve` arrives, and an approval sent before the draft exists
  changes nothing. With no approval, the test server skips 24 hours and the run ends as
  `expired`. A worker that raises, and a bogus proof, both end as `needs_human` without failing
  the run.
- **The gate was run against the five apps**, with claims written by the stand-in:
  - `billing-api`, the hidden route: the proof exits 1 on authlib 1.8.0 and 0 on 1.9.0, the suite
    passes after the fix, 9 tests collected before and 10 after. The verdict stands.
  - Negative test: a proof that passes on the vulnerable version too is downgraded to
    `needs_human` on `proof_fails_on_vulnerable`.
  - A `not_affected` claim whose work copy has an edited file is downgraded on `no_diff`.
- **The plain-Python fallback** ran all eight services end to end in 18 s, with a stand-in that
  takes 2 s per repository. The eight workers started within 3 ms of each other.
- **The page** was driven in a browser on the fallback: start, pending placeholders, tiles after
  the gate, the clock, approval.

### What was NOT checked

- **A real agent.** Every run so far used the stand-in for track A's `run_repo`. Eight stand-in
  activities at once say nothing about eight model-driven agents at once, or any rate limit.
- **`sandbox/douane`.** The gate was tested with a wrapper that has the same interface and no
  sandbox. The live runs used `LE_CHONK_ALLOW_UNSANDBOXED=1`.
- **The Studio timeline.** Nobody looked at the run in Mistral's console.
- **The 24-hour expiry on the hosted service.** It was tested on Temporal's local test server,
  which can skip time.
- **Worker and web server on different machines.** They share `runs/` on one disk.

### Decisions that go beyond the brief

1. **The gate runs per repository, straight after its triage**, not once after all of them.
   Tiles appear as each repository clears the gate. `gate()` still takes a list.
2. **How the gate builds its two states.** Vulnerable: the fleet's copy of the repository plus
   the files the agent added, with the fleet's requirements. Fixed: the agent's work copy with
   its requirements, plus `package==fix.target` for an upgrade. The gate never uses the agent's
   environment, so editing the installed library gains an agent nothing.
3. **`proof_passes_on_fixed` is enforced for `affected_fixed` only.** For `affected_proven`
   there is no fix to pass on. The gate still tries the proof on the newest wheelhouse version
   outside the affected range and records the result. `ENFORCE_FIXED_PASS_FOR_PROVEN` in
   `gate.py` flips this.
4. **A test file that existed before must be byte-identical.** Proof tests belong in new files.
   An agent that adds a test to an existing file is sent to a human.
5. **Requirements the gate will install are plain pins only.** A line with `-e`, a path or a URL
   could run code outside the sandbox at install time, so it fails the gate.
6. **The gate fails closed without the sandbox.** If `sandbox/douane` is missing it will not run
   agent-written tests, and `affected_*` claims become `needs_human`.
   `LE_CHONK_ALLOW_UNSANDBOXED=1` exists for tests with the stand-in only.
7. **An approval before the draft exists is ignored**, in the workflow and in the web API (409).
8. **`execution_timeout` is 26 hours.** The SDK's default is 1 hour, which would kill the run
   long before the 24-hour wait ends.
9. **The triage activity returns a slim `usage`**, not Vibe's whole `export.json`. Activity
   results are limited to 2 MB. The full export stays in `runs/<run>/<repo>/vibe/`.
10. **A rejected claim is never repeated as a result.** The grid and the report say which gate
    rule failed and show nothing the agent claimed. The inspector does show the claim, under a
    notice that the gate rejected it, because that view exists to look under the hood.
11. **The advisory reader's answer is held to four short strings with fixed patterns.** The
    advisory is untrusted text and its facts go into every agent's prompt.
12. **The web server listens on 127.0.0.1 and takes JSON only on POST.** It has no sign-in.
13. **`pyproject.toml` pins a dependency cooldown** (`exclude-newer`), and `mistralai-workflows`
    to 3.20.0. Move the date forward to take newer releases.
14. **A worker crash is not retried.** The brief gives triage one attempt, so a repository whose
    worker died goes to a person. That is the safe reading, and it is expensive in a demo: one
    crash turned eight tiles to "needs a human". A second attempt only after a heartbeat
    timeout, on a wiped work copy, would let those repositories run again. Not done: it changes
    the brief's one-attempt rule, and `run_repo` would have to clear `src/` first.

### Three fresh advisories and six more apps (21 November)

The fleet grew from five apps to eleven, and from one advisory to four. See `docs/FLEET.md`.

- **Where the advisories came from.** GitHub's advisory database, reviewed `pip` advisories of low
  and moderate severity published 1 to 21 November 2026: 72 rows. Three were chosen because each
  can be shown with a harmless input and a test that does not depend on timing: Tornado
  (CVE-2026-126347, low), Soup Sieve (CVE-2026-126193) and mail-parser (CVE-2026-129300).
  Timing-based denial-of-service advisories were left out: a proof that measures time is flaky.
- **Each was reproduced first**, on the old and the fixed version, before any app was written.
- **Five apps were built**, each by a separate builder and then checked again on a clean copy:
  an exposed and a not-exposed app for Tornado and for Soup Sieve, and a not-exposed app for
  mail-parser (the package is pinned and nothing imports it).
- **The sixth was built by hand, later.** The builder for `mail-intake`, the exposed mail-parser
  app, was stopped by a safety check at its first command and wrote nothing. It was reported, and
  the app was then written directly once the person running the session said to. Its first
  version listed the `Received` hops in the wrong order; its own test caught that.
- **The stand-in now answers per advisory.** An answer belongs to the advisories it names. For
  any other advisory the stand-in checks `requirements.txt` for the package: not listed means
  "no reachable path found", with that as the reason; listed means it asks for a person.
- **The reader normalises a version range** to comma-separated bounds. The live model wrote
  `>=3.7.0 <4.6.3` and `>=0.4, <3.0.2`.

Checked: the gate proved and fixed the Tornado and Soup Sieve flaws on the fetched apps (the
proof exits 1 before and 0 after, the suite passes). Three runs on Mistral's hosted Workflows,
each started by typing only the CVE identifier, ended with a tile for every app:

| Typed | Affected, proven and fixed | Has the package, not exposed | Package not pinned | Draft pull request |
|---|---|---|---|---|
| `CVE-2026-126347` | `link-redirector` | `docs-portal` | 8 apps | on `link-redirector` |
| `CVE-2026-126193` | `html-extractor` | `link-checker` | 8 apps | on `html-extractor` |
| `CVE-2026-129300` | `mail-intake` | `ticket-mailer` | 9 apps | on `mail-intake` |

The Soup Sieve run took 136 s, most of it the one model call. The Tornado run took 41 s. The
mail-parser run, repeated with eleven apps once `mail-intake` existed, took 94 s.

### A pull request for each verified fix (21 November)

The workflow has one more step. When the gate passes a claim of "affected and fixed", the run
opens a draft pull request with that fix on the app's own repository. The card, the inspector
and the draft early warning link to it.

What may go into a pull request:

- **Only what the gate checked.** Each changed or added file must be byte-for-byte the file in
  the gate's fixed state. A work copy that changed after the gate ran is refused.
- **Nothing under `.github/`.** A pull request from this tool must not change what CI runs.
- **None of the worker's own words.** The title, the commit and the body are built from checked
  values: package, version, advisory identifier, file names, test names, exit codes. The
  worker's reason and notes are left out, because they are untrusted and GitHub notifies anyone
  a pull request names with "@". The advisory facts come from the tool's own `advisory.json`,
  not from the copy in the worker's verdict.
- **One commit, on a branch** named `le-chonk/<advisory>-<run>`, on top of the commit the run
  inspected. The default branch is never touched. It is a draft. Nothing merges it.

Decisions:

- **It is off by default**, and the switch is read once, at intake, so a replayed workflow
  decides the same way. Runs started before this step existed are not affected.
- **It opens straight after the gate, not after the person's approval.** The approval in this
  workflow is for the early warning. A draft pull request is itself a proposal for a person.
  Waiting for the approval instead would be a small change in `workflow.py`.
- **A failure to open one never fails the run.** The reason is recorded and shown.
- **One open proposal per advisory and repository.** If an earlier run's pull request for the
  same advisory is still open, a later run links to it and pushes nothing. It does not compare
  the two fixes.
- **Credentials:** the step uses `git` and `gh` as they are signed in on the machine. It never
  reads a token, and the worker has finished before it starts.
- **The pull request says how it was made.** With the stand-in worker it says so in bold.

Checked: 12 tests against a repository made on the spot, with GitHub faked; the real workflow
class on Temporal's test server ran the step for the two fixed apps and not for the third; and
one run on Mistral's hosted Workflows opened two real draft pull requests, on `auth-gateway`
and `billing-api`. Each was one commit with two files (`requirements.txt` and the proof test),
and each default branch stayed where it was. A second run on the hosted service then linked
to those two pull requests and opened no new ones.

Not checked: a patch-type fix (only the upgrade has been proposed), a repository whose default
branch has moved since the run started, and a repository with branch protection.

**A risk for whoever turns this on.** Opening a pull request can start the repository's CI, and
CI then runs the worker's proof test. On a branch of the same repository, CI may have the
repository's secrets. The five demo apps have no CI. For a real repository, decide first whether
agent-written tests may run there, or change the step to propose from a fork.

### The page, second version (21 November)

What it shows now:

- **Each repository's card** has a link to the repository and to the commit the run inspected.
  Every step of a cited code path links to that exact line on GitHub, at that commit. A file
  the worker wrote itself gets no link, because it is not on GitHub.
- **Progress while it happens.** A card shows which phase its repository is in (agent, gate,
  verdict) and the latest step. A stepper shows the run: intake, advisory read, agents, gate,
  draft, approval. An activity panel lists every event, and can be filtered by who wrote it.
- **Under the hood, per repository.** A side panel with five views: the timeline; every gate
  rule with its measured detail; what the worker changed (new files in full, changed files as
  a diff); what the worker claimed; and the raw gate log and worker export.

Where it comes from:

- `runs/<run>/events.jsonl`, appended to by three writers: the run's steps, the gate, and the
  worker. `GET /runs/{id}/stream` sends it as server-sent events and ends when the run closes.
- `GET /runs/{id}/repos/{repo}/detail` reads the verdict files, compares the work copy with the
  fleet's copy, and returns the last part of the gate's log.
- Links are built on the server from `orchestrator/fleet.json` and the commits actually fetched.
  Only `https://github.com/` addresses become links.

Checked: in a browser on the local fallback and on Mistral's hosted Workflows, light and dark,
at 1360 and 375 pixels wide. A five-app run on the hosted service produced 91 events, and the
cards followed them live. A link was opened on GitHub and pointed at the cited line.

Not checked: a real agent's progress lines (only the stand-in has reported any), more than one
person watching a run, and a run with thousands of events (the activity panel keeps the last 600).

**For track A:** whatever short text `run_repo` passes to `heartbeat_fn` appears on the page as
that repository's progress, marked "worker". For example `heartbeat_fn("reading src/app.py")`.
It is cut to 400 characters, and one repository can add at most 300 lines. It is shown as
text and nobody checks it, so it must not be where a verdict is announced.

The stand-in reports only what it really does: that it copied the app, that it is waiting, that
it looked the answer up, which files it wrote. It does not pretend to read code.

### What the switch to five apps changed

- **The tool reads `runs/_fleet/` when it exists.** `LE_CHONK_FLEET_ROOT` still wins. Without
  either it falls back to `fleet/`.
- **Apps are fetched at a pinned commit**, as plain files without `.git`. A folder that is
  already there is never overwritten.
- **The stand-in writes a self-contained proof test.** It used to call a script in the app's own
  `proof/` folder. Now the test holds the forged token and the request, as an agent's would.
- **The stand-in can say "needs a human"**, for `profile-api`. The draft report then gives the
  worker's reason and the path it followed, marked as not verified by the gate. A claim the gate
  rejected is still never repeated.
- **`billing-api` as first built had a customer named "attacker"**, so that the forged token would
  resolve. That was removed before the app was published. The forged token for that app claims
  to be an existing customer instead.

### What the live run changed

- **`top_p=1` on the advisory call.** The API refuses `temperature=0` unless `top_p` is 1, and
  the default for `mistral-large-4-0` is not 1. Any other call at temperature 0 needs the same.
- **The reader is asked for exactly one identifier.** Given an advisory with a GHSA and a CVE
  identifier, the model first answered with both in `id`, and the check stopped the run. The
  prompt now asks for the CVE identifier when there is one.
- **The package name is normalised.** The model spells it as the advisory does ("Authlib").
  Later steps get the registry's spelling ("authlib").
- **A tile for a lost worker says so**: "the worker process stopped responding", not the name
  of an exception class.
- **The reader's facts must be in the advisory's own text.** Given an advisory that names no
  function (urllib3, CVE-2023-43804), the model supplied
  `urllib3.connectionpool.HTTPConnectionPool.urlopen` from memory. That would have gone into
  every agent's prompt, and into the draft as "see ... in the advisory". The identifier, the
  package and the function name are now looked for in the text, and the run stops if one is
  missing. A person can then supply the four facts with `LE_CHONK_ADVISORY_JSON`.

### What the reader accepts, tried on the live model

| Advisory | Result |
|---|---|
| Authlib, CVE-2026-96760, with or without the GHSA identifier | Four facts, `<1.9.0`, `JsonWebSignature.deserialize_json` |
| The same with an instruction added for "automated triage" | The same four facts |
| Requests, CVE-2023-32681, function named | `>=2.3.0,<2.31.0`, `requests.sessions.rebuild_proxies` |
| Jinja2, CVE-2024-22195, the flaw is a template filter | `<3.1.3`, `xmlattr` |
| `Authlib, CVE-2026-96760`, an identifier and nothing else | Looked up at OSV, then the four facts, `<1.9.0`, `JsonWebSignature.deserialize_json` |
| "There is a signature bug in Authlib", no identifier | Stopped, with a message naming the three missing facts |
| urllib3, CVE-2023-43804, no function named | Stopped: the function is not in the text |
| urllib3 with two affected ranges | Stopped: the model wrote `<1.26.17 \|\| >=2.0.0 <2.0.6` |
| A note about a meeting | Stopped: no identifier |

- **An identifier alone is looked up.** A person typed `Authlib, CVE-2026-96760` and the run
  failed with "unusable 'affected_range': ''", which said nothing about what to do. Now a text
  under 300 characters with a CVE or GHSA identifier in it is looked up at OSV
  (`api.osv.dev/v1/vulns/<id>`), the GitHub advisory beside a CVE record is fetched too, and the
  model reads those records. Only the identifier is sent. The record is untrusted like any other
  advisory text, and the facts must still be found in it. `LE_CHONK_ADVISORY_LOOKUP=0` turns it
  off. If the lookup fails, the run goes on with the typed text and says so in the event log.
  This is the tool's only outbound request besides the model call.
- **A missing fact is named.** The reader is told to leave a fact empty rather than fill it from
  memory, and the run then stops with a message that says which facts the text lacks.
- **Two affected ranges stop the run.** A version specifier cannot say "or", and neither the
  check nor the gate handles a list of ranges. Not fixed.
- **The call took 3 to 106 s.** The activity allows 180 s and one attempt.
- Only the Authlib advisory means anything further down today: the fleet pins Authlib, and the
  stand-in reads the fleet's answers whatever the advisory says.

### For track A

- **Heartbeats.** `temporalio.activity.heartbeat` only works in the activity's own context. A
  bare thread calling `workflows.activity_heartbeat` raises, and the skeleton in
  `docs/build-prompt.md` swallows that, so no heartbeat would ever be sent and the activity
  would be killed after 60 s. The `heartbeat_fn` this track passes to `run_repo` is safe to
  call from any thread, and the activity also heartbeats on its own every 10 s.
- **`run_repo` blocks**, so the activity runs it in a thread. That is what lets the other
  repositories start at the same moment.
- **The gate calls the wrapper as** `sandbox/douane '<one shell command>'` with
  `SANDBOX_WORKDIR=runs/<run>/<repo>/gate/vulnerable` (or `/fixed`). The environment is inside
  that folder, at `.venv`. The sandbox profile must also allow reading the base interpreter
  that `uv venv --python 3.12` links to, under `~/.local/share/uv/python/`.
- **Put proof tests in new files**, and keep `requirements.txt` to plain pins.

### The fleet no longer gives the answer away

Track B's eight services each stated their own verdict in `README.md` and carried a `proof/`
folder, so an agent could read the answer. The five apps that replace them hold neither. The
answers are in `orchestrator/tests/fixtures/fleet_answers/` and `orchestrator/stub_answers.json`,
which an agent never sees.

- The gate's exception for a work copy without `README.md` or `proof/` is gone. A file missing
  from a work copy is a deleted file.
- **For track A:** copy an app's folder as it is. There is nothing to leave out any more.
- The eight-service fleet on `build/track-b-fleet` is not used by the tool once
  `runs/_fleet/` exists. `LE_CHONK_FLEET_ROOT=fleet` points back at it, but the stand-in has no
  answers for those names and the tests no longer use them.

### Other findings

- The wheelhouse is for Python 3.12 (`pydantic-core` wheels are per version). The gate builds
  its environments with `uv venv --python 3.12`; `LE_CHONK_PYTHON` changes that.
- Upgrading authlib to 1.9.0 fixes CVE-2026-96760. OSV lists two other advisories for 1.8.0
  that are fixed only in 1.9.1, so a judge may ask why the fix stops at 1.9.0.
- CVE-2026-96760 is not in CISA's exploited-vulnerabilities catalog (version 2026.11.20). The
  24-hour duty is for actively exploited vulnerabilities, so the draft leaves "basis for active
  exploitation" for a person to fill in.
- The early warning itself needs little: Article 14(2)(a) asks for the Member States where the
  product is available. The draft also carries notes for the 72-hour notification.

### Moved to the design's run contract (21 November)

The design branch pinned a run contract after this build was written: `docs/contract.md`, with
its schemas and helpers in `src/vulnerability_agent/` (three commits from `dev-matteo`, brought
over unchanged). This build now writes that contract. The old `schema/verdict.schema.json` and
its two examples are gone.

What a run leaves on disk now:

| File | Owner | Was |
|---|---|---|
| `run.json` | orchestrator | Held the page's working state. It is now the contract's record only: clock start, workflow run id, fleet, approved-at, expired-at |
| `orchestrator.json` | orchestrator | New. The working state the page polls (stage, counts, advisory text). Not part of the contract |
| `advisory.json` | orchestrator | Four facts under other names, plus where they came from. Now the contract's five facts and nothing else: the fixed version is new |
| `advisory.source.json` | orchestrator | New. Model or file, and any OSV record that was read |
| `<repo>/verdict.json` | worker | Was rewritten by the gate. Now agent-owned fields only, and never touched after the worker wrote it |
| `<repo>/state.json` | orchestrator | New. The final verdict, each gate rule's result, usage, and the saved proof output. The page and the report read the verdict from here |
| `<repo>/proof/` | worker | New. Proof tests used to be new test files inside the work copy |
| `<repo>/fix.diff` | orchestrator | New. `src/` against the fleet copy, computed by the gate |
| `<repo>/gate/` | gate | Each baseline now has the layout of a repo-run root: `src/`, `proof/`, `venv/` |

What changed in behaviour:

1. **The gate's rules follow the spec.** `no_test_pass_to_fail_between_baselines` replaces "the
   suite passes" and "no test disappeared": the repository's own tests run on both baselines and
   are compared test by test. `cited_path_exists` checks every cited file and line of a "not
   affected" verdict, not only that a path is cited. `installed_library_matches_wheelhouse`
   compares the worker's own `venv/` with the wheel, file for file, when the worker left one.
   `proof_in_proof_folder` refuses a proof that sits inside the work copy.
2. **A proof says what it expects.** Each proof entry carries `on_vulnerable` and `on_fixed`. The
   gate requires the outcome it measured and the claim to agree.
3. **A worker that did not finish is not believed.** If the activity failed or timed out, the
   gate writes a "needs a human" state itself and reads nothing the worker left, even a
   `verdict.json` that a process outliving its activity wrote later.
4. **Every rule in `state.json` decides the verdict.** Checks that were recorded and not
   enforced (the wording of a "not affected" reason, an application change without a claimed
   fix, the proof on the fixed version for "affected and proven") now go to the event log only.
5. **At most ten repositories at a time**, the design's default. `LE_CHONK_MAX_PARALLEL` changes it.
   The workflow takes the number from the intake step, so a replay decides the same way.
6. **The fixed version comes from the advisory.** The reader asks for it and requires it to be
   in the advisory's own text, like the identifier, the package and the function. The gate uses
   it where it used to pick the newest wheel outside the affected range.
7. **A pull request carries `fix.diff` and nothing else.** The proof test lives outside the work
   copy, so it stays with the run. The version in the title is read from the work copy's
   `requirements.txt`, not from the worker's description of its fix.
8. **The stand-in writes the same layout**, with its verdict checked against the contract's
   schema before it is written. It no longer has built-in advisory facts: without the run's
   `advisory.json` it stops.

Checked: 121 tests pass, among them the contract's own 24. A run in the browser on the plain
fallback with the stand-in and the eleven-app fleet ended with eleven tiles (2 fixed, 7 with no
reachable path found, 2 for a person), the clock, and links to the cited lines on GitHub.

Not checked: a run on Mistral's hosted Workflows with this contract (no key on the machine this
was written on), whether the live model returns the fixed version for a pasted advisory, and a
real agent.

Not done from the spec: replay of a saved run from `fixtures/`, and killing orphaned Vibe
processes when a worker dies.
