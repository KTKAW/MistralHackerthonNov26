# TRACK A — Sandbox + per-repository worker

Branch: `build/track-a-sandbox-worker` · You are build agent **1 of 3**.

## Launch (your human, YOUR OWN Mistral key)

```sh
git checkout build/track-a-sandbox-worker
export MISTRAL_API_KEY=sk-...     # your own subscription key — never commit it
export OTEL_ENABLED=false
vibe --prompt-file docs/prompts/track-a-sandbox-worker.md --workdir . --trust \
  --auto-approve --model mistral-large-4-0
```

## Read first

`PROJECT.md` · `docs/architecture.html` · `docs/COORDINATION.md` · `docs/build-prompt.md`
(the master plan — your work is the detailed version of its **Steps 3, 4 and 5**; reuse its
code blocks verbatim as starting points, and follow every `ADAPT` note against the real
Vibe 3.1.3 hook interface).

## You OWN — edit only these

- `sandbox/sandbox2.py` — `pre_tool` hook: rewrite every `bash`/`process_start` command to run
  through `douane`; strict — deny the call if the rewrite fails.
- `sandbox/douane` — wrapper: `env -i` scrubbed environment, then `sandbox-exec -f <profile>`.
- `sandbox/profile.sb.template` — macOS Seatbelt profile with a `__WORKDIR__` placeholder:
  deny `network*`; writes only inside the work copy + `/tmp`; deny reads of `.env` and `secrets/`.
- `sandbox/path_hook.py` — the file-tool hook (the dashed "to build" box in the architecture
  diagram): `write_file`/`edit` only inside `$SANDBOX_WORKDIR/src/`; `read_file` never `.env`,
  `secrets/`, or anything outside the work copy.
- `worker/prompt.md` — the per-repo agent prompt: 3 rules + stages
  read → trace → prove → fix → re-verify + the `verdict.json` output contract.
- `worker/run_repo.py` — fresh work copy + offline venv + one headless Vibe + 10 s heartbeat.
- `vibe-home/` — gitignored isolated Vibe home for the spawned workers; register both hooks
  there and add the **absolute path of `douane`** to `[tools.bash] allowlist` (otherwise every
  rewritten command stops for approval).

## Do NOT touch

`schema/` (shared contract, already on `build/base`), `fleet/` (track B — for self-tests use a
throwaway service under `runs/selftest/`, which is gitignored), `orchestrator/`, `web/`
(track C), `.gitignore` (already on base).

## Pinned interface contract — track C codes against this; do not change it

```python
def run_repo(run_id: str, repo: str, *, fleet_root="fleet", runs_root="runs",
             vibe_home="vibe-home", heartbeat_fn=None) -> dict:
    # work copy:  runs/<run_id>/<repo>/src
    # outputs:    runs/<run_id>/<repo>/verdict.json        (valid vs schema/verdict.schema.json)
    #             runs/<run_id>/<repo>/vibe/export.json     (tokens, cost, outcome)
    # returns:    {"repo": repo, "rc": int, "verdict": dict, "export": dict}
```

`worker/prompt.md` must tell the agent to read `../advisory.json` and write `verdict.json` at
the work-copy root.

## Non-negotiable rules

1. Never commit `.env`, `vibe-home/`, `runs/`, `wheelhouse/`.
2. Proof tests only against our own code, isolated. Publicly known flaws only. Harmless proof
   inputs only. Never auto-post to third-party trackers.
3. Agent prompt rules: change nothing if not affected · never delete/weaken a test · never edit
   the installed library.
4. Web tools disabled in every worker (`connector_web_search_web_search`,
   `connector_web_search_open_url`); packages only from the wheelhouse via
   `pip --no-index --find-links`.
5. "Not affected" = "no reachable path found", never "safe".
6. Vibe pinned to **3.1.3**; macOS `sandbox-exec` only (Linux `bwrap` is out of scope);
   `OTEL_ENABLED=false`.
7. Commit after each step, with the heredoc format in `docs/COORDINATION.md`.

## Steps

- [ ] **A1 — isolated Vibe.** Create `vibe-home/`, put your key in `vibe-home/.env`
      (gitignored), confirm `VIBE_HOME=$PWD/vibe-home vibe --version` reports **3.1.3**.
      Do not upgrade.
- [ ] **A2 — sandbox files.** Write the four `sandbox/` files, starting from the code blocks in
      `docs/build-prompt.md` Steps 3–4. Register both hooks in `vibe-home` and add the absolute
      `douane` path to `[tools.bash] allowlist`.
- [ ] **A3 — manual sandbox tests** with `SANDBOX_WORKDIR` pointed at a scratch dir:
      `douane 'curl -s https://example.com'` → **denied** · `douane 'touch ../escape'` →
      **denied** · `douane 'cat .env'` → **denied** · `douane 'touch /tmp/ok'` → **allowed** ·
      offline `pip --no-index` → works.
- [ ] **A4 — throwaway service + worker.** Create a tiny FastAPI service in
      `runs/selftest/src` pinned to `authlib==1.8.0` with one pytest test; write
      `worker/prompt.md` and `worker/run_repo.py` (skeleton in `docs/build-prompt.md` Step 5;
      the exact Vibe command line is specified there — keep it).
- [ ] **A5 — one end-to-end self-test.** Run `run_repo("selftest", "selftest")` directly.
      Verify: every shell command went through `douane` (hook log — target 100%);
      file-tool denials fired; `python schema/validate.py runs/selftest/selftest/verdict.json`
      passes; `runs/selftest/selftest/vibe/export.json` exists; the work copy's git status is
      clean apart from agent-written files.
- [ ] **A6 — log.** Record what passed/failed in `docs/BUILD-LOG.md`.
- [ ] Commit after each step.

## Done when

A3 and A5 pass and the produced `verdict.json` validates against the schema.

## Merge

```sh
git checkout build/base && git merge --no-ff build/track-a-sandbox-worker
```

Push only if the team agreed to share the remote.
