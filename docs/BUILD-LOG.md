# BUILD LOG — track A (sandbox + per-repo worker)

Branch `build/track-a-sandbox-worker`. Machine: macOS 26.3 (Darwin 25.3.0, arm64), 2026-11-21.
Repo: `/Users/kymani/Documents/nov26hack/track-a-sandbox-worker`.

## A1 — isolated Vibe home

- `vibe-home/` created (gitignored). Vibe **pinned to 3.1.3** by installing
  `mistral-vibe==3.1.3` into `vibe-home/tool-venv` (uv, python 3.14) and putting
  `vibe-home/tool-venv/bin` first on `PATH` in `run_repo.py`.
  `VIBE_HOME=$PWD/vibe-home PATH=... vibe --version` → **vibe 3.1.3**.
  (The machine-wide CLI is 3.1.4 — deliberately not used for workers.)
- API key: none pasted; Vibe reads `MISTRAL_API_KEY` from the **macOS Keychain** at
  startup, so `vibe-home/.env` was not needed on this machine and was not created.
  `enable_telemetry/enable_otel = false` in `vibe-home/config.toml`; `OTEL_ENABLED=false`
  in every worker env.
- vibe 3.1.3 migrated `config.toml` on first run (`bash_read_only_defaults_v1`): read-only
  commands are allowlisted by default; the absolute `sandbox/douane` path stays in
  `[tools.bash] allowlist` so rewritten commands never stop for approval.
- Worker model config: `mistral-large-4-0` with `thinking = "low"` (see A5 note).

## A2 — sandbox files + registration

- `sandbox/sandbox2.py` — `pre_tool` hook, `match = 're:bash|process_start|process\.start'`,
  `strict = true`. Reads the Vibe 3.1.3 wire protocol (JSON on stdin, `tool_name` qualified,
  `tool_input.command`), rewrites to `<abs douane> '<shquoted>'` via
  `{"decision":"allow","hook_specific_output":{"tool_input":...}}`; denies empty/unparseable
  (strict → deny on crash too). Logs every decision as a JSON line to `$HOOK_LOG`.
- `sandbox/douane` — `env -i` scrubbed env + `sandbox-exec -f <generated profile> /bin/bash -c "$*"`;
  substitutes `__WORKDIR__`, `__PYDIR__`, `__VIBEHOME__` (realpath-normalized — Seatbelt
  matches realpaths, `/tmp` → `/private/tmp`).
- `sandbox/profile.sb.template` — Seatbelt profile, **adapted to macOS 26.3** (see below).
- `sandbox/path_hook.py` — `pre_tool`, `match = 're:read_file|write_file|edit'`, `strict = true`.
  Writes only under `$SANDBOX_WORKDIR/src/` plus `$SANDBOX_WORKDIR/verdict.json`; reads never
  `.env` (anywhere) or `secrets/`, work copy + narrow system paths only. Same wire protocol.
- Registered in `vibe-home/hooks.toml` (both hooks) + `vibe-home/config.toml` (douane allowlist).

## A3 — manual sandbox tests (all pass)

With a scratch work copy (`SANDBOX_WORKDIR` pointed at it), via `sandbox/douane`:

| Test | Result |
|---|---|
| `curl -s https://example.com` | **denied** (network*) |
| `touch ../escape` | **denied** (write outside work copy, EPERM) |
| `cat .env` (in workdir) / `cat /tmp/x/.env` / vibe-home contents | **denied** |
| `touch /tmp/ok` | **allowed** |
| `cat README.md`, `touch inside.txt` in workdir | **allowed** |
| `pip install --no-index --find-links wheelhouse authlib==1.8.0` into the work venv, offline, in-sandbox | **works** (authlib 1.8.0 imports) |
| env scrubbed (`MISTRAL_API_KEY` empty inside) | **yes** |

Hook unit tests (payload piped on stdin, as Vibe does): bash/process_start rewritten,
non-shell pass-through, empty command denied; path_hook allows/denies per the table above.
Full suite in `tests/`: **80 passed**.

### macOS 26.3 Seatbelt adaptation (important)

- `(deny default)` + `(allow process-exec*)` + only narrow `file-read*` subpaths makes the
  sandboxed child **die with SIGABRT** at startup on this build. Multiple `(subpath ...)`
  filters in one rule are ANDed, so per-directory rules are required — and even then the
  child aborts unless reads are effectively broad. Final profile: `(allow file-read* (subpath "/"))`
  + deny rules carving out secrets (deny wins over allow):
  any `/.env` (regex), `$WORKDIR/secrets`, `$VIBE_HOME` (holds the key), `~/.vibe`,
  `/private/dev/urandom`. Writes remain confined: work copy + `/private/tmp` + `/private/var/tmp`
  + `/dev/null` only.
- Use realpaths in filters (`/private/tmp`, not `/tmp`).

## A4 — throwaway service + worker

- `runs/selftest/src/` (gitignored): tiny FastAPI service, `POST /token` →
  `auth.py::verify_token` → `JsonWebSignature.deserialize_json`, pinned `authlib==1.8.0`,
  one pytest test. Hand-verified on this machine: suite passes on 1.8.0; forged
  empty-`signatures` token → **200 on 1.8.0, 401 on 1.9.0**; suite passes on 1.9.0.
- `worker/prompt.md` — 3 rules + read→trace→prove→fix→re-verify + verdict contract;
  reads `../advisory.json`, writes `../verdict.json`; offline wheelhouse at `../wheelhouse`;
  efficiency note + "write verdict.json as soon as the verdict is decided".
- `worker/run_repo.py` — pinned signature kept:
  `run_repo(run_id, repo, *, fleet_root="fleet", runs_root="runs", vibe_home="vibe-home", heartbeat_fn=None)`.
  Produces `runs/<run>/<repo>/src` (fresh copy + git baseline), `.venv` (offline, py3.12),
  `wheelhouse/` + `schema/` copies, `advisory.json`, then runs the pinned vibe command line
  verbatim with `SANDBOX_WORKDIR=<work root>`, `HOOK_LOG`, `VIBE_HOME`, `OTEL_ENABLED=false`,
  `PATH` pinned to the 3.1.3 tool-venv; 10 s heartbeat thread; returns
  `{"repo","rc","verdict","export"}`.

## A5 — end-to-end self-test: `run_repo("selftest", "selftest")` — PASS

Result: `rc=0`, verdict **`affected_fixed`**, `export.json` outcome `finished` (vibe 3.1.3,
29 steps, 588k tokens, $0.08).

| Check | Result |
|---|---|
| shell commands through douane | **27/27 = 100%** (hook.log: every bash/process_start rewritten) |
| file-tool denials fired | yes — 1 in-vivo `path_hook` deny (read outside work copy); unit tests cover .env/secrets/outside writes |
| `schema/validate.py runs/selftest/selftest/verdict.json` | **OK** (valid vs verdict.schema.json) |
| `runs/selftest/selftest/vibe/export.json` | exists (tokens, cost, outcome, vibe_version 3.1.3) |
| work-copy `git status` | clean apart from agent-written `tests/test_proof.py` |
| proof test semantics | `tests/test_proof.py::test_empty_signatures_forged_token_rejected` **fails on authlib 1.8.0** (forged token → 200), **passes on 1.9.0** (401); suite 2 passed on 1.9.0 |
| verdict content | path entry point → `auth.py` → `authlib/jose/.../jws.py` flawed branch; fix upgrade authlib==1.9.0 from wheelhouse |

Notes / adaptations:
- First three runs hit the pinned `--time-limit 560` (outcome `deadline`) before writing
  verdict.json; fixed by (a) prompt: write `../verdict.json` immediately after the verdict
  decision + minimize tool calls, (b) `thinking = "low"` for the worker model in
  `vibe-home/config.toml`. The pinned vibe command line itself was kept verbatim.
- `SANDBOX_WORKDIR` = work-copy root `runs/<run>/<repo>` (contains `src/`); seatbelt confines
  shell writes to it, path_hook confines file tools to its `src/` + `verdict.json`.
- run_repo template resolution: `fleet/<repo>`, else a pre-seeded throwaway at
  `runs/<run_id>/src` (used by the selftest). Wheelhouse: copied from track B's local
  `wheelhouse/` (gitignored, per-machine) and hard-copied into each work root so it is
  readable inside the sandbox.

## A6 — this log. Done when: A3 + A5 pass and verdict.json validates — met.

## Not done / follow-ups

- Key never touched disk: workers authenticate via the macOS Keychain. On a machine without
  a keychain key, put `MISTRAL_API_KEY` in `vibe-home/.env` (gitignored) or export it.
- 10-parallel rate limits untested (out of track A scope).
- Linux `bwrap` out of scope per plan.
