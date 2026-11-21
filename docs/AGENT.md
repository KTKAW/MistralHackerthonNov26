# The per-repository agent

One headless Mistral Vibe 3.1.3 process per repository, inside a sandbox. It decides whether the
advisory's flawed function can be reached from outside, proves it with a test, fixes it, and writes
`verdict.json`. The gate re-runs every claim afterwards; nothing here decides what is shown.

This page says how to set it up, what exactly runs, what the sandbox allows, and what has and has
not been checked by running it. The run layout it works in is pinned in [contract.md](contract.md).

**Not verified: a run with the real model.** There was no Mistral API key on the machine this was
built on. Everything up to the model call was run: the real Vibe 3.1.3 binary, started by the real
worker, with both hooks and the sandbox, driven by a scripted stand-in for the model. What the model
does with the prompt is untested. See [What is not verified](#what-is-not-verified).

## Files

| File | What it is |
| --- | --- |
| `sandbox/douane` | The wrapper. Runs one shell command under `sandbox-exec` with a clean environment. The gate uses it too. |
| `sandbox/profile.sb.template` | The Seatbelt profile the wrapper fills in. Its header records how rules combine on this macOS. |
| `sandbox/sandbox2.py` | Vibe `pre_tool` hook. Rewrites every shell command to run through the wrapper. |
| `sandbox/path_hook.py` | Vibe `pre_tool` hook. Limits the file tools; refuses every tool it does not know. |
| `sandbox/hook_common.py` | What the two hooks share: reading the payload, answering, logging. |
| `worker/setup_vibe_home.py` | Creates the isolated Vibe home. Never touches an API key. |
| `worker/prompt.md` | The agent's prompt template. |
| `worker/run_repo.py` | The worker: `run_repo(run_id, repo, ...)`, which the orchestrator loads as `worker.run_repo:run_repo`. |
| `worker/vibe_child.py` | Sits between the worker and Vibe so that Vibe never outlives the worker. |
| `tests/test_sandbox.py`, `tests/test_worker.py` | 65 tests. `uv run --no-sync pytest tests/test_sandbox.py tests/test_worker.py -q` |

## Setting up the Vibe home

```sh
uv run --no-sync python -m worker.setup_vibe_home        # creates ./vibe-home (git-ignored); safe to run again
```

It leaves three things in `vibe-home/`:

- `tool-venv/`: a Python 3.12 venv with exactly `mistral-vibe==3.1.3` (needs PyPI the first time).
- `config.toml`: model `mistral-large-4-0`; an allow-list of four tools; telemetry, OpenTelemetry,
  update checks and notifications off; connectors and MCP off; the two web tools off by name;
  subagents and background processes off; project context and pull-request monitoring off; the
  absolute path of `sandbox/douane` on `[tools.bash] allowlist`.
- `hooks.toml`: the two hooks, both `type = "pre_tool"`, `match = "*"`, `strict = true`,
  `sandbox2.py` first.

**The API key.** The script never reads, writes, prints or asks for a key. A person supplies it,
in one of two ways:

- `MISTRAL_API_KEY` in the environment of the process that runs the worker, or
- one line `MISTRAL_API_KEY=...` in `vibe-home/.env`, written by hand. Vibe loads that file itself
  and puts its values into its own environment (`vibe/core/config/vibe_schema.py`, `load_dotenv_values`).

Vibe 3.1.3 has a third source: when it finds no key in its environment it asks the macOS Keychain
(service `ai.mistral.vibe`, `vibe/utils/keyring.py`). The worker turns that lookup off
(`VIBE_TEST_DISABLE_KEYRING=1`) so that ten unattended agents never wait on a Keychain dialog and
a personal Vibe login is not used by accident. Export `VIBE_TEST_DISABLE_KEYRING=0` to allow it.

Without a key the worker fails in about a second: Vibe exits 1 with `Missing MISTRAL_API_KEY
environment variable for mistral provider`, its export says `outcome: config_error`, and the
worker returns `"verdict": None`. (Run this way on 21 Nov 2026.)

## Running one agent by hand

Once a key is in place and `runs/<run>/advisory.json` exists:

```sh
uv run --no-sync python -m worker.run_repo <run> <repo> --fleet-root runs/_fleet
```

Progress lines go to stderr; the result (exit code, verdict, usage) to stdout. For a first try:

```sh
mkdir -p runs/manual-1
cat > runs/manual-1/advisory.json <<'EOF'
{"advisory_id": "CVE-2026-96760", "package": "authlib", "affected_version_range": "<1.9.0",
 "fixed_version": "1.9.0", "flawed_function": "authlib.jose.JsonWebSignature.deserialize_json"}
EOF
uv run --no-sync python -m worker.run_repo manual-1 billing-api --fleet-root runs/_fleet
```

## What the worker does

`run_repo(run_id, repo, *, fleet_root="fleet", runs_root="runs", vibe_home="vibe-home", heartbeat_fn=None)`
returns `{"repo", "rc", "verdict", "export"}`. Relative paths are taken from the repository root.

1. Checks both names (plain folder names only) and that the Vibe home registers both hooks as strict
   and does not trust the run folder. An agent without its sandbox is never started.
2. Reads the five facts from `runs/<run>/advisory.json`. No file, no run: there are no defaults.
   Each fact must look like what it claims to be (an identifier, a package name, a version range,
   a version, a dotted path), because it goes into the prompt and came from a model that read pasted text.
3. Empties `runs/<run>/<repo>/`, keeping only the orchestrator's `state.json`, and builds the
   contract layout with `vulnerability_agent.runs`: `src/` (work copy), `proof/`. A work copy that
   holds a symlink pointing outside itself is refused.
4. Builds `venv/` offline: `uv venv --python 3.12`, then `uv pip install --offline --no-index
   --find-links <wheelhouse> --only-binary :all:` with the pins from `src/requirements.txt`. Any
   line that is not `name==version` is refused, so no option, URL or path from the repository
   reaches the installer. The wheelhouse is `LE_CHONK_WHEELHOUSE`, default `./wheelhouse`.
5. Writes `proof/conftest.py` (puts `src/` and `src/src/` on `sys.path`), `pytest.ini` (so pytest
   takes the repo-run root as its root and does not climb to this repository's `pyproject.toml`),
   and the rendered prompt at `vibe/prompt.md`.
6. Starts Vibe in its own process group and waits. Vibe's output goes to `vibe/stdout.txt` and
   `vibe/stderr.txt`.
7. Stops the whole process group, whatever happened, and returns what is on disk. A missing or
   invalid `verdict.json` is returned as `None`. The file is never rewritten or repaired.

It never writes `state.json`, `fix.diff` or `gate/`.

### The command line

```sh
vibe --workdir <repo-run> \
  --prompt-file <repo-run>/vibe/prompt.md \
  --model mistral-large-4-0 \
  --output text --output-dir <repo-run>/vibe \
  --max-turns 80 --max-price 3 --time-limit 560 \
  --enabled-tools bash --enabled-tools read_file --enabled-tools write_file --enabled-tools edit \
  --disabled-tools connector_web_search_web_search \
  --disabled-tools connector_web_search_open_url \
  --auto-approve
```

The working directory is the repo-run root. The model can be changed with `LE_CHONK_MODEL`.
All of these flags exist in 3.1.3 (`vibe --help`). Two things differ from the command in the design:

- **No `--trust`.** In a trusted folder Vibe loads `.vibe/hooks.toml`, `.vibe/config.toml` and
  `AGENTS.md`, and a project hook with the same name as a user hook replaces it. Tried with
  `--trust`: a `.vibe/hooks.toml` in the work folder, with a hook named like the one in the Vibe
  home, ran instead of it, and the `AGENTS.md` files in the work folder and in `src/` appeared in the
  model's context. Tried without `--trust`: none of that happened; Vibe
  printed that the folder is not trusted and its project configuration is ignored. A headless run
  never asks about trust. The worker also refuses to start if `vibe-home/trusted_folders.toml`
  trusts the run folder or a folder above it, and the sandbox denies creating `.vibe/` in the run folder.
- **`--enabled-tools` four times.** An allow-list instead of a list of tools to turn off. The two
  `--disabled-tools` flags from the design are kept; with connectors off they have nothing left to do.

### The environment Vibe gets

The worker's own environment, minus every `VIBE_*`, `SANDBOX_*` and `PYTHON*` variable and
`VIRTUAL_ENV`, plus:

| Variable | Value |
| --- | --- |
| `VIBE_HOME` | the isolated home |
| `OTEL_ENABLED` | `false` |
| `PATH` | `<vibe home>/tool-venv/bin` first |
| `SANDBOX_WORKDIR` | the repo-run root |
| `SANDBOX_DENY_READ` | see [What the agent cannot read](#what-the-agent-cannot-read) |
| `SANDBOX_DENY_WRITE` | `state.json`, `fix.diff`, `gate/`, `vibe/`, `.vibe/` in the repo-run root |
| `SANDBOX_WHEELHOUSE` | the wheelhouse |
| `SANDBOX_HOOK_LOG` | `<repo-run>/vibe/hooks.jsonl` |
| `VIBE_TEST_DISABLE_KEYRING` | `1` unless already set |

Vibe hands its whole environment to every hook and every command (`vibe/app_server/_runtime.py`,
the `env=` of the runtime adapter). The hooks need it. The commands must not have it, which is why
the wrapper builds theirs from nothing.

### Stopping

- Vibe stops itself at `--time-limit 560`, writes its export and exits 3 (so `vibe --help` says;
  not run to the limit here). If it is still there 30 s
  later, the worker sends SIGTERM to the process group, waits 15 s, then SIGKILL. It also kills the
  processes below Vibe that it listed beforehand, since Vibe may start commands in other process groups.
- The same happens in a `finally` block when `run_repo` leaves for any other reason.
- If the worker process itself is killed, even with `kill -9`, `worker/vibe_child.py` notices within
  half a second that its parent is gone and stops Vibe the same way.

The stop at the time limit and the killed worker are tested with a fake Vibe that hangs, once with
one that ignores SIGTERM.

### Progress

`heartbeat_fn` is called about every 10 s from a thread, once per line. The lines come from the
hooks' log, not from the agent's output: `shell: <command>`, `read <path>`, `wrote <path>`,
`refused <tool>: <reason>`, each flattened to one line and cut at 120 characters, at most eight per
beat, followed by one line of totals (`agent running for 40 s: 12 shell commands, 12 of them
through the sandbox, ...`). The totals are the count ticket 03 asks for. A heartbeat that raises
does not end the run.

## The hook protocol in Vibe 3.1.3

Read from the installed package, then confirmed by running. Paths are below
`vibe-home/tool-venv/lib/python3.12/site-packages/`.

| Fact | Where it is in the package |
| --- | --- |
| Hooks are declared as `[[hooks]]` in `hooks.toml`, not in `config.toml`. Fields: `name`, `type`, `command`, `match`, `timeout` (default 60), `strict`, `description` | `vibe/core/hooks/models.py` (`HookConfig`), `vibe/core/hooks/config.py` |
| Files read: `<project>/.vibe/hooks.toml` for a trusted folder first, then `$VIBE_HOME/hooks.toml`. On a duplicate name the project entry wins | `vibe/core/config/harness_files/_harness_manager.py` (`hook_files`); `vibe/plugins/builtins/vibe/skills/vibe/SKILL.md`, section "Hooks" |
| `strict` is allowed on `pre_tool`, `post_tool`, `pre_agent`, `pre_llm`, `post_llm` | `vibe/core/hooks/models.py` (`STRICT_HOOK_TYPES`) |
| The command is a shell line, run in the session's working directory with Vibe's environment, in its own process group, killed at the timeout | `mistralai_vibe_local_harness/vibe/_foreign_hooks.py` (`_run_command`, `_spawn_hook_command`) |
| stdin: one JSON object with `hook_event_name` (`"pre_tool"`), `tool_name`, `tool_call_id`, `tool_input`, `session_id`, `parent_session_id`, `transcript_path`, `cwd` | same file, `_stdin_payload`, `_base_payload` |
| `tool_name` is the qualified name: `file_system.bash`, `file_system.read_file`, `file_system.write_file`, `file_system.edit`, `process.start`, `skill.read`, `vibe.todo`, ... | `mistralai_vibe_local_harness/protocol.py` (`RUNTIME_BUILTIN_TOOL_NAMES`), `_hook_matcher.py` (`_BUILTIN_MODEL_NAMES`) |
| `tool_input` uses the names hooks have always seen: `file_path` for `read_file` and `write_file` (the model sends `path`), `timeout` for `bash` (the model sends `timeout_seconds`). A rewrite is translated back | `_foreign_hooks.py` (`_AUTHOR_ARGUMENTS`, `_RUNTIME_ARGUMENTS`) |
| stdout, exit 0: empty means go ahead; `{"decision": "deny", "reason": "..."}` refuses and the model gets the reason; `{"hook_specific_output": {"tool_input": {...}}}` replaces the arguments | `_foreign_hooks.py` (`_interpret_stdout`) |
| Any other outcome (non-zero exit, timeout, stdout that is not such an object) is a failure: allowed for a normal hook, **denied for a strict one** | `_foreign_hooks.py` (`_fail`) |
| `match` is a case-insensitive glob, or `re:<regex>`, tried against the qualified name, its last part and the name the model uses | `_hook_matcher.py` (`match_predicate`, `candidate_names`) |
| Hooks of one type run in file order; each sees the arguments as the one before left them | `SKILL.md`, "Wire protocol" and "Execution semantics" |

Observed in runs with a logging hook and a scripted model:

- The hooks fire for every tool call that does something on the machine, **including each call made
  from inside a `run_typescript` program**. They do not fire for `run_typescript` itself or for
  `search_tool_functions`.
- A rewritten `bash` command is what runs, and what the model sees in its history afterwards. So the
  model may send a command that already starts with the wrapper; `sandbox2.py` unwraps it and wraps
  it once.
- A command Vibe starts without the wrapper inherits Vibe's environment (a variable set for Vibe was
  visible to `env`). Through the wrapper it is gone.
- With the wrapper on `[tools.bash] allowlist`, a run **without** `--auto-approve` still executed the
  rewritten command. Vibe's reference says that under `--auto-approve` the allowlist is not consulted.

### What differs from the design

- **Hooks live in `hooks.toml`**, a file of their own in the Vibe home.
- **Vibe 3.1.3 has more tools than `bash`, `read_file`, `write_file` and `edit`**, and the allow-list
  does not remove all of them (next section).
- **`--trust` is dropped** and **`--enabled-tools` is added** (above).
- **The sandbox is tighter than "no network, writes in the work area, `secrets/` unreadable"**:
  reads are limited too (below), and the temp folder is inside the work area instead of `/tmp`.
- `OTEL_ENABLED=false` is set as the design says. That variable belongs to the Workflows worker.
  Vibe's own switches are `enable_telemetry` and `enable_otel` in `config.toml`; both are off.
- Vibe 3.1.3 also has a sandbox of its own (`mistralai_vibe_local_harness/vibe/_sandbox.py`). It is
  not used here; the design's wrapper is.

## Every Vibe tool, and how it is handled

With a default configuration Vibe 3.1.3 offered the model these tools in a headless run: `todo`,
`unified_harness_scratchpad`, `search_tool_functions`, `run_typescript`, `wait`, `read_file`,
`write_file`, `edit`, `bash`, `skill`. Through `run_typescript` a program can call
`tools.file_system.{bash, read_file, write_file, edit}`, `tools.process.{start, output, write, list, stop}`,
`tools.agents.{spawn, list, send_message, interrupt}`, `tools.self.sleep` and `tools.vibe.todo`.
Vibe's own reference says the `web_search` connector adds `connector_web_search_web_search` and
`connector_web_search_open_url`; without a key they were never offered here.

With this configuration the model is offered `bash`, `read_file`, `write_file`, `edit`,
`run_typescript`, `search_tool_functions` and `skill`. The last three stay whatever the allow-list
says (tried with the flag and with `enabled_tools` in the config).

| Tool (name in the hook payload) | Takes a path? | Handled by |
| --- | --- | --- |
| `bash` (`file_system.bash`) | runs anything | **Hooked.** `sandbox2.py` rewrites it to run through `douane`; `path_hook.py` refuses it if it arrives unwrapped |
| `read_file` (`file_system.read_file`) | yes | **Hooked.** `path_hook.py`: read roots only, symlinks resolved |
| `write_file` (`file_system.write_file`) | yes | **Hooked.** `path_hook.py`: `src/**`, `proof/**`, `verdict.json` only |
| `edit` (`file_system.edit`) | yes | **Hooked.** Same rule as `write_file` |
| `run_typescript` | no | Not hooked and cannot be turned off. The program has no file or network access of its own; each tool it calls goes through both hooks like a direct call. Its `tools.process`, `tools.agents` and `tools.vibe` groups are off or refused, see below |
| `search_tool_functions` | no | Not hooked and cannot be turned off. It only lists tool functions |
| `skill` (`skill.read`) | a skill name; reads skill files | Cannot be turned off (`disabled_tools`, `disabled_skills = ["*"]` and the allow-list were tried). **Refused by `path_hook.py`** |
| `unified_harness_scratchpad` (`vibe.unified_harness_scratchpad`) | yes, in a per-session folder in the Vibe home | **Disabled** by the allow-list; refused by `path_hook.py` as well |
| `todo` (`vibe.todo`) | no | **Disabled** by the allow-list; refused by `path_hook.py` as well. The prompt tells the agent there is no todo tool |
| `process.start` | runs anything | **Disabled** (`enable_background_processes = false`). If it were on, `sandbox2.py` would wrap it like `bash` |
| `process.output`, `process.write`, `process.list`, `process.stop` | no | **Disabled** with the above; refused by `path_hook.py` |
| `wait` (`self.wait`), `self.sleep` | no | `wait` is not offered once subagents and background processes are off; both refused by `path_hook.py` |
| `agents.spawn`, `agents.list`, `agents.send_message`, `agents.interrupt` | no | **Disabled** (`enable_subagents = false`); refused by `path_hook.py` |
| `connector_web_search_web_search`, `connector_web_search_open_url` | URLs | **Disabled** three times: `enable_connectors = false`, `disabled_tools`, and the two `--disabled-tools` flags; refused by `path_hook.py` |
| any MCP tool (`mcp_<server>.<tool>`) | may | **Disabled** (`enable_mcp = false`, no servers configured); refused by `path_hook.py` |
| `ask_user_question` | no | Not offered in a headless run; refused by `path_hook.py` |
| anything else | unknown | **Refused by `path_hook.py`**, which allows only what it has a rule for |

Both hooks are registered for every tool (`match = "*"`). A test checks that each enabled tool has
a rule of its own in a hook, and the test with the real Vibe checks the list of tools offered.

## What the sandbox allows and denies

### Shell commands (`sandbox/douane`, `sandbox-exec`)

Called as `sandbox/douane '<one shell command string>'` with `SANDBOX_WORKDIR=<absolute folder>`.
It runs `/bin/bash -c "<string>"` and exits with the command's exit code; its own failures exit 125.
The gate calls it the same way with only `PATH`, `HOME`, `LANG` and `TMPDIR` set.

| | |
| --- | --- |
| Network | Denied, loopback included. |
| Writes | Only inside `SANDBOX_WORKDIR`, and to `/dev/null` and the terminal. Not `/tmp`. |
| `HOME`, `TMPDIR` | Folders the wrapper owns in `<workdir>/.sandbox/`. A `HOME` or `TMPDIR` from the caller is kept if it already lies inside the workdir, as the gate's `HOME` does. |
| Reads | Names and attributes of files: everywhere. File contents and folder listings: not under `/Users`, the user's home, `/private/tmp`, `/private/var/folders`, `/private/var/tmp` or `/Volumes`, **except** the workdir, the wheelhouse (`SANDBOX_WHEELHOUSE`), the Python install behind `<workdir>/venv`, `~/.local/share/uv/python`, the uv binary, and `SANDBOX_READ_ALLOW`. System folders stay readable. |
| Never readable or writable | Any file named `.env` or `.env.*`; any folder named `secrets` in the workdir, at any depth; the Vibe home (`VIBE_HOME`); `~/.vibe`; every path in `SANDBOX_DENY_READ`. |
| Not writable | Every path in `SANDBOX_DENY_WRITE`. |
| Symlinks | Cannot be created in the workdir, except in `.sandbox/` (uv's cache and pytest's temp folders use them). |
| System services | No mach lookups, so no Keychain daemon. |
| Environment | Built from nothing: `PATH` (the workdir's `venv/bin`, a link to `uv`, the system folders), `HOME`, `TMPDIR`, `LANG`, `VIRTUAL_ENV`, and switches that keep `uv` and `pip` offline and stop Python writing `__pycache__` into the work copy. |

No profile file is written: the profile text goes to `sandbox-exec -p` and the three paths to `-D`,
so parallel agents cannot collide on a file name. (On this macOS `mktemp /tmp/name-XXXXXX.sb` creates
a file literally called `name-XXXXXX.sb`; nothing here depends on it.)

### File tools (`sandbox/path_hook.py`)

- `write_file`, `edit`: only `<workdir>/src/**`, `<workdir>/proof/**` and `<workdir>/verdict.json`,
  the contract's `AGENT_WRITABLE`. So not `venv/`, not `state.json`, not `vibe/`.
- `read_file`: only the workdir, the wheelhouse, the Python install behind `venv/`, and `SANDBOX_READ_ALLOW`.
- Neither: `.env` files, `secrets` folders, `.sandbox/`, the Vibe home, `~/.vibe`, `SANDBOX_DENY_READ`.
- Every check is made on the path as written and on the path with symlinks resolved.

### What the agent cannot read

`SANDBOX_DENY_READ` is built by the worker. Starting at the repository root and at the runs folder,
every entry is denied unless the repo-run root or the wheelhouse lies inside it. That covers what
the ticket names (the fleet copy, `orchestrator/tests/fixtures/fleet_answers`,
`orchestrator/stub_answers.json`, the other repositories' folders under `runs/<run>/`, named even
before they exist) and also `docs/FLEET.md`, which holds the answers, and every earlier run.
`LE_CHONK_SANDBOX_DENY_READ` (colon-separated absolute paths) adds more.

### How Seatbelt rules combine on this machine

macOS 26.5.2 (build 25F84), `/usr/bin/sandbox-exec`. Each line is a small profile that was run.

| Profile | Result |
| --- | --- |
| `(deny default)`, `(allow process*)`, `(allow file-read* (subpath W))` | The child aborts before bash starts (exit 134). |
| The same with `(allow file-read*)` | Starts. So reads of names and attributes are allowed everywhere. |
| `(allow file-write* (subpath W))` then `(deny file-write*)`, and the reverse order | Writes in W work, elsewhere fail, in both orders. **A rule with a path filter beats one without.** |
| `(deny file-read* (subpath W/secrets))` then `(allow file-read* (subpath W))` | The secret is readable. |
| `(allow file-read* (subpath W))` then `(deny file-read* (subpath W/secrets))` | It is not. **Among filtered rules, the last match wins**, whichever path is more specific. |
| `(deny file-read* (regex "/\.env$"))` then `(allow file-read* (subpath W))` | `.env` is readable: last match again. |
| `(allow file-write* (subpath W))` then `(deny file-write* (subpath "/"))` | Writes in W fail: last match again. |
| `(deny file-read-data (subpath H))` then `(allow file-read* (subpath H/W))` | Files in W stay unreadable. |
| `(deny file-read-data (subpath H))` then `(allow file-read-data (subpath H/W))` | Files in W are readable. |
| The line above, then `(deny file-read* (subpath W/secrets))` | The secret is still readable (only its attributes are denied). **A rule that names the operation beats one that names it through a wildcard, wherever each stands.** |
| The same with `(deny file-read-data (subpath W/secrets))` | Denied. |
| A read deny on `W/secrets`, W writable, then `mv secrets/key elsewhere` | The move works and the file is readable under its new name. So read denies are write denies too. |
| The same, then `ln secrets/key elsewhere` or `ln <file outside> W/x` | Refused without any extra rule. |
| `(deny file-write-create (require-all (subpath W) (vnode-type SYMLINK)))` | `ln -s` fails in W; files, folders, hard links and renames still work. |

So in the profile every deny for a secret comes last and names `file-read-data`, `file-read*` and
`file-write*`, and every exception to the read limit names `file-read-data`.

## What was verified by running

On 21 Nov 2026, macOS 26.5.2, Vibe 3.1.3, uv 0.11.7.

- `uv run --no-sync pytest tests/test_sandbox.py tests/test_worker.py -q`: **65 passed**.
- Through `douane`, each with a control where it matters: network denied (a loopback listener that
  the same command reaches outside the sandbox); writes outside the workdir and to `/tmp` denied;
  writes inside, to `$TMPDIR` and to `$HOME` allowed; `.env`, nested `secrets/`, a
  `SANDBOX_DENY_READ` file, the Vibe home unreadable; a secret cannot be moved, copied or hard-linked
  into the open; another folder next to the workdir, the user's home and this repository unreadable
  without any deny list; the environment scrubbed; the exit code passed through; misuse exits 125
  without running anything.
- In a venv made by `uv venv --python 3.12`, through `douane`: an offline install of
  `authlib==1.8.0` and `pytest==9.2.0` from `./wheelhouse`; the pinned `venv/bin/python -m pytest
  proof/ -q`; the same from the gate's environment (`PATH`, `HOME` = the folder, `LANG`, `TMPDIR`
  only); the upgrade to `authlib==1.9.0`; a package that is not in the wheelhouse fails to install.
  A fleet app's own nine tests pass inside as well.
- Both hooks with the payloads Vibe sends: rewrite, deny on malformed input, each allowed and each
  denied write location, the read allow-list, symlinks that leave the workdir or point at a secret,
  every unknown tool refused.
- **The real Vibe 3.1.3, started by `run_repo`, with a scripted model** (`test_real_vibe_...`):
  the hooks load from the isolated home; 2 of 2 shell commands ran through the wrapper, one of them
  from inside a `run_typescript` program; a variable in Vibe's environment did not reach the command;
  the fleet copy and the run root were unreadable; `write_file` outside the allowed places,
  `read_file` of `/etc/hosts` and `skill` were refused; an `AGENTS.md` and a `.vibe/hooks.toml`
  planted in the repository were not picked up; the verdict written through `write_file` came back
  valid; `export.json` was read.
- The same with the run folder inside this repository: without the two extra switches Vibe put this
  repository's branch name and last five commit subjects into the system prompt. With
  `include_project_context = false` it does not.

## What is not verified

- **Any run with a real model.** Whether Le Chonk follows the prompt, finishes inside 560 s, writes
  a valid `verdict.json`, or gets the verdicts right is untested. The prompt is written from the
  design and from what the earlier runs reported; no model has read it.
- **Whether the prompt is too long or too strict.** It tells the agent to write `verdict.json` as soon
  as it has decided, because an earlier build reportedly ran out of time before writing one.
- **The web tools with a key.** Without a key Vibe never offered the connector tools, so their being
  switched off was not observed directly.
- **Ten agents at once.** One at a time was run.
- **The Keychain.** That the sandboxed shell cannot reach it follows from the profile (no mach
  lookups) and was not tried, on purpose.
- **Linux.** macOS only, as in the design.

## Known limits

- The sandboxed shell can still read system folders (`/etc`, `/Library`, `/opt`, `/Applications`).
  Nothing of this project is there.
- `path_hook.py` checks a path and Vibe opens it a moment later. Symlinks cannot be created in the
  workdir and a work copy with a link that leaves it is refused, which closes the known ways to
  swap a path in between; it is not a proof that there are none.
- Vibe's system prompt still lists its five built-in skills and mentions a todo list and a
  scratchpad. Calls to them are refused, and the agent's prompt says so. A model may still spend a
  turn finding out.
- The gate, not this code, checks the three prompt rules. The sandbox only stops the file tools
  from writing to `venv/`; a shell command can.
