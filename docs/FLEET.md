# The demo fleet: five apps

Five small FastAPI services, each in its own repository. Every one pins `authlib==1.8.0`, so a
dependency scanner flags all five. The tool's job is to tell them apart.

The flaw is CVE-2026-96760, Authlib before 1.9.0: `JsonWebSignature.deserialize_json` accepts a
JWS in JSON serialization whose `signatures` array is empty. Authlib 1.9.0 rejects it.

## Get the apps

```sh
uv run python -m orchestrator.fetch_fleet
```

This puts the five apps in `runs/_fleet/`, each at the commit pinned in `orchestrator/fleet.json`.
The tool uses that folder as its fleet from then on, unless `LE_CHONK_FLEET_ROOT` says otherwise.
The apps land as plain files without `.git`.

The commits are pinned because the gate installs these apps and runs their tests. To take a
newer commit of an app, review it, change the id in `fleet.json`, remove that app's folder from
`runs/_fleet/` and fetch again.

## Build the wheelhouse

The gate installs offline, from `wheelhouse/`. With network and Python 3.12:

```sh
python3.12 -m venv /tmp/wh-venv
/tmp/wh-venv/bin/pip download -r runs/_fleet/billing-api/requirements.txt -d wheelhouse/
/tmp/wh-venv/bin/pip download authlib==1.9.0 -d wheelhouse/
```

Two commands, because one resolve cannot hold two versions of Authlib. All five apps have the
same `requirements.txt`. On 21 November 2026 this gave 28 files. The apps pin five packages;
what those depend on is not pinned, so the list can change. `pydantic-core` and `cffi` are
built per Python version and per machine.

## Ground truth

Checked by hand on 21 November 2026 on clean copies, Python 3.12, offline. "Probe" is
`verify_trigger.py` with the forged token in `input.json`: it exits 0 when the token is accepted.

| App | Case | Entry point | Probe on 1.8.0 | Probe on 1.9.0 | Tests on both | Tile it should end on |
|---|---|---|---|---|---|---|
| `auth-gateway` | Exposed: calls `deserialize_json` directly | `POST /introspect` | accepted | rejected 401 | 9 pass | Affected, proven and fixed |
| `billing-api` | Exposed through a hidden route: route, `current_customer`, `verify_bearer`, `jws.deserialize`. The app never names the flawed function | `POST /charge` | accepted | rejected 401 | 9 pass | Affected, proven and fixed |
| `session-service` | Not exposed: `JsonWebToken.decode` takes the compact format only | `GET /me` | rejected 401 | rejected 401 | 8 pass | No reachable path found |
| `token-signer` | Not exposed: signs with `serialize_compact`, never reads an inbound token | `POST /sign` | not accepted | not accepted | 8 pass | No reachable path found |
| `profile-api` | Exposed only if `PROFILE_ACCEPT_JSON_TOKENS` is on. It is off by default | `GET /profile` | off: rejected 401. On: accepted | rejected 401 either way | 8 pass | Needs a human |

The gate has confirmed the two exposed rows on its own: for `auth-gateway` and `billing-api` the
stand-in's proof test fails on 1.8.0 and passes on 1.9.0, and each suite passes after the fix.
The other three rows rest on the hand check. The gate runs no code for "not affected" or "needs
a human".

## Where the answers are kept

Not in the apps. An agent gets a copy of one app and must work the answer out from the code. No
app mentions the flaw, the advisory or its own verdict.

- `orchestrator/tests/fixtures/fleet_answers/<app>/`: `truth.md` (the code path as `file:line`),
  `input.json` (the forged token) and `verify_trigger.py` (the probe).
- `orchestrator/stub_answers.json`: the same answers in the form the stand-in worker reads. A
  test checks that every line it cites is in the fetched app.

To run a probe, build an environment outside the fleet folder and point the script at the app:

```sh
uv venv --python 3.12 /tmp/probe-venv
uv pip install --python /tmp/probe-venv/bin/python --offline --no-index --find-links wheelhouse -r runs/_fleet/billing-api/requirements.txt
/tmp/probe-venv/bin/python orchestrator/tests/fixtures/fleet_answers/billing-api/verify_trigger.py runs/_fleet/billing-api
```

It prints `ACCEPTED ...` on Authlib 1.8.0. For `profile-api`, add `--setting-on` to probe with the
setting on.

## Not known

- **No agent has inspected these apps.** Every tile so far came from the stand-in.
- **`profile-api` is the open case.** An agent could turn the setting on in a test, prove the flaw,
  and claim "affected". The gate would accept that, because the proof would fail on 1.8.0 and pass
  on 1.9.0. Whether "needs a human" is what a real agent says has to be rehearsed.
- **Five agents at once is untested.** Three worked on 21 November.
