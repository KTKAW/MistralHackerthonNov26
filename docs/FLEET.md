# The demo fleet: ten apps, four advisories

Ten small services, each in its own repository. A run takes one advisory and checks all ten.
For any advisory, a dependency scanner flags every app that pins the package. The tool's job
is to tell apart the apps where the flaw can be reached from the apps where it cannot.

| Advisory | Package, fixed in | Severity | Published | What the flaw is |
|---|---|---|---|---|
| CVE-2026-96760 | `authlib` < 1.9.0, fixed in 1.9.0 | | 27 Oct 2026 | `JsonWebSignature.deserialize_json` accepts a token whose `signatures` array is empty |
| CVE-2026-126347 | `tornado` <= 6.6.0, fixed in 6.6.1 | low | 13 Nov 2026 | `RedirectHandler` redirects to another host when a path starts with three slashes |
| CVE-2026-126193 | `soupsieve` 0.4 to 2.10, fixed in 3.0.2 | moderate | 13 Nov 2026 | The selector parser recurses without limit on nested pseudo-classes and raises `RecursionError` |
| CVE-2026-129300 | `mail-parser` 3.7.0 to 4.6.2, fixed in 4.6.3 | moderate | 16 Nov 2026 | A `Received` header with an out-of-range year raises `OverflowError` and the message is lost |

The three November advisories were taken from GitHub's advisory database on 21 November 2026
(reviewed `pip` advisories, low and moderate, published that month: 72 rows). They were chosen
because each can be shown with a harmless input and a test that does not depend on timing.
Each was reproduced on the old and the fixed version before any app was written.

## Get the apps

```sh
uv run python -m orchestrator.fetch_fleet
```

This puts the ten apps in `runs/_fleet/`, each at the commit pinned in `orchestrator/fleet.json`.
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
/tmp/wh-venv/bin/pip download --only-binary :all: tornado==6.6.0 -d wheelhouse/
/tmp/wh-venv/bin/pip download --only-binary :all: tornado==6.6.1 -d wheelhouse/
/tmp/wh-venv/bin/pip download --only-binary :all: beautifulsoup4==4.15.0 soupsieve==2.10 -d wheelhouse/
/tmp/wh-venv/bin/pip download --only-binary :all: soupsieve==3.0.2 -d wheelhouse/
/tmp/wh-venv/bin/pip download --only-binary :all: mail-parser==4.6.2 -d wheelhouse/
/tmp/wh-venv/bin/pip download --only-binary :all: mail-parser==4.6.3 -d wheelhouse/
```

One command per version, because one resolve cannot hold two versions of a package. On
21 November 2026 this gave 35 files. The apps pin their direct dependencies; what those depend on
is not pinned, so the list can change. `pydantic-core`, `cffi` and `tornado` are built per
machine. Tornado 6.6.0 comes as a file named `tornado-6.6`.

## Ground truth

Checked by hand on 21 November 2026 on clean copies, Python 3.12, offline. "Probe" is the app's
`verify_trigger.py`: it exits 0 when the flaw is triggered.

### CVE-2026-96760, Authlib

| App | Case | Entry point | Probe on 1.8.0 | Probe on 1.9.0 | Tests on both | Tile it should end on |
|---|---|---|---|---|---|---|
| `auth-gateway` | Exposed: calls `deserialize_json` directly | `POST /introspect` | accepted | rejected 401 | 9 pass | Affected, proven and fixed |
| `billing-api` | Exposed through a hidden route: route, `current_customer`, `verify_bearer`, `jws.deserialize` | `POST /charge` | accepted | rejected 401 | 9 pass | Affected, proven and fixed |
| `session-service` | Not exposed: `JsonWebToken.decode` takes the compact format only | `GET /me` | rejected 401 | rejected 401 | 8 pass | No reachable path found |
| `token-signer` | Not exposed: signs with `serialize_compact`, never reads an inbound token | `POST /sign` | not accepted | not accepted | 8 pass | No reachable path found |
| `profile-api` | Exposed only if `PROFILE_ACCEPT_JSON_TOKENS` is on. It is off by default | `GET /profile` | off: rejected 401. On: accepted | rejected 401 either way | 8 pass | Needs a human |

### CVE-2026-126347, Tornado

| App | Case | Entry point | Probe on 6.6.0 | Probe on 6.6.1 | Tests on both | Tile it should end on |
|---|---|---|---|---|---|---|
| `link-redirector` | Exposed: `/legacy/(.*)` redirects to `"/{0}"`, so the caller's path starts the target | `GET /legacy/(.*)` | 301 to `///other-site.example/x` | 400 | 9 pass | Affected, proven and fixed |
| `docs-portal` | Not exposed: the same class, but every target is fixed or has the prefix `/manual/` | `GET /docs/(.*)` | stays on the site | stays on the site | 7 pass | No reachable path found |

### CVE-2026-126193, Soup Sieve

| App | Case | Entry point | Probe on 2.10 | Probe on 3.0.2 | Tests on both | Tile it should end on |
|---|---|---|---|---|---|---|
| `html-extractor` | Exposed through Beautiful Soup: the caller's selector reaches `soup.select()` | `POST /extract` | `RecursionError` | 200 | 8 pass | Affected, proven and fixed |
| `link-checker` | Not exposed: the same function, but every selector is a constant; the caller controls the HTML only | `POST /links` | no error, 44 requests | no error | 9 pass | No reachable path found |

### CVE-2026-129300, mail-parser

| App | Case | Entry point | Probe on 4.6.2 | Probe on 4.6.3 | Tests on both | Tile it should end on |
|---|---|---|---|---|---|---|
| `ticket-mailer` | Not exposed: the package is pinned but no file imports it. The service only writes mail | `POST /tickets/{id}/notify` | no error, 35 requests | no error | 8 pass | No reachable path found |

There is no exposed app for the mail-parser advisory. One was planned (`mail-intake`); the
builder for it was stopped by a safety check before it wrote anything, and it was not built.

For an advisory about a package an app does not pin, the right tile is "No reachable path
found", and the stand-in says exactly that: `requirements.txt` does not list the package.

The gate has confirmed the four "affected, proven and fixed" rows on its own: for each, the
proof test fails on the old version and passes on the fixed one, and the suite passes after the
fix. The other rows rest on the hand check. The gate runs no code for "not affected" or "needs
a human".

## Where the answers are kept

Not in the apps. An agent gets a copy of one app and must work the answer out from the code. No
app mentions a flaw, an advisory or its own verdict.

- `orchestrator/tests/fixtures/fleet_answers/<app>/`: `truth.md` (the code path as `file:line`),
  `verify_trigger.py` (the probe), and for the Authlib apps `input.json` (the forged token). The
  two exposed November apps also have `proof.py`, the proof test the stand-in adds.
- `orchestrator/stub_answers.json`: the same answers in the form the stand-in worker reads, each
  tied to its advisory. A test checks that every line it cites is in the fetched app.

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
  and claim "affected". The gate would accept that. Whether "needs a human" is what a real agent
  says has to be rehearsed.
- **Ten agents at once is untested.** Three worked on 21 November.
- **The two OSV records for the Soup Sieve advisory disagree on the upper bound.** The CVE record
  says "until 3.0" and the GitHub advisory says fixed in 3.0.2. The reader answered `<3.0.2` in
  one run and `<3.0` in another. The fix the gate verified is 3.0.2.
