# Demo fleet — ground truth

Eight small FastAPI services pinned to **authlib 1.8.0** (the version with
**CVE-2026-96760**, a signature-check bypass fixed in **1.9.0**). The flaw:
`JsonWebSignature.deserialize_json` accepts a JWS *general JSON serialization*
whose `signatures` array is empty (`[]`) — the signature loop never runs and
the token is accepted without any signature check. `JsonWebSignature.deserialize`
routes JSON input (dict or `{...}` string) to that function, so any service that
verifies a JSON-serialized JWS with attacker-controlled input is affected.

The fixed version is **authlib 1.9.0**, which rejects empty/null `signatures`
with `BadSignatureError`.

## Rebuilding the wheelhouse (gitignored — built locally per machine)

On a machine WITH network, with Python 3.12 (e.g. `uv python install 3.12`):

```sh
mkdir -p wheelhouse
python3.12 -m venv /tmp/wh-venv && /tmp/wh-venv/bin/pip install pip --upgrade
/tmp/wh-venv/bin/pip download authlib==1.8.0 -d wheelhouse/
/tmp/wh-venv/bin/pip download authlib==1.9.0 -d wheelhouse/
/tmp/wh-venv/bin/pip download fastapi uvicorn pytest httpx -d wheelhouse/
ls wheelhouse/ | grep -i authlib     # must show BOTH 1.8.0 and 1.9.0
```

Everything installs offline afterwards with
`pip install --no-index --find-links <repo>/wheelhouse -r requirements.txt`.

## Ground-truth matrix (hand-verified on this machine, 2026-11, macOS arm64, Python 3.12.13)

Verification per service (`cd fleet/<svc>`):

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python --offline --find-links ../../wheelhouse -r requirements.txt
.venv/bin/python -m pytest tests/ -q        # suite passes on 1.8.0 (before any fix)
.venv/bin/python proof/verify_trigger.py    # forged token outcome on 1.8.0
uv pip install --python .venv/bin/python --offline --find-links ../../wheelhouse authlib==1.9.0
.venv/bin/python proof/verify_trigger.py    # forged token outcome on 1.9.0
.venv/bin/python -m pytest tests/ -q        # suite still passes on 1.9.0
```

`proof/input.json` is the same harmless forged token everywhere: a general JSON
serialization `{"payload": <b64url of {"sub":"attacker","role":"admin",...}>, "signatures": []}`.
For affected services `verify_trigger.py` exits 0 when the forged token is
ACCEPTED (flaw triggered); for unaffected services it exits 0 when the forged
token is REJECTED (no trigger).

| Service | Name | Affected? | Hidden route? | Entry point | 1.8.0 proof | 1.9.0 proof | Suite 1.8.0 | Suite 1.9.0 |
|---|---|---|---|---|---|---|---|---|
| svc-01 | gateway | **YES** | no (calls `deserialize_json` directly) | `POST /introspect` | TRIGGERED (accepted) | rejected 401 | 3 passed | 3 passed |
| svc-02 | billing | **YES** | **YES** — `security.verify_bearer()` wrapper → `jws.deserialize`; grep for the flawed function name finds nothing in the service | `POST /charge` (Bearer) | TRIGGERED (accepted) | rejected 401 | 3 passed | 3 passed |
| svc-03 | webhooks | **YES** | no (`jws.deserialize(dict)` on JSON body) | `POST /hooks/payment` | TRIGGERED (accepted) | rejected 401 | 3 passed | 3 passed |
| svc-04 | sessions | no — `jwt.decode` is compact-only; JSON input → `DecodeError` before any signature check | no | `GET /me` (Bearer compact JWT) | rejected 401 | rejected 401 | 3 passed | 3 passed |
| svc-05 | legacy | no — explicit `deserialize_compact`; JSON input fails segment check | no | `POST /verify` (Bearer compact) | rejected 401 | rejected 401 | 3 passed | 3 passed |
| svc-06 | oauth-client | no — outbound OAuth2 URL building only; no inbound JWS verification | no | `GET /login` | n/a (no verify endpoint) | n/a | 2 passed | 2 passed |
| svc-07 | signer | no — signs only (`serialize_compact`); never deserializes inbound input | no | `POST /sign` | n/a (no verify endpoint) | n/a | 2 passed | 2 passed |
| svc-08 | profiles | **YES** — JSON bearer branch → `jws.deserialize(json.loads(token))` | no | `GET /profile` (Bearer) | TRIGGERED (accepted) | rejected 401 | 3 passed | 3 passed |

Composition: 4 affected (svc-01, svc-02, svc-03, svc-08 — one of them the hidden-route
case svc-02), 4 unaffected (svc-04…svc-07). Every install resolves fully offline
with `--no-index --find-links ../../wheelhouse`.

### Re-verification (2026-11-21, automated re-run of the whole matrix)

All 8 services re-verified end-to-end on this machine, fully offline: fresh
`uv venv --python 3.12`, `uv pip install --no-index --find-links ../../wheelhouse
-r requirements.txt`, suite on 1.8.0, `proof/verify_trigger.py` on 1.8.0, upgrade
to `authlib==1.9.0` from the same wheelhouse, proof + suite again. Results matched
the matrix above exactly: svc-01/02/03/08 TRIGGERED on 1.8.0 (forged token accepted)
and REJECTED (401) on 1.9.0; svc-04/05 REJECTED on both; svc-06/07 have no
verification endpoint (no trigger on either); every suite passed on both
versions (3 passed for svc-01…05/08, 2 passed for svc-06/07). The library-level
premise (empty-`signatures` JSON JWS accepted on 1.8.0, `BadSignatureError` on
1.9.0) is additionally pinned as an automated test in `tests/test_cve_premise.py`
(run `uv run pytest -q` from the repo root).

## Scope rules honoured

- Proof inputs are harmless: a forged token that our own demo service accepts and echoes.
  No destructive payloads, no network calls, no posting anywhere.
- Only the publicly known flaw CVE-2026-96760 (Authlib < 1.9.0) is exercised.
- `wheelhouse/` and each service's `.venv/` are gitignored; no secrets are committed.
