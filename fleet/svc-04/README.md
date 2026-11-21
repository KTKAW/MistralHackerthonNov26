# svc-04 — sessions (compact JWT only)

- **Affected?** NO — no reachable path found. Verification goes through
  `JsonWebToken.decode()`, which accepts only compact JWS (2 dots) or compact JWE (4 dots) and
  raises `DecodeError` otherwise. The flawed `deserialize_json` path is never called with
  attacker-controlled input, so the empty-`signatures` bypass cannot trigger here.
- **Entry point:** `GET /me` — `Authorization: Bearer <compact JWT>`.
- **Hidden route?** No.
- **Proof input:** `proof/input.json` — the same forged empty-`signatures` JWS. It is REJECTED
  on both 1.8.0 and 1.9.0 (`proof/verify_trigger.py` exits 0 only when rejected).
- **Verify by hand:** same sequence as `svc-01/README.md`; on both versions the proof must be
  rejected and the suite must pass.
- **Verification result:** see `fleet/README.md` matrix.
