# svc-08 — profiles (bearer token, compact or JSON)

- **Affected?** YES. `GET /profile` accepts a JSON-serialized JWS as the bearer token and
  verifies it via `jws.deserialize(json.loads(token), key)` (dict input → JSON serialization
  verification path).
- **Entry point:** `GET /profile` — `Authorization: Bearer <token>`.
- **Hidden route?** No (the JSON branch is visible in the handler).
- **Proof input:** `proof/input.json` — forged empty-`signatures` JWS claiming `role: admin`.
  Accepted on authlib 1.8.0 (profile of "attacker" returned), rejected on 1.9.0. Harmless:
  only our own demo service echoes it.
- **Verify by hand:** same sequence as `svc-01/README.md`.
- **Verification result:** see `fleet/README.md` matrix.
