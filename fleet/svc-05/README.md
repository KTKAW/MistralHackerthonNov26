# svc-05 — legacy (compact JWS only)

- **Affected?** NO — no reachable path found. The service calls
  `jws.deserialize_compact(...)` explicitly, so a JSON-serialized token is parsed as compact
  and fails (`Not enough segments`) before any signature logic runs. `deserialize_json` is
  never reached.
- **Entry point:** `POST /verify` — `Authorization: Bearer <compact JWS>`.
- **Hidden route?** No.
- **Proof input:** `proof/input.json` — forged empty-`signatures` JWS; REJECTED on both 1.8.0
  and 1.9.0.
- **Verify by hand:** same sequence as `svc-01/README.md`; proof rejected on both versions.
- **Verification result:** see `fleet/README.md` matrix.
