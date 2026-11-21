# svc-07 — signer (outbound signing only)

- **Affected?** NO — no reachable path found. The service only SIGNS payloads
  (`jws.serialize_compact`); it never deserializes attacker-controlled input, so the flawed
  verification path is unreachable.
- **Entry point:** `POST /sign` — body is the payload to sign; returns a compact JWS.
- **Hidden route?** No.
- **Proof input:** `proof/input.json` — forged empty-`signatures` JWS; svc-07 accepts no token,
  so no trigger on 1.8.0 or 1.9.0.
- **Verify by hand:** same sequence as `svc-01/README.md`.
- **Verification result:** see `fleet/README.md` matrix.
