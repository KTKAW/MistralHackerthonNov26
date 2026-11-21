# svc-03 — webhooks (inbound payment webhook)

- **Affected?** YES. `POST /hooks/payment` takes the whole JSON body as a JWS and verifies it
  with `jws.deserialize(body, key)` (dict input → JSON serialization path).
- **Entry point:** `POST /hooks/payment` — body is the JWS JSON serialization.
- **Hidden route?** No (calls the general `deserialize`, but the body itself is JSON, so the
  flawed path is hit directly).
- **Proof input:** `proof/input.json` — forged webhook with an EMPTY `signatures` array,
  carrying a fake `payment.demo` event from "attacker". Accepted on authlib 1.8.0, rejected on
  1.9.0. Harmless: the demo service only echoes the event.
- **Verify by hand:** same sequence as `svc-01/README.md`.
- **Verification result:** see `fleet/README.md` matrix.
