# svc-06 — oauth-client (outbound OAuth2 only)

- **Affected?** NO — no reachable path found. The service imports authlib only to build an
  OAuth2 authorization URL (`OAuth2Client.create_authorization_url`). It never deserializes an
  inbound JWS, so the flawed signature-check path is unreachable.
- **Entry point:** `GET /login` (returns the IdP authorize URL).
- **Hidden route?** No.
- **Proof input:** `proof/input.json` — forged empty-`signatures` JWS; the service has no
  verification endpoint, and the proof script shows it cannot pass the compact path either.
  No trigger on 1.8.0 or 1.9.0.
- **Verify by hand:** same sequence as `svc-01/README.md`.
- **Verification result:** see `fleet/README.md` matrix.
