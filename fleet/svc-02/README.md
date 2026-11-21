# svc-02 — billing (HIDDEN ROUTE)

- **Affected?** YES — **hidden route**. `app.py` never mentions any authlib function; it calls
  the general-purpose wrapper `security.verify_bearer()`, which forwards to
  `JsonWebSignature.deserialize()`. Only by reading the installed library's source does one see
  that `deserialize()` routes JSON input to the flawed `deserialize_json()`. A text search for
  the flawed function's name in this repository finds NOTHING — this tile is the centre of the
  demo.
- **Entry point:** `POST /charge` — `Authorization: Bearer <token>`, JSON body `{"amount": N}`.
- **Proof input:** `proof/input.json` — forged JWS general JSON serialization with an EMPTY
  `signatures` array. Accepted on authlib 1.8.0 (a charge is "performed"), rejected with
  `BadSignatureError` on 1.9.0. Harmless: only our own demo service echoes the forged claims.
- **Verify by hand:** same sequence as `svc-01/README.md` (offline install from
  `../../wheelhouse`, pytest, `proof/verify_trigger.py` on 1.8.0 then on 1.9.0).
- **Verification result:** see `fleet/README.md` matrix.
