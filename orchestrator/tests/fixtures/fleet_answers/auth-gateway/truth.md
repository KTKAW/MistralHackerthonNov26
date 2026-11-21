# auth-gateway — ground truth

- **Case:** EXPOSED, by a direct call. The service verifies a JSON-serialized
  JWS with caller-controlled input through a direct `deserialize_json` call.
- **Entry point:** `POST /introspect`, JSON body `{"token": "<forged token>"}`.
- **Code path (file:line):**
  - `src/auth_gateway/app.py:111` — `introspect()` calls `_verify_token(request.token)`.
  - `src/auth_gateway/app.py:70` — `_verify_token()`: the token starts with `{`, so it is routed to
  - `src/auth_gateway/app.py:71` — `jws.deserialize_json(token, settings.signing_key)` (the flawed library call).
- **Forged token:** `input.json` — general JSON serialization, payload is base64url of
  `{"sub":"attacker","role":"admin"}`, with `"signatures": []`.
- **Expected outcome:**
  - authlib **1.8.0**: the empty `signatures` loop never runs, the token is ACCEPTED,
    `/introspect` returns `200` with `active: true` and the attacker claims. `verify_trigger.py` exits 0.
  - authlib **1.9.0**: the empty signatures array raises `BadSignatureError`,
    `/introspect` returns `401`. `verify_trigger.py` prints `REJECTED 401` and exits 1.
