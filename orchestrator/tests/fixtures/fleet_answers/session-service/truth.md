# session-service: ground truth

- Case: NOT EXPOSED (no reachable path), although authlib==1.8.0 is pinned and inbound tokens are verified.
- Entry point: `GET /me` with `Authorization: Bearer <token>` (also `POST /sessions/revoke`, same dependency).
- Code path: `src/session_service/app.py:73` `me` -> `Depends(current_claims)` `app.py:41` -> `tokens.verify` `app.py:49` -> `src/session_service/tokens.py:43` `JsonWebToken(["HS256"]).decode(...)` (`authlib.jose.jwt`-style JWT decode).
- Why JSON input cannot reach the flaw: `JsonWebToken.decode` (authlib `jose/rfc7519/jwt.py:102-108` in 1.8.0) counts dots: 2 -> `deserialize_compact`, 4 -> JWE compact, anything else -> `DecodeError("Invalid input segments length")`. It never calls `JsonWebSignature.deserialize` or `deserialize_json`. A JSON-serialized JWS has no dots, so it fails before any signature logic; even one with dots would go to the compact parser and fail there. No code in the app calls `deserialize` / `deserialize_json`.
- Expected for `input.json` (general JSON serialization, payload `{"sub":"attacker","role":"admin"}`, `"signatures": []`): REJECTED 401 on authlib 1.8.0 and REJECTED 401 on 1.9.0. `verify_trigger.py` exits 1 on both.
- Hand-verified 2026-11-21, Python 3.12.13, macOS arm64: suite 8 passed on both versions.
