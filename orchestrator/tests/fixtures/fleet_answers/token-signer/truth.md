# token-signer: truth

- **Case:** NOT EXPOSED. Same class (`authlib.jose.JsonWebSignature`), opposite direction: signs only.
- **Endpoints:** `GET /health`, `GET /keys` (kid + alg, no key material), `POST /sign` (caller named by `X-Caller-Service`, checked against an allow-list; body is a pydantic `SignRequest` with `extra="forbid"`).
- **Authlib use:** `src/token_signer/signing.py:6` (import), `src/token_signer/signing.py:19` (`JsonWebSignature(algorithms=["HS256"])`), `src/token_signer/signing.py:44` (`serialize_compact`). Nothing else imports Authlib.
- **Why unreachable:** no code calls `deserialize`, `deserialize_compact`, `deserialize_json` or `jwt.decode`. No endpoint reads an `Authorization` header or treats any inbound token as identity; caller identity is a plain header name. Inbound data only flows into claims that the service itself signs.
- **Forged token:** `input.json` (general JSON serialization, payload `{"sub":"attacker","role":"admin"}`, `"signatures": []`). As a bearer header it is ignored; as a `/sign` body it fails `SignRequest` validation (422); without an allowed caller it is 401/403.
- **authlib 1.8.0:** REJECTED, no endpoint verifies tokens. **authlib 1.9.0:** REJECTED, same. Upgrading changes nothing observable here; the right verdict is "no reachable path found".
- **Trap to avoid:** a scanner that flags on the class name alone (`JsonWebSignature` is imported) would report a false positive.
