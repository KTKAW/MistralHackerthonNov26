# profile-api — answer key

- **Case:** EXPOSED ONLY IF A SETTING IS ON. A person must decide; the outcome
  depends on configuration.
- **Entry point:** `GET /profile` with `Authorization: Bearer <token>`.
- **Setting:** `PROFILE_ACCEPT_JSON_TOKENS`, read at request time via
  `config.accept_json_tokens()` (`src/profile_api/config.py:27`). Default: OFF.

## Code path (entry point to library call)

- `src/profile_api/app.py:132` — `get_profile` depends on `current_user`.
- `src/profile_api/app.py:96` — `current_user` strips the bearer prefix and calls `_verify_token`.
- `src/profile_api/app.py:83` — token starts with `{`, so the JSON branch is taken.
- `src/profile_api/app.py:84` — if the setting is OFF, refuse with 401 (no library call reached).
- `src/profile_api/app.py:86` — if the setting is ON, call `_jws.deserialize(json.loads(token), signing_key())`,
  which routes the dict to Authlib's `JsonWebSignature.deserialize_json` — the flawed path.

The forged token (`input.json`) has an empty `signatures` array, so the
signature loop never runs and the payload is returned as verified on the
affected library version.

## Expected outcome at the entry point

| Setting | authlib 1.8.0 | authlib 1.9.0 |
|---------|---------------|---------------|
| off (default) | REJECTED 401 | REJECTED 401 |
| on            | ACCEPTED (profile of "attacker" returned) | REJECTED 401 |

With the setting off the JSON branch refuses the token before any library call.
With it on, 1.8.0 accepts the empty-signature token and 1.9.0 rejects it with a
signature error.
