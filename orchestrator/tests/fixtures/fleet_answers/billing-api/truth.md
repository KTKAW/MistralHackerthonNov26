# billing-api — answer key

- **Case:** AFFECTED, via a hidden route. The app never names the flawed
  function. The route depends on a general-purpose helper that calls
  `JsonWebSignature.deserialize(token, key)`, which routes JSON input to the
  empty-`signatures` bypass (CVE-2026-96760, Authlib < 1.9.0). A text search for
  `deserialize_json` in the app finds nothing.
- **Entry point:** `POST /charge` with `Authorization: Bearer <token>`.

## Code path (entry point → library call)

1. `src/billing_api/app.py:81` — `charge(...)` handler, depends on
2. `src/billing_api/app.py:83` — `Depends(current_customer)` (FastAPI dependency)
3. `src/billing_api/security.py:54` — `current_customer(...)`
4. `src/billing_api/security.py:68` — `claims = verify_bearer(token)`
5. `src/billing_api/security.py:47` — `_jws.deserialize(token.strip(), settings.signing_key)`
   → Authlib routes the JSON-serialized token to `deserialize_json`, whose
   signature loop never runs for an empty `signatures` array.

## Expected outcome

- **authlib 1.8.0:** forged token (`{"sub":"alice","role":"admin"}`, an existing customer,
  `"signatures": []`) is ACCEPTED → `POST /charge` returns `201` with an invoice
  for customer `alice`. `verify_trigger.py` prints `ACCEPTED ...`, exits 0.
- **authlib 1.9.0:** empty signatures raise `BadSignatureError` → the dependency
  returns `401`. `verify_trigger.py` prints `REJECTED 401`, exits 1.
- The pytest suite passes on both 1.8.0 and 1.9.0 (no test uses an
  empty-`signatures` token).
