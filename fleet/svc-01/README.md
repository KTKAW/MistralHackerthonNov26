# svc-01 — gateway (token introspection)

- **Affected?** YES — direct. `app.py` calls `jws.deserialize_json(...)` explicitly, so a text
  search for the flawed function finds it.
- **Entry point:** `POST /introspect` — raw body is a JWS in JSON serialization.
- **Hidden route?** No.
- **Proof input:** `proof/input.json` — a forged general JSON serialization whose `signatures`
  array is EMPTY (`[]`). On authlib 1.8.0 the signature loop never runs and the token is
  accepted; on 1.9.0 it is rejected with `BadSignatureError`. Harmless: the forged claims are
  only echoed back by our own demo service.
- **Verify by hand:**

  ```sh
  python -m venv .venv
  .venv/bin/pip install --no-index --find-links ../../wheelhouse -r requirements.txt
  .venv/bin/python -m pytest tests/ -q          # suite passes on 1.8.0
  .venv/bin/python proof/verify_trigger.py      # exit 0 -> TRIGGERED on 1.8.0
  .venv/bin/pip install --no-index --find-links ../../wheelhouse authlib==1.9.0
  .venv/bin/python proof/verify_trigger.py      # exit 1 -> rejected on 1.9.0
  .venv/bin/python -m pytest tests/ -q          # suite still passes on 1.9.0
  ```

- **Verification result:** see `fleet/README.md` matrix.
