# ticket-mailer: truth

- Case: NOT EXPOSED, stale dependency. `requirements.txt:1` pins `mail-parser==4.6.2` (in the affected range for CVE-2026-129300 / GHSA-xhrq-2mqv-q8wx), but no file imports `mailparser`.
- How checked: `grep -rn -i mailparser . --exclude-dir=.venv` returns nothing; every import under `src/` is stdlib (`email`, `string`, `os`, ...), `fastapi` or `pydantic`; `verify_trigger.py` confirms `"mailparser" not in sys.modules` after importing the app and after all requests.
- Entry points: `POST /tickets/{ticket_id}/notify` (JSON: event, recipient, agent_name, summary, subject, status), `GET /outbox`, `GET /outbox/{id}`, `GET /health`. All input is `int` path params or a pydantic `NotifyRequest`; there is no raw-body or inbound-mail endpoint.
- Mail is only written, never parsed: `src/ticket_mailer/compose.py:43` (`EmailMessage()`), headers set at lines 44-51, body at `compose.py:52` (`set_content`), serialised at `src/ticket_mailer/app.py:55` (`as_string()`).
- The README changelog (2.0.0) says inbound customer replies moved to another service; that feature is what once needed the parser.
- Expected on 4.6.2 and 4.6.3: no request reaches mail-parser; nothing raises `OverflowError`. Trigger text in `summary` is accepted (202) and stored as plain body text; in single-line fields it is refused with 422.
- Verified: `verify_trigger.py` prints `NOT TRIGGERED (35 requests, mailparser not loaded)` and exits 1 on both versions. Positive control: `mailparser.parse_from_string(RAW)` raises `OverflowError` on 4.6.2 in the same venv.
- Correct agent verdict: "no reachable path found"; remediation is to drop or bump the unused pin, not an urgent fix.
