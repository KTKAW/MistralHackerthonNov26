# mail-intake: ground truth

- Advisory: CVE-2026-129300 / GHSA-xhrq-2mqv-q8wx, `mail-parser` >= 3.7.0, < 4.6.3, fixed in 4.6.3.
- Case: EXPOSED. Raw mail from the internet goes straight into `mailparser.parse_from_bytes`.
- Entry point: `POST /inbound`, the mail provider's webhook. The body is the raw message.
- Code path: `src/mail_intake/app.py:58` `inbound` -> `app.py:69` `summarise(raw)` ->
  `src/mail_intake/parsing.py:38` `mailparser.parse_from_bytes(raw)`.
- What the app catches: `MailParserError` only (`parsing.py:39`), turned into `UnreadableMessage` and a 422.
  `OverflowError` and `OSError` are outside that hierarchy, so they are not caught.
- Trigger: one `Received` header whose date has the year 292277026596.
- Expected on mail-parser 4.6.2: `OverflowError` comes out of the app. `verify_trigger.py` prints
  `TRIGGERED OverflowError` and exits 0. The proof test fails.
- Expected on mail-parser 4.6.3: 201, the message is stored. `verify_trigger.py` prints `NOT TRIGGERED 201`
  and exits 1. The proof test passes.
- Checked by hand on 21 November 2026, Python 3.12, offline.
