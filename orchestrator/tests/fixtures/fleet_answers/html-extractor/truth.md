# html-extractor — answer key

- **Case:** EXPOSED. Attacker-controllable input (the `selector` field of the
  request body) reaches Beautiful Soup's `soup.select(...)`, which parses the
  selector through Soup Sieve. The app never names Soup Sieve's parser
  functions directly.
- **Entry point:** `POST /extract` with JSON `{"html", "selector", "attribute"}`.
- **Reachable, uncontrolled-depth selector parsing.** `select_matches` passes
  the raw selector straight into `soup.select`.

## Code path (route → vulnerable call)

- `src/html_extractor/app.py:101` — `@app.post("/extract")` route decorator
- `src/html_extractor/app.py:103` — `def extract(request: ExtractRequest)`
- `src/html_extractor/app.py:108` — `matches = select_matches(request.html, request.selector, request.attribute)`
- `src/html_extractor/extractor.py:33` — `def select_matches(...)`
- `src/html_extractor/extractor.py:43` — `elements = soup.select(selector)`  ← reaches the Soup Sieve parser

The selector length cap is 8192 chars (`config.py`, env `HTML_EXTRACTOR_MAX_SELECTOR_LENGTH`);
the depth-330 probe selector is ~1.6 KB, well under the cap, so it is not blocked.

## Expected outcome

- **soupsieve 2.10:** the depth-330 selector overflows the parser's call stack.
  `POST /extract` raises inside the app; Starlette's TestClient re-raises, so
  `verify_trigger.py` prints `TRIGGERED` and exits 0; `proof_test.py` FAILS.
- **soupsieve 3.0.2 (fixed):** the same selector parses normally. `POST /extract`
  returns 200; `verify_trigger.py` prints `NOT TRIGGERED 200` and exits 1;
  `proof_test.py` PASSES.
