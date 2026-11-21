# link-checker: NOT EXPOSED (uses the flawed function, but only with constant selectors)
Advisory: CVE-2026-126193 / GHSA-7g44-g9rc-x53w, soupsieve >= 0.4, <= 2.10 (pinned 2.10; fixed 3.0.2).
Entry points: `POST /links`, `POST /summary` (body `{"html", "base_url"}`, both go through `_parse` -> `extract.parse_page`); `GET /health` takes no input.
Calls (selector constants defined at src/link_checker/extract.py:11-15):
- src/link_checker/extract.py:62 `soup.select_one(BASE_SELECTOR)` = `"base[href]"`
- src/link_checker/extract.py:67 `soup.select_one(TITLE_SELECTOR)` = `"title"`
- src/link_checker/extract.py:70 `soup.select_one(CANONICAL_SELECTOR)` = `"link[rel=canonical]"`
- src/link_checker/extract.py:77 `soup.select(LINK_SELECTOR)` = `"a[href]"`
- src/link_checker/extract.py:93 `soup.select(IMAGE_SELECTOR)` = `"img[src]"`
Why unreachable: every selector is a module constant; the caller controls only `html` (the document searched) and `base_url` (passed to `urljoin` only). `PageRequest` has no selector field, extra JSON fields are ignored by pydantic, and no request value is formatted into a selector. The flaw is in selector parsing, not in the searched HTML.
Expected: no request raises RecursionError on soupsieve 2.10 or 3.0.2; `verify_trigger.py` prints NOT TRIGGERED and exits 1 on both. Upgrading to 3.0.2 is still hygiene, not urgent.
