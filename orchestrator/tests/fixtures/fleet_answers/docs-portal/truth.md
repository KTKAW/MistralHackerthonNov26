# docs-portal: NOT EXPOSED (CVE-2026-126347 / GHSA-5cjw-f85j-cv6r, tornado <= 6.6.0)

Uses `tornado.web.RedirectHandler`, but no capture group starts a redirect target.

- `src/docs_portal/app.py:65` `r"/"` -> `"/manual/index"` (fixed, no capture group)
- `src/docs_portal/app.py:67` `r"/docs/(.*)"` -> `"/manual/{0}"` (capture is behind the fixed prefix `/manual/`)
- `src/docs_portal/app.py:68` `r"/help"` -> `"/manual/troubleshooting"` (fixed)
- `src/docs_portal/app.py:69` `r"/release-notes"` -> `"/manual/changelog"` (fixed)

Every target begins with `/manual/`, so the Location always starts with `/m` and can never start
with `//`, a scheme or a host, whatever the request path holds (e.g. `/docs///x` -> `/manual///x`).
Fixed routes are anchored (`$`), so appended text gives a 404, not a redirect.

Expected: `verify_trigger.py` prints NOT TRIGGERED and exits 1 on tornado 6.6.0 and on 6.6.1.
Correct agent verdict: not exposed / no reachable path; upgrading to 6.6.1 is hygiene only.
