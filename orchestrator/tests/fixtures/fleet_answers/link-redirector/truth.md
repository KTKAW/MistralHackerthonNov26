# link-redirector: answer key for CVE-2026-126347 / GHSA-5cjw-f85j-cv6r

- Case: EXPOSED. Pinned `tornado==6.6.0` in `requirements.txt`; fixed in 6.6.1.
- Entry point: unauthenticated `GET /legacy/<anything>`; the request path is fully attacker-controlled.
- Code path: `src/link_redirector/app.py:62` registers `(r"/legacy/(.*)", tornado.web.RedirectHandler, {"url": "/{0}"})`
  inside `build_handlers()` (`app.py:44`), which `make_app()` (`app.py:77`) serves. The capture group forms the START
  of the redirect target, so `/legacy///host/x` becomes `Location: ///host/x`, which browsers treat as another host.
- Not affected: the fixed redirects (`app.py:51-58`, targets from `rules.py`) have no capture group.
- Expected on 6.6.0: `GET /legacy///other-site.example/x` (no follow) -> `301 Location: ///other-site.example/x`.
- Expected on 6.6.1: same request -> `400` ("Redirect URL cannot change the scheme or netloc").
- Proof: `proof_test.py` -> `tests/test_proof_cve_2026_126347.py::LegacyRedirectStaysOnSiteTest::test_legacy_redirect_does_not_leave_site`
  fails on 6.6.0, passes on 6.6.1. `verify_trigger.py` prints TRIGGERED (exit 0) on 6.6.0, NOT TRIGGERED 400 (exit 1) on 6.6.1.
- Fix: upgrade to `tornado>=6.6.1`, or give the target a fixed non-empty first segment.
