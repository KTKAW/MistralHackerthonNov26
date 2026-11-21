# Repo-level unit tests

Tests for the parts of the build that exist as code on this branch: the
`verdict.json` contract (`schema/`), the demo fleet's structure and ground
truth (`fleet/`), and the CVE-2026-96760 premise itself, re-proven offline
against both authlib wheels in `wheelhouse/`.

Run from the repo root (this machine has network; `uv` creates `.venv`, which
is gitignored):

```sh
uv run pytest -q
```

Notes:

- `test_cve_premise.py` builds two throwaway venvs with
  `uv pip install --no-index --find-links wheelhouse authlib==<ver>` and is
  skipped if `uv` is not on `PATH`. It encodes the "hand-verified" column of
  `fleet/README.md` as a repeatable check.
- Each fleet service's *own* suite (`fleet/<svc>/tests/`) is not collected
  here — it needs that service's venv. See `fleet/README.md` for the exact
  per-service commands.
