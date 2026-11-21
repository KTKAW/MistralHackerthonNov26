# TRACK B — Demo fleet + offline wheelhouse

Branch: `build/track-b-fleet` · You are build agent **2 of 3**.
This track needs **no model calls** — triggers are verified by hand.

## Launch

```sh
git checkout build/track-b-fleet
vibe --prompt-file docs/prompts/track-b-fleet.md --workdir . --trust \
  --auto-approve --model mistral-large-4-0
```

## Read first

`PROJECT.md` ("What we have tested", "What is left to build", "Risks", "Scope rules") ·
`docs/architecture.html` · `docs/COORDINATION.md` · `docs/build-prompt.md` Step 2.

## You OWN — edit only these

- `fleet/` — 8 demo services plus `fleet/README.md`, the ground-truth matrix.
- `wheelhouse/` is **gitignored**: build it locally on YOUR machine and document the exact
  command at the top of `fleet/README.md` so the other two humans reproduce the same set.

## Do NOT touch

`sandbox/`, `worker/` (track A) · `orchestrator/`, `web/` (track C) · `schema/`, `.gitignore`
(already on base).

## The flaw under test

**CVE-2026-96760** — signature-check bypass in **Authlib < 1.9.0** (published 2026-10-27).
Every fleet service pins `authlib==1.8.0`; the fixed version is `1.9.0`.

## Steps

- [ ] **B1 — wheelhouse.** On a machine WITH network:
      `uv pip download authlib==1.8.0 authlib==1.9.0 -d wheelhouse/`
      (pulls dependencies too). Verify both versions are present; record the command in
      `fleet/README.md`.
- [ ] **B2 — service template**, repeated for `fleet/svc-01` … `fleet/svc-08`:

```
fleet/<svc>/
├── requirements.txt     # authlib==1.8.0 + minimal web deps; every dep must resolve from wheelhouse/
├── src/<svc>/           # the service (FastAPI), one clear entry point
├── tests/               # pytest suite (must pass on the vulnerable version, before any fix)
├── proof/input.*        # HARMLESS proof input: forged token the bypass accepts, or marker-file payload
└── README.md            # ground truth: affected? entry point? hidden route? verification result
```

- [ ] **B3 — composition.** At least 2 **affected** and 2 **unaffected**; the rest mixed.
      One affected service MUST be the **hidden route**: it calls a general-purpose wrapper
      that forwards to the flawed authlib function, so grepping for the flawed function's name
      misses it — this tile is the centre of the demo. If time allows, replace one synthetic
      service with one real open-source project pinned to 1.8.0.
- [ ] **B4 — hand-verify EVERY service on your machine, before any agent sees it:**

```sh
cd fleet/<svc>
python -m venv .venv
.venv/bin/pip install --no-index --find-links ../../wheelhouse -r requirements.txt
.venv/bin/python -m pytest tests/ -q                 # suite passes
# apply proof/input against 1.8.0  -> MUST trigger the flaw
# then install authlib==1.9.0 from the wheelhouse and re-apply -> MUST NOT trigger
```

      Record each result in the `fleet/README.md` matrix (service · affected? · hidden route? ·
      verified on 1.8.0 · verified on 1.9.0 · notes).
- [ ] **B5 — proof inputs stay harmless** (forged request accepted, or an empty marker file
      created). No destructive payloads. Publicly known flaw only. No auto-posting anywhere.
- [ ] **B6 — commit per service**, with the heredoc format in `docs/COORDINATION.md`.
      Commit the fleet code — NOT `wheelhouse/` (gitignored).

## Done when

The `fleet/README.md` matrix shows all 8 services hand-verified, and every service installs
fully offline with `--no-index` and runs its suite.

## Merge

```sh
git checkout build/base && git merge --no-ff build/track-b-fleet
```

Push only if the team agreed to share the remote.
