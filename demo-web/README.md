# ChonkSweep — demo front-end (Vercel)

Static, dependency-free single page (`index.html`). Deployed to Vercel as
**https://chonksweep-demo.vercel.app** (project `chonksweep-demo`, account
`jaydenwong233-8480`).

## Two modes

- **Mock demo (default)** — no backend needed. The simulation mirrors the
  hand-verified demo fleet in `fleet/README.md`: svc-01/03/08 affected+fixed
  (direct calls), **svc-02 billing affected via the hidden wrapper route**
  (`security.verify_bearer()` → `jws.deserialize` — invisible to grep),
  svc-04…07 not affected ("no reachable path found", never "safe").
- **Live mode** — point the page at the FastAPI backend (`web/app.py` on
  :8000, branch `build/base`):
  `https://chonksweep-demo.vercel.app/?api=http://<demo-machine>:8000`
  It then speaks `POST /runs {advisory_text}`, polls `GET /runs/{id}`,
  fetches `GET /artifacts/{run}/{repo}/verdict.json` for tile details, and
  `POST /runs/{id}/approve` on approve. If the backend is unreachable it
  falls back to the mock, so the demo never breaks on stage.

## Redeploy

```sh
# the Vercel CLI is a Windows binary here — deploy from a /mnt/c path, not a UNC path
cp -r demo-web/. /mnt/c/tmp/chonksweep/
cd /mnt/c/tmp/chonksweep && npx vercel deploy --prod --yes
```

(`vercel.json` keeps the `chonksweep-demo.vercel.app` alias; first deploy
created the project.)

## Demo video

`chonksweep-demo.mp4` (37 s, H.264, ~4 MB) — recorded headlessly (Playwright +
Chrome) driving the deployed page end to end: paste advisory → agent fleet
fills the 8-tile grid live → open the svc-02 hidden-route tile → replay the
forged-JWS exploit (200 on authlib 1.8.0 / 401 on 1.9.0) → signed audit trail
→ ENISA early-warning draft with the 24 h clock → approve. Also served at
https://chonksweep-demo.vercel.app/chonksweep-demo.mp4

Re-record: `node record.mjs` in a Windows-side copy of this dir with
`playwright-core` (see /mnt/c/tmp/vid/record.mjs), then transcode webm→mp4
with any ffmpeg (`-c:v libx264 -crf 21 -pix_fmt yuv420p -movflags +faststart`).
