# Deploying the Le Chonk web UI

## Frontend: static on Vercel

`web/page.html` is a single self-contained static page (vanilla JS, no build step, no
dependencies). Deploy it from this repository with the Vercel project's **Root Directory** set
to `web/`, so `page.html` is the site root. `vercel.json` at the repo root rewrites `/` to
`/page.html`.

The page talks to the backend through a configurable base URL, in this order:

1. the `?api=` query parameter, e.g. `https://<site>.vercel.app/?api=https://<tunnel>.ngrok-free.app`
2. `window.KB_API_BASE`, set by a small inline script before the page's main script
3. same-origin (default), which is what `python -m web.app` serves directly on `127.0.0.1:8000`

The kb-scan voice brief falls back to `http://127.0.0.1:8787/brief` (`kb-scan serve`); override
with `window.KB_SCAN_BASE`.

## Backend: FastAPI + kb-scan serve

The backend is **not** static and is not deployed to Vercel: `web/app.py` (FastAPI, the runs API,
event stream, reports) plus `kb-scan serve` (the kb-scan engine's HTTP side on `127.0.0.1:8787`).

- **Dev:** run both locally and expose the FastAPI port with ngrok:

      MISTRAL_API_KEY=... uv run python -m web.app        # 127.0.0.1:8000
      ngrok http 8000                                       # https://<tunnel>.ngrok-free.app

  then open the Vercel page with `?api=https://<tunnel>.ngrok-free.app`.

- **Prod:** run them on a VM (or any host) behind HTTPS, and point `?api=` at that origin.

## CORS

The page on the Vercel origin calls the backend cross-origin (including the
`/runs/{id}/stream` EventSource), so the backend must send CORS headers for the Vercel origin.

<!-- TODO(backend-owner): web/app.py is owned by another agent — add env-var-driven CORS there,
     e.g. read LE_CHONK_ALLOWED_ORIGINS (comma-separated, default same-origin only) and pass it
     to FastAPI's CORSMiddleware with allow_origins=that list, allow_methods=["GET","POST"],
     allow_headers=["content-type"], and expose nothing else. Do not hardcode the Vercel origin. -->

Prefer configuring the allowed origin through an environment variable
(`LE_CHONK_ALLOWED_ORIGINS=https://<site>.vercel.app`), never by hardcoding a deployment URL.

## Notes

- All run, feed and scan data the page renders is untrusted: the backend size-caps and
  sanitises it, and the page inserts it as text only (no `innerHTML`), with the kb-scan tiles
  labelled "unverified feed data".
- Voice in the GUI uses the browser's Web Speech API (`speechSynthesis` /
  `SpeechRecognition`). The server-side Voxtral TTS brief remains the CLI path:
  `python3 tools/scan.py brief`.
