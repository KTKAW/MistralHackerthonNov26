#!/bin/sh
# run_local.sh — ONE entrypoint for all three local workflows. Everything stays on localhost.
#
#   ./run_local.sh            start everything, Ctrl-C stops everything
#   ./run_local.sh demo       same, but the UI uses bundled demo data (no engine run needed)
#
# What starts:
#   1. kb-scan engine loop   tools/scan.py loop      -> tools/scan/out/latest.json (sandboxed shards)
#   2. adversarial simulator tools/scan/simulate.py loop -> runs/<run>/sim-triage.json (SIMULATED)
#   3. kb-scan query/voice   kb-scan serve           -> http://127.0.0.1:8787 (/latest /brief ...)
#   4. Le Chonk backend+UI   uvicorn web.app:app     -> http://127.0.0.1:8000/  (serves web/page.html)
#
# The Le Chonk Mistral Workflow (le_chonk_run) is started separately from your shell with your
# own key:  MISTRAL_API_KEY=... DEPLOYMENT_NAME=... OTEL_ENABLED=false uv run python -m orchestrator.workflow
# Its runs appear in the UI at http://127.0.0.1:8000/ automatically (same runs/ root).
set -eu
cd "$(dirname "$0")"

PORT_UI="${PORT_UI:-8000}"
PORT_SCAN="${PORT_SCAN:-8787}"
ENGINE_INTERVAL="${ENGINE_INTERVAL:-300}"
SIM_INTERVAL="${SIM_INTERVAL:-600}"
DEMO="${1:-}"

BIN=tools/scan/target/x86_64-unknown-linux-musl/release/kb-scan
if [ ! -x "$BIN" ]; then
  echo "building kb-scan (musl, static)..."
  export PATH="$HOME/.cargo/bin:$PATH"
  (cd tools/scan && cargo build --release --target x86_64-unknown-linux-musl)
fi

pids=""
cleanup() {
  echo "stopping..."
  for pid in $pids; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup INT TERM

start() { # name, command...
  name="$1"; shift
  "$@" >/tmp/kb-scan-local-$name.log 2>&1 &
  pids="$pids $!"
  echo "  $name (pid $!) — log: /tmp/kb-scan-local-$name.log"
}

echo "kb-scan local stack"
if [ "$DEMO" = "demo" ]; then
  echo "  demo mode: UI will use bundled sample data"
  UI_URL="http://127.0.0.1:$PORT_UI/?demo=1"
else
  start engine-loop python3 tools/scan.py loop --interval "$ENGINE_INTERVAL"
  start simulator python3 tools/scan/simulate.py loop --interval "$SIM_INTERVAL"
  UI_URL="http://127.0.0.1:$PORT_UI/"
fi
start scan-serve "$BIN" serve --port "$PORT_SCAN" --out-dir tools/scan/out
start ui uv run uvicorn web.app:app --host 127.0.0.1 --port "$PORT_UI"

echo
echo "ready:"
echo "  UI (Le Chonk grid + kb-scan feed watch + voice): $UI_URL"
echo "  kb-scan query/voice API:                          http://127.0.0.1:$PORT_SCAN/ (health, latest, sync, findings?tier=2, brief)"
echo "  start a Le Chonk run in Studio/your shell:        MISTRAL_API_KEY=... DEPLOYMENT_NAME=... OTEL_ENABLED=false uv run python -m orchestrator.workflow"
echo
wait
