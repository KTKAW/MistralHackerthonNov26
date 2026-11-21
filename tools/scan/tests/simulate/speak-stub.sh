#!/bin/sh
# SIMULATED speak stub for tools/scan/simulate.py: used as KB_SCAN_SPEAK_STUB so the
# audio-loop never calls a real model API. Appends the spoken text (stdin) to
# $SIM_STUB_LOG so assertions can prove no alert was spoken for a fake finding.
echo "--- SIMULATED speak $(date -u +%Y-%m-%dT%H:%M:%SZ) ---" >> "${SIM_STUB_LOG:-/dev/null}"
cat >> "${SIM_STUB_LOG:-/dev/null}"
