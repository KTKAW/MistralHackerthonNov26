#!/bin/sh
# Passthrough "sandbox" wrapper for kb-scan tests: records that it wrapped a
# child (one line: the wrapped argv), then execs the child unchanged.
# Set KB_SCAN_SANDBOX_MARKER to a file path to collect the log lines.
if [ -n "$KB_SCAN_SANDBOX_MARKER" ]; then
    printf '%s\n' "$*" >> "$KB_SCAN_SANDBOX_MARKER" 2>/dev/null || true
fi
exec "$@"
