#!/bin/sh
# tools/scan/bwrap.example.sh — run kb-scan on the host under bubblewrap.
#
# Dev/local shape per tools/scan/containerisation.md: the repo is bind-mounted
# READ-ONLY, only the out dir (reports + lock file) is writable, and the sandbox
# keeps the host network namespace because the engine is host-side and needs its
# allowlisted feed egress (the allowlist itself is enforced inside the engine).
#
# Le Chonk per-repo workers are the opposite: add --unshare-net and never run
# kb-scan inside (see containerisation.md "The boundary rule").
#
# This exact bwrap invocation was tested in this environment on 2026-11-21
# (bubblewrap 0.11.1, unprivileged userns enabled; the `docker` binary on PATH
# here is a non-functional Windows Docker-Desktop path). On this usrmerge
# system /bin, /lib and /lib64 are symlinks into /usr, so they are recreated
# with --symlink instead of being bind-mounted.
#
# Usage:
#   tools/scan/bwrap.example.sh self-test
#   tools/scan/bwrap.example.sh scan --inventory tools/scan/inventory.example.json
#   tools/scan/bwrap.example.sh watch --interval 3600 --out-dir tools/scan/out
#
# Env overrides: REPO, OUT, KB_SCAN_BIN.

set -eu

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
OUT="${OUT:-$REPO/tools/scan/out}"
KB_SCAN_BIN="${KB_SCAN_BIN:-$REPO/tools/scan/target/x86_64-unknown-linux-musl/release/kb-scan}"

mkdir -p "$OUT"

exec bwrap \
  --ro-bind /usr /usr \
  --symlink usr/bin /bin \
  --symlink usr/lib /lib \
  --symlink usr/lib64 /lib64 \
  --ro-bind /etc /etc \
  --proc /proc \
  --dev /dev \
  --ro-bind "$REPO" "$REPO" \
  --bind "$OUT" "$OUT" \
  --chdir "$REPO" \
  "$KB_SCAN_BIN" "$@"
