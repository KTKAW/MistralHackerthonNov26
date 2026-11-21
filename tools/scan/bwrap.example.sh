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
# /etc is bound selectively, not whole: TLS roots from the host, plus a
# generated /etc/hosts that pins the engine's allowlisted hosts (on WSL the DNS
# proxy does not answer inside bwrap, so resolution must come from `files` —
# the same trick tools/scan.py's write_sandbox_etc uses). Everything else fails
# closed. This mirrors BWRAP_TEMPLATE in tools/scan.py.
#
# Usage:
#   tools/scan/bwrap.example.sh scan --inventory tools/scan/inventory.example.json --out /tmp/report.json
#   tools/scan/bwrap.example.sh watch --interval 3600
#
# Env overrides: REPO, OUT, KB_SCAN_BIN.

set -eu

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
OUT="${OUT:-$REPO/tools/scan/out}"
KB_SCAN_BIN="${KB_SCAN_BIN:-$REPO/tools/scan/target/x86_64-unknown-linux-musl/release/kb-scan}"

mkdir -p "$OUT/sandbox-etc"

HOSTS_FILE="$OUT/sandbox-etc/hosts"
{
  echo "127.0.0.1 localhost"
  echo "::1 localhost ip6-localhost ip6-loopback"
  for h in www.cisa.gov api.osv.dev api.github.com services.nvd.nist.gov api.first.org github.com; do
    getent ahosts "$h" 2>/dev/null | awk '{print $1, "'"$h"'"}' | sort -u || true
  done
} > "$HOSTS_FILE"
printf '# DNS is not available in the sandbox; hosts are pinned in /etc/hosts\nnameserver 127.0.0.1\n' \
  > "$OUT/sandbox-etc/resolv.conf"

exec bwrap \
  --clearenv \
  --setenv PATH /usr/bin:/bin \
  --setenv KB_SCAN_IN_SANDBOX 1 \
  --ro-bind /usr /usr \
  --symlink usr/bin /bin \
  --symlink usr/lib /lib \
  --symlink usr/lib64 /lib64 \
  --ro-bind /etc/ssl /etc/ssl \
  --ro-bind "$HOSTS_FILE" /etc/hosts \
  --ro-bind "$OUT/sandbox-etc/resolv.conf" /etc/resolv.conf \
  --ro-bind /etc/nsswitch.conf /etc/nsswitch.conf \
  --proc /proc \
  --dev /dev \
  --ro-bind "$REPO" "$REPO" \
  --bind "$OUT" "$OUT" \
  --chdir "$REPO" \
  "$KB_SCAN_BIN" "$@"
