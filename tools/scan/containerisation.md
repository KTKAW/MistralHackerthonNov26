# kb-scan containerisation strategy

This file is the written form of the "Containerisation strategy (decision)" section
of `tools/scan/ORCHESTRATION.md`. The deliverables it describes are `Dockerfile`,
`compose.example.yaml` and `bwrap.example.sh` in this directory.

## The boundary rule

**kb-scan is host-side and needs network egress. The Le Chonk per-repository
workers are not, and must never run kb-scan.**

- The engine polls live feeds (CISA KEV, OSV, GitHub Advisory Database, EPSS, NVD
  optional — `feeds.md`) and `git fetch`es, so it runs on the host side of the
  boundary, where its egress goes **only to the compiled-in host allowlist**
  (`www.cisa.gov`, `api.osv.dev`, `api.github.com`, `services.nvd.nist.gov`,
  `api.first.org`). Every request goes through `curl` as an argv array with
  https-only, no redirects, byte caps and timeouts; the host must exactly match
  the allowlist. No other egress exists.
- This matches `system.md` "In production": inside a company's own cloud account
  each job "runs in a container sandbox … holds no credentials, and reaches only
  a package mirror and a model gateway" — i.e. the sandboxed workers get no
  general internet, while feed ingestion is a separate, host-side concern.
- It also matches the track A prompt (`build/track-a-sandbox-worker`,
  `docs/prompts/track-a-sandbox-worker.md`): web tools are **disabled in every
  per-repo worker** and packages come only from the local wheelhouse
  (`pip --no-index --find-links`). Those workers run inside the sandbox
  (bwrap on Linux) with **no network**, and they never invoke `kb-scan` —
  the engine's reports are their *input*, produced host-side.

So there are exactly two runtime shapes:

| Where | What runs | Network |
|---|---|---|
| Host / dev (this machine) | `kb-scan` under `bwrap` | yes, allowlist-only (enforced in the engine) |
| Deployment (scratch container) | `kb-scan` | yes, allowlist-only (enforced at the network layer too) |
| Le Chonk per-repo workers | the worker agent, never `kb-scan` | **none** (`--unshare-net`) |

## Why bwrap for local and dev runs here

Verified in this environment on 2026-11-21:

- `/usr/bin/bwrap` exists (bubblewrap 0.11.1) and unprivileged user namespaces
  are enabled (`/proc/sys/user/max_user_namespaces` is non-zero), so bwrap works
  without root.
- The `docker` binary on `PATH` is a Windows Docker-Desktop path
  (`/mnt/c/Program Files/Docker/Docker/resources/bin/docker`) and does not run
  here — it fails with "could not be found in this WSL 2 distro". So a container
  runtime is not a usable local/dev option in this sandbox; bwrap is.

`bwrap.example.sh` therefore runs the engine as an ordinary host process inside a
bubblewrap sandbox with the repo bind-mounted read-only and only the out dir
writable. The sandbox keeps the host network namespace (the engine needs its
allowlisted egress); the allowlist itself is enforced inside the engine, not by
bwrap. The exact command in `bwrap.example.sh` was tested in this environment.

## Deployment: the scratch image

`Dockerfile` builds a two-stage image:

1. **Build stage** `FROM rust:1-musl`: copies the crate and runs
   `cargo build --release --target x86_64-unknown-linux-musl`. The crate's
   `.cargo/config.toml` sets `linker = "rust-lld"` (no `cc`/libc dev files
   needed; `rust-lld` ships with the toolchain), and the Dockerfile pins the
   same via `CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER`.
2. **Final stage** `FROM scratch`: copies **only** the static binary as
   `/kb-scan`, sets `USER 65534:65534` (non-root `nobody:nogroup`) and
   `ENTRYPOINT ["/kb-scan"]`. There is no shell, no package manager and no
   dynamic loader in the image — nothing extra to attack, and the zero-crate,
   `forbid(unsafe_code)` binary is the only thing that can run.

At runtime (see `compose.example.yaml`) the container is hardened:

- `read_only: true` — read-only rootfs (the image is scratch anyway; the only
  writable path is the mounted out dir for reports and the lock file).
- `cap_drop: ALL` plus `no-new-privileges` — all Linux capabilities dropped.
- Non-root `user: "65534:65534"`.
- Resource limits: memory, CPU and PID caps (`mem_limit`, `cpus`, `pids_limit`).
- `restart: unless-stopped` for the continuous `watch` loop.
- **Network-layer egress allowlist matching the engine's compiled-in host
  allowlist** (`www.cisa.gov`, `api.osv.dev`, `api.github.com`,
  `services.nvd.nist.gov`, `api.first.org`): on the deployment network, egress
  from the kb-scan container is restricted to those hosts on 443, so even a bug
  in the engine cannot exfiltrate anywhere else. Defense in depth: the engine
  itself refuses any host outside the same list.
