# kb-scan container image — see tools/scan/containerisation.md for the strategy.
#
# Build (context is the crate directory, tools/scan):
#   docker build -t kb-scan:latest -f tools/scan/Dockerfile tools/scan
#
# Stage 1: build the static musl binary with the rust:1-musl toolchain.
FROM rust:1-musl AS build

WORKDIR /src

# Copy only the crate sources needed to build (zero external dependencies).
COPY Cargo.toml ./
COPY .cargo/ .cargo/
COPY src/ src/

# The crate's .cargo/config.toml sets linker = "rust-lld" because the build
# environment has no cc/libc dev files; rust-lld ships with the toolchain.
# The env var below is belt-and-braces so the link mode cannot silently change.
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld

RUN cargo build --release --target x86_64-unknown-linux-musl

# Stage 2: scratch — the final image contains only the static binary.
# No shell, no package manager, no dynamic loader, nothing to exploit.
FROM scratch

COPY --from=build /src/target/x86_64-unknown-linux-musl/release/kb-scan /kb-scan

# Non-root, no passwd entry needed (nobody:nogroup).
USER 65534:65534

ENTRYPOINT ["/kb-scan"]
