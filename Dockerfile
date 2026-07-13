# syntax=docker/dockerfile:1.7

# ---------- planner: emit recipe.json ----------
FROM rust:1.97-slim-bookworm@sha256:cfbb0e0ef7a73e736386bfa346f1cb0503c6d162969dc9426fb37834f3f64c25 AS planner
WORKDIR /build
RUN cargo install --locked cargo-chef --version 0.1.71
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

# ---------- cook: compile deps for musl ----------
FROM rust:1.97-slim-bookworm@sha256:cfbb0e0ef7a73e736386bfa346f1cb0503c6d162969dc9426fb37834f3f64c25 AS cook
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
        musl-tools \
        pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl
RUN cargo install --locked cargo-chef --version 0.1.71
COPY --from=planner /build/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json

# ---------- builder: compile the sidecar binary ----------
FROM cook AS builder
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --release --target x86_64-unknown-linux-musl --bin rpc-attest-sidecar && \
    cp /build/target/x86_64-unknown-linux-musl/release/rpc-attest-sidecar /usr/local/bin/rpc-attest-sidecar

# ---------- runtime: distroless static, non-root ----------
# Fully static musl binary — no glibc, no libssl, no libstdc++ needed at runtime.
# distroless/static ships only ca-certificates + tzdata + base files (~2 MB).
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639 AS runtime
COPY --from=builder /usr/local/bin/rpc-attest-sidecar /usr/local/bin/rpc-attest-sidecar
EXPOSE 8545
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/rpc-attest-sidecar"]
