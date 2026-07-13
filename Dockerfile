# syntax=docker/dockerfile:1.7

# ---------- planner: emit recipe.json ----------
FROM rust:1.95-slim-bookworm@sha256:b8ecdb97c5b9c1ae058249f72710dbe33d4da19f7b8d911bd3c72e5f048af251 AS planner
WORKDIR /build
RUN cargo install --locked cargo-chef --version 0.1.71
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

# ---------- cook: compile deps for musl ----------
FROM rust:1.95-slim-bookworm@sha256:b8ecdb97c5b9c1ae058249f72710dbe33d4da19f7b8d911bd3c72e5f048af251 AS cook
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
FROM gcr.io/distroless/static-debian12:nonroot@sha256:b7bb25d9f7c31d2bdd1982feb4dafcaf137703c7075dbe2febb41c24212b946f AS runtime
COPY --from=builder /usr/local/bin/rpc-attest-sidecar /usr/local/bin/rpc-attest-sidecar
EXPOSE 8545
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/rpc-attest-sidecar"]
