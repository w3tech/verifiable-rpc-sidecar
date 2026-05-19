# syntax=docker/dockerfile:1.7

# ---------- planner: emit recipe.json ----------
FROM rust:1.95-slim-bookworm@sha256:b8ecdb97c5b9c1ae058249f72710dbe33d4da19f7b8d911bd3c72e5f048af251 AS planner
WORKDIR /build
RUN cargo install --locked cargo-chef --version 0.1.71
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

# ---------- cook: compile deps (release + test) for musl ----------
# This stage is the heavyweight one. It is the shared base for lint, test,
# builder. CI fan-out exploits this — cook is materialised once, all downstream
# jobs reuse the layer via GHA cache.
FROM rust:1.95-slim-bookworm@sha256:b8ecdb97c5b9c1ae058249f72710dbe33d4da19f7b8d911bd3c72e5f048af251 AS cook
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
        musl-tools \
        pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl \
    && rustup component add rustfmt clippy
RUN cargo install --locked cargo-chef --version 0.1.71
COPY --from=planner /build/recipe.json recipe.json
# --tests so dev-deps are baked too — `cargo test --lib` reuses them.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo chef cook --release --tests --target x86_64-unknown-linux-musl --recipe-path recipe.json

# ---------- sources: shared layer with code copied in ----------
# Separated so lint / test / builder all share the same COPY layer instead of
# each repeating it (and busting BuildKit dedup heuristics).
FROM cook AS sources
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY tests ./tests

# ---------- lint: cargo fmt + cargo clippy ----------
FROM sources AS lint
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo fmt --all -- --check && \
    cargo clippy --all-targets --target x86_64-unknown-linux-musl -- -D warnings

# ---------- test: cargo test --lib ----------
FROM sources AS test
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo test --lib --target x86_64-unknown-linux-musl

# ---------- builder: compile the sidecar binary ----------
FROM sources AS builder
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
