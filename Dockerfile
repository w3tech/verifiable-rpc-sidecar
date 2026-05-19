# syntax=docker/dockerfile:1.7

# ---------- planner: emit recipe.json ----------
FROM rust:1.95-slim-bookworm AS planner
WORKDIR /build
RUN cargo install --locked cargo-chef --version 0.1.71
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

# ---------- cook: compile deps only ----------
FROM rust:1.95-slim-bookworm AS cook
WORKDIR /build
RUN cargo install --locked cargo-chef --version 0.1.71
COPY --from=planner /build/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json

# ---------- builder: compile the sidecar binary ----------
FROM cook AS builder
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --release --bin rpc-attest-sidecar && \
    cp /build/target/release/rpc-attest-sidecar /usr/local/bin/rpc-attest-sidecar

# ---------- runtime: distroless cc, non-root ----------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
COPY --from=builder /usr/local/bin/rpc-attest-sidecar /usr/local/bin/rpc-attest-sidecar
EXPOSE 8545
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/rpc-attest-sidecar"]
