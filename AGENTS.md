# rpc-attest-sidecar

Rust sidecar that signs HTTP responses with an Intel TDX-attested Ed25519 key — clients verify the signature against a TDX quote to prove the response came from an approved upstream image inside an enclave (Phala dstack). See [README.md](./README.md) for end-user docs and curl examples.

## Commands

| Action | Command |
|--------|---------|
| Build | `cargo build` |
| Format check | `cargo fmt --all -- --check` |
| Format fix | `cargo fmt --all` |
| Lint  | `cargo clippy --all-targets -- -D warnings` |
| Unit tests | `cargo test --lib` |
| Integration tests | `cargo test --test integration_blackbox --test integration_harness --test dstack_baseline -- --test-threads=1` |
| Run | `cargo run -- --listen-addr 0.0.0.0:8545 --upstream-url <url> --chain-id <id>` |

Integration tests require `DSTACK_SIMULATOR_BIN` + `DSTACK_SIMULATOR_FIXTURES_DIR` env vars. Live upstream node tests additionally require `NODE_RPC_URL` + `NODE_API_KEY`. See `tests/common/mod.rs:1-19`.

## Pre-push gate (mandatory)

**Before every `git push`** run all four in order. CI runs the same set — fix locally instead of letting CI fail.

```sh
cargo fmt --all -- --check       # exit 0 — no diff
cargo clippy --all-targets -- -D warnings   # exit 0
cargo test --lib                  # all green
DSTACK_SIMULATOR_BIN=/path/to/dstack-simulator \
DSTACK_SIMULATOR_FIXTURES_DIR=/path/to/fixtures \
  cargo test --test integration_blackbox --test integration_harness --test dstack_baseline -- --test-threads=1
```

If `cargo fmt --check` fails: run `cargo fmt --all`, commit the diff as a separate commit, do not amend the offending commit.

If the local pre-commit hook does not enforce these (it currently does not run `cargo fmt --check`), the gate above is the contract — agents must run it manually.

## Architecture

Single-process HTTP server (`axum` + `hyper`). Boots, derives a TDX-attested keypair via dstack, then byte-opaque proxies every request to the upstream and signs the response post-serialisation.

```
client ──HTTP──▶ [sidecar :8545] ──HTTP/HTTPS──▶ upstream
                       │
                       ├─ /attestation  TDX quote, REPORTDATA = pubkey ‖ user_nonce
                       ├─ /info         dstack info() pass-through — testing only (no auth)
                       └─ *             byte-opaque proxy (inbound path+query appended to the upstream base) + Ed25519 sig on response
```

Boot order (`src/main.rs`):

1. `Config::parse` (clap) — CLI flags + env.
2. `DstackClient` (from the external `dstack-sdk` crate — no in-repo dstack module) opens `/var/run/dstack.sock` (or simulator socket).
3. `bootstrap_tdx_identity` derives the signing key and fetches a TDX quote — REPORTDATA binds the signing pubkey into the quote.
4. `UpstreamClient::new` parses the upstream URL once; malformed URL aborts boot.
5. `build_router` wires `AppState` → `axum::serve` with graceful shutdown.

## Source layout

| File | Responsibility |
|------|----------------|
| `src/main.rs` | Entry point, boot order, graceful shutdown, fail-fast on init errors |
| `src/lib.rs` | Module re-exports for the library crate |
| `src/config.rs` | CLI flags + env config (clap-derive) |
| `src/server.rs` | `axum::Router` wiring, `AppState` shared across handlers |
| `src/signing.rs` | `SigningState`, canonical 104-byte pre-image (`sha256(chain_id)` ‖ req ‖ resp hashes ‖ ts), string chain-id validation, `now_ms` clock guard |
| `src/attestation.rs` | `/attestation` handler — quote bound to caller-supplied nonce + signing pubkey; also `/info` handler — serves `dstack.info()` JSON cached at boot |
| `src/proxy.rs` | Byte-opaque pass-through proxy — `upstream_uri` (configured base + inbound path+query), RFC 7230 §6.1 hop-by-hop filter, per-request body cap, forces Accept-Encoding: identity on the upstream leg |
| `src/util.rs` | Tiny shared helpers (e.g. 0x-prefixed hex encoding). |
| `tests/common/mod.rs` | Test harness — simulator spawn, mock upstream, sidecar binary spawn, signature verifier |
| `tests/integration_harness.rs` | White-box integration tests |
| `tests/integration_blackbox.rs` | End-to-end black-box tests via the compiled binary |
| `tests/dstack_baseline.rs` | dstack SDK baseline tests (get_key byte-compat, info against simulator). |

## Where to look first

| Task | Start here |
|------|-----------|
| Add a new HTTP endpoint | `src/server.rs::build_router` + new handler module |
| Touch signing / pre-image | `src/signing.rs` (pre-image is byte-exact — see `pre_image_layout_is_byte_exact`) |
| Touch attestation / quote | `src/attestation.rs::build_report_data` (REPORTDATA = pubkey ‖ nonce, 64 B) |
| Touch proxy semantics | `src/proxy.rs::UpstreamClient::forward` (request body byte-opaque; upstream URI = configured base + inbound path+query via `upstream_uri`; response signature covers the content-decoded body — upstream forced to identity, client-facing compression by the router's `CompressionLayer`) |
| Touch dstack protocol | `src/attestation.rs` (uses the external `dstack-sdk` `DstackClient` over the guest-agent socket) |
| Add a config flag | `src/config.rs` (clap-derive struct) |

## Conventions

- **Byte-opaque request, content-decoded response signing.** The request body is forwarded verbatim — never parsed, never mutated. On the response path the sidecar forces `Accept-Encoding: identity` to upstream (so the node returns plaintext) and re-encodes the response to the client per the client's `Accept-Encoding` (gzip/identity) via `tower-http`'s `CompressionLayer` — strictly AFTER signing. The signature covers the **content-decoded** (plaintext) response body; the client recovers it by decoding `Content-Encoding`, then verifies.
- **Sign over the content-decoded body.** Signature covers the content-decoded (plaintext) response body — never the transport encoding. Compression is post-signing transport (`CompressionLayer`); it never mutates the signed bytes or `vRPC-*` headers.
- **Identity-to-upstream is cheap.** Forcing identity on the upstream leg costs almost nothing because the sidecar and node are co-located — uncompressed transfer there avoids a compress→sign-plaintext→re-compress mismatch.
- **Fail-fast at boot.** Invalid config aborts with exit code 2 after `FAIL_FAST_DEADLINE`; do not silently degrade.
- **Clippy `-D warnings` is a hard gate.** Lib + integration test code paths must stay clean before push.
- **Worktree rule:** never push directly from the primary checkout — do work in a dedicated git worktree off main.
