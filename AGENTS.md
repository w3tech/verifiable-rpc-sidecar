# rpc-attest-sidecar

Rust sidecar that signs HTTP responses with an Intel TDX-attested Ed25519 key — clients verify the signature against a TDX quote to prove the response came from an approved upstream image inside an enclave (Phala dstack). See [README.md](./README.md) for end-user docs and curl examples.

## Commands

| Action | Command |
|--------|---------|
| Build | `cargo build` |
| Lint  | `cargo clippy --all-targets -- -D warnings` |
| Unit tests | `cargo test --lib` |
| Integration tests | `cargo test --test integration_blackbox --test integration_harness -- --test-threads=1` |
| Run | `cargo run -- --listen-addr 0.0.0.0:8545 --upstream-url <url>` |

Integration tests require `DSTACK_SIMULATOR_BIN` + `DSTACK_SIMULATOR_FIXTURES_DIR` env vars. Live shark-proxy tests additionally require `SHARK_RPC_URL` + `SHARK_API_KEY`. See `tests/common/mod.rs:1-19`.

## Architecture

Single-process HTTP server (`axum` + `hyper`). Boots, derives a TDX-attested keypair via dstack, then byte-opaque proxies every request to the upstream and signs the response post-serialisation.

```
client ──HTTP──▶ [sidecar :8545] ──HTTP/HTTPS──▶ upstream
                       │
                       ├─ /attestation  TDX quote, REPORTDATA = pubkey ‖ user_nonce
                       ├─ /healthz      liveness (process responsive)
                       ├─ /readyz       upstream POST web3_clientVersion → 2xx
                       └─ *             byte-opaque proxy + Ed25519 sig on response
```

Boot order (`src/main.rs`):

1. `Config::parse` (clap) — CLI flags + env.
2. `DstackClient` opens `/var/run/dstack.sock` (or simulator socket).
3. `bootstrap_tdx_identity` derives signing key and fetches TDX quote — REPORTDATA binds the signing pubkey (closes C3).
4. `UpstreamClient::with_readyz_auth` parses upstream URL once; malformed URL aborts boot.
5. `build_router` wires `AppState` → `axum::serve` with graceful shutdown.

## Source layout

| File | Responsibility |
|------|----------------|
| `src/main.rs` | Entry point, boot order, graceful shutdown, fail-fast on init errors |
| `src/lib.rs` | Module re-exports for the library crate |
| `src/config.rs` | CLI flags + env config (clap-derive) |
| `src/server.rs` | `axum::Router` wiring, `AppState` shared across handlers |
| `src/dstack.rs` | Unix-socket JSON-RPC client to `dstack-guest-agent` (`get_key`, `get_quote`, `info`); reuses one connection across calls (WR-05); response-size cap (IN-06) |
| `src/signing.rs` | `SigningState`, SPEC-04 80-byte pre-image, `now_ms` clock guard (CR-01/02), `parse_chain_id_hex` (WR-01 hex/decimal trap) |
| `src/attestation.rs` | `/attestation` handler — quote bound to caller-supplied nonce + signing pubkey |
| `src/proxy.rs` | Byte-opaque pass-through proxy — hop-by-hop filter (RFC 7230 §6.1, IN-02), per-request body cap (WR-02), `/readyz` probe with optional auth header (WR-03) |
| `src/health.rs` | `/healthz`, `/readyz` handlers |
| `tests/common/mod.rs` | Test harness — simulator spawn, mock upstream, sidecar binary spawn, signature verifier |
| `tests/integration_harness.rs` | White-box integration tests |
| `tests/integration_blackbox.rs` | End-to-end black-box tests via the compiled binary |

## Where to look first

| Task | Start here |
|------|-----------|
| Add a new HTTP endpoint | `src/server.rs::build_router` + new handler module |
| Touch signing / pre-image | `src/signing.rs` (pre-image is byte-exact — see `pre_image_layout_is_byte_exact`) |
| Touch attestation / quote | `src/attestation.rs::build_report_data` (REPORTDATA = pubkey ‖ nonce, 64 B) |
| Touch proxy semantics | `src/proxy.rs::UpstreamClient::forward` (byte-opaque; never parse the body) |
| Touch dstack protocol | `src/dstack.rs` (single UDS connection, JSON-RPC, response cap) |
| Add a config flag | `src/config.rs` (clap-derive struct) |
| Trace a `C-`/`WR-`/`IN-`/`CR-`/`SPEC-` ref | Grep the tag across `src/` — every tag points to a design artifact in `../.planning/workstreams/secure-rpc/` |

## Conventions

- **Byte-opaque proxy.** Request and response bodies are forwarded verbatim — never parsed, never mutated. Closes C2 and C7.
- **Sign post-serialisation.** Signature covers the exact bytes returned to the client, not a re-serialised form.
- **Fail-fast at boot.** Invalid config aborts with exit code 2 after `FAIL_FAST_DEADLINE`; do not silently degrade.
- **Comment tags are load-bearing.** `// C3:`, `// WR-05:`, `// SPEC-04:`, etc. reference design pitfalls and workarounds. Preserve them when refactoring; the tests assert on the invariants they document.
- **No TLS deps on the inbound side.** `Cargo.toml` must stay free of TLS for the listener (closes C1). Outbound `hyper-rustls` is permitted.
- **Clippy `-D warnings` is a hard gate.** Lib + integration test code paths must stay clean before push.
- **Worktree rule** from parent `../AGENTS.md` applies — never push directly from this repo's main checkout.

## Tag glossary

| Tag | Meaning |
|-----|---------|
| `C1`–`C7` | Catastrophic pitfalls from the v1 spec (TLS placement, body mutation, REPORTDATA binding, registry mutability, key reuse, TCB policy, signing wrong bytes) |
| `WR-01`–`WR-05` | Wider concerns / workarounds (chain-id parse, body cap, readyz probe, nonce freshness, dstack connection reuse) |
| `IN-01`–`IN-06` | Implementation notes (empty compose-hash, hop-by-hop case, pubkey caching, etc.) |
| `CR-01`–`CR-02` | Clock-related rules (refuse to sign with unusable clock) |
| `SPEC-01`–`SPEC-04` | Wire-protocol spec sections — pre-image layout, response headers |
| `DEC-01`–`DEC-06` | Locked architectural decisions (Rust, EVM, co-located CVM, shark-edge TLS) |

Authoritative definitions live in `../.planning/workstreams/secure-rpc/`.

## Related

- Jira: `SHARK-3278`
- PR: https://github.com/w3tech/verifiable-rpc-sidecar/pull/1
- Planning workstream: `../.planning/workstreams/secure-rpc/`
