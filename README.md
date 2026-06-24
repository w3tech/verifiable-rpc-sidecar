# rpc-attest-sidecar

> Cryptographic proof that an HTTP response came from an unmodified, approved upstream running inside an Intel TDX TEE.

`rpc-attest-sidecar` is a Rust service that sits in front of any HTTP upstream inside an Intel TDX confidential VM (via [Phala dstack](https://docs.phala.com/dstack/)) and signs every response with a hardware-attested key. Clients verify the signature against a TDX quote and gain a trust-minimised guarantee that the response came from a specific, approved upstream image — not a compromised or mis-routed one.

## Requirements

- Rust 1.75+ toolchain to build (latest stable recommended).
- Linux host with access to a dstack-guest-agent Unix socket:
  - **Production:** Intel TDX-capable hardware running [Phala dstack](https://github.com/Dstack-TEE/dstack).
  - **Local development:** the [Phala dstack simulator](https://docs.phala.com/dstack/local-development) exposing the same socket interface.
- One HTTP or HTTPS upstream reachable from the sidecar. The inbound listener is plain HTTP only — TLS terminates outside the enclave for incoming traffic.

## Pulling and verifying the image

Released images are published publicly on GHCR:

```bash
docker pull ghcr.io/w3tech/verifiable-rpc-sidecar:v0.4.1
```

Every image is signed with [cosign](https://github.com/sigstore/cosign) keyless
(Sigstore/Fulcio via GitHub OIDC) by this repository's `publish.yml` workflow —
no long-lived signing key. Verify provenance before running it:

```bash
# a specific release tag
cosign verify ghcr.io/w3tech/verifiable-rpc-sidecar:v0.4.1 \
  --certificate-identity "https://github.com/w3tech/verifiable-rpc-sidecar/.github/workflows/publish.yml@refs/tags/v0.4.1" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

```bash
# or accept any release tag (regexp identity)
cosign verify ghcr.io/w3tech/verifiable-rpc-sidecar:v0.4.1 \
  --certificate-identity-regexp '^https://github.com/w3tech/verifiable-rpc-sidecar/\.github/workflows/publish\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A successful verify confirms the image was built and signed by this repo's
release workflow. Images also carry SLSA build provenance and an SBOM:

```bash
cosign download attestation ghcr.io/w3tech/verifiable-rpc-sidecar:v0.4.1
docker buildx imagetools inspect ghcr.io/w3tech/verifiable-rpc-sidecar:v0.4.1
```

For production, pin by immutable digest (tag is only a convenience label):

```yaml
image: ghcr.io/w3tech/verifiable-rpc-sidecar@sha256:<digest>  # v0.4.1
```

> Note: this verifies *who built the image*. The runtime trust guarantee —
> that a specific approved image is actually running inside the TEE — comes from
> the TDX quote returned by `/attestation`, which binds the signing pubkey and
> the compose measurement.

## Calling the upstream

The sidecar listens on `--listen-addr` (default `0.0.0.0:8545`). Send the same HTTP request you would send to the upstream directly — method, headers and body are forwarded byte-for-byte. The sidecar appends three response headers (see below).

The sidecar forces `Accept-Encoding: identity` on the upstream request, so the node returns an uncompressed (plaintext) body, and the `vRPC-Signature` covers that **content-decoded** body. The client-facing response is then re-encoded per **your** `Accept-Encoding`: a client that accepts gzip receives `Content-Encoding: gzip` and MUST decode the body before rebuilding the pre-image; everyone else (including brotli/zstd-only clients) receives identity (documented fallback — only gzip + identity are supported).

```bash
curl -sS \
  -X POST http://sidecar:8545/ \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  -D headers.txt
```

`headers.txt` then contains the three `vRPC-*` headers along with whatever headers the upstream returned.

### Response headers

Every response forwarded through `/` (or any non-health, non-attestation path) carries:

| Header | Meaning |
|--------|---------|
| `vRPC-Pubkey` | `0x`-prefixed 32-byte hex — the Ed25519 verifying key. Must match the `pubkey` in `/attestation`. |
| `vRPC-Timestamp` | Unix milliseconds (u64) when the sidecar signed this response. Clients enforce their own freshness window (e.g. 60 s). |
| `vRPC-Signature` | `0x`-prefixed 64-byte Ed25519 signature over the 80-byte canonical pre-image: `chain_id (8B LE) ‖ sha256(request_body) (32B) ‖ sha256(response_body) (32B) ‖ timestamp_ms (8B LE)`. |

The pre-image hashes the request body bytes the client sent (verbatim) and the **content-decoded** response body (the upstream's plaintext, before any client-facing compression). To verify:

1. Fetch and validate `/attestation`; extract `pubkey`.
2. For each response: if `Content-Encoding: gzip` is set, decode the body first. Rebuild the pre-image from the request body you sent, the **content-decoded** response body, the `vRPC-Timestamp` value, and the agreed `chain_id`.
3. Ed25519-verify `vRPC-Signature` against the pre-image and `pubkey`.

Standard HTTP clients (`fetch`/browsers) auto-decode `Content-Encoding` before exposing the body, so they hash the decoded plaintext and verification just works. (Compression-oracle attacks like CRIME/BREACH are not a concern here: RPC responses are not secret and there is no attacker-controlled secret reflected into the body; the signed bytes are deterministic plaintext.)

`/attestation` does **not** emit these headers.

## Getting an attestation

`GET /attestation?nonce=<hex>` returns a TDX quote bound to `REPORTDATA = signing_pubkey || user_nonce`. The caller MUST supply a 32-byte nonce as a freshness challenge; the enclave produces a fresh quote against it on every call (no caching).

Missing or malformed nonce returns `400 Bad Request`.

**Nonce freshness (security-critical):** callers MUST sample a fresh CSPRNG-generated 32-byte nonce per request; reused nonces enable replay of captured quotes. The sidecar does not police this — it honours whatever nonce the caller sends and returns a fresh quote bound to it. If you reuse a static nonce, a man-in-the-middle who captured a `(quote, pubkey, nonce)` tuple from an earlier session can replay it against you.

```bash
curl -sS "http://sidecar:8545/attestation?nonce=0x$(openssl rand -hex 32)"
```

Nonce format: 32 raw bytes, hex-encoded, with or without the `0x` prefix.

Response:

```json
{
  "quote": {
    "quote":       "…",
    "event_log":   "…",
    "report_data": "…",
    "vm_config":   ""
  },
  "pubkey":      "0x…",
  "composeHash": "…",
  "app_compose": "{…}"
}
```

| Field | Meaning |
|-------|---------|
| `quote` | Raw `GetQuote` response from `dstack-guest-agent`, nested verbatim. See sub-fields below. |
| `quote.quote` | Hex-encoded TDX quote (bare hex, no `0x` prefix). Validate against Intel's PCK chain to verify the enclave identity and that REPORTDATA contains the sidecar's signing pubkey and the nonce you supplied. |
| `quote.event_log` | Hex-encoded RTMR event log (bare hex). Reconstructs the launch measurement that the quote attests over. |
| `quote.report_data` | Echo of REPORTDATA bound into the quote (bare hex). |
| `quote.vm_config` | Hex-encoded VM configuration. Empty unless the agent supplies it. |
| `pubkey` | Sidecar Ed25519 signing pubkey (32 raw bytes, `0x`-prefixed hex). Identical to the `vRPC-Pubkey` value on every signed response. |
| `composeHash` | `app-compose.json` hash reported by the dstack-guest-agent. Anchors the deployed image to a known, auditable compose file. |
| `app_compose` | Raw `app-compose.json` text, verbatim from `dstack info` (`tcb_info.app_compose`) — the **preimage** of `composeHash`: `sha256(utf8(app_compose)) == composeHash`, with **no canonicalization** (dstack hashes the raw bytes). Lets a verifier recompute the compose hash and replay it into RTMR3 from a single `/attestation` fetch, without a separate `/info` call. Empty when no compose is bound (e.g. the simulator with `--allow-empty-compose-hash`). |

The inner `quote.*` fields are bare hex matching the dstack-guest-agent wire format. Add the `0x` prefix yourself if your hex parser requires it.

`/attestation` itself is **not signed** — verification happens against the TDX quote.

## Configuration

| Flag / env | Default | What it sets |
|------------|---------|--------------|
| `--listen-addr` / `SIDECAR_LISTEN_ADDR` | `0.0.0.0:8545` | Plain-HTTP listener |
| `--upstream-url` / `SIDECAR_UPSTREAM_URL` | _required_ | Upstream URL — `http://` or `https://` (Mozilla webpki roots) |
| `--chain-id` / `SIDECAR_CHAIN_ID` | _required_ | u64 mixed into the signing pre-image (decimal or `0x`-hex) |
| `--dstack-endpoint` / `DSTACK_SIMULATOR_ENDPOINT` | `/var/run/dstack.sock` | dstack-guest-agent Unix socket |
| `--key-path` / `SIDECAR_KEY_PATH` | `rpc-sign/v1` | Key derivation path (the `/v1` segment prevents key reuse across versions/chains) |
| `--key-purpose` / `SIDECAR_KEY_PURPOSE` | _unset_ | Optional `purpose` argument to `get_key` |
| `--max-body-bytes` / `SIDECAR_MAX_BODY_BYTES` | _unset_ (unbounded) | Per-request body byte cap applied to both inbound request and upstream response. Unset → no cap (large `eth_getLogs` / `debug_traceTransaction` allowed through). Recommended explicit value: `8388608` (8 MiB) when the upstream is not fully trusted — removing the cap removes one of the two memory-exhaustion guards on the CVM. |
| `--allow-empty-compose-hash` / `SIDECAR_ALLOW_EMPTY_COMPOSE_HASH` | `false` | Allow boot to continue when `dstack info` reports no compose hash. Dev/simulator only — production deployments MUST bind a real compose hash so `/attestation` returns a non-empty `composeHash` to verifiers. |

## Local development

### 1. Start the dstack simulator

```bash
git clone https://github.com/Dstack-TEE/dstack.git
cd dstack/sdk/simulator
./build.sh
./dstack-simulator
```

`build.sh` requires a Rust toolchain. The simulator creates `dstack.sock` in its working directory; leave the process running.

### 2. Run the sidecar against the simulator

In another shell, point the sidecar at the simulator's socket and at any HTTP upstream you want to wrap:

```bash
export DSTACK_SIMULATOR_ENDPOINT=/absolute/path/to/dstack/sdk/simulator/dstack.sock

cargo run -- \
  --upstream-url http://127.0.0.1:8546 \
  --chain-id 1
```

The sidecar will log `signing_pubkey = 0x…` on startup once the simulator answers `get_key`. Then `curl` it as in the [Calling the upstream](#calling-the-upstream) and [Getting an attestation](#getting-an-attestation) sections.

dstack simulator docs: <https://docs.phala.com/dstack/local-development>.

## Running integration tests

The integration suite (`tests/integration_harness.rs` + `tests/integration_blackbox.rs`, with shared helpers in `tests/common/mod.rs`) spawns the actual sidecar binary against a fresh dstack simulator and a tiny in-process mock upstream, then drives end-to-end checks: byte-identical body forwarding, signature verification over the canonical pre-image, attestation freshness, batch JSON-RPC, HTTPS upstream, optional live upstream node call.

### Prerequisites

1. Build the dstack simulator (only once):

   ```bash
   git clone https://github.com/Dstack-TEE/dstack.git
   cd dstack/sdk/simulator
   ./build.sh
   ```

2. Export the simulator binary path and fixtures directory:

   ```bash
   export DSTACK_SIMULATOR_BIN=/abs/path/to/dstack/sdk/simulator/dstack-simulator
   export DSTACK_SIMULATOR_FIXTURES_DIR=/abs/path/to/dstack/sdk/simulator
   ```

3. (Optional) For the live upstream node test, also export:

   ```bash
   export NODE_RPC_URL=https://your-node/eth   # full URL to an upstream chain endpoint
   export NODE_API_KEY=<your-api-key>           # forwarded as `x-api-key` to upstream
   ```

   When either is missing the live-upstream test skips cleanly (no failure).

### Run

Three test binaries:

```bash
# 14 tests — spawn sidecar + simulator + mock upstream per test
cargo test --test integration_harness -- --test-threads=1

# 10 black-box tests — run against any sidecar (local spawn by default,
# or an externally-deployed sidecar via SIDECAR_URL — see below)
cargo test --test integration_blackbox -- --test-threads=1

# 2 tests — dstack SDK baseline
cargo test --test dstack_baseline -- --test-threads=1
```

Each harness test gets its own simulator (own temp dir) and own sidecar on an ephemeral port. Tests are `#[serial]` so they don't fight over resources.

### Testing a deployed sidecar (black-box only)

To point the black-box suite at an already-running sidecar (e.g. a real TDX CVM deploy or a shared dev box), set:

```bash
export SIDECAR_URL=https://verified.example.com   # base URL of the running sidecar
export SIDECAR_CHAIN_ID=1                          # u64 matching the sidecar's --chain-id

# Optional: forwarded as an upstream-auth header on the method-POST tests
export SIDECAR_AUTH_HEADER_KEY=x-api-key
export SIDECAR_AUTH_HEADER_VAL=$NODE_API_KEY      # or hard-coded

# Optional: body to POST `/` (default = eth_blockNumber JSON-RPC)
# export SIDECAR_TEST_BODY='{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'

cargo test --test integration_blackbox -- --test-threads=1
```

The harness bootstraps the signing pubkey from `/attestation` once at startup, then verifies every method response's `vRPC-Signature` against it. No simulator is spawned in this mode — `DSTACK_SIMULATOR_*` env vars are ignored.

The harness suite (`integration_harness`) always spawns locally and is not affected by `SIDECAR_URL`.

## License

Copyright (c) 2026 Web3 Technologies, Inc.

`rpc-attest-sidecar` is free software licensed under the **GNU Affero General
Public License v3.0 only** (`AGPL-3.0-only`). See [`LICENSE`](LICENSE) for the
full text. Every source file carries an `SPDX-License-Identifier: AGPL-3.0-only`
header.

Because this is AGPL-3.0 software, if you run a modified version of the sidecar
and make it available to users over a network, AGPL section 13 (Remote Network
Interaction) requires you to offer those users the corresponding source of your
modified version. The complete corresponding source of this program is published
at <https://github.com/w3tech/verifiable-rpc-sidecar>.

Dependency licenses are verified for AGPL compatibility in CI via
`cargo deny check licenses` (see [`deny.toml`](deny.toml)).

