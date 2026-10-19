# rpc-attest-sidecar

> Cryptographic proof that an HTTP response came from an unmodified, approved upstream running inside an Intel TDX TEE.

`rpc-attest-sidecar` is a Rust service that sits in front of any HTTP upstream inside an Intel TDX confidential VM (via [Phala dstack](https://docs.phala.com/dstack/)) and signs every response with a hardware-attested key. Clients verify the signature against a TDX quote and gain a trust-minimised guarantee that the response came from a specific, approved upstream image — not a compromised or mis-routed one.

## Requirements

- Rust 1.91+ toolchain to build (latest stable recommended).
- Linux host with access to a dstack-guest-agent Unix socket:
  - **Production:** Intel TDX-capable hardware running [Phala dstack](https://github.com/Dstack-TEE/dstack).
  - **Local development:** the [Phala dstack simulator](https://docs.phala.com/dstack/local-development) exposing the same socket interface.
- One HTTP or HTTPS upstream reachable from the sidecar. The inbound listener is plain HTTP only — TLS terminates outside the enclave for incoming traffic.

## Calling the upstream

The sidecar listens on `--listen-addr` (default `0.0.0.0:8545`). Send the same HTTP request you would send to the upstream directly — method, headers and body are forwarded byte-for-byte, and the request's path and query are appended to the configured `--upstream-url` base (e.g. base `http://127.0.0.1:43677` + inbound `GET /getConsensusBlock?limit=1` → `http://127.0.0.1:43677/getConsensusBlock?limit=1`). This makes path-based REST upstreams (TON HTTP API, Stellar Horizon) work through the sidecar, not just single-endpoint JSON-RPC. The sidecar appends three response headers (see below).

The upstream URL is the scheme and authority of `--upstream-url`, then its path without a trailing `/` (a prefix like `/api/v2` is kept), then the request's path and query; the query of `--upstream-url` is not used. Point it at the upstream's base origin, not at a full endpoint path.

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

Every proxied response — any path other than `/attestation` and `/info`, which are always served locally by the sidecar and never forwarded upstream, and `/confidential`, which has its own format (see [Ankr Confidential RPC](#ankr-confidential-rpc-post-confidential)) — carries:

| Header | Meaning |
|--------|---------|
| `vRPC-Pubkey` | `0x`-prefixed 32-byte hex — the Ed25519 verifying key. Must match the `pubkey` in `/attestation`. |
| `vRPC-Timestamp` | Unix milliseconds (u64) when the sidecar signed this response. Clients enforce their own freshness window (e.g. 60 s). |
| `vRPC-Signature` | `0x`-prefixed 64-byte Ed25519 signature over the 104-byte canonical pre-image: `sha256(utf8(chain_id)) (32B) ‖ sha256(request_body) (32B) ‖ sha256(response_body) (32B) ‖ timestamp_ms (8B LE)`. The chain id is an opaque string — `42161`, `0x89`, TON's `-239` are all hashed as UTF-8 bytes, never parsed numerically. |

The pre-image hashes the request body bytes the client sent (verbatim) and the **content-decoded** response body (the upstream's plaintext, before any client-facing compression). To verify:

1. Fetch and validate `/attestation`; extract `pubkey`.
2. For each response: if `Content-Encoding: gzip` is set, decode the body first. Rebuild the pre-image from the request body you sent, the **content-decoded** response body, the `vRPC-Timestamp` value, and `sha256(utf8(chain_id))` at `[0..32]`. The verifier learns the chain id string out-of-band (its own config); no new wire headers.
3. Ed25519-verify `vRPC-Signature` against the pre-image and `pubkey`.

**Version gate (breaking change):** this contract replaces the previous 80-byte pre-image (`chain_id` u64 LE at `[0..8]`). There is no dual-accept — verifiers must build the matching 104-byte pre-image (SDK ≥ next minor). Deployed nodes keep the old image until their compose is updated; upgrade the node's sidecar image and the verifier SDK together.

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

## Ankr Confidential RPC (POST /confidential)

Ankr Confidential RPC keeps the request and the response readable only by the client and the enclave. The client encrypts an HTTP request to the node's attested key and posts it to `/confidential`; the sidecar decrypts it inside the enclave, sends exactly the inner request to the upstream and returns the upstream's answer encrypted to the client and signed. The outer path, query and headers never reach the upstream.

### Formats

- HPKE base mode ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)) with one suite: KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF `0x0001` HKDF-SHA256, AEAD `0x0002` AES-256-GCM.
- Request and response encapsulation as in [RFC 9458](https://www.rfc-editor.org/rfc/rfc9458) §4.3 and §4.4 (byte formats only).
- Inner request and response in known-length Binary HTTP ([RFC 9292](https://www.rfc-editor.org/rfc/rfc9292)).
- Key: the X25519 (Montgomery) form of the Ed25519 `pubkey` returned by `/attestation` (libsodium `crypto_sign_ed25519_pk_to_curve25519`). The private key is derived from the same signing seed, so the TDX quote binds the encryption key too. `key_id` is `0`.

Request:

```
POST /confidential
Content-Type: message/ohttp-req        (ignored by the sidecar)

body = hdr ‖ enc (32 B) ‖ ct
hdr  = key_id 0x00 ‖ 0x0020 ‖ 0x0001 ‖ 0x0002
ct   = HPKE SealBase(pkR, info = "message/bhttp request" ‖ 0x00 ‖ hdr, aad = "", pt = BHTTP request)
```

Response:

```
status = inner status; inner 204, 205 and 304 become 200
Content-Type: message/ohttp-res

body   = response_nonce (32 B) ‖ ct
secret = Export("message/bhttp response", 32);  prk = Extract(salt = enc ‖ response_nonce, secret)
key    = Expand(prk, "key", 32);  nonce = Expand(prk, "nonce", 12)
ct     = AES-256-GCM(key, nonce, aad = "", pt = BHTTP response)
```

Every encrypted response carries:

| Header | Meaning |
|--------|---------|
| `vRPC-Signature`, `vRPC-Timestamp`, `vRPC-Pubkey` | As on proxied responses, with the same 104-byte pre-image computed over the outer request body (the encapsulated request) and the outer response body (the encapsulated response). |
| `vRPC-Batch-Size` | Number of calls counted in the inner body (see [Batches](#batches)). Not covered by the signature. |

Encrypted responses are never compressed, so the signature covers the bytes on the wire.

### Inner request

- Known-length Binary HTTP only, with the framing indicator encoded as the single byte `0x00`.
- Method: any valid token except `CONNECT`.
- Path: path and query in origin form, starting with `/` (not `//`, no fragment). The upstream URL is the scheme and authority of `--upstream-url`, then its path without a trailing `/`, then this path and query; the query of `--upstream-url` is not used.
- `:scheme`, `:authority` and padding are ignored.
- Forwarded fields: `content-type` (required when there is a body, one value only) and `accept` (every value, in order), plus `Accept-Encoding: identity` set by the sidecar. A value with bytes not allowed in an HTTP header is a 400.
- The inner header section and trailer section are each at most 65536 bytes (64 KiB).
- Every other field and all trailers are dropped. Outer headers never reach the upstream, so the upstream must not require auth headers.
- The upstream's answer is returned as its status, every `content-type` value in order, and its body. The upstream must answer with identity content encoding.

### Batches

The sidecar counts calls the way go-ethereum reads them. If the first byte after whitespace (`0x20`, `0x09`, `0x0A`, `0x0D`) is `[`, N is the number of elements of the first JSON value and any bytes after it are ignored; `[]` and a first value that does not parse count as 1, and any other body counts as 1. There is no depth limit: an element nested 10 000 or more levels deep is counted normally, while go-ethereum answers the whole body with one parse error. The count does not materialise the elements.

If N is above `--max-batch-size`, the answer is an encrypted 413 and the upstream is not called. Otherwise the body reaches the upstream unchanged, as one request. `vRPC-Batch-Size` carries N (1 for an error raised before counting).

### Differences from RFC 9458

- No key configuration resource: the key comes from `/attestation`, there is one fixed suite with `key_id` 0, and the key is derived from the signing key.
- The outer status mirrors the inner status (inner 204, 205 and 304 become 200).
- Errors after decryption are encrypted and signed responses.
- The request `Content-Type` is not checked.
- The inner request rules above: the single-byte framing indicator, 400 on invalid bytes in `content-type` or `accept`, every `accept` value forwarded and every upstream `content-type` value returned, and the 64 KiB limit per field section.

### Errors

After decryption, errors are encrypted and signed like any answer, carry `vRPC-Batch-Size`, and the outer status equals the inner one. The inner response has `Content-Type: application/problem+json` and body `{"type":"<type>","title":"<title>"}`. Errors from the upstream itself are relayed as the upstream sent them.

| Status | `type` | `title` | Cause | Upstream called |
|--------|--------|---------|-------|-----------------|
| 400 | `urn:vrpc:error:bad-request` | `Bad request` | Malformed Binary HTTP, framing other than `0x00`, invalid method token, pseudo-field, `CONNECT`, path not in origin form, repeated `content-type`, invalid bytes in `content-type` or `accept`, field section over 64 KiB | no |
| 415 | `urn:vrpc:error:unsupported-media-type` | `Unsupported media type` | Body without `content-type` | no |
| 413 | `urn:vrpc:error:batch-too-large` | `Batch too large` | Batch over `--max-batch-size` | no |
| 502 | `urn:vrpc:error:upstream` | `Upstream error` | Upstream transport failure, response over `--confidential-max-response-bytes`, upstream status 1xx or ≥ 600, `Content-Encoding` other than identity | maybe |
| 504 | `urn:vrpc:error:upstream-timeout` | `Upstream timeout` | No complete answer within `--confidential-upstream-timeout-secs` (connect, headers and body) | maybe |
| 500 | `urn:vrpc:error:internal` | `Internal error` | Other internal failure that can still be sealed | depends |

For 502 and 504, a failure to connect or a timeout while connecting never reaches the upstream; a failure after the request was sent may come after the upstream executed it.

Before decryption, errors are plaintext and unsigned, carry no `vRPC-*` header, and the upstream is not called:

| Status | Body | Cause |
|--------|------|-------|
| 400 | `Content-Type: application/problem+json`, exactly `{"type":"https://iana.org/assignments/http-problem-types#ohttp-key","title":"Oblivious HTTP key configuration not acceptable"}` | Wrong `key_id` or suite, short body, decapsulation or decryption failure (one answer for all of them) |
| 413 | empty | Outer body over `--confidential-max-body-bytes` |
| 400 | empty | Outer body that could not be read (for example, the client aborted the upload) |
| 405 | empty | Method other than `POST` |

One exception after decryption: if the response cannot be sealed or signed (random number generator or clock failure), the answer is a plaintext, unsigned `500` with an empty body.

### Operator notes

- The upstream node logs failed calls with their method and error data. Keep container log export off in the CVM: no diagnostic log export, `public_logs: false` in the app compose.
- The sidecar logs one `confidential call` line per `/confidential` call with the outcome class, outer and inner status, batch size, byte counts and durations; it never logs content. A call whose client disconnects before the answer is logged with outcome `cancelled` and status 0; an outer body that fails to arrive for a reason other than the cap gets an empty 400 and is logged as `request-read-failed`.
- Memory per call is about twice the node response (about 260 MiB at the 128 MiB default cap) plus up to about four times the request (about 32 MiB at the 8 MiB default). There is no concurrency limit, so concurrent large calls add up. Details in [DEPENDENCIES.md](DEPENDENCIES.md#memory-hygiene).

## Configuration

| Flag / env | Default | What it sets |
|------------|---------|--------------|
| `--listen-addr` / `SIDECAR_LISTEN_ADDR` | `0.0.0.0:8545` | Plain-HTTP listener |
| `--upstream-url` / `SIDECAR_UPSTREAM_URL` | _required_ | Upstream **base** URL — `http://` or `https://` (Mozilla webpki roots). The inbound request's path+query is appended to its path; its query is not used |
| `--chain-id` / `SIDECAR_CHAIN_ID` | _required_ | Chain id bound into the signing pre-image as `sha256(utf8(chain_id))`. Opaque string, never parsed numerically: non-empty, ≤ 64 bytes, printable ASCII, no whitespace (e.g. TON's global id `-239`, Stellar's network id = sha256 of the passphrase (64-char hex); numeric-looking ids like `42161` are fine too) |
| `--dstack-endpoint` / `DSTACK_SIMULATOR_ENDPOINT` | `/var/run/dstack.sock` | dstack-guest-agent Unix socket |
| `--key-path` / `SIDECAR_KEY_PATH` | `rpc-sign/v1` | Key derivation path (the `/v1` segment prevents key reuse across versions/chains) |
| `--key-purpose` / `SIDECAR_KEY_PURPOSE` | _unset_ | Optional `purpose` argument to `get_key` |
| `--max-body-bytes` / `SIDECAR_MAX_BODY_BYTES` | _unset_ (unbounded) | Passthrough routes only (not `/confidential`): per-request body byte cap applied to both inbound request and upstream response. Unset → no cap (large `eth_getLogs` / `debug_traceTransaction` allowed through). Recommended explicit value: `8388608` (8 MiB) when the upstream is not fully trusted — removing the cap removes one of the two memory-exhaustion guards on the CVM. |
| `--confidential-max-body-bytes` / `SIDECAR_CONFIDENTIAL_MAX_BODY_BYTES` | `8388608` | Maximum outer request body of `/confidential` in bytes (8 MiB); a larger body is a plaintext 413 |
| `--max-batch-size` / `SIDECAR_MAX_BATCH_SIZE` | `1000` | Maximum number of calls in one `/confidential` batch; allowed 1 to 1000, any other value stops the sidecar at startup. A larger batch is an encrypted 413 |
| `--confidential-upstream-timeout-secs` / `SIDECAR_CONFIDENTIAL_UPSTREAM_TIMEOUT_SECS` | `25` | Timeout in seconds (at least 1) for the upstream call of `/confidential`: connect, headers and body. Keep it below the timeout of whatever calls the sidecar, so the client receives a signed 504 |
| `--confidential-max-response-bytes` / `SIDECAR_CONFIDENTIAL_MAX_RESPONSE_BYTES` | `134217728` | Maximum upstream response body of `/confidential` in bytes (128 MiB); a larger body is an encrypted 502. Keep it below the response cap of whatever calls the sidecar |
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

The integration suite (`tests/integration_harness.rs`, `tests/integration_blackbox.rs` and `tests/integration_confidential.rs`, with shared helpers in `tests/common/mod.rs`) spawns the actual sidecar binary against a fresh dstack simulator and a tiny in-process mock upstream, then drives end-to-end checks: byte-identical body forwarding, signature verification over the canonical pre-image, attestation freshness, batch JSON-RPC, HTTPS upstream, optional live upstream node call, and Ankr Confidential RPC end to end with the key taken from `/attestation`.

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

Four test binaries:

```bash
# 14 tests — spawn sidecar + simulator + mock upstream per test
cargo test --test integration_harness -- --test-threads=1

# 10 black-box tests — run against any sidecar (local spawn by default,
# or an externally-deployed sidecar via SIDECAR_URL — see below)
cargo test --test integration_blackbox -- --test-threads=1

# 2 tests — dstack SDK baseline
cargo test --test dstack_baseline -- --test-threads=1

# 8 tests — Ankr Confidential RPC end to end
cargo test --test integration_confidential -- --test-threads=1
```

Each harness test gets its own simulator (own temp dir) and own sidecar on an ephemeral port. Tests are `#[serial]` so they don't fight over resources.

### Testing a deployed sidecar (black-box only)

To point the black-box suite at an already-running sidecar (e.g. a real TDX CVM deploy or a shared dev box), set:

```bash
export SIDECAR_URL=https://verified.example.com   # base URL of the running sidecar
export SIDECAR_CHAIN_ID=1                          # string matching the sidecar's --chain-id

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

