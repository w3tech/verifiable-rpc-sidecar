# rpc-attest-sidecar

> Cryptographic proof that an HTTP response came from an unmodified, approved upstream running inside an Intel TDX TEE.

`rpc-attest-sidecar` is a Rust service that sits in front of any HTTP upstream inside an Intel TDX confidential VM (via [Phala dstack](https://docs.phala.com/dstack/)) and signs every response with a hardware-attested key. Clients verify the signature against a TDX quote and gain a trust-minimised guarantee that the response came from a specific, approved upstream image — not a compromised or mis-routed one.

## Requirements

- Rust 1.75+ toolchain to build (latest stable recommended).
- Linux host with access to a dstack-guest-agent Unix socket:
  - **Production:** Intel TDX-capable hardware running [Phala dstack](https://github.com/Dstack-TEE/dstack).
  - **Local development:** the [Phala dstack simulator](https://docs.phala.com/dstack/local-development) exposing the same socket interface.
- One HTTP upstream reachable from the sidecar (plain HTTP — TLS terminates outside the enclave).

## Calling the upstream

The sidecar listens on `--listen-addr` (default `0.0.0.0:8545`). Send the same HTTP request you would send to the upstream directly — method, headers and body are forwarded byte-for-byte. The sidecar appends three response headers (see below); the response body is whatever the upstream returned, unchanged.

```bash
curl -sS \
  -X POST http://sidecar:8545/ \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  -D headers.txt
```

`headers.txt` then contains the three `X-Phala-*` headers along with whatever headers the upstream returned.

### Response headers

Every response forwarded through `/` (or any non-health, non-attestation path) carries:

| Header | Meaning |
|--------|---------|
| `X-Phala-Pubkey` | `0x`-prefixed 32-byte hex — the Ed25519 verifying key. Must match the `pubkey` in `/attestation`. |
| `X-Phala-Timestamp` | Unix milliseconds (u64) when the sidecar signed this response. Clients enforce their own freshness window (e.g. 60 s). |
| `X-Phala-Signature` | `0x`-prefixed 64-byte Ed25519 signature over the 80-byte canonical pre-image: `chain_id (8B LE) ‖ sha256(request_body) (32B) ‖ sha256(response_body) (32B) ‖ timestamp_ms (8B LE)`. |

The pre-image hashes the body bytes the client sent and the body bytes the upstream returned — verbatim, no parsing. To verify:

1. Fetch and validate `/attestation`; extract `pubkey`.
2. For each response: rebuild the pre-image from the request body you sent, the response body you received, the `X-Phala-Timestamp` value, and the agreed `chain_id`.
3. Ed25519-verify `X-Phala-Signature` against the pre-image and `pubkey`.

`/healthz`, `/readyz`, and `/attestation` do **not** emit these headers.

## Getting an attestation

`GET /attestation` returns a TDX quote bound to `REPORTDATA = signing_pubkey || user_nonce`. The caller MUST supply a 32-byte nonce as a freshness challenge; the enclave produces a fresh quote against it on every call (no caching).

The nonce is read from `?nonce=<hex>` (priority) or the `X-Phala-Nonce` header. Missing or malformed nonce returns `400 Bad Request`.

```bash
# verifier-supplied nonce via query string
curl -sS "http://sidecar:8545/attestation?nonce=0x$(openssl rand -hex 32)"

# or via header (lower precedence than ?nonce=)
curl -sS http://sidecar:8545/attestation \
  -H "X-Phala-Nonce: $(openssl rand -hex 32)"
```

Nonce format: 32 raw bytes, hex-encoded, with or without the `0x` prefix.

Response:

```json
{
  "quote":       "0x…",
  "eventLog":    "0x…",
  "pubkey":      "0x…",
  "composeHash": "…"
}
```

| Field | Meaning |
|-------|---------|
| `quote` | Hex-encoded TDX quote. Validate against Intel's PCK chain to verify the enclave identity and that REPORTDATA contains the sidecar's signing pubkey and the nonce you supplied. |
| `eventLog` | Hex-encoded RTMR event log. Reconstructs the launch measurement that the quote attests over. |
| `pubkey` | Sidecar Ed25519 signing pubkey (32 raw bytes, `0x`-prefixed hex). Identical to the `X-Phala-Pubkey` value on every signed response. |
| `composeHash` | `app-compose.json` hash reported by the dstack-guest-agent. Anchors the deployed image to a known, auditable compose file. |

`/attestation` itself is **not signed** — verification happens against the TDX quote.

## Configuration

| Flag / env | Default | What it sets |
|------------|---------|--------------|
| `--listen-addr` / `SIDECAR_LISTEN_ADDR` | `0.0.0.0:8545` | Plain-HTTP listener |
| `--upstream-url` / `SIDECAR_UPSTREAM_URL` | _required_ | Upstream HTTP URL |
| `--chain-id` / `SIDECAR_CHAIN_ID` | _required_ | u64 mixed into the signing pre-image (decimal or `0x`-hex) |
| `--dstack-endpoint` / `DSTACK_SIMULATOR_ENDPOINT` | `/var/run/dstack.sock` | dstack-guest-agent Unix socket |
| `--key-path` / `SIDECAR_KEY_PATH` | `rpc-sign/v1` | Key derivation path |
| `--key-purpose` / `SIDECAR_KEY_PURPOSE` | _unset_ | Optional `purpose` argument to `get_key` |

## Local development

Run against the dstack simulator:

```bash
export DSTACK_SIMULATOR_ENDPOINT=/path/to/dstack-simulator.sock
cargo run -- \
  --upstream-url http://127.0.0.1:8546 \
  --chain-id 1
```

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
