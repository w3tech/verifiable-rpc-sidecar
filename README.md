# rpc-attest-sidecar

> Cryptographic proof that a JSON-RPC response came from an unmodified, approved blockchain client running inside an Intel TDX TEE.

`rpc-attest-sidecar` is a Rust service that sits in front of a blockchain JSON-RPC node inside an Intel TDX confidential VM (via [Phala dstack](https://docs.phala.com/dstack/)) and signs every response with a hardware-attested key. Clients verify the signature against a TDX quote and gain a trust-minimised guarantee that the response came from a specific, approved blockchain client image — not a compromised or mis-routed node.

## What it does

- **Byte-opaque reverse-proxy** in front of one EVM JSON-RPC upstream over plain HTTP.
- **Per-response Ed25519 signing** with a key derived from the dstack-guest-agent (`get_key("rpc-sign/v1", …)`). Every method response carries `X-Phala-Signature`, `X-Phala-Timestamp`, and `X-Phala-Pubkey` over an 80-byte canonical pre-image (`chain_id || sha256(request) || sha256(response) || timestamp_ms`).
- **`GET /attestation`** returns a cached TDX quote with REPORTDATA bound to the signing pubkey, plus `eventLog`, `pubkey`, and `composeHash`.
- **Unsigned `/healthz` and `/readyz`** for load-balancer health checks.

## Architecture principles

- **Byte-opaque proxy** — the sidecar never parses JSON-RPC. Same code path handles single calls, batch arrays, and any future JSON-RPC shape.
- **No error invention** — upstream errors propagate as plain HTTP. The sidecar never synthesises its own `{"error": ...}` envelope.
- **No TLS in the enclave** — TLS terminates at the edge; only plain HTTP enters the CVM.
- **Logs only** — structured `tracing` logs; no metrics endpoint, no OTel tracing.
- **Readability first** — no numeric SLOs; avoid obvious anti-patterns.

## Configuration

| Flag / env | Default | What it sets |
|------------|---------|--------------|
| `--listen-addr` / `SIDECAR_LISTEN_ADDR` | `0.0.0.0:8545` | Plain-HTTP listener |
| `--upstream-url` / `SIDECAR_UPSTREAM_URL` | _required_ | Upstream EVM JSON-RPC URL |
| `--chain-id` / `SIDECAR_CHAIN_ID` | _required_ | u64, decimal or `0x`-hex, mixed into the signing pre-image |
| `--dstack-endpoint` / `DSTACK_SIMULATOR_ENDPOINT` | `/var/run/dstack.sock` | dstack-guest-agent Unix socket |
| `--key-path` / `SIDECAR_KEY_PATH` | `rpc-sign/v1` | Key derivation path |
| `--key-purpose` / `SIDECAR_KEY_PURPOSE` | _unset_ | Optional `purpose` argument to `get_key` |
| `--user-nonce` / `SIDECAR_USER_NONCE` | 32 zero bytes | 32-byte nonce mixed into REPORTDATA |

## Local development

Use the [Phala dstack local simulator](https://docs.phala.com/dstack/local-development) to run the sidecar without real TDX hardware:

```bash
export DSTACK_SIMULATOR_ENDPOINT=/path/to/dstack-simulator.sock
cargo run -- \
  --upstream-url http://127.0.0.1:8546 \
  --chain-id 1
```

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
