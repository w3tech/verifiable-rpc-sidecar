# rpc-attest-sidecar

> Cryptographic proof that a JSON-RPC response came from an unmodified, approved blockchain client running inside an Intel TDX TEE.

`rpc-attest-sidecar` is a Rust service that sits in front of a blockchain JSON-RPC node inside an Intel TDX confidential VM (via [Phala dstack](https://docs.phala.com/dstack/)) and signs every response with a hardware-attested key. Clients verify the signature against a TDX quote and gain a trust-minimised guarantee that the response came from a specific, approved blockchain client image — not a compromised or mis-routed node.

## Status

Milestone **v2.0 — Implementation MVP — Sidecar** (in progress, Jira: [SHARK-3278](https://w3tech.atlassian.net/browse/SHARK-3278)).

Vision artefacts (v1.0, shipped 2026-05-19):
- [Confluence: TEE Attestation & Signed Responses for RPC Nodes (Phala dstack)](https://w3tech.atlassian.net/wiki/spaces/AIQT/pages/1141244060)
- `vision/PRD.md`, `vision/TRUST-MODEL.md`, `vision/TECH-SPEC.md` §1–§19, `vision/PITFALL-MITIGATIONS.md` (kept in the [secure-rpc workstream](https://github.com/w3tech/ankr) — TODO: cross-link once a public copy exists)

## v2.0 scope

| Phase | Deliverable |
|-------|-------------|
| 5 | Pass-through proxy — Rust crate, byte-opaque reverse-proxy over plain HTTP, unsigned `/healthz` + `/readyz`, no TLS code |
| 6 | Key derivation + per-response signing — `get_key("rpc-sign/v1", None)` via dstack-guest-agent, Ed25519 sign over the SPEC-04 80-byte pre-image, SPEC-03 headers |
| 7 | Attestation endpoint — `GET /attestation` returning a TDX quote with REPORTDATA binding the signing pubkey |

Deferred to v3.0: hardware validation on real TDX, real-TDX deployment, shark-edge wiring, client-side verifier SDK, compose-hash registry, metrics/tracing, integration tests, WebSocket, customer UX content.

## Architecture principles

- **Byte-opaque proxy** — sidecar never parses JSON-RPC; signs over response body bytes as-is. Same code handles single calls, batch arrays, and any future JSON-RPC shape.
- **No error invention** — upstream errors propagate as plain HTTP. The sidecar never synthesizes its own `{"error": ...}` envelope.
- **No TLS in the enclave** — TLS terminates at the shark edge; only plain HTTP enters the CVM (closes pitfall C1).
- **Logs only** — structured `tracing` logs; no metrics endpoint, no OTel tracing in v2.
- **Readability before micro-perf** — no numeric SLOs in v2.

## Local development

Use the [Phala dstack local simulator](https://docs.phala.com/dstack/local-development) to run the sidecar without real TDX hardware. Real-TDX deployment is a v3 concern.

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
