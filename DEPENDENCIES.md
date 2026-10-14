<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 Web3 Technologies, Inc. -->
# Dependencies

The crates below implement Ankr Confidential RPC encryption (HPKE, RFC 9180;
Oblivious HTTP message encapsulation, RFC 9458; Binary HTTP, RFC 9292); every
cryptographic primitive comes from a library, none is written in this repository.
Release dates and MSRVs are from crates.io; licenses and repositories are from
the committed `Cargo.lock` (`cargo metadata --locked`). None of the pinned
versions is yanked, and `cargo deny check licenses` accepts all of them with the
existing `deny.toml`.

**hpke 0.14.1** opens the HPKE request envelope (Base mode, DHKEM(X25519,
HKDF-SHA256), HKDF-SHA256, AES-256-GCM) and exports the response secret.
Pinned `=0.14.1` with default features off and only `alloc`, `aes` and `x25519`
enabled: the sidecar needs one KEM and one AEAD, so ChaCha20-Poly1305, ML-KEM
and X-Wing, the NIST P-curves, SHAKE and the crate's own random source stay out
of the build. License MIT/Apache-2.0;
single owner Michael Rosenberg, <https://github.com/rozbb/rust-hpke>; released
2026-09-06; MSRV 1.85. It rejects an all-zero X25519 shared secret as RFC 9180
requires. The bus factor of one is mitigated by the exact pin and by the CFRG
known-answer vector the test suite runs for this exact cipher suite.

**bhttp 0.8.0** decodes the known-length Binary HTTP request inside the envelope
and encodes the response. Pinned `=0.8.0` with no optional features; the `http`
conversion and `stream` modes are not needed. License MIT OR Apache-2.0;
single owner Martin Thomson, author of RFC 9292 and RFC 9458,
<https://github.com/martinthomson/ohttp>; released 2026-07-15; MSRV 1.86.0. Its
only dependency is `thiserror` 2, which the sidecar already uses. The exact pin
and the RFC 9458 Appendix A test cover the single-owner risk.

**hkdf 0.13.0** derives the response key and nonce from the exported secret
(`Extract(enc || response_nonce, secret)`, `Expand("key")`, `Expand("nonce")`).
Pinned `=0.13.0` with no optional features. License MIT OR Apache-2.0;
RustCrypto developers, <https://github.com/RustCrypto/KDFs/>; released
2026-03-30; MSRV 1.85. It shares the `sha2` 0.11 family with the sidecar's
existing `sha2` dependency.

**aes-gcm 0.11.1** seals the response with AES-256-GCM (the test suite also runs
it at AES-128 for the RFC 9458 Appendix A vector). Pinned `=0.11.1` with default
features off and only `aes`, `alloc` and `zeroize`: `aes` brings the AES block
cipher (AES-NI when the CPU has it), `alloc` the `Vec` returning encrypt call,
`zeroize` wipes the key schedule on drop; the default `getrandom` feature is
dropped because the AEAD nonce is derived with HKDF, not drawn at random. License Apache-2.0 OR MIT;
RustCrypto developers, <https://github.com/RustCrypto/AEADs>; released
2026-08-21; MSRV 1.85.

**getrandom 0.4.3** is the source of the 32-byte random `response_nonce` that
RFC 9458 requires for each encapsulated response. Pinned `=0.4.3` with no optional
features; on Linux it calls `getrandom(2)`. License MIT OR Apache-2.0;
rust-random project, <https://github.com/rust-random/getrandom>; released
2026-06-17; MSRV 1.85.

**ed25519-dalek 2.2.0 to 3.0.0** (existing dependency, major bump). The sidecar
signs responses with it and derives the X25519 decryption key from the same
seed. Version 3 is the one built on `curve25519-dalek` 5, the same curve crate
that `hpke` reaches through `x25519-dalek` 3, so the tree carries one
curve25519 implementation instead of two. Pinned `=3.0.0` with default features
off and only `fast` and `zeroize`; `std` is no longer needed. License
BSD-3-Clause; dalek-cryptography project,
<https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek>;
released 2026-07-06; MSRV 1.85. The RFC 8032 test vector and the existing
signing known-answer tests pass unchanged after the bump.

**sha2** (existing dependency) gains the `zeroize` feature; it adds no crate to
the tree. See Memory hygiene below.

The crate's `rust-version` is 1.91. `Cargo.lock` uses Cargo's lock format
version 4, which every toolchain from that version on reads.

## Pinning

The crate is a binary (`publish = false`) and `Cargo.lock` is committed. CI
(clippy, tests, cargo-deny) and the release image (`cargo chef cook`,
`cargo build`) run with `--locked`, so a build fails instead of resolving a
version that is not in the lock. The new cryptographic crates and the bumped
`ed25519-dalek` use exact `=` requirements. Together this fixes every transitive
version: no dependency floats in a released build.

Limit of this vetting: the direct crates were reviewed through their source,
release history and known-answer tests; the build scripts of transitive crates
were not audited line by line. All of them come from the RustCrypto, dalek and
rust-random projects or were already in the tree.

## Transitive changes

Generated from the committed `Cargo.lock` against the `main` branch, comparing
`name@version` pairs (the lock format header is ignored).

Added (19):

- `aead` 0.6.1
- `aes` 0.9.3
- `aes-gcm` 0.11.1
- `bhttp` 0.8.0
- `cipher` 0.5.2
- `cmov` 0.5.4
- `cpubits` 0.1.1
- `ctr` 0.10.1
- `ctutils` 0.4.3
- `ghash` 0.6.0
- `hkdf` 0.13.0
- `hmac` 0.13.0 (next to 0.12.1, which stays)
- `hpke` 0.14.1
- `inout` 0.2.3
- `polyval` 0.7.3
- `rand_core` 0.10.1 (next to 0.6.4 and 0.9.5, which stay)
- `signature` 3.0.0 (next to 2.2.0, which stays through `k256` and `ecdsa`)
- `universal-hash` 0.6.1
- `x25519-dalek` 3.0.0

Updated (9):

- `crypto-common` 0.2.1 to 0.2.2
- `curve25519-dalek` 4.1.3 to 5.0.0
- `ed25519` 2.2.3 to 3.0.0
- `ed25519-dalek` 2.2.0 to 3.0.0
- `fiat-crypto` 0.2.9 to 0.3.0
- `getrandom` 0.4.2 to 0.4.3
- `hybrid-array` 0.4.12 to 0.4.15
- `zeroize` 1.8.2 to 1.9.1
- `zeroize_derive` 1.4.3 to 1.5.0

Removed (14), all wasm-only: they came in through the `wasip3` dependency of
`getrandom` 0.4.2, which 0.4.3 no longer has.

- `foldhash` 0.1.5
- `hashbrown` 0.15.5
- `id-arena` 2.3.0
- `leb128fmt` 0.1.0
- `wasip3` 0.4.0+wasi-0.3.0-rc-2026-01-06
- `wasm-encoder` 0.244.0
- `wasm-metadata` 0.244.0
- `wasmparser` 0.244.0
- `wit-bindgen` 0.51.0
- `wit-bindgen-core` 0.51.0
- `wit-bindgen-rust` 0.51.0
- `wit-bindgen-rust-macro` 0.51.0
- `wit-component` 0.244.0
- `wit-parser` 0.244.0

## Memory hygiene

- `aes-gcm` feature `zeroize` wipes the AES key schedule on drop, including the
  one inside `hpke`'s AEAD, since Cargo unifies the feature across the tree.
- `sha2` feature `zeroize` wipes the keyed HMAC state of every HKDF instance on
  drop, the sidecar's own and the one in `hpke`'s key schedule.
- Secrets the sidecar owns (the X25519 private key, the exported secret, the
  response key and nonce) sit in `Zeroizing` buffers.

Residue that no feature reaches, documented rather than worked around (fixing
it would mean reimplementing HKDF): the pseudorandom key that `hkdf`'s extract
step returns and discards, the intermediate blocks of `hkdf`'s expand step, the
64-byte SHA-512 output inside `ed25519-dalek`'s scalar derivation, and stack
copies the compiler makes on moves. Each lives for microseconds inside the TEE.
