<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 Web3 Technologies, Inc. -->

# Contributing to rpc-attest-sidecar

Thanks for your interest in contributing.

## License & Contributor License Agreement (CLA)

This project is licensed under **AGPL-3.0-only** (see [`LICENSE`](LICENSE)).

By submitting a contribution you agree that:

1. Your contribution is licensed under **AGPL-3.0-only**, and
2. You grant **Web3 Technologies, Inc.** the rights described in the project
   **Contributor License Agreement** ([`CLA.md`](CLA.md)) — a license grant
   (not a copyright assignment) that lets the maintainer relicense the project,
   including offering a separate commercial license.

You must **sign the CLA before your pull request can be merged**. A bot
([CLA Assistant](.github/workflows/cla.yml)) comments on your first PR with a
one-time signing link; once signed it applies to all future PRs.

> The CLA text is a **DRAFT pending legal sign-off** (tracked as LIC-06). Do not
> rely on it as final until legal has approved it and the CLA bot is activated.

## Source headers

Every source file under `src/` must start with:

```rust
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) <year> Web3 Technologies, Inc.
```

CI fails any `src/*.rs` missing the SPDX header (see `.github/workflows/ci.yml`).

## Development

```bash
cargo fmt --all -- --check     # formatting
cargo clippy --all-targets -- -D warnings
cargo test --lib               # unit tests
cargo deny check licenses      # dependency license compatibility (AGPL)
```

New dependencies must carry an AGPL-compatible license — `cargo deny check
licenses` is gated in CI; update the allow-list in [`deny.toml`](deny.toml) only
for genuinely compatible licenses.

## Pull requests

- Branch name: `SHARK-<ticket>-<short-desc>`.
- Keep PRs focused; ensure `cargo fmt`, `clippy`, tests, and the license checks pass.
