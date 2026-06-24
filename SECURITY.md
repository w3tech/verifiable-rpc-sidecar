<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 Web3 Technologies, Inc. -->

# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**. Do **not** open public
issues, pull requests, or discussions for security problems.

Use GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability** (GitHub Security Advisories). This opens a
private channel with the maintainers.

Please include:

- affected version / git commit, or the image digest (`sha256:…`);
- a description of the issue and its impact;
- reproduction steps or a proof of concept.

## Scope

This repository is `verifiable-rpc-sidecar` (Rust). In scope:

- the response-signing pre-image and `vRPC-*` signature;
- the `/attestation` quote binding (pubkey ‖ nonce, compose measurement);
- the byte-opaque proxy / encoding handling;
- supply-chain integrity of the published image (images are cosign-signed with
  SLSA provenance + SBOM — see the README "Pulling and verifying the image").

Out of scope (report to the respective projects/operators):

- upstream blockchain nodes the sidecar fronts;
- the dstack / KMS / Intel TDX platform itself;
- third-party deployments and their operational configuration.

## Supported versions

Security fixes target the latest published `v*.*.*` release. Pin images by
digest and verify their signatures before running (see the README).

## Disclosure

We aim to acknowledge reports within a few business days and will coordinate a
fix and a disclosure timeline with the reporter.
