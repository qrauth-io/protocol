# QRVA — QR Verification and Attestation Protocol

An open specification for signing and verifying physical QR codes.

**Version**: 2.0 · **Status**: Draft · **Date**: 2026-10-20

## Overview

QRVA defines a protocol for cryptographically signing QR code verification records, binding them to physical locations, and verifying them at scan time. It addresses QR code substitution, where a fraudulent sticker is placed over a legitimate code to redirect people to a phishing site.

## Protocol Summary

- **Payload**: `https://[verifier-domain]/v/[token]`; signatures are held by the verifier, not encoded in the QR image
- **Canonical form**: `algVersion|token|tenantId|destHash|geoHash|expiresAt` (SHA3-256 commitments), with a nonce-extended Merkle leaf form
- **Hybrid signature**: ECDSA-P256 (DER) over the domain-prefixed canonical core, plus a Merkle inclusion proof against a batch root signed with SLH-DSA-SHA2-128s (FIPS 205); both legs required, and the verifier recomputes the Merkle leaf from the same canonical core and the stored nonce
- **Algorithm agility**: every record carries an `alg_version`; `hybrid-ecdsa-slhdsa-v1` is the only accepted version, and unknown and rejected versions (including v1 `ecdsa-p256-sha256-v1` and the reserved SLH-DSA-only versions) fail closed
- **Geospatial binding**: WGS84 coordinates with a radius, haversine distance check
- **Issuance log**: hash-chained log of issued records; an RFC 6962-style log with signed tree heads is planned ([ADR-0001](https://github.com/qrauth-io/qrauth/blob/main/docs/adr/0001-transparency-log.md))
- **Proximity attestations and webhooks**: signed-bytes envelopes and verification steps as shipped by QRAuth

## Specification

The current specification is [PROTOCOL.md](./PROTOCOL.md) (v2.0, Draft). The superseded v1.0 specification is kept for reference in [PROTOCOL-v1.md](./PROTOCOL-v1.md); it is not implemented by current QRAuth releases.

## Reference Implementation

The reference implementation of QRVA is [QRAuth](https://github.com/qrauth-io/qrauth). Implementation detail is in its [ALGORITHM.md](https://github.com/qrauth-io/qrauth/blob/main/ALGORITHM.md).

## Compliance Tests

The `compliance-tests/` directory contains test vectors written for QRVA v1.0. They exercise the v1 signing math with `node:crypto` and do not call an implementation under test. They do not validate QRVA v2 or any implementation.

```bash
cd compliance-tests
npm install
npm test
```

## Contributing

We welcome contributions to the protocol specification. To propose changes:

1. Open an issue describing the proposed change and rationale
2. Submit a PR with changes to `PROTOCOL.md`
3. Protocol changes require review and consensus before merging

## License

- Protocol specification (`PROTOCOL.md`, `PROTOCOL-v1.md`): [CC BY 4.0](./LICENSE)
- Compliance test code (`compliance-tests/`): MIT, as declared in [compliance-tests/package.json](./compliance-tests/package.json)
- Reference implementation: [QRAuth](https://github.com/qrauth-io/qrauth), under the Business Source License 1.1; the QRAuth SDKs (`@qrauth/animated-qr`, `@qrauth/web-components`, `@qrauth/node`, `@qrauth/cli`) are MIT
