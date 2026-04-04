# QRVA — QR Verification and Authentication Protocol

An open specification for signing and verifying physical QR codes.

## Overview

QRVA defines a standard protocol for cryptographically signing QR codes, binding them to physical locations, and verifying their authenticity at scan time. The protocol is designed to prevent QR code fraud — where attackers place fake QR stickers over legitimate ones to redirect victims to phishing sites.

## Protocol Summary

- **Signing Algorithm**: ECDSA with P-256 curve, SHA-256 hash, 64-byte compact signatures
- **Payload Format**: `https://[verifier-domain]/v/[token]`
- **Geospatial Binding**: WGS84 coordinates with accuracy radius, Haversine distance verification
- **Transparency Log**: Append-only Merkle tree, RFC 6962 compatible inclusion proofs
- **Event Schema**: Standardized JSON event types for interoperability

## Specification

The full protocol specification is in [PROTOCOL.md](./PROTOCOL.md).

## Reference Implementation

The reference implementation of QRVA is the [QRAuth Platform](https://github.com/qrauth-io/qrauth).

## Compliance Test Suite

The `compliance-tests/` directory contains a test suite that validates whether an implementation conforms to the QRVA specification.

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

- Protocol specification (`PROTOCOL.md`): [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
- Compliance test suite code: [MIT](./compliance-tests/LICENSE)
