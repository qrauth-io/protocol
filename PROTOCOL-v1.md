> **Historical. QRVA v1.0 (2026-04-03). Superseded by QRVA v2 ([PROTOCOL.md](./PROTOCOL.md)). Not implemented by current QRAuth releases; v1 tokens (`ecdsa-p256-sha256-v1`) are rejected.**

# QRVA Protocol Specification v1.0

**Status**: Draft
**Date**: 2026-04-03
**Authors**: QRAuth Contributors

---

## 1. Introduction

QRVA (QR Verification and Authentication) is a protocol for cryptographically signing physical QR codes and verifying their authenticity at scan time. It addresses the growing threat of QR code fraud, where attackers overlay fake QR stickers on legitimate installations (parking meters, payment terminals, government signs) to redirect users to phishing sites.

The protocol defines mechanisms for:
- Cryptographic signing of QR code payloads
- Binding QR codes to physical geographic locations
- Verifying QR code authenticity at scan time
- Publishing an auditable transparency log of issued QR codes
- Emitting standardized events for monitoring and integration

## 2. Terminology

- **Issuer**: An entity that generates and deploys QR codes (e.g., a municipality, business, or payment operator).
- **Verifier**: A service that validates QR code signatures and returns verification results.
- **Scanner**: An end user who scans a QR code with a phone camera or app.
- **Token**: A unique, URL-safe identifier for a registered QR code.
- **Tenant**: An isolated namespace within a verifier platform, representing a single issuer account.
- **Trust Score**: A numeric value (0-100) representing the confidence level of a verification result.

## 3. QR Payload Format

A QRVA-compliant QR code encodes a verification URL:

```
https://[verifier-domain]/v/[token]
```

Where:
- `[verifier-domain]` is the FQDN of the verification service (e.g., `qrauth.io`)
- `[token]` is a URL-safe base64-encoded identifier, 6-12 characters

The token resolves to a verification record containing:

| Field | Type | Required | Description |
|---|---|---|---|
| token | string | yes | Unique identifier |
| destination_url | string | yes | The intended destination URL |
| issuer_id | string | yes | Identifier of the issuing tenant |
| signature | bytes | yes | ECDSA-P256 signature (64 bytes) |
| location | object | no | Geospatial binding (see Section 6) |
| metadata | object | no | Arbitrary key-value pairs |
| created_at | datetime | yes | ISO 8601 timestamp |
| expires_at | datetime | no | ISO 8601 expiry timestamp |
| log_index | integer | yes | Transparency log sequence number |

## 4. Signing Algorithm

### 4.1 Key Generation

Issuers generate an ECDSA key pair using the P-256 curve (secp256r1, NIST P-256) as defined in FIPS 186-4.

```
Private key: 32 bytes (256 bits)
Public key:  65 bytes (uncompressed) or 33 bytes (compressed)
```

### 4.2 Payload Construction

The canonical payload for signing is constructed by concatenating:

```
canonical_payload = token || destination_url || geo_hash || expires_at
```

Where:
- `token`: UTF-8 encoded token string
- `destination_url`: UTF-8 encoded destination URL (normalized per RFC 3986)
- `geo_hash`: If location is present, `SHA-256(lat || lng || radius)` as hex string; otherwise empty string
- `expires_at`: ISO 8601 string if present; otherwise empty string

### 4.3 Signing

```
hash = SHA-256(canonical_payload)
signature = ECDSA_Sign(issuer_private_key, hash)
```

The signature MUST be encoded in compact format (IEEE P1363): `r || s`, each 32 bytes, totaling 64 bytes. DER encoding is NOT used.

### 4.4 Verification

```
hash = SHA-256(canonical_payload)
result = ECDSA_Verify(issuer_public_key, hash, signature)
```

A verification result of `true` confirms the QR code was issued by the holder of the corresponding private key and has not been tampered with.

## 5. Verification Flow

When a scanner accesses a verification URL, the verifier executes the following steps in order:

### 5.1 Token Resolution

Look up the token in the verification record store. If not found, return `verified: false` with reason `token_not_found`.

### 5.2 Expiry Check

If `expires_at` is present and the current time exceeds it, return `verified: false` with reason `token_expired`.

### 5.3 Signature Verification

Reconstruct the canonical payload from the stored record. Verify the signature using the issuer's public key. If verification fails, return `verified: false` with reason `signature_invalid`.

### 5.4 Geospatial Check (Optional)

If the record includes a location binding AND the scanner provides their coordinates, compute the Haversine distance between the two points. If the distance exceeds the registered radius plus a tolerance of 50 meters, set `location_match: false`. The verification can still succeed (location mismatch is a warning, not a failure).

### 5.5 Trust Score Computation

Compute a trust score (0-100) based on:

| Signal | Weight | Description |
|---|---|---|
| Signature valid | 40 | Binary: 40 if valid, 0 if invalid |
| Location match | 20 | 20 if matched, 10 if no location data, 0 if mismatch |
| Issuer verification level | 15 | 15 for government, 10 for verified business, 5 for unverified |
| Token age | 10 | 10 if < 1 year, 5 if < 3 years, 2 if older |
| Transparency log inclusion | 15 | 15 if logged and proof valid, 0 if not logged |

### 5.6 Response

Return a verification result:

```json
{
  "verified": true,
  "issuer": {
    "id": "iss_example",
    "name": "Example Municipality",
    "trust_level": "government"
  },
  "destination_url": "https://example.com/pay",
  "location_match": {
    "matched": true,
    "distance_m": 12
  },
  "trust_score": 94,
  "scanned_at": "2026-04-01T14:32:07Z"
}
```

## 6. Geospatial Binding

### 6.1 Coordinate System

All coordinates use the WGS84 geodetic datum (EPSG:4326), consistent with GPS and web mapping standards.

### 6.2 Location Record

```json
{
  "lat": 40.6321,
  "lng": 22.9414,
  "radius_m": 15,
  "address": "Tsimiski Street, Thessaloniki"
}
```

- `lat`: Latitude in decimal degrees (-90 to 90)
- `lng`: Longitude in decimal degrees (-180 to 180)
- `radius_m`: Accuracy radius in meters (minimum 5, maximum 1000)
- `address`: Human-readable address (optional, informational only)

### 6.3 Distance Computation

Distance between scanner and registered location is computed using the Haversine formula:

```
a = sin2(dlat/2) + cos(lat1) * cos(lat2) * sin2(dlng/2)
c = 2 * atan2(sqrt(a), sqrt(1-a))
d = R * c
```

Where R = 6371000 (Earth's mean radius in meters).

A scan is considered location-matched if `d <= radius_m + 50` (50m tolerance for GPS inaccuracy).

## 7. Transparency Log

### 7.1 Structure

The transparency log is an append-only Merkle tree. Each leaf contains:

```
leaf_hash = SHA-256(issuer_id || token || SHA-256(destination_url) || geo_hash || created_at)
```

Note: The destination URL is hashed (not stored in plaintext) to protect issuer privacy while maintaining verifiability.

### 7.2 Inclusion Proof

For any token, an inclusion proof can be generated consisting of the sibling hashes along the path from the leaf to the Merkle root. Verifiers can validate that a token was included in the log without downloading the entire tree.

The proof format is compatible with RFC 6962 (Certificate Transparency) tooling.

### 7.3 Signed Tree Head

The verifier periodically publishes a Signed Tree Head (STH):

```json
{
  "tree_size": 48291,
  "timestamp": "2026-04-01T00:00:00Z",
  "root_hash": "a1b2c3...",
  "signature": "MEUCIQD..."
}
```

### 7.4 Auditability

The transparency log is publicly queryable. Third parties (security researchers, municipalities, competing verifiers) can:
- Verify that a specific token exists in the log
- Monitor the log for unauthorized issuances
- Detect inconsistencies between the log and verification responses

## 8. Event Schema

QRVA defines a standardized event schema for interoperability between verifiers, issuers, and monitoring systems.

### 8.1 Event Envelope

```json
{
  "id": "evt_a1b2c3d4",
  "type": "qr.scanned",
  "version": "1.0",
  "tenant_id": "ten_example",
  "created_at": "2026-04-01T14:32:07Z",
  "data": { }
}
```

### 8.2 Event Types

| Type | Description |
|---|---|
| `qr.created` | A new QR code was generated and signed |
| `qr.updated` | A QR code's destination or metadata was modified |
| `qr.revoked` | A QR code was revoked |
| `qr.expired` | A QR code reached its expiry time |
| `scan.completed` | A QR code was scanned and verification succeeded |
| `scan.failed` | A QR code was scanned and verification failed |
| `fraud.detected` | Anomalous scan activity detected |
| `fraud.proxy_detected` | Potential MitM proxy detected during verification |
| `passkey.enrolled` | A user enrolled a WebAuthn passkey |
| `passkey.verified` | A user authenticated via WebAuthn passkey |

### 8.3 Webhook Delivery

Events are delivered to registered HTTPS endpoints via POST requests. Each delivery includes an HMAC-SHA256 signature in the `X-QRAuth-Signature` header for authenticity verification:

```
signature = HMAC-SHA256(webhook_secret, request_body)
```

Deliveries that fail (non-2xx response) are retried with exponential backoff: 1s, 5s, 30s, 5m, 30m, 2h. Events that fail all retries are stored in a dead-letter queue for 30 days.

## 9. Security Considerations

### 9.1 Key Management

Issuer private keys MUST be stored in a hardware security module (HSM) or equivalent key management service (e.g., AWS KMS, HashiCorp Vault). Private keys MUST NOT be stored in application code, environment variables, or configuration files.

### 9.2 Key Rotation

Issuers SHOULD rotate signing keys annually. Upon rotation, the previous public key MUST remain available for verification of previously signed QR codes until their expiry.

### 9.3 Token Entropy

Tokens MUST contain at least 48 bits of entropy to prevent brute-force enumeration. A 8-character base64url token provides approximately 48 bits.

### 9.4 Replay Prevention

Each verification response SHOULD include a unique nonce or timestamp to prevent replay of verification results.

### 9.5 Transport Security

All communication between scanners, verifiers, and issuers MUST use TLS 1.2 or higher. HSTS headers SHOULD be set on all verifier endpoints.

### 9.6 Rate Limiting

Verifiers MUST implement rate limiting on the verification endpoint to prevent denial-of-service and enumeration. Recommended limits: 100 requests per IP per minute for unauthenticated requests.

## 10. References

- FIPS 186-4: Digital Signature Standard (DSS)
- RFC 6962: Certificate Transparency
- RFC 3986: Uniform Resource Identifier (URI): Generic Syntax
- RFC 7519: JSON Web Token (JWT)
- WebAuthn Level 2: Web Authentication API
- WGS84: World Geodetic System 1984
