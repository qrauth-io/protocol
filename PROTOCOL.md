# QRVA — QR Verification and Attestation Protocol

**Version**: 2.0
**Status**: Draft
**Date**: 2026-10-20
**Authors**: QRAuth Contributors

> **Status note.** Draft. The verification procedure (Sections 8 and 9) matches QRAuth as deployed on 2026-10-20. The document becomes Final once the remaining implementation work is merged.

The previous version is kept for reference in [PROTOCOL-v1.md](./PROTOCOL-v1.md). It is historical and is not implemented by current QRAuth releases.

---

## 1. Introduction

QRVA is a protocol for issuing QR codes whose verification records are cryptographically signed, optionally bound to a physical location, and checked at scan time by a verifier. It addresses QR code substitution, where a fraudulent code is placed over or instead of a legitimate one.

This document specifies:

- the QR payload and token format (Section 4);
- the canonical form that every signing and MAC operation binds to (Section 6);
- the hybrid signature: an ECDSA-P256 signature plus a Merkle batch whose root is signed with SLH-DSA-SHA2-128s (Section 7);
- the verification procedure (Section 8) and algorithm-version policy (Section 9);
- geospatial binding (Section 10), the issuance log (Section 11), proximity attestations (Section 12) and webhooks (Section 13);
- informative descriptions of the QRAuth trust score (Section 14) and Living Codes frame envelope (Section 15).

QRAuth (<https://github.com/qrauth-io/qrauth>) is the reference implementation. Implementation detail beyond what is needed for interoperability is in QRAuth's [ALGORITHM.md](https://github.com/qrauth-io/qrauth/blob/main/ALGORITHM.md).

### 1.1 Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

Sections marked **Informative** describe the QRAuth reference implementation and are not requirements for other implementations.

Notation:

- `||` denotes byte concatenation. String literals in quotes are their UTF-8 bytes.
- `SHA3-256(x)` is SHA3-256 as defined in FIPS 202. `SHA-256(x)` is SHA-256 as defined in FIPS 180-4.
- `hex(x)` is lowercase hexadecimal encoding. `base64(x)` is standard base64 with padding (RFC 4648 §4). `base64url(x)` is RFC 4648 §5 without padding.
- All strings are encoded as UTF-8 before hashing, signing or MAC computation.

## 2. Terminology

- **QRVA**: this protocol.
- **QRAuth**: the platform that serves as the reference implementation of QRVA.
- **Issuer** (tenant): an organization that issues QR codes. Identified by a `tenantId`.
- **Verifier**: the service that holds verification records, signs them on the issuer's behalf, and answers verification requests. In QRAuth, the verifier generates and holds the tenant's signing keys.
- **Scanner**: the person or client that scans a QR code and requests verification.
- **Token**: the short identifier encoded in a QR code's URL.
- **Verification record**: the verifier-side data a token resolves to (destination, location binding, expiry, signatures).
- **Canonical core** / **canonical leaf**: the byte strings defined in Section 6.
- **Hybrid signature**: the pair of an ECDSA-P256 signature over the canonical core and a Merkle inclusion proof against an SLH-DSA-SHA2-128s-signed batch root (Section 7).
- **Merkle batch**: a set of canonical leaves arranged in a binary hash tree whose root is signed once with SLH-DSA-SHA2-128s.
- **MAC pre-filter**: an optional, implementation-local HMAC-SHA3-256 check that can only reject (Section 8.3).
- **`alg_version`**: the algorithm-version identifier carried by every verification record and committed to in the canonical form (Section 9).
- **Issuance log**: the verifier's hash-chained log of issued records (Section 11).
- **Proximity attestation**: a signed statement that a device reported a location within a given distance of a QR code's registered location (Section 12).
- **Living Codes**: animated QR codes whose frames carry a short HMAC tag (Section 15).
- **Ephemeral session**: a short-lived, delegated-access session claimed by scanning a QR code. Ephemeral sessions use their own API and are outside the scope of this version except for the webhook events in Section 13.
- **Trust score**: an implementation-specific risk heuristic in the range 0 to 100 (Section 14). It is not a probability and does not include the signature result.

## 3. Cryptographic Primitives

| Use | Primitive | Standard |
|---|---|---|
| Canonical, destination, geo and Merkle hashing | SHA3-256 | FIPS 202 |
| Classical signature leg | ECDSA-P256 with SHA-256 | FIPS 186-5 |
| Post-quantum leg (batch root) | SLH-DSA-SHA2-128s | FIPS 205 |
| MAC pre-filter, signing-key webhook | HMAC-SHA3-256 | FIPS 198-1, FIPS 202 |
| Integration webhook, Living Codes frame tag | HMAC-SHA-256 | FIPS 198-1, FIPS 180-4 |
| Issuance log chain | SHA-256 | FIPS 180-4 |

## 4. QR Payload and Token

### 4.1 Payload

A QRVA QR code encodes a verification URL and nothing else:

```
https://<verifier-domain>/v/<token>
```

Signatures, MACs and Merkle proofs are held by the verifier and MUST NOT be required in the QR image. A verifier MAY expose the same verification at other paths (QRAuth also serves `/api/v1/verify/<token>`, returning JSON when the request sends `Accept: application/json`).

### 4.2 Token

A token MUST consist only of unreserved URL characters (RFC 3986 §2.3) so that it appears in the path without percent-encoding, and therefore contains none of the characters forbidden in canonical fields (Section 6.4). Tokens MUST be generated with a cryptographically secure random number generator and MUST be unique per verifier.

QRAuth generates 8-character tokens drawn uniformly, by rejection sampling over a CSPRNG, from this 57-symbol alphabet, which omits the look-alike characters `0`, `O`, `1`, `l` and `I`:

```
ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789
```

This gives 57^8 possible tokens (approximately 46.7 bits). Because token space alone does not prevent enumeration, verifiers MUST rate-limit unauthenticated verification requests (Section 16.7).

## 5. Verification Record

For each token the verifier stores at least:

| Field | Description |
|---|---|
| `token` | The token (Section 4.2). |
| `tenantId` | Identifier of the issuing tenant. |
| `alg_version` | Algorithm version (Section 9). |
| `contentType` | `url` or another content-type identifier (for example `vcard`, `coupon`, `event`, `pdf`, `feedback`). |
| `destinationUrl` | Destination URL, for `url` content. |
| `content` | Structured content, for other content types. |
| `lat`, `lng`, `radiusM` | Optional location binding (Section 10). |
| `expiresAt` | Optional expiry instant. |
| `ecdsaSignature` | ECDSA-P256 signature, DER, base64 (Section 7.2). |
| `signingKeyId` | The tenant signing key that produced both legs. |
| Merkle data | For hybrid records: batch identifier, leaf index, leaf hash, leaf nonce and inclusion path (Section 7.3). |
| `status` | At least: active or revoked. |

## 6. Canonical Form

Every signature leg and the MAC pre-filter bind to the same canonical byte string. Implementations MUST reproduce it byte for byte.

### 6.1 Core form

The canonical core is six fields joined by a single `|` (U+007C), in this fixed order:

```
canonical_core = algVersion "|" token "|" tenantId "|" destHash "|" geoHash "|" expiresAt
```

### 6.2 Merkle leaf form

The canonical leaf is the core form with the per-leaf nonce appended:

```
canonical_leaf = canonical_core "|" nonce
```

The leaf form is used only by the Merkle batch (Section 7.3). The ECDSA leg and the MAC pre-filter use the core form.

### 6.3 Fields

- **`algVersion`**: the record's algorithm-version string (Section 9), for example `hybrid-ecdsa-slhdsa-v1`.
- **`token`**: the token, as encoded in the URL.
- **`tenantId`**: the issuing tenant's identifier, as stored by the verifier.
- **`destHash`**: a content-type-aware destination commitment:
  - for `contentType = url`: `hex(SHA3-256("qrauth:dest:v1:url:" || destinationUrl))`;
  - for any other content type: `hex(SHA3-256("qrauth:dest:v1:" || contentType || ":" || contentHashHex))`, where `contentHashHex = hex(SHA-256(stable_json(content)))`. `stable_json` serializes the content as ECMAScript `JSON.stringify` does, except that object keys are sorted in UTF-16 code-unit order at every nesting level, members whose value is undefined are omitted, and no whitespace is emitted.

  The destination URL is used byte for byte; no URL normalization is applied. The domain tag `qrauth:dest:v1:<contentType>:` separates content types so that a URL cannot collide with a content commitment.
- **`geoHash`**: the literal string `none` when the record has no location binding (either coordinate absent). Otherwise `hex(SHA3-256(lat_s || ":" || lng_s || ":" || r_s))`, where `lat_s` and `lng_s` are the decimal degrees formatted with exactly 7 digits after the decimal point exactly as ECMAScript `Number.prototype.toFixed(7)` formats the IEEE 754 double value, and `r_s` is the radius in metres truncated to an integer and written in decimal without leading zeros.
- **`expiresAt`**: the expiry instant as an ISO 8601 UTC string with millisecond precision and a `Z` suffix (`YYYY-MM-DDTHH:mm:ss.sssZ`), or the empty string for records that do not expire.
- **`nonce`** (leaf form only): 32 bytes from a CSPRNG, generated per leaf at issuance, hex-encoded (64 characters). The nonce keeps two leaves distinct even when their core forms are identical. The verifier stores it with the record.

All hash outputs above are lowercase hex.

### 6.4 Forbidden characters

No field value may contain `|` (U+007C), line feed (U+000A) or NUL (U+0000). Issuers MUST reject such input before constructing a canonical form; verifiers MUST treat a record whose fields contain them as invalid. Fields are otherwise opaque UTF-8 strings and are not trimmed or case-folded.

## 7. Hybrid Signature

Each record is signed under one tenant signing key, which comprises an ECDSA-P256 key pair and an SLH-DSA-SHA2-128s key pair. In QRAuth, the verifier generates these per tenant; tenants do not hold private keys.

### 7.1 Overview

A hybrid signature has two legs:

1. **ECDSA leg**: an ECDSA-P256 signature over the domain-prefixed canonical core.
2. **Merkle/SLH-DSA leg**: a Merkle inclusion proof for the record's canonical leaf, against a batch root signed with SLH-DSA-SHA2-128s.

A record with `alg_version = hybrid-ecdsa-slhdsa-v1` is valid only if both legs verify.

### 7.2 ECDSA leg

```
M_ecdsa   = "qrauth:ecdsa-canonical:v1:" || canonical_core
signature = ECDSA-P256-Sign(sk_ecdsa, SHA-256(M_ecdsa))
```

The signature MUST be ASN.1 DER-encoded (`SEQUENCE { r INTEGER, s INTEGER }`) and transported as `base64(DER)`. IEEE P1363 (`r || s`) encoding is not used for this leg.

### 7.3 Merkle batch

Issuers group one or more records into a batch. For each record at position `i`:

```
leaf_i = SHA3-256(0x00 || canonical_leaf_i)
```

The leaf list is padded to the next power of two, `size >= 1`. A padding leaf at position `j` (where `j` runs from the number of real leaves to `size - 1`) is:

```
pad_j = SHA3-256(0x00 || "qrauth-pad:" || decimal(j))
```

where `decimal(j)` is the ASCII decimal representation of `j` without leading zeros. Each padding leaf is distinct because it includes its own index.

Internal nodes concatenate the raw 32-byte child digests (not their hex strings):

```
node = SHA3-256(0x01 || left || right)
```

The root is the single node at the top level. A batch with one real leaf has `size = 1`; its root is that leaf and its inclusion path is empty.

The inclusion path for leaf `i` is the ordered list, from the leaf level upward, of sibling digests, each tagged with the sibling's side (`left` or `right`). QRAuth transports each element as `{ "hash": hex(sibling), "side": "left" | "right" }`.

The `0x00` and `0x01` prefixes separate leaf hashes from internal-node hashes. Implementations MUST NOT omit them.

### 7.4 Batch-root signature

```
M_root         = "qrauth:merkle-root:v1:" || root          (root as 32 raw bytes)
root_signature = SLH-DSA-SHA2-128s.Sign(sk_slhdsa, M_root)
```

`SLH-DSA-SHA2-128s.Sign` is the FIPS 205 pure signing interface with an empty context string. The signature is 7,856 bytes; the public key is 32 bytes. QRAuth transports the signature as `base64`.

### 7.5 Domain-separation prefixes

The prefixes `qrauth:ecdsa-canonical:v1:` and `qrauth:merkle-root:v1:` MUST be applied by the signer and reconstructed by the verifier. A signer MUST NOT produce a signature under either key over bytes that do not begin with the prefix for that key's use.

### 7.6 Issuance (Informative)

In QRAuth, every new QR record is issued with `alg_version = hybrid-ecdsa-slhdsa-v1`. Leaves are queued per signing key and flushed into a batch at 64 leaves or 200 ms, whichever comes first. Issuance waits for both the ECDSA signature and the signed batch before the record is stored, so every stored record carries complete Merkle data. Records MUST NOT be stored or published with `alg_version = ecdsa-pending-slhdsa-v1`; that former transient state is rejected (Section 9.1).

## 8. Verification Procedure

A verifier MUST perform the following steps in order. A failure at any step ends verification with a negative result.

### 8.1 Record resolution

1. Resolve the token to a verification record. An unknown token is a failure.
2. If the record is revoked, fail.
3. If `expiresAt` is set and is in the past, fail.

A verifier MAY apply further record-level policy (for example scan limits) at this point.

### 8.2 Algorithm-version check

Classify the record's `alg_version` against the registry (Section 9):

- `accepted`: continue.
- `deprecated`: continue, and SHOULD surface a warning to the relying party or operator.
- `rejected`: fail, even if the signatures are mathematically valid.
- `unknown` (any value not in the registry, including an absent value): fail.

### 8.3 MAC pre-filter (optional)

A verifier MAY keep, per record, an HMAC-SHA3-256 tag over the canonical core under a verifier-held per-tenant key. QRAuth computes it as `HMAC-SHA3-256(K_mac, "qrauth:mac:v1:" || canonical_core)`. The MAC pre-filter is implementation-local and is not part of the interoperable record.

If a MAC is present and does not match (compared in constant time), verification MUST fail. A matching MAC MUST NOT be treated as evidence of validity and MUST NOT skip any later step.

### 8.4 Canonical reconstruction

Reconstruct `canonical_core` from the stored record (Section 6), including recomputing `destHash` and `geoHash` from the stored destination, content and location. Verifiers MUST NOT use a stored copy of the canonical string, `destHash` or `geoHash` in place of recomputation.

### 8.5 ECDSA leg

Verify the DER-encoded ECDSA-P256 signature over `"qrauth:ecdsa-canonical:v1:" || canonical_core` with the public key of the record's signing key. If verification fails, fail.

### 8.6 Merkle/SLH-DSA leg

For `alg_version = hybrid-ecdsa-slhdsa-v1`, the record MUST carry Merkle data (batch identifier, leaf hash, leaf nonce, inclusion path). A record with this version and any of these missing MUST fail; it MUST NOT be verified on the ECDSA leg alone.

1. **Leaf recomputation.** Compute `leaf' = SHA3-256(0x00 || canonical_leaf)` where `canonical_leaf = canonical_core || "|" || nonce`, using the core reconstructed in Section 8.4 (the same bytes the ECDSA leg verifies) and the stored nonce. A nonce that is empty or contains a character forbidden by Section 6.4 MUST fail. Compare `leaf'` with the stored leaf hash in constant time; if they differ, fail. The verifier MUST use `leaf'`, not the stored leaf hash, as the starting point of the path walk.
2. **Batch resolution.** Resolve the batch by its identifier. An unknown batch MUST fail. The batch MUST belong to the record's tenant; otherwise fail.
3. **Path walk.** Starting from `leaf'`, for each path element in order: if the sibling's side is `right`, `current = SHA3-256(0x01 || current || sibling)`; if `left`, `current = SHA3-256(0x01 || sibling || current)`. An element with any other side value is a failure. Compare the result with the batch's stored root in constant time. If they differ, fail.
4. **Root signature.** Verify the batch's `root_signature` over `"qrauth:merkle-root:v1:" || root` with the SLH-DSA-SHA2-128s public key of the record's signing key. If verification fails, fail.

A verifier MAY cache a successful root-signature verification per batch (QRAuth caches for one hour). Failed verifications MUST NOT be cached.

### 8.7 Result

The signature result is positive only if Section 8.5 and every step of Section 8.6 passed. `hybrid-ecdsa-slhdsa-v1` is the only accepted version in this revision, so every positive result covers both legs, bound to the same canonical core. The verifier then MAY evaluate location (Section 10) and risk signals (Section 14) before returning a result.

A positive signature result shows that the stored verification record (token, tenant, destination commitment, location binding and expiry) was signed with the tenant's keys. It does not show that the physical code is in its original placement: a copy of a genuine code verifies in the same way.

The response format is implementation-defined in this version. It MUST include an overall boolean result and SHOULD include a failure reason and the record's `alg_version`. Each response SHOULD carry the time it was produced, so that a stale response can be recognized.

## 9. Algorithm Versions

### 9.1 Registry

| `alg_version` | Status | Meaning |
|---|---|---|
| `hybrid-ecdsa-slhdsa-v1` | accepted | ECDSA-P256 leg and Merkle/SLH-DSA-SHA2-128s leg; both required. Used for all new issuance. |
| `slhdsa-sha2-128s-v1` | rejected (reserved) | SLH-DSA-SHA2-128s only. Reserved; not issued. Becomes accepted only in a revision that specifies its verification procedure. |
| `slhdsa-sha2-256s-v1` | rejected (reserved) | SLH-DSA-SHA2-256s only. Reserved; not issued. Becomes accepted only in a revision that specifies its verification procedure. |
| `ecdsa-pending-slhdsa-v1` | rejected | Former transient state (ECDSA leg signed, Merkle data not attached). No longer issued. Fails closed. |
| `ecdsa-p256-sha256-v1` | rejected | QRVA v1 ECDSA-only format. Fails closed. |

`hybrid-ecdsa-slhdsa-v1` is the only accepted version. The deprecated set is currently empty. A version is accepted only when its verification procedure is specified and implemented.

### 9.2 Semantics

- **accepted**: verification proceeds.
- **deprecated**: verification proceeds with a warning. Issuers MUST NOT issue new records under a deprecated version.
- **rejected**: verification fails, regardless of signature validity. A rejected string stays in the registry so it cannot be re-enabled by accident.
- **unknown**: any string not in the registry. Verification fails.

The expected lifecycle is unknown → accepted → deprecated → rejected. A reserved version is registered as rejected and moves to accepted in the revision that specifies its verification procedure.

### 9.3 Version-bump invariants

The following MUST NOT change under an existing `alg_version`. Changing any of them requires a new QRVA protocol version, a new accepted `alg_version`, regenerated cross-language test vectors, and re-issuance of affected records:

1. Canonical field order, field count, field names and separator (Section 6).
2. Merkle construction: `0x00` leaf prefix, `0x01` node prefix, power-of-two padding with unique padding leaves, bytes-level node concatenation (Section 7.3).
3. Signer domain-separation prefixes `qrauth:ecdsa-canonical:v1:` and `qrauth:merkle-root:v1:` (Section 7.5).
4. Proximity attestation header, claim structure and signed-bytes envelope (Section 12). Adding a claim is compatible; removing or repurposing one is not.
5. Living Codes frame-signing input and 8-byte tag truncation (Section 15).

Because `algVersion` is the first canonical field, a signature produced under one version cannot be presented as a signature under another.

## 10. Geospatial Binding

### 10.1 Location record

- `lat`: decimal degrees, -90 to 90, WGS84 (EPSG:4326).
- `lng`: decimal degrees, -180 to 180, WGS84.
- `radiusM`: integer metres. QRAuth accepts 1 to 1000.

The location binding enters the signed bytes through `geoHash` (Section 6.3). A human-readable address MAY be stored alongside it and is informational only.

### 10.2 Distance and match

Distance between the scanner-reported position and the registered position is computed with the haversine formula and R = 6371000 m:

```
a = sin²(Δlat/2) + cos(lat1) · cos(lat2) · sin²(Δlng/2)
c = 2 · atan2(√a, √(1−a))
d = R · c
```

A scan is location-matched if `d <= radiusM`. No tolerance is added; issuers should choose `radiusM` large enough to absorb GPS error.

An issuer MAY require proximity for a record. When it does, a verification request without coordinates, or with `d > radiusM`, MUST fail. Otherwise a location mismatch is advisory.

Scanner coordinates are reported by the client and are not authenticated by this protocol.

## 11. Issuance Log

A verifier SHOULD append an entry to an issuance log for every issued record.

In QRAuth, the issuance log is a hash-chained log in the verifier's database. Each entry stores the previous entry's hash, and each entry hash is computed with SHA-256 over the previous entry's hash and the entry's content. Entries for hybrid records also carry the record's SHA3-256 Merkle leaf hash and a reference to the signed batch root (SHA3-256 of the root bytes).

The log provides tamper-evidence against a party that can read but not write the verifier's database, when the log is compared with a previously saved copy. It is not tamper-evident against a party with write access to that database. It is intended for forensic use.

An RFC 6962-style Merkle log with signed tree heads and external witnesses is planned and specified in [ADR-0001](https://github.com/qrauth-io/qrauth/blob/main/docs/adr/0001-transparency-log.md). This version of QRVA does not define a log format for third-party verification.

## 12. Proximity Attestation

A proximity attestation states that the device reported a location within Y metres of the QR code's registered location at time T, signed by the issuing organization. The location is reported by the client; the attestation is not proof of physical presence.

### 12.1 Request

A client requests an attestation for a token that has a registered location, supplying `clientLat`, `clientLng`, `rpId` (the relying party the attestation is for) and `deviceFingerprint`. In QRAuth: `POST /api/v1/proximity/<token>`.

### 12.2 Format

The attestation is a three-part compact token `base64url(header) "." base64url(payload) "." base64url(signature)`.

Header:

```json
{ "alg": "ES256", "typ": "JWT", "kid": "<signing key id>" }
```

Claims:

| Claim | Value |
|---|---|
| `iss` | The issuing organization's identifier. |
| `sub` | `hex(SHA3-256("qrauth:proximity-sub:v1:" || token))` |
| `aud` | The `rpId` supplied in the request. |
| `device` | `hex(SHA3-256("qrauth:proximity-device:v1:" || deviceFingerprint))` |
| `loc` | A geohash of the QR code's registered location (not the device's coordinates). |
| `proximity` | `{ "matched": d <= radiusM, "distanceM": round(d), "radiusM": radiusM }` |
| `alg_version` | `proximity-es256-v1` |
| `iat` | Issue time, seconds since the Unix epoch. |
| `exp` | `iat + 300` |

### 12.3 Signature

```
signing_input = base64url(header) "." base64url(payload)
M_prox        = "qrauth:ecdsa-canonical:v1:" || signing_input
signature     = ECDSA-P256-Sign(sk_ecdsa, SHA-256(M_prox))      (DER-encoded)
```

The third part of the token is `base64url(DER signature)`. Because the signed bytes carry the domain prefix and the signature is DER rather than IEEE P1363, the attestation is not verifiable by stock JWT libraries (for example `jsonwebtoken`, PyJWT, `jose`, `jwt-go`).

### 12.4 Verification

A verifier MUST:

1. require `alg = ES256` and `typ = JWT`;
2. resolve the public key by (`iss`, `kid`) among the organization's ES256 signing keys that are active or in their post-rotation verification window;
3. verify the DER signature over `M_prox`;
4. reject the attestation if `exp` is in the past, if `iat` is more than 30 seconds in the future, or if `iat` is older than 300 + 30 seconds.

A relying party SHOULD check that `aud` equals its own `rpId` and that `proximity.matched` is `true` before acting on the attestation.

In QRAuth, attestations are verified through `POST /api/v1/proximity/verify`; `verifyProximityAttestation` in `@qrauth/node` calls this endpoint.

## 13. Webhooks

QRAuth sends two independent kinds of webhook. Both are HTTP `POST` requests with a JSON body, and both carry the event type in `X-QRAuth-Event` and an HMAC in `X-QRAuth-Signature`. They differ in algorithm, key and body shape.

### 13.1 Integration webhooks

Sent to an app's registered webhook URL.

- Body: `{ "event": "<type>", "timestamp": "<ISO 8601>", "data": { ... } }`.
- Event types: `qr.created`, `qr.scanned`, `auth.approved`, `auth.denied`, `ephemeral.claimed`, `ephemeral.expired`.
- Signature header: `X-QRAuth-Signature: sha256=<hex>`, where `<hex>` is `hex(HMAC-SHA-256(K_app, raw_body))`.
- Key: `K_app` is the app's webhook signing key, the lowercase hex string of `SHA-256(client_secret)`, used as UTF-8 bytes (64 bytes).
- Delivery (Informative): up to 5 attempts with exponential backoff starting at 2 s.

### 13.2 Signing-key security webhook

Sent to an organization's security webhook URL whenever a signing key is created for that organization.

- Body: `{ "eventId", "eventType": "signing-key.created", "occurredAt", "organizationId", "signingKey": { "kid", "algorithm", "slhdsaAlgorithm", "status", "createdAt" }, "operatorIdentity" }`.
- Signature header: `X-QRAuth-Signature: sha3-256=<hex>`, where `<hex>` is `hex(HMAC-SHA3-256(K_org, raw_body))`.
- Key: `K_org` is the organization's webhook secret: 32 random bytes, delivered to the organization base64-encoded. The HMAC key is the decoded 32 bytes.
- Delivery (Informative): up to 4 attempts, with retries after 1 s, 5 s and 30 s.

A `signing-key.created` event that does not correspond to a key rotation the organization expects should be treated as a security incident.

### 13.3 Receiver verification

A receiver SHOULD verify every delivery as follows:

1. Read the request body as raw bytes before any JSON parsing. Do not re-serialize parsed JSON for verification.
2. Read `X-QRAuth-Signature`. Split it at the first `=` into a scheme and a hex value. The scheme MUST be the one expected for this endpoint (`sha256` for integration webhooks, `sha3-256` for the security webhook); reject any other.
3. Compute the HMAC over the raw body with the corresponding algorithm and key (Section 13.1 or 13.2) and hex-encode it in lowercase.
4. Compare the computed value with the received value in constant time. Reject on mismatch.
5. Only then parse the body and act on it. Receivers MAY reject deliveries whose `timestamp` or `occurredAt` is older than their tolerance, and SHOULD process each `eventId` at most once.

## 14. Trust Score (Informative: QRAuth reference implementation)

The trust score is a risk heuristic in the range 0 to 100 returned with QRAuth verification results. It is not part of the interoperable protocol, is not a probability, and does not include the signature result, which is reported separately.

1. Start at 100.
2. For each distinct type of unresolved fraud incident recorded against the QR code, subtract by severity: CRITICAL 30, HIGH 20, MEDIUM 10, LOW 5. Each incident type is counted once.
3. Scan velocity on this QR code in the last 5 minutes: more than 20 scans subtracts 10; otherwise more than 10 scans subtracts 5.
4. Clamp to the range 30 to 100.
5. If the destination domain is similar to another organization's verified domain, subtract 30 (floor 0).

The overall result is `verified = signatureValid && trustScore > 20 && not geo-blocked`. A score of 20 or below yields `verified: false` with a low-trust reason. The scan page shows the score in bands: 80 and above high, 50 and above medium, otherwise low.

## 15. Living Codes Frame Envelope (Informative)

Living Codes are animated QR codes whose frames rotate on an implementation-defined interval (the QRAuth renderer defaults to 1000 ms). Each frame encodes:

```
<baseUrl>?f=<frameIndex>&t=<timestampMs>&h=<tag>
```

where `tag` is the first 8 bytes (16 lowercase hex characters) of `HMAC-SHA-256(frameSecret, baseUrl || ":" || timestampMs || ":" || frameIndex)`. The frame secret is derived server-side per session and supplied to the rendering client.

The frame-verify endpoint (QRAuth: `POST /api/v1/animated-qr/validate`) accepts a frame only if its timestamp is at most 5 s old and at most 2 s in the future, its tag matches, and its frame index is strictly greater than the highest index previously accepted for the session. These checks run only at the frame-verify endpoint.

## 16. Security Considerations

### 16.1 Scope of a positive result

A positive result means the stored verification record was signed with the tenant's keys and passed the verifier's checks. It does not establish that the physical code has not been copied or moved, and it does not assess the destination itself.

### 16.2 Post-quantum coverage

The SLH-DSA-SHA2-128s leg, SHA3-256 hashing, and the HMAC-based constructions are believed to resist known quantum attacks at their stated security levels. The following artifacts in this specification are classical only (vulnerable to a large-scale quantum computer running Shor's algorithm): the ECDSA-P256 leg of the hybrid signature and proximity attestations (ES256). TLS is outside the scope of this document.

### 16.3 Issuance log

The issuance log is not tamper-evident against a party with write access to the verifier's database (Section 11). Relying parties should not treat it as an independently auditable record.

### 16.4 Location

Scanner and device coordinates are reported by the client. Neither the location match (Section 10) nor a proximity attestation (Section 12) is proof of physical presence.

### 16.5 Key management

Tenant private keys SHOULD be encrypted at rest and SHOULD be used only by a signing process isolated from request handling. In QRAuth, tenant ECDSA-P256 and SLH-DSA-SHA2-128s private keys are encrypted at rest with AES-256-GCM, and production signing operations run on a separate signer host. Signers MUST enforce the domain-separation prefixes in Section 7.5.

Verifiers SHOULD rotate tenant signing keys periodically and MUST keep the public keys needed to verify records that remain in use. QRAuth rotates tenant signing keys every 90 days.

### 16.6 Implementation

- All comparisons of MACs, hashes, Merkle roots and webhook signatures MUST be constant-time.
- Canonical forms MUST be built by a single, shared routine on both issuer and verifier sides; divergence causes permanent verification failure.
- Implementations SHOULD validate their canonical form and Merkle construction against the cross-language test vectors published with the reference implementation.

### 16.7 Enumeration and transport

Verifiers MUST rate-limit unauthenticated verification requests; 100 requests per client IP per minute is RECOMMENDED. All communication MUST use TLS 1.2 or later, and verifier endpoints SHOULD send HSTS headers.

## 17. Versioning and Changes from v1

Changes in QRVA v2 relative to v1.0 ([PROTOCOL-v1.md](./PROTOCOL-v1.md)):

- Signing is hybrid: ECDSA-P256 over the canonical core plus a Merkle batch whose root is signed with SLH-DSA-SHA2-128s. ECDSA-only v1 records (`ecdsa-p256-sha256-v1`) are rejected.
- The canonical form has six `|`-separated fields beginning with `algVersion` and including `tenantId`, with a nonce-extended Merkle leaf form; v1 concatenated four fields without separators.
- Canonical hashing uses SHA3-256; the destination is committed as a domain-separated, content-type-aware `destHash`; `geoHash` uses fixed-precision formatting and the `none` sentinel.
- ECDSA signatures are DER-encoded and domain-prefixed; v1 specified unprefixed IEEE P1363.
- Every record carries an `alg_version` checked against a registry; unknown and rejected versions fail closed. `hybrid-ecdsa-slhdsa-v1` is the only accepted version.
- Verification recomputes the Merkle leaf from the reconstructed canonical core and the stored nonce and walks the inclusion proof from the recomputed leaf; a hybrid record without complete Merkle data fails.
- The location match uses `d <= radiusM` without the v1 50 m tolerance.
- The v1 "transparency log" is replaced by a hash-chained issuance log with stated limits; an RFC 6962-style log is planned (ADR-0001).
- Proximity attestations and the two webhook systems are specified as shipped; the v1 event schema and trust-score weights are removed.

## 18. References

- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels.
- [RFC 8174] Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.
- [RFC 3986] Uniform Resource Identifier (URI): Generic Syntax.
- [RFC 4648] The Base16, Base32, and Base64 Data Encodings.
- [RFC 7519] JSON Web Token (JWT) (format reference for Section 12; see Section 12.3 for differences).
- [FIPS 180-4] Secure Hash Standard (SHA-256).
- [FIPS 186-5] Digital Signature Standard (ECDSA).
- [FIPS 198-1] The Keyed-Hash Message Authentication Code (HMAC).
- [FIPS 202] SHA-3 Standard (SHA3-256).
- [FIPS 205] Stateless Hash-Based Digital Signature Standard (SLH-DSA).
- [RFC 6962] Certificate Transparency (basis of the planned issuance-log redesign; not implemented).
- QRAuth [ALGORITHM.md](https://github.com/qrauth-io/qrauth/blob/main/ALGORITHM.md) and [THREAT_MODEL.md](https://github.com/qrauth-io/qrauth/blob/main/THREAT_MODEL.md).
