import { describe, it, expect } from 'vitest';
import { createECDH, createSign, createVerify, generateKeyPairSync, createHash } from 'node:crypto';

/**
 * QRVA Protocol Compliance Tests — Signing (Section 4)
 *
 * These tests validate that an implementation correctly generates
 * ECDSA-P256 signatures over canonical payloads as defined in the
 * QRVA protocol specification.
 */

function generateQRVAKeyPair() {
  return generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
}

function buildCanonicalPayload(
  token: string,
  destinationUrl: string,
  geoHash: string,
  expiresAt: string
): Buffer {
  const payload = token + destinationUrl + geoHash + expiresAt;
  return Buffer.from(payload, 'utf-8');
}

function sha256(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}

function signPayload(privateKey: Buffer, payload: Buffer): Buffer {
  const hash = sha256(payload);
  const sign = createSign('SHA256');
  sign.update(payload);
  const derSignature = sign.sign({ key: privateKey, format: 'der', type: 'pkcs8' });

  // Convert DER to compact (r || s) format per QRVA spec Section 4.3
  return derToCompact(derSignature);
}

function derToCompact(derSig: Buffer): Buffer {
  // DER: 0x30 [len] 0x02 [rLen] [r] 0x02 [sLen] [s]
  let offset = 2; // skip 0x30 and length byte
  if (derSig[1] & 0x80) offset++; // long form length

  // Parse r
  offset++; // skip 0x02
  const rLen = derSig[offset++];
  let r = derSig.subarray(offset, offset + rLen);
  offset += rLen;

  // Parse s
  offset++; // skip 0x02
  const sLen = derSig[offset++];
  let s = derSig.subarray(offset, offset + sLen);

  // Remove leading zero padding if present
  if (r.length === 33 && r[0] === 0) r = r.subarray(1);
  if (s.length === 33 && s[0] === 0) s = s.subarray(1);

  // Pad to 32 bytes each
  const rPadded = Buffer.alloc(32);
  const sPadded = Buffer.alloc(32);
  r.copy(rPadded, 32 - r.length);
  s.copy(sPadded, 32 - s.length);

  return Buffer.concat([rPadded, sPadded]);
}

function verifyPayload(publicKey: Buffer, payload: Buffer, derSignature: Buffer): boolean {
  const verify = createVerify('SHA256');
  verify.update(payload);
  return verify.verify({ key: publicKey, format: 'der', type: 'spki' }, derSignature);
}

describe('QRVA Signing — Section 4', () => {
  const { publicKey, privateKey } = generateQRVAKeyPair();

  it('generates a valid ECDSA-P256 key pair', () => {
    expect(privateKey).toBeDefined();
    expect(publicKey).toBeDefined();
    // P-256 uncompressed public key in SPKI DER is 91 bytes
    expect(publicKey.length).toBe(91);
  });

  it('signs a canonical payload and produces a 64-byte compact signature', () => {
    const payload = buildCanonicalPayload(
      'xK9m2pQ7',
      'https://parking.thessaloniki.gr/pay/zone-b',
      '',
      '2027-01-01T00:00:00Z'
    );

    const signature = signPayload(Buffer.from(privateKey), payload);

    // QRVA spec requires 64-byte compact format (r || s, each 32 bytes)
    expect(signature.length).toBe(64);
  });

  it('verifies a valid signature', () => {
    const payload = buildCanonicalPayload(
      'xK9m2pQ7',
      'https://parking.thessaloniki.gr/pay/zone-b',
      '',
      '2027-01-01T00:00:00Z'
    );

    const sign = createSign('SHA256');
    sign.update(payload);
    const derSignature = sign.sign({ key: Buffer.from(privateKey), format: 'der', type: 'pkcs8' });

    const valid = verifyPayload(Buffer.from(publicKey), payload, derSignature);
    expect(valid).toBe(true);
  });

  it('rejects a tampered payload', () => {
    const payload = buildCanonicalPayload(
      'xK9m2pQ7',
      'https://parking.thessaloniki.gr/pay/zone-b',
      '',
      '2027-01-01T00:00:00Z'
    );

    const sign = createSign('SHA256');
    sign.update(payload);
    const derSignature = sign.sign({ key: Buffer.from(privateKey), format: 'der', type: 'pkcs8' });

    // Tamper with the payload (change destination URL)
    const tamperedPayload = buildCanonicalPayload(
      'xK9m2pQ7',
      'https://evil-parking.com/pay',
      '',
      '2027-01-01T00:00:00Z'
    );

    const valid = verifyPayload(Buffer.from(publicKey), tamperedPayload, derSignature);
    expect(valid).toBe(false);
  });

  it('rejects a signature from a different key', () => {
    const otherKeyPair = generateQRVAKeyPair();

    const payload = buildCanonicalPayload(
      'xK9m2pQ7',
      'https://parking.thessaloniki.gr/pay/zone-b',
      '',
      '2027-01-01T00:00:00Z'
    );

    // Sign with the other key
    const sign = createSign('SHA256');
    sign.update(payload);
    const derSignature = sign.sign({
      key: Buffer.from(otherKeyPair.privateKey),
      format: 'der',
      type: 'pkcs8',
    });

    // Verify with the original public key — must fail
    const valid = verifyPayload(Buffer.from(publicKey), payload, derSignature);
    expect(valid).toBe(false);
  });

  it('includes geospatial hash in canonical payload when location is present', () => {
    const lat = '40.6321';
    const lng = '22.9414';
    const radius = '15';
    const geoHash = createHash('sha256')
      .update(lat + lng + radius)
      .digest('hex');

    const payload = buildCanonicalPayload(
      'xK9m2pQ7',
      'https://parking.thessaloniki.gr/pay/zone-b',
      geoHash,
      '2027-01-01T00:00:00Z'
    );

    const sign = createSign('SHA256');
    sign.update(payload);
    const derSignature = sign.sign({ key: Buffer.from(privateKey), format: 'der', type: 'pkcs8' });

    const valid = verifyPayload(Buffer.from(publicKey), payload, derSignature);
    expect(valid).toBe(true);

    // Verify that changing the location invalidates the signature
    const wrongGeoHash = createHash('sha256')
      .update('41.0000' + '23.0000' + '15')
      .digest('hex');

    const tamperedPayload = buildCanonicalPayload(
      'xK9m2pQ7',
      'https://parking.thessaloniki.gr/pay/zone-b',
      wrongGeoHash,
      '2027-01-01T00:00:00Z'
    );

    const invalidResult = verifyPayload(Buffer.from(publicKey), tamperedPayload, derSignature);
    expect(invalidResult).toBe(false);
  });
});
