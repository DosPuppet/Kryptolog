/**
 * PQC migration test gate (browser/extension side, @noble/post-quantum).
 *
 * Covers:
 *   - FIPS 203/204 size conformance (ML-KEM-768, ML-DSA-44).
 *   - ML-KEM-768 wrap -> unwrap round-trips through the crypto.js envelope
 *     helpers (the KEM is browser-internal; the server never touches it, so
 *     only the clients need to agree — and both clients use this same lib).
 *   - ML-DSA-44 sign -> verify round-trip + tamper rejection.
 *   - Cross-library interop: a signature produced by liboqs on the SERVER must
 *     verify here under noble (committed fixture). The mirror direction
 *     (noble -> liboqs) is asserted in backend/tests/test_pqc.py.
 *   - Deterministic seeded-keygen byte-pin: regression anchor against any
 *     future lib bump that would silently change the key encoding.
 */
import { describe, it, expect } from 'vitest';
import vec from '../../../tests/fixtures/pqc_interop.json';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import {
  signMessagePQC,
  verifySignaturePQC,
  encryptMessagePQC,
  decryptMessagePQC,
  generateSessionKey,
  wrapSessionKey,
  unwrapSessionKey,
  generateKyberKeyPair,
  generateDilithiumKeyPair,
  toHex,
  domainSeparate,
  SIGNING_CONTEXT,
} from '../utils/crypto';

const fromHexLocal = (h) => new Uint8Array(Buffer.from(h, 'hex'));

describe('FIPS size conformance', () => {
  it('ML-KEM-768 keys are 1184 / 2400 bytes', async () => {
    const { publicKey, privateKey } = await generateKyberKeyPair();
    expect(fromHexLocal(publicKey).length).toBe(1184);
    expect(fromHexLocal(privateKey).length).toBe(2400);
  });

  it('ML-DSA-44 keys are 1312 / 2560 bytes', async () => {
    const { publicKey, privateKey } = await generateDilithiumKeyPair();
    expect(fromHexLocal(publicKey).length).toBe(1312);
    expect(fromHexLocal(privateKey).length).toBe(2560);
  });
});

describe('ML-DSA-44 sign/verify', () => {
  it('round-trips and rejects tampering', async () => {
    const { publicKey, privateKey } = await generateDilithiumKeyPair();
    const msg = 'Sign in to Kryptolog with nonce: 0123456789abcdef';
    const sig = await signMessagePQC(msg, privateKey);
    expect(fromHexLocal(sig).length).toBe(2420);
    expect(await verifySignaturePQC(msg, sig, publicKey)).toBe(true);
    expect(await verifySignaturePQC(msg + ' ', sig, publicKey)).toBe(false);
  });

  it('verifies a liboqs-produced signature (server -> client interop)', async () => {
    const ok = await verifySignaturePQC(
      Buffer.from(vec.message, 'hex').toString('utf8'),
      vec.liboqs_dsa_signature,
      vec.liboqs_dsa_publicKey
    );
    expect(ok).toBe(true);
  });

  it('verifySignaturePQC returns false on malformed input instead of throwing', async () => {
    await expect(verifySignaturePQC('x', 'zz', 'zz')).resolves.toBe(false);
  });
});

describe('ML-KEM-768 hybrid envelope round-trips', () => {
  it('encryptMessagePQC -> decryptMessagePQC', async () => {
    const { publicKey, privateKey } = await generateKyberKeyPair();
    const plaintext = 'hello post-quantum world 🛡️';
    const env = await encryptMessagePQC(plaintext, publicKey);
    expect(fromHexLocal(env.kem).length).toBe(1088); // ML-KEM-768 ciphertext
    expect(await decryptMessagePQC(env, privateKey)).toBe(plaintext);
  });

  it('wrapSessionKey -> unwrapSessionKey', async () => {
    const { publicKey, privateKey } = await generateKyberKeyPair();
    const sessionKey = await generateSessionKey();
    const wrapped = await wrapSessionKey(sessionKey, publicKey);
    const unwrapped = await unwrapSessionKey(wrapped, privateKey);
    expect(unwrapped).toBe(sessionKey);
  });
});

describe('domain separation (audit H1)', () => {
  it('login and content contexts produce disjoint signed bytes', () => {
    const body = 'Sign in to Kryptolog with nonce: abc\nEncryption key: xyz';
    const asLogin = domainSeparate(SIGNING_CONTEXT.LOGIN, body);
    const asContent = domainSeparate(SIGNING_CONTEXT.CONTENT, body);
    expect(asLogin).not.toBe(asContent);
    expect(asLogin.startsWith('Kryptolog Signed Message v1\ncontext=login\n')).toBe(true);
    expect(asContent.startsWith('Kryptolog Signed Message v1\ncontext=content\n')).toBe(true);
  });

  it('a content-domain signature does NOT verify as a login challenge', async () => {
    const { publicKey, privateKey } = await generateDilithiumKeyPair();
    // Attacker coerces the victim into approving content that equals a login body.
    const loginBody = 'Sign in to Kryptolog with nonce: 0123456789abcdef\nEncryption key: kem';
    const contentSig = await signMessagePQC(
      domainSeparate(SIGNING_CONTEXT.CONTENT, loginBody), privateKey
    );

    // The harvested signature is valid for the content it covers...
    expect(await verifySignaturePQC(
      domainSeparate(SIGNING_CONTEXT.CONTENT, loginBody), contentSig, publicKey
    )).toBe(true);

    // ...but is NOT a valid signature over the login challenge (replay blocked).
    expect(await verifySignaturePQC(
      domainSeparate(SIGNING_CONTEXT.LOGIN, loginBody), contentSig, publicKey
    )).toBe(false);
    // ...nor over the raw, unwrapped login body (the pre-fix attack target).
    expect(await verifySignaturePQC(loginBody, contentSig, publicKey)).toBe(false);
  });
});

describe('deterministic seeded-keygen byte-pin', () => {
  it('ML-DSA-44 seeded public key matches the committed fixture', () => {
    const k = ml_dsa44.keygen(fromHexLocal(vec.ml_dsa_seed));
    expect(toHex(k.publicKey)).toBe(vec.noble_dsa_publicKey);
  });

  it('ML-KEM-768 seeded public key matches the committed fixture', () => {
    const k = ml_kem768.keygen(fromHexLocal(vec.ml_kem_seed));
    expect(toHex(k.publicKey)).toBe(vec.noble_kem_publicKey);
  });
});
