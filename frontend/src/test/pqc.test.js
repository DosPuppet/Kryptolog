/**
 * The crypto the SPA imports, through its own shim (utils/crypto.js) —
 * crypto-core 4: composite ML-DSA-65 + Ed25519 signatures and X-Wing.
 *
 * The primitives themselves are pinned in crypto-core: the specifications'
 * vectors, the noble <-> OpenSSL fixture in both directions, the seed pins
 * (packages/crypto-core/test/hybrid.test.js and byte-compat.test.js). What is
 * left to check HERE is that the app's view of them is the right one: the
 * shim hands out the hybrid primitives at their sizes, and the app-level
 * properties — envelopes open, domains stay disjoint, approvals bind the
 * ciphertext — hold through it.
 */
import { describe, it, expect } from 'vitest';
import {
  signMessagePQC,
  verifySignature,
  encryptMessagePQC,
  decryptMessagePQC,
  generateSessionKey,
  wrapSessionKey,
  unwrapSessionKey,
  generateEncryptionKeyPair,
  generateIdentityKeyPair,
  generateAccount,
  addressOf,
  domainSeparate,
  SIGNING_CONTEXT,
  sha384Hex,
  multisigApprovalMessage,
  CRYPTO_CORE_VERSION,
} from '../utils/crypto';

const fromHexLocal = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const fromB64Local = (b) => new Uint8Array(Buffer.from(b, 'base64'));

describe('the shim hands out crypto-core 5', () => {
  it('is the 5.0.0 package, not a stale copy', () => {
    expect(CRYPTO_CORE_VERSION).toBe('5.0.0');
  });

  it('composite identity keys: 2049-byte public key, 80-byte seed, 96-hex address', () => {
    const { publicKey, seed } = generateIdentityKeyPair();
    expect(fromHexLocal(publicKey).length).toBe(2049);
    expect(fromHexLocal(seed).length).toBe(80);
    expect(addressOf(publicKey)).toMatch(/^[0-9a-f]{96}$/);
  });

  it('CatKDF encryption keys: 1281-byte public key, 112-byte seed', () => {
    const { publicKey, seed } = generateEncryptionKeyPair();
    expect(fromHexLocal(publicKey).length).toBe(1281);
    expect(fromHexLocal(seed).length).toBe(112);
  });

  it('an account is the same shape in the SPA as everywhere: its id is its address', () => {
    const account = generateAccount('A');
    expect(account.id).toBe(addressOf(account.identity.publicKey));
  });
});

describe('composite sign/verify', () => {
  it('round-trips and rejects tampering', async () => {
    const { publicKey, seed } = generateIdentityKeyPair();
    const msg = 'login-challenge-abc';
    const sig = await signMessagePQC(msg, seed);
    // ML-DSA-65 (3 309) + a DER ECDSA-P384 half (8..104).
    expect(fromB64Local(sig).length).toBeGreaterThanOrEqual(3317);
    expect(fromB64Local(sig).length).toBeLessThanOrEqual(3413);
    expect(await verifySignature(msg, sig, publicKey)).toBe(true);
    expect(await verifySignature(msg + ' ', sig, publicKey)).toBe(false);
  });

  it('verifySignature returns false on malformed input instead of throwing', async () => {
    await expect(verifySignature('x', 'zz', 'zz')).resolves.toBe(false);
  });
});

describe('CatKDF envelopes round-trip', () => {
  it('encryptMessagePQC -> decryptMessagePQC', async () => {
    const { publicKey, seed } = generateEncryptionKeyPair();
    const env = await encryptMessagePQC('hello pqc', publicKey);
    expect(env.alg).toBe('HKDFwSHA384_P384_ML-KEM-768_CatKDF-A256GCM');
    expect(fromB64Local(env.kem).length).toBe(1185);
    expect(await decryptMessagePQC(env, seed)).toBe('hello pqc');
  });

  it('wrapSessionKey -> unwrapSessionKey', async () => {
    const { publicKey, seed } = generateEncryptionKeyPair();
    const sk = await generateSessionKey();
    const wrapped = await wrapSessionKey(sk, publicKey);
    expect(await unwrapSessionKey(wrapped, seed)).toBe(sk);
  });
});

describe('domain separation (audit H1)', () => {
  it('login and content contexts produce disjoint signed bytes', () => {
    const body = 'same-body';
    expect(domainSeparate(SIGNING_CONTEXT.LOGIN, body))
      .not.toBe(domainSeparate(SIGNING_CONTEXT.CONTENT, body));
  });

  it('a content-domain signature does NOT verify as a login challenge', async () => {
    const { publicKey, seed } = generateIdentityKeyPair();
    const body = 'nonce=abc';
    const contentSig = await signMessagePQC(domainSeparate(SIGNING_CONTEXT.CONTENT, body), seed);
    expect(await verifySignature(domainSeparate(SIGNING_CONTEXT.LOGIN, body), contentSig, publicKey)).toBe(false);
  });
});

describe('multisig ciphertext-bound approval (audit M1)', () => {
  it('sha384Hex matches a known vector (interop with Python hashlib)', async () => {
    // echo -n "abc" | sha384sum
    expect(await sha384Hex('abc')).toBe(
      'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'
    );
  });

  it('approval message is distinct from a content signature over the same body', () => {
    const approval = multisigApprovalMessage(1, 2, 'ab'.repeat(48));
    expect(approval.startsWith('Kryptolog Signed Message v1\ncontext=multisig-approval\n')).toBe(true);
    expect(approval).not.toBe(domainSeparate(SIGNING_CONTEXT.CONTENT, 'workflow=1\nsecret=2\nct=' + 'ab'.repeat(48)));
  });

  it('signs sha384(ciphertext) and verifies; rejects a different ciphertext', async () => {
    const { publicKey, seed } = generateIdentityKeyPair();
    const approve = async (ct) => multisigApprovalMessage(7, 9, await sha384Hex(ct));
    const sig = await signMessagePQC(await approve('ciphertext-A'), seed);
    expect(await verifySignature(await approve('ciphertext-A'), sig, publicKey)).toBe(true);
    expect(await verifySignature(await approve('ciphertext-B'), sig, publicKey)).toBe(false);
  });
});
