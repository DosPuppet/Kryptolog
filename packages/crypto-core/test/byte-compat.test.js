// Cross-build byte-compatibility suite for @kryptolog/crypto-core.
//
// This file REPLACES the old "SHARED CRYPTO CORE — KEEP IN SYNC" comment that
// used to live (twice) in the apps' crypto.js. There is now one source of truth,
// so byte-compatibility between the SPA build and the extension build is
// structural; this suite is the executable contract that pins the wire/storage
// formats so an accidental change fails CI instead of silently breaking interop.
//
// It guards three things:
//   1. Golden constants — the exact format strings / KDF params the wire depends on.
//   2. Round-trips — every randomized envelope decodes back to its input.
//   3. Server interop — ML-DSA (FIPS 204) keygen/sign/verify byte encoding, which
//      the backend's liboqs must keep matching (see backend/tests/test_pqc.py).
//   4. Single-source guard — both apps resolve the SAME CRYPTO_CORE_VERSION.
import { describe, it, expect } from 'vitest';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';
import * as core from '../src/index.js';

const enc = (s) => new TextEncoder().encode(s);

describe('golden constants (wire/storage format contract)', () => {
    it('domain-separation header + message prefix are byte-exact', () => {
        expect(core.MESSAGE_SIGNING_PREFIX).toBe('Kryptolog Signed Message v1\ncontext=message\n');
        expect(core.domainSeparate('login', 'abc')).toBe('Kryptolog Signed Message v1\ncontext=login\nabc');
        expect(core.SIGNING_CONTEXT).toEqual({
            LOGIN: 'login',
            CONTENT: 'content',
            MULTISIG_APPROVAL: 'multisig-approval',
            MESSAGE: 'message',
        });
    });

    it('message signing body is byte-exact', () => {
        expect(core.messageSigningBody({ from: 'A', conv: 'B', sid: 'S', ct: 'C' }))
            .toBe('Kryptolog Signed Message v1\ncontext=message\nfrom=A\nconv=B\nsid=S\nct=C');
    });

    it('message signing body binds the ciphertext object canonically (not "[object Object]")', () => {
        // Production passes the AES-GCM envelope object, not a string. The signed
        // bytes must commit to the actual iv+content so a same-session ciphertext
        // cannot be swapped under a valid signature.
        expect(core.messageSigningBody({ from: 'A', conv: 'B', sid: 'S', ct: { iv: '00', content: 'ff' } }))
            .toBe('Kryptolog Signed Message v1\ncontext=message\nfrom=A\nconv=B\nsid=S\nct=00.ff');
        // Different ciphertext => different signed bytes.
        expect(core.messageSigningBody({ from: 'A', conv: 'B', sid: 'S', ct: { iv: '00', content: 'ee' } }))
            .not.toBe(core.messageSigningBody({ from: 'A', conv: 'B', sid: 'S', ct: { iv: '00', content: 'ff' } }));
    });

    it('multisig approval message matches the server format', () => {
        expect(core.multisigApprovalMessage('wf1', 'sec1', 'deadbeef'))
            .toBe('Kryptolog Signed Message v1\ncontext=multisig-approval\nworkflow=wf1\nsecret=sec1\nct=deadbeef');
    });

    it('sha256Hex matches Python hashlib.sha256().hexdigest()', async () => {
        // echo -n "kryptolog" | sha256sum
        expect(await core.sha256Hex('kryptolog'))
            .toBe(createHash('sha256').update('kryptolog').digest('hex'));
    });

    it('hex round-trips bytes', () => {
        const bytes = new Uint8Array([0, 1, 254, 255]);
        expect(core.toHex(bytes)).toBe('0001feff');
        expect(Array.from(core.fromHex('0001feff'))).toEqual([0, 1, 254, 255]);
    });
});

describe('randomized envelope round-trips', () => {
    it('KEM message envelope: encrypt -> decrypt', async () => {
        const { publicKey, privateKey } = await core.generateKyberKeyPair();
        const env = await core.encryptMessage('secret payload', publicKey);
        expect(env).toHaveProperty('kem');
        expect(env).toHaveProperty('iv');
        expect(env).toHaveProperty('content');
        expect(await core.decryptMessage(env, privateKey)).toBe('secret payload');
    });

    it('session-key wrap -> unwrap, then encrypt/decrypt under it', async () => {
        const { publicKey, privateKey } = await core.generateKyberKeyPair();
        const sessionKey = await core.generateSessionKey();
        const wrapped = await core.wrapSessionKey(sessionKey, publicKey);
        expect(wrapped).toHaveProperty('encKey');
        expect(await core.unwrapSessionKey(wrapped, privateKey)).toBe(sessionKey);

        const ct = await core.encryptWithSessionKey('hello', sessionKey);
        expect(await core.decryptWithSessionKey(ct, sessionKey)).toBe('hello');
    });

    it('unwrapSessionKey still accepts the legacy {ct} field name', async () => {
        const { publicKey, privateKey } = await core.generateKyberKeyPair();
        const sessionKey = await core.generateSessionKey();
        const { kem, iv, encKey } = await core.wrapSessionKey(sessionKey, publicKey);
        const legacy = { kem, iv, ct: encKey }; // pre-standardization shape
        expect(await core.unwrapSessionKey(legacy, privateKey)).toBe(sessionKey);
    });

    it('symmetric envelope: encrypt -> decrypt', async () => {
        const key = await core.generateSymmetricKey();
        const env = await core.encryptSymmetric('plaintext', key);
        expect(await core.decryptSymmetric(env, key)).toBe('plaintext');
    });

    it('binary chunk: encrypt -> decrypt', async () => {
        const key = await core.generateSymmetricKey();
        const chunk = new Uint8Array([5, 6, 7, 8, 9]);
        const { iv, ciphertext } = await core.encryptChunk(chunk, key);
        const out = await core.decryptChunk(iv, ciphertext, key);
        expect(Array.from(out)).toEqual([5, 6, 7, 8, 9]);
    });

    it('vault: password encrypt -> decrypt (PBKDF2 600k / SHA-512)', async () => {
        const vault = await core.encryptVault({ a: 1, b: 'two' }, 'hunter2');
        expect(vault).toHaveProperty('salt');
        expect(vault).toHaveProperty('iv');
        expect(vault).toHaveProperty('data');
        expect(await core.decryptVault(vault, 'hunter2')).toEqual({ a: 1, b: 'two' });
        await expect(core.decryptVault(vault, 'wrong')).rejects.toThrow();
    });

    it('vault: pre-derived key encrypt -> decrypt', async () => {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const key = await core.deriveKey('pw', salt);
        const vault = await core.encryptVaultWithKey({ x: 9 }, key, salt);
        expect(await core.decryptVaultWithKey(vault, key)).toEqual({ x: 9 });
    });
});

describe('ML-DSA server-interop guard (FIPS 204 byte encoding)', () => {
    // The backend verifies client login/multisig signatures with liboqs ML-DSA-44.
    // noble and liboqs both emit FIPS 204 encodings; this pins noble's so a silent
    // upstream change can't break that cross-lib agreement. Seeded keygen is
    // deterministic, so the public-key bytes are a stable golden vector.
    const SEED = new Uint8Array(32).fill(7);
    const GOLDEN_PK_SHA256 = '86c769d3b468de487eb9a09f242f7fa0b997a07ef4ded49627e7bf9539f28b62';

    it('seeded keygen produces the pinned public-key bytes', () => {
        const { publicKey } = ml_dsa44.keygen(SEED);
        expect(createHash('sha256').update(Buffer.from(publicKey)).digest('hex')).toBe(GOLDEN_PK_SHA256);
    });

    it('signMessage -> verifySignature round-trips, exact-match only (audit H4)', async () => {
        const { publicKey, secretKey } = ml_dsa44.keygen(SEED);
        const pkHex = core.toHex(publicKey);
        const skHex = core.toHex(secretKey);
        const sig = await core.signMessage('login-challenge-123', skHex);
        expect(await core.verifySignature('login-challenge-123', sig, pkHex)).toBe(true);
        // A different message must NOT verify against the same signature.
        expect(await core.verifySignature('login-challenge-124', sig, pkHex)).toBe(false);
    });
});

describe('single-source / version guard', () => {
    it('exports a version both app builds can assert against', () => {
        expect(core.CRYPTO_CORE_VERSION).toBe('1.1.0');
    });
});
