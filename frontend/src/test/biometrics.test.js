// Biometric vault unlock (WebAuthn PRF), against a mocked authenticator.
//
// This path had no coverage at all, and it broke: the crypto-core module split
// left webauthn.js calling toHex/fromHex without importing them, so every
// biometric path threw `ReferenceError: fromHex is not defined` before it ever
// reached the authenticator. Nobody noticed because the module needs `window`,
// which put it outside both test suites.
//
// A mock cannot prove a fingerprint reader works. What it can prove is the part
// that actually broke — the wiring and the encodings on either side of the
// authenticator call — and that is what these cover. The hardware behaviour
// stays a manual step (E2E-RECIPE.md).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
    registerBiometricCredential,
    getBiometricKey,
    checkPrfSupport,
    encryptSymmetric,
    decryptSymmetric,
} from '../utils/crypto';

const CREDENTIAL_ID = 'AQIDBAUGBwgJCgsM'; // base64url, as a real credential id is

// A PRF authenticator derives its output from the salt it is given, and returns
// the same bytes for the same salt. SHA-256 stands in for that: it makes
// register and authenticate agree, which is the property the round-trip needs.
//
// getClientExtensionResults() is synchronous in the real API, so the digest is
// computed inside the async create/get call and closed over.
const prfFor = (saltBytes) => crypto.subtle.digest('SHA-256', saltBytes);

/** Install a mock authenticator. `prf: false` models a device without PRF. */
const installAuthenticator = ({ prf = true } = {}) => {
    const respond = async (opts) => {
        const salt = new Uint8Array(opts.publicKey.extensions.prf.eval.first);
        const results = prf ? { prf: { results: { first: await prfFor(salt) } } } : {};
        return { id: CREDENTIAL_ID, getClientExtensionResults: () => results };
    };
    const credentials = { create: vi.fn(respond), get: vi.fn(respond) };
    Object.defineProperty(window, 'PublicKeyCredential', {
        value: function PublicKeyCredential() {}, configurable: true, writable: true,
    });
    Object.defineProperty(window.navigator, 'credentials', {
        value: credentials, configurable: true, writable: true,
    });
    return credentials;
};

describe('biometric vault unlock (WebAuthn PRF)', () => {
    let credentials;

    beforeEach(() => {
        credentials = installAuthenticator();
        localStorage.clear();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('registers a credential and returns hex key material', async () => {
        const result = await registerBiometricCredential('Alice');

        expect(result.mode).toBe('prf');
        expect(result.credentialId).toBe(CREDENTIAL_ID);
        // Key HANDLES stay hex through the L-12 cutover — they are in-memory
        // values, not wire or storage values.
        expect(result.prfKey).toMatch(/^[0-9a-f]{64}$/);   // 32-byte AES key
        expect(result.prfSalt).toMatch(/^[0-9a-f]{64}$/);  // 32-byte PRF salt
    });

    it('asks for a platform authenticator with user verification', async () => {
        // 'platform' is what keeps the prompt on the device's own biometrics
        // instead of opening the cross-device Bluetooth/QR picker.
        await registerBiometricCredential('Alice');
        const opts = credentials.create.mock.calls[0][0].publicKey;
        expect(opts.authenticatorSelection.authenticatorAttachment).toBe('platform');
        expect(opts.authenticatorSelection.userVerification).toBe('required');
        expect(opts.extensions.prf.eval.first).toBeInstanceOf(Uint8Array);
    });

    it('re-derives the same key from the stored salt', async () => {
        // The whole point: the key is never stored, it is re-derived from the
        // hardware on each unlock.
        const { prfKey, prfSalt, credentialId } = await registerBiometricCredential('Alice');
        expect(await getBiometricKey(credentialId, prfSalt, 'prf')).toBe(prfKey);
    });

    it('round-trips the vault password, which is the actual unlock path', async () => {
        // enableBiometrics encrypts the password under the PRF key;
        // recoverPasswordWithBiometrics re-derives the key and decrypts it.
        const password = 'correct horse battery staple';
        const { prfKey, prfSalt, credentialId } = await registerBiometricCredential('Alice');

        const encryptedPass = await encryptSymmetric(password, prfKey);
        // The ENVELOPE is base64 while the key stays hex — the L-12 split, on
        // the one path where both meet.
        expect(encryptedPass.iv).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
        expect(encryptedPass.ciphertext).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);

        const rederived = await getBiometricKey(credentialId, prfSalt, 'prf');
        expect(await decryptSymmetric(encryptedPass, rederived)).toBe(password);
    });

    it('refuses a different salt, so the stored salt is load-bearing', async () => {
        const password = 'correct horse battery staple';
        const { prfKey, credentialId } = await registerBiometricCredential('Alice');
        const encryptedPass = await encryptSymmetric(password, prfKey);

        const otherSalt = 'ab'.repeat(32);
        const wrongKey = await getBiometricKey(credentialId, otherSalt, 'prf');

        expect(wrongKey).not.toBe(prfKey);
        await expect(decryptSymmetric(encryptedPass, wrongKey)).rejects.toThrow();
    });

    it('refuses a device with no hardware-bound PRF instead of falling back', async () => {
        // There is deliberately no software fallback: a non-hardware-bound key
        // would have to live in JS-readable storage, which defeats the vault's
        // at-rest encryption. The message must be the documented one — a
        // ReferenceError here is the bug this file exists for.
        installAuthenticator({ prf: false });
        await expect(registerBiometricCredential('Alice'))
            .rejects.toThrow(/hardware-bound biometric keys/i);
    });

    it('refuses a legacy fallback credential', async () => {
        await expect(getBiometricKey(CREDENTIAL_ID, 'ab'.repeat(32), 'fallback'))
            .rejects.toThrow(/legacy mode/i);
    });

    it('reports PRF support only when WebAuthn exists', async () => {
        expect(await checkPrfSupport()).toBe(true);
        Object.defineProperty(window, 'PublicKeyCredential', {
            value: undefined, configurable: true, writable: true,
        });
        expect(await checkPrfSupport()).toBe(false);
    });
});
