/**
 * Replacing one's own encryption key, driven through the real provider
 * (crypto-core 5.1.0): rotate on the device, publish, and move everything the
 * account holds onto the new key — undoing the local rotation only when the
 * server REFUSED it, never when it may have taken it.
 *
 * The custodian is a stand-in for TrustKeys over a real crypto-core account,
 * so what is re-wrapped is real: the test opens it afterwards with the new key.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act } from '@testing-library/react';
import {
    generateAccount, rotateAccountEncryptionKey, revertAccountEncryptionKeyRotation, encryptionSeedFor,
    encryptMessage, decryptMessage, wrapSessionKey, unwrapSessionKey, generateSessionKey, generateSymmetricKey,
} from '../utils/crypto';

vi.mock('../services/vault', () => ({
    vaultService: {
        isLocked: true, hasBiometrics: () => false, biometricMode: () => null, hasVault: () => false,
        clearKeyCache: vi.fn(), getCacheTTL: () => 0, getAccounts: () => [], getActiveAccount: () => null,
    },
}));

const { PQCProvider, usePQC } = await import('../context/PQCContext');
const { AuthProvider } = await import('../context/AuthContext');

let api;
function Probe() {
    api = usePQC();
    return null;
}

let account; // what the stand-in custodian holds
let rows; // what the server holds: { kind, id, encrypted_key }
let rotateAnswer; // how the server answers POST …/rotate

const custodian = () => ({
    rotateEncryptionKey: vi.fn(async ({ ts }) => {
        const before = account;
        account = rotateAccountEncryptionKey(account, ts);
        return {
            encryptionPublicKey: account.encryption.publicKey,
            oldKid: before.encryption.kid, newKid: account.encryption.kid,
            attestation: 'attestation', signature: 'rotation-signature',
        };
    }),
    revertEncryptionKeyRotation: vi.fn(async ({ newKid }) => {
        account = revertAccountEncryptionKeyRotation(account, newKid);
    }),
    // As the extension does: per item, a failure (a key it does not hold) is null.
    unwrapManySessionKeys: vi.fn(async (wraps) => Promise.all(wraps.map(async (w) => {
        try { return await unwrapSessionKey(w, encryptionSeedFor(account, w)); } catch { return null; }
    }))),
    decryptMany: vi.fn(async (items) => Promise.all(items.map(async (e) => {
        try { return await decryptMessage(e, encryptionSeedFor(account, e)); } catch { return null; }
    }))),
    wrapSessionKey: (key, pk) => wrapSessionKey(key, pk),
    encrypt: (content, pk) => encryptMessage(content, pk),
});

const server = () => vi.fn(async (url, init = {}) => {
    const u = String(url);
    if (u.endsWith('/account/encryption-key/rotate')) return rotateAnswer();
    if (u.includes('/account/encryption-key/stale-wraps')) {
        const params = new URL(u).searchParams;
        const current = account.encryption.kid;
        const stale = rows.filter((r) => JSON.parse(r.encrypted_key).kid !== current);
        const offset = Number(params.get('offset'));
        return { ok: true, status: 200, json: async () => stale.slice(offset, offset + Number(params.get('limit'))) };
    }
    if (u.endsWith('/account/encryption-key/wraps') && init.method === 'PUT') {
        for (const item of JSON.parse(init.body).items) {
            rows.find((r) => r.kind === item.kind && r.id === item.id).encrypted_key = item.encrypted_key;
        }
        return { ok: true, status: 200, json: async () => ({}) };
    }
    return { ok: true, status: 200, json: async () => [] };
});

beforeEach(async () => {
    account = generateAccount('Bob');
    const stranger = generateAccount('Nobody');
    const fileKey = await generateSymmetricKey();
    const sessionKey = await generateSessionKey();
    rows = [
        { kind: 'grant', id: 1, encrypted_key: JSON.stringify(await encryptMessage(fileKey, account.encryption.publicKey)) },
        { kind: 'signer', id: 2, encrypted_key: JSON.stringify(await wrapSessionKey(sessionKey, account.encryption.publicKey)) },
        // Sealed to a key this device does not have: stepped past, never resealed.
        { kind: 'recipient', id: 3, encrypted_key: JSON.stringify(await encryptMessage(fileKey, stranger.encryption.publicKey)) },
    ];
    rows.fileKey = fileKey;
    rows.sessionKey = sessionKey;
    rotateAnswer = async () => ({
        ok: true, status: 200, json: async () => ({ address: account.id, encryption_public_key: account.encryption.publicKey }),
    });
    window.trustkeys = custodian();
    global.fetch = server();
    await act(async () => { render(<AuthProvider><PQCProvider><Probe /></PQCProvider></AuthProvider>); });
});

afterEach(() => { delete window.trustkeys; });

describe('rotating the encryption key', () => {
    it('publishes the new key and moves both shapes of held key onto it', async () => {
        const original = account.encryption;
        let result;
        await act(async () => { result = await api.rotateEncryptionKey(); });
        expect(result).toMatchObject({ rewrapped: 2, unreadable: 1, newKid: account.encryption.kid });
        expect(account.encryption.kid).not.toBe(original.kid);
        expect(api.ownEncryptionKey).toBe(account.encryption.publicKey);

        const [grant, signer, recipient] = rows.map((r) => JSON.parse(r.encrypted_key));
        expect([grant.kid, signer.kid]).toEqual([account.encryption.kid, account.encryption.kid]);
        // Opened with the NEW key's seed, to the same keys as before.
        expect(await decryptMessage(grant, account.encryption.seed)).toBe(rows.fileKey);
        expect(await unwrapSessionKey(signer, account.encryption.seed)).toBe(rows.sessionKey);
        expect('content' in grant && 'encKey' in signer).toBe(true); // shapes kept
        expect(recipient.kid).not.toBe(account.encryption.kid); // left as it was
        // The old key is retired, not gone.
        expect(account.retiredEncryption.map((k) => k.kid)).toEqual([original.kid]);
    });

    it('undoes the local rotation when the server refuses it', async () => {
        const original = account.encryption.kid;
        rotateAnswer = async () => ({ ok: false, status: 400, json: async () => ({ detail: 'Invalid encryption key attestation.' }) });
        await act(async () => {
            await expect(api.rotateEncryptionKey()).rejects.toThrow(/refused the new key: Invalid encryption key attestation/);
        });
        expect(window.trustkeys.revertEncryptionKeyRotation).toHaveBeenCalledTimes(1);
        expect(account.encryption.kid).toBe(original);
        // The refused key is kept retired, never dropped.
        expect(account.retiredEncryption).toHaveLength(1);
        expect(account.retiredEncryption[0].kid).not.toBe(original);
    });

    it.each([
        ['a network failure', async () => { throw new TypeError('Failed to fetch'); }],
        ['a server error', async () => ({ ok: false, status: 502, json: async () => ({ detail: 'Bad gateway' }) })],
    ])('keeps the new key after %s — the server may have taken it', async (_, answer) => {
        rotateAnswer = answer;
        await act(async () => {
            await expect(api.rotateEncryptionKey()).rejects.toThrow(/Sign in again to publish it/);
        });
        expect(window.trustkeys.revertEncryptionKeyRotation).not.toHaveBeenCalled();
        expect(account.retiredEncryption).toHaveLength(1);
    });
});
