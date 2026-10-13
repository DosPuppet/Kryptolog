/**
 * Which key custodian each PQC operation reaches for.
 *
 * The provider serves the same nine operations from two places — the TrustKeys
 * extension, or an unlocked local vault — and must refuse when neither is
 * available. That choice used to be nine copies of one if/else-if/throw; it is
 * now one factory, so it is worth pinning that the factory routes the same way
 * the copies did, and that the local-vault path still asks for a password
 * exactly when it used to.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act } from '@testing-library/react';

const vault = {
    isLocked: true,
    hasBiometrics: () => false,
    biometricMode: () => null,
    hasVault: () => false,
    clearKeyCache: vi.fn(),
    getCacheTTL: () => 0,
    getAccounts: () => [],
    generateSessionKey: vi.fn(async () => 'vault-session-key'),
    sign: vi.fn(async () => 'vault-signature'),
    signMessage: vi.fn(async () => 'vault-message-signature'),
    hasCachedSigningKey: vi.fn(() => false),
    decryptMany: vi.fn(async () => ['vault-plaintext']),
    unwrapManySessionKeys: vi.fn(async () => ['vault-unwrapped']),
    importEncryptedBlob: vi.fn(async () => ({
        name: 'Moved', mldsa: { publicKey: 'aa'.repeat(16) }, mlkem: { publicKey: 'bb'.repeat(16) },
    })),
};

vi.mock('../services/vault', () => ({ vaultService: vault }));

const { PQCProvider, usePQC } = await import('../context/PQCContext');
const { AuthProvider } = await import('../context/AuthContext');

let api;
function Probe() {
    api = usePQC();
    return null;
}

const mount = () => act(() => {
    render(<AuthProvider><PQCProvider><Probe /></PQCProvider></AuthProvider>);
});

beforeEach(() => {
    vault.isLocked = true;
    vault.hasCachedSigningKey.mockReturnValue(false);
    vi.clearAllMocks();
    delete window.trustkeys;
});
afterEach(() => { delete window.trustkeys; });

describe('with neither custodian available', () => {
    it('refuses rather than silently doing nothing', async () => {
        mount();
        await expect(api.generateSessionKey()).rejects.toThrow(/not ready/i);
        await expect(api.sign('x')).rejects.toThrow(/not ready/i);
        await expect(api.decryptMany([{}])).rejects.toThrow(/not ready/i);
    });
});

describe('with an unlocked local vault', () => {
    beforeEach(() => { vault.isLocked = false; });

    it('serves an operation that needs no private key without prompting', async () => {
        mount();
        await expect(api.generateSessionKey()).resolves.toBe('vault-session-key');
        expect(vault.generateSessionKey).toHaveBeenCalled();
    });

    it('skips the password prompt once the signing key is cached', async () => {
        // This is what keeps per-message chat signing silent (audit S1).
        vault.hasCachedSigningKey.mockReturnValue(true);
        mount();
        await expect(api.signMessage('body')).resolves.toBe('vault-message-signature');
        expect(vault.signMessage).toHaveBeenCalledWith('body', undefined);
    });
});

describe('with the extension present', () => {
    beforeEach(() => {
        vault.isLocked = false; // the extension must still win
        window.trustkeys = {
            generateSessionKey: vi.fn(async () => 'ext-session-key'),
            sign: vi.fn(async () => 'ext-signature'),
            decrypt: vi.fn(async () => 'ext-plaintext'),
            unwrapSessionKey: vi.fn(async () => 'ext-unwrapped'),
        };
    });

    it('prefers the extension over an unlocked vault', async () => {
        mount();
        await expect(api.generateSessionKey()).resolves.toBe('ext-session-key');
        expect(vault.generateSessionKey).not.toHaveBeenCalled();
    });

    it('falls back per key when the extension has no batch unwrap', async () => {
        // Older extensions lack unwrapManySessionKeys; the batch must still work.
        mount();
        await expect(api.unwrapManySessionKeys(['a', 'b'])).resolves.toEqual(
            ['ext-unwrapped', 'ext-unwrapped']
        );
        expect(window.trustkeys.unwrapSessionKey).toHaveBeenCalledTimes(2);
    });

    it('signs chat messages only through signMessage, never the generic sign()', async () => {
        // sign() refuses message bodies since crypto-core 3.0.0 (K-03).
        window.trustkeys.signMessage = vi.fn(async () => 'ext-message-signature');
        mount();
        await expect(api.signMessage('body')).resolves.toBe('ext-message-signature');
        expect(window.trustkeys.sign).not.toHaveBeenCalled();
    });

    it('approves a workflow through the typed API, with fields and not a body', async () => {
        // The extension builds the approval body itself and names the
        // workflow in its window (audit 2026-10-12 K-03).
        window.trustkeys.signMultisigApproval = vi.fn(async () => 'ext-approval');
        mount();
        const fields = { workflowId: 7, secretId: 42, ciphertextSha256: 'ab'.repeat(32) };
        await expect(api.signApproval(fields)).resolves.toBe('ext-approval');
        expect(window.trustkeys.signMultisigApproval).toHaveBeenCalledWith(fields);
        expect(window.trustkeys.sign).not.toHaveBeenCalled();
    });

    it('keeps the rest of a batch when one item fails to decrypt', async () => {
        window.trustkeys.decrypt = vi.fn()
            .mockResolvedValueOnce('first')
            .mockRejectedValueOnce(new Error('bad'))
            .mockResolvedValueOnce('third');
        mount();
        await expect(api.decryptMany([{}, {}, {}])).resolves.toEqual(
            ['first', 'Error: Decryption Failed', 'third']
        );
    });
});

describe('receiving a vault from another device', () => {
    // It signed the login body's FIELDS ("[object Object]") and sent no
    // attestation, so the server refused it after the vault was already
    // written: a device transfer could never finish signing in.
    it('signs the real login challenge and attests the encryption key', async () => {
        const posted = [];
        global.fetch = vi.fn(async (url, init = {}) => {
            if (String(url).includes('/auth/nonce/')) {
                return { ok: true, json: async () => ({ nonce: 'ab12', deployment: 'dev' }) };
            }
            posted.push(JSON.parse(init.body));
            return { ok: true, json: async () => ({ access_token: 'tok', user: { address: 'aa'.repeat(16) } }) };
        });
        await mount();
        await act(async () => { await api.receiveVault('{}', 'transfer-pass', 'new local password'); });

        const signed = vault.sign.mock.calls.map(([body]) => body);
        expect(signed.some((b) => typeof b === 'string' && b.includes('\ncontext=login\n'))).toBe(true);
        expect(signed.some((b) => typeof b === 'string' && b.includes('\ncontext=key-attestation\n'))).toBe(true);
        expect(signed.every((b) => typeof b === 'string')).toBe(true);
        expect(posted[0]).toMatchObject({
            signature: 'vault-signature', encryption_key_attestation: 'vault-signature',
        });
    });
});

