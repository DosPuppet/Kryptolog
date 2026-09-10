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

    it('falls back to sign() when the extension has no silent signMessage', async () => {
        mount();
        await expect(api.signMessage('body')).resolves.toBe('ext-signature');
        expect(window.trustkeys.sign).toHaveBeenCalledWith('body');
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
