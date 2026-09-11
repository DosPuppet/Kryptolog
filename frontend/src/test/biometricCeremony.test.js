/**
 * One WebAuthn ceremony at a time.
 *
 * A browser permits a single outstanding navigator.credentials.get(): a second
 * overlapping call is rejected with NotAllowedError ("a request is already
 * pending"). The app starts custody operations in parallel by design, and every
 * biometric failure degrades to the password box, so the browser's own
 * concurrency rule was reaching the user as "biometrics doesn't work".
 *
 * The authenticator is modelled here with that rule, because a mock that
 * happily answers two ceremonies at once would pass with or without the fix.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const crypto = vi.hoisted(() => ({
    getBiometricKey: vi.fn(),
    decryptSymmetric: vi.fn(),
}));
vi.mock('../utils/crypto', () => crypto);

const { biometricMethods } = await import('../services/vaultBiometrics');

const PASSWORD = 'correct horse battery staple';
const PREFS = {
    mode: 'prf',
    credentialId: 'Y3JlZA',
    encryptedPass: { iv: 'aXY=', content: 'Y3Q=' },
    prfSalt: 'ab'.repeat(32),
};

/** The singleton these methods are merged onto (see services/vault.js). */
let vault;
/** Ceremonies currently open on the authenticator — must never exceed one. */
let open;
let overlapped;

beforeEach(() => {
    vi.clearAllMocks();
    localStorage.setItem('kryptolog_biometrics', JSON.stringify(PREFS));
    vault = { _bioInFlight: null, ...biometricMethods };
    open = 0;
    overlapped = false;

    crypto.getBiometricKey.mockImplementation(async () => {
        if (open > 0) {
            overlapped = true;
            throw new Error('NotAllowedError: a request is already pending');
        }
        open++;
        try {
            await new Promise(r => setTimeout(r, 0));
            return 'ab'.repeat(32);
        } finally {
            open--;
        }
    });
    crypto.decryptSymmetric.mockResolvedValue(PASSWORD);
});

describe('recoverPasswordWithBiometrics', () => {
    it('serves concurrent callers from one ceremony', async () => {
        const results = await Promise.all([
            vault.recoverPasswordWithBiometrics(),
            vault.recoverPasswordWithBiometrics(),
            vault.recoverPasswordWithBiometrics(),
        ]);

        expect(results).toEqual([PASSWORD, PASSWORD, PASSWORD]);
        expect(overlapped, 'two ceremonies overlapped on the authenticator').toBe(false);
        expect(crypto.getBiometricKey).toHaveBeenCalledTimes(1);
    });

    it('starts a fresh ceremony for a later call — nothing is cached', async () => {
        await vault.recoverPasswordWithBiometrics();
        await vault.recoverPasswordWithBiometrics();

        expect(crypto.getBiometricKey).toHaveBeenCalledTimes(2);
        // The recovered password must not outlive the ceremony that produced it.
        expect(vault._bioInFlight).toBeNull();
    });

    it('does not leave a failed ceremony latched in place', async () => {
        crypto.getBiometricKey.mockRejectedValueOnce(new Error('user cancelled'));
        await expect(vault.recoverPasswordWithBiometrics()).rejects.toThrow(/cancelled/);

        // A cancel must not poison every later attempt with the same rejection.
        await expect(vault.recoverPasswordWithBiometrics()).resolves.toBe(PASSWORD);
    });

    it('refuses when biometrics were never set up', async () => {
        localStorage.removeItem('kryptolog_biometrics');
        await expect(vault.recoverPasswordWithBiometrics()).rejects.toThrow(/not set up/i);
        expect(crypto.getBiometricKey).not.toHaveBeenCalled();
    });
});
