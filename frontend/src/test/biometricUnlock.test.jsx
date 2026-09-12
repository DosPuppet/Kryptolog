/**
 * Biometric unlock has to answer for the whole session, not just the login.
 *
 * Reported as "biometric unlock works, but the app asks for the password just
 * after, so it is no use". Two causes, both about how many WebAuthn ceremonies
 * the app starts and when:
 *
 *   1. Logging in ran two ceremonies — one to unlock the vault, a second to
 *      recover the same password for the login-challenge signature.
 *   2. A browser permits ONE outstanding navigator.credentials.get(); an
 *      overlapping call is rejected with NotAllowedError. The app issues custody
 *      calls in parallel by design (own + shared secrets, each batch-decrypting
 *      its titles), so the loser's biometric attempt failed and fell through —
 *      silently — to the password box.
 *
 * The password is deliberately never cached, so these pin the *sharing of a
 * ceremony in flight*, not a stored secret: a fresh operation re-authenticates.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act, screen, fireEvent } from '@testing-library/react';

const PASSWORD = 'correct horse battery staple';

// --- The vault singleton, for the provider-level tests ------------------------
const vault = {
    isLocked: false,
    hasVault: () => true,
    hasBiometrics: () => true,
    biometricMode: () => 'prf',
    getCacheTTL: () => 0,
    getAccounts: () => [],
    clearKeyCache: vi.fn(),
    // "Always ask" is the default TTL, so nothing is ever cached — which is why
    // every operation reaches requestPassword in the first place.
    hasCachedKey: () => false,
    hasCachedSigningKey: () => false,
    unlock: vi.fn(async () => true),
    getActiveAccount: () => ({
        name: 'Alice',
        mldsa: { publicKey: 'a'.repeat(64) },
        mlkem: { publicKey: 'b'.repeat(64) },
    }),
    sign: vi.fn(async () => 'signature'),
    decryptMany: vi.fn(async () => ['plaintext']),
    recoverPasswordWithBiometrics: vi.fn(),
    disableBiometrics: vi.fn(),
};
vi.mock('../services/vault', () => ({ vaultService: vault }));

const { PQCProvider, usePQC } = await import('../context/PQCContext');
const { AuthProvider } = await import('../context/AuthContext');

let api;
function Probe() {
    api = usePQC();
    return null;
}
const mount = async () => {
    await act(async () => {
        render(<AuthProvider><PQCProvider><Probe /></PQCProvider></AuthProvider>);
    });
};

/** Let the mount effect that reads hasBiometrics() settle before acting. */
const settle = () => act(async () => { await Promise.resolve(); });

beforeEach(() => {
    vi.clearAllMocks();
    delete window.trustkeys;
    vault.isLocked = false;
    vault.unlock.mockResolvedValue(true);
    vault.recoverPasswordWithBiometrics.mockResolvedValue(PASSWORD);
    global.fetch = vi.fn(async (url) =>
        /nonce/i.test(String(url))
            ? { ok: true, json: async () => ({ nonce: 'n' }) }
            : { ok: true, json: async () => ({ user: { address: 'a'.repeat(64) }, access_token: 't' }) }
    );
});
afterEach(() => { vi.restoreAllMocks(); });

describe('logging in with biometrics', () => {
    it('asks the authenticator once, not once per thing that needs the password', async () => {
        await mount();
        await settle();
        await act(async () => { await api.unlockWithBiometrics(); });

        expect(vault.recoverPasswordWithBiometrics).toHaveBeenCalledTimes(1);
        // The same recovered password unlocks the vault AND signs the challenge.
        expect(vault.unlock).toHaveBeenCalledWith(PASSWORD);
        expect(vault.sign).toHaveBeenCalledWith(expect.any(String), PASSWORD);
    });

    it('turns itself off when the recovered password no longer opens the vault', async () => {
        // The ceremony WORKED and the vault still said no, so the registration
        // belongs to a vault this device no longer has — replacing a vault used
        // to leave the old registration behind, and the result was a fingerprint
        // button that failed every time and could not be cleared from the login
        // screen. Dropping it is what makes the next attempt reach the password.
        vault.unlock.mockResolvedValue(false);
        await mount();
        await settle();

        await expect(api.unlockWithBiometrics()).rejects.toThrow(/no longer matches this vault/);
        expect(vault.disableBiometrics).toHaveBeenCalledTimes(1);
    });
});

describe('custody operations that start together', () => {
    it('share one ceremony instead of racing the authenticator', async () => {
        await mount();
        await settle();

        // This is the dashboard's own-secrets / shared-secrets pair.
        await act(async () => {
            await Promise.all([api.decryptMany([{}]), api.decryptMany([{}])]);
        });

        expect(vault.recoverPasswordWithBiometrics).toHaveBeenCalledTimes(1);
        expect(vault.decryptMany).toHaveBeenCalledTimes(2);
        // The point of the whole fix: no password box.
        expect(screen.queryByPlaceholderText('Enter Password')).toBeNull();
    });

    it('re-authenticates for a later operation rather than caching the password', async () => {
        await mount();
        await settle();

        await act(async () => { await api.decryptMany([{}]); });
        await act(async () => { await api.decryptMany([{}]); });

        expect(vault.recoverPasswordWithBiometrics).toHaveBeenCalledTimes(2);
    });
});

describe('when the authenticator cannot be used', () => {
    it('falls back to the password box and says why', async () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        vault.recoverPasswordWithBiometrics.mockRejectedValue(new Error('NotAllowedError'));
        await mount();
        await settle();

        let result;
        await act(async () => { result = api.decryptMany([{}]); });
        expect(screen.getByPlaceholderText('Enter Password')).toBeTruthy();
        // Silence here is what made the report undiagnosable.
        expect(warn).toHaveBeenCalledWith(expect.stringMatching(/Biometric/), expect.any(Error));

        await act(async () => {
            fireEvent.change(screen.getByPlaceholderText('Enter Password'), { target: { value: PASSWORD } });
            fireEvent.click(screen.getByText('Confirm'));
            await result;
        });
        expect(vault.decryptMany).toHaveBeenCalledWith([{}], PASSWORD);
    });

    it('answers two waiting operations with one prompt', async () => {
        // The modal holds a single resolve/reject pair, so the second request
        // used to overwrite the first and leave it pending forever.
        vault.recoverPasswordWithBiometrics.mockRejectedValue(new Error('no authenticator'));
        vi.spyOn(console, 'warn').mockImplementation(() => {});
        await mount();
        await settle();

        let first, second;
        await act(async () => {
            first = api.decryptMany([{ a: 1 }]);
            second = api.decryptMany([{ b: 2 }]);
        });
        expect(screen.getAllByPlaceholderText('Enter Password')).toHaveLength(1);

        await act(async () => {
            fireEvent.change(screen.getByPlaceholderText('Enter Password'), { target: { value: PASSWORD } });
            fireEvent.click(screen.getByText('Confirm'));
        });

        await expect(first).resolves.toEqual(['plaintext']);
        await expect(second).resolves.toEqual(['plaintext']);
        expect(vault.decryptMany).toHaveBeenNthCalledWith(1, [{ a: 1 }], PASSWORD);
        expect(vault.decryptMany).toHaveBeenNthCalledWith(2, [{ b: 2 }], PASSWORD);
    });
});
