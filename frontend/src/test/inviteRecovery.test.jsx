/**
 * A refused signup must not strand the identity it already created.
 *
 * Reported as: on an invite-only server, a new user who creates a local vault
 * without a code is rejected — but `vaultService.setup()` has already written
 * the vault to localStorage, because it runs before the server is asked
 * anything. The login screen then offers "Unlock Local Vault", whose path had
 * no invite field and no way to carry a code, so the only way in once the code
 * arrived was to clear localStorage from the browser console.
 *
 * The fix is deliberately non-destructive: the vault holds the user's keys and
 * is the *right* identity — only the server-side registration is missing — so
 * the unlock path carries an invite code rather than the create path rolling
 * the vault back. These drive the real provider against a stubbed server, since
 * the bug lived in the seam between the two.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

const PASSWORD = 'correct horse battery staple';
const CODE = 'INVITE-1234';

const account = {
    name: 'Alice',
    mldsa: { publicKey: 'a'.repeat(64) },
    mlkem: { publicKey: 'b'.repeat(64) },
};
const vault = {
    isLocked: false,
    // The refused signup's leftover: the vault is on the device already.
    hasVault: () => true,
    hasBiometrics: () => false,
    biometricMode: () => null,
    getCacheTTL: () => 0,
    getAccounts: () => [],
    clearKeyCache: vi.fn(),
    hasCachedKey: () => false,
    hasCachedSigningKey: () => false,
    unlock: vi.fn(async () => true),
    setup: vi.fn(async () => account),
    getActiveAccount: () => account,
    sign: vi.fn(async () => 'signature'),
};
vi.mock('../services/vault', () => ({ vaultService: vault }));
vi.mock('../context/ThemeContext', () => ({
    useTheme: () => ({ theme: 'light', toggleTheme: () => { } }),
}));

const { PQCProvider, usePQC } = await import('../context/PQCContext');
const { AuthProvider } = await import('../context/AuthContext');
const Login = (await import('../components/Login')).default;

/**
 * Stub the server. `statuses` is the sequence of answers to the login POST, so
 * a test can say "refuse the first attempt, accept the second".
 */
const stubServer = (...statuses) => {
    const queue = [...statuses];
    global.fetch = vi.fn(async (url) => {
        if (/nonce/i.test(String(url))) return { ok: true, json: async () => ({ nonce: 'n' }) };
        const status = queue.length > 1 ? queue.shift() : queue[0];
        if (status === 200) {
            return { ok: true, json: async () => ({ user: { address: account.mldsa.publicKey }, access_token: 't' }) };
        }
        return { ok: false, status, json: async () => ({ detail: 'An invite code is required' }) };
    });
};

const loginBodies = () =>
    global.fetch.mock.calls
        .filter(([, init]) => init?.method === 'POST')
        .map(([, init]) => JSON.parse(init.body));

beforeEach(() => { vi.clearAllMocks(); delete window.trustkeys; });
afterEach(() => { vi.restoreAllMocks(); });

describe('unlocking a vault the server has never seen', () => {
    let api;
    const mount = async () => {
        function Probe() { api = usePQC(); return null; }
        await act(async () => {
            render(<AuthProvider><PQCProvider><Probe /></PQCProvider></AuthProvider>);
        });
    };

    it('sends the invite code the unlock screen collected', async () => {
        stubServer(200);
        await mount();

        await act(async () => { await api.loginLocalVault(PASSWORD, CODE); });

        expect(loginBodies()[0].invite_code).toBe(CODE);
    });

    it('omits it for an ordinary returning user', async () => {
        stubServer(200);
        await mount();

        await act(async () => { await api.loginLocalVault(PASSWORD); });

        expect(loginBodies()[0].invite_code).toBeUndefined();
    });

    it('tags a 403 so the screen can ask for a code instead of dead-ending', async () => {
        stubServer(403);
        await mount();

        await expect(api.loginLocalVault(PASSWORD)).rejects.toMatchObject({ code: 'INVITE_REQUIRED' });
    });
});

describe('the login screen after a refused signup', () => {
    const inviteField = () => screen.queryByPlaceholderText('Paste your invite code');

    it('asks for a code on the unlock form, and gets the user in with it', async () => {
        stubServer(403, 200);
        render(<MemoryRouter><AuthProvider><PQCProvider><Login /></PQCProvider></AuthProvider></MemoryRouter>);

        // The leftover vault is why this says "Unlock", not "Create".
        fireEvent.click(screen.getByText('Unlock Local Vault'));
        // Before any refusal the returning-user form stays uncluttered.
        expect(inviteField()).toBeNull();

        fireEvent.change(screen.getByPlaceholderText('Enter secure password'), { target: { value: PASSWORD } });
        await act(async () => { fireEvent.click(screen.getByText('Unlock & Connect')); });

        // The modal stays open on an invite field rather than closing or
        // reporting a bare 403 the user can do nothing about.
        expect(inviteField()).not.toBeNull();
        expect(screen.getByText(/invite-only/i)).toBeInTheDocument();

        fireEvent.change(inviteField(), { target: { value: CODE } });
        await act(async () => { fireEvent.click(screen.getByText('Unlock & Connect')); });

        const bodies = loginBodies();
        expect(bodies).toHaveLength(2);
        expect(bodies[1].invite_code).toBe(CODE);
        // Registered at last: the modal closes instead of asking again.
        expect(inviteField()).toBeNull();
    });
});
