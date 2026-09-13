/**
 * Two ways a session can end from the OUTSIDE, and what the app does about it.
 *
 * Deleting an account kills every session it has, on every device. The server
 * does its part — it bumps token_version, closes the sockets it holds, and
 * fans out a reserved ACCOUNT_DELETED frame — but a tab that ignores all of
 * that carries on showing the account's conversations and secrets until
 * something makes it reload (audit 2026-09-12 I-4).
 *
 * Both paths matter, and neither covers the other. A worker on the PREVIOUS
 * build delivers ACCOUNT_DELETED as an ordinary message and never closes the
 * socket, so the frame has to mean something on its own during a rolling
 * restart. And a tab that is idle when the account goes never sees a frame at
 * all — it finds out on its next request, as a 401.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act } from '@testing-library/react';
import { useRef } from 'react';

vi.mock('../services/vault', () => ({
    vaultService: {
        isLocked: true, hasBiometrics: () => false, biometricMode: () => null,
        hasVault: () => false, getAccounts: () => [], clearKeyCache: vi.fn(),
        getCacheTTL: () => 0,
    },
}));

const { MessengerProvider } = await import('../context/MessengerContext');
const { AuthProvider, useAuth } = await import('../context/AuthContext');
const { PQCProvider } = await import('../context/PQCContext');
const { apiFetch } = await import('../services/api');

const ME = 'a'.repeat(64);

let auth;
function Probe() {
    auth = useAuth();
    // ONCE. Signing in whenever isAuthenticated is false would put the session
    // straight back on the next render, which is the thing under test here.
    const signedIn = useRef(false);
    if (!signedIn.current) {
        signedIn.current = true;
        auth.login({ username: 'A', address: ME }, 'vault', 'tok');
    }
    return null;
}

/** The socket the provider opened, so a test can push a frame down it. */
let socket;

const mount = async () => {
    await act(async () => {
        render(
            <AuthProvider><PQCProvider><MessengerProvider>
                <Probe />
            </MessengerProvider></PQCProvider></AuthProvider>
        );
    });
};

const deliver = async (frame) => {
    await act(async () => {
        await socket.onmessage({ data: JSON.stringify(frame) });
        await Promise.resolve();
    });
};

beforeEach(() => {
    global.fetch = vi.fn(async () => ({ ok: true, status: 200, json: async () => [] }));
    global.WebSocket = class {
        constructor() { this.readyState = 0; socket = this; }
        close() {}
        send() {}
        addEventListener() {}
    };
});
afterEach(() => { vi.restoreAllMocks(); });

describe('the account is deleted while a tab is open', () => {
    it('signs out on the hangup frame', async () => {
        await mount();
        expect(auth.isAuthenticated).toBe(true);

        await deliver({ type: 'ACCOUNT_DELETED' });

        // Not "the socket closed" — that happens too, and a worker on the
        // previous build does not do it. The frame has to be enough by itself.
        expect(auth.isAuthenticated).toBe(false);
        expect(auth.token).toBeNull();
    });

    it('ignores it for any other frame type', async () => {
        await mount();
        await deliver({ type: 'SECRET_SHARED', data: {} });
        expect(auth.isAuthenticated).toBe(true);
    });
});

describe('a request comes back 401', () => {
    it('ends the session rather than failing one call', async () => {
        await mount();
        global.fetch = vi.fn(async () => ({
            ok: false,
            status: 401,
            json: async () => ({ detail: 'Could not validate credentials' }),
        }));

        await act(async () => {
            await expect(apiFetch('/anything', 'tok')).rejects.toThrow();
        });

        // The token is dead for every other call too, so staying signed in
        // only produces a series of identical failures with nothing on screen
        // to say why. AuthContext's expiry guard cannot catch this one: a
        // REVOKED token still looks valid to a clock.
        expect(auth.isAuthenticated).toBe(false);
    });

    it('ends it for a raw caller too', async () => {
        await mount();
        global.fetch = vi.fn(async () => ({ ok: false, status: 401, json: async () => ({}) }));

        // `raw: true` hands the Response back instead of throwing — the
        // deletion loop reads statuses that way — so the session check cannot
        // live in the throwing branch.
        await act(async () => {
            await apiFetch('/anything', 'tok', { raw: true });
        });

        expect(auth.isAuthenticated).toBe(false);
    });

    it('leaves the session alone on any other failure', async () => {
        await mount();
        global.fetch = vi.fn(async () => ({
            ok: false,
            status: 403,
            json: async () => ({ detail: 'nope' }),
        }));

        await act(async () => {
            await expect(apiFetch('/anything', 'tok')).rejects.toThrow('nope');
        });

        expect(auth.isAuthenticated).toBe(true);
    });
});
