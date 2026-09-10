/**
 * What the messenger actually puts on the wire.
 *
 * This layer had no coverage, so a body encoded twice broke every send and
 * every history load with a 422 and nothing failed in CI. These assert the
 * request shape the server's Pydantic models expect.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act } from '@testing-library/react';

vi.mock('../services/vault', () => ({
    vaultService: {
        isLocked: true, hasBiometrics: () => false, biometricMode: () => null,
        hasVault: () => false, getAccounts: () => [], clearKeyCache: vi.fn(),
        getCacheTTL: () => 0,
    },
}));

const { MessengerProvider, useMessengerContext } = await import('../context/MessengerContext');
const { AuthProvider, useAuth } = await import('../context/AuthContext');
const { PQCProvider } = await import('../context/PQCContext');

let messenger;
function Probe() {
    messenger = useMessengerContext();
    const { login, isAuthenticated } = useAuth();
    if (!isAuthenticated) login({ username: 'A', address: 'a'.repeat(64) }, 'vault', 'tok');
    return null;
}

const mount = async () => {
    await act(async () => {
        render(
            <AuthProvider><PQCProvider><MessengerProvider>
                <Probe />
            </MessengerProvider></PQCProvider></AuthProvider>
        );
    });
};

/** Every POST body this test run put on the wire, already parsed. */
const postedBodies = () =>
    global.fetch.mock.calls
        .filter(([, init]) => init?.body)
        .map(([url, init]) => ({ url, body: init.body }));

beforeEach(() => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => [] });
    // The provider opens a socket on mount; a class, since it is used with new.
    global.WebSocket = class {
        constructor() { this.readyState = 0; }
        close() {}
        send() {}
        addEventListener() {}
    };
});
afterEach(() => { vi.restoreAllMocks(); });

describe('message history', () => {
    it('posts an object, not a JSON string of one', async () => {
        await mount();
        await act(async () => {
            await messenger.loadConversation({ address: 'b'.repeat(64), username: 'B' });
        });

        const historyPost = postedBodies().find(r => String(r.url).includes('/messages/history'));
        expect(historyPost, 'no /messages/history request was made').toBeTruthy();

        const parsed = JSON.parse(historyPost.body);
        // Double-encoding leaves a string here, and the server answers 422.
        expect(typeof parsed).toBe('object');
        expect(parsed).toHaveProperty('partner_address');
        expect(typeof parsed.partner_address).toBe('string');
    });
});

describe('every messenger POST', () => {
    it('sends a JSON object body', async () => {
        await mount();
        await act(async () => {
            // loadConversation also fires the mark-read POST internally.
            await messenger.loadConversation({ address: 'b'.repeat(64), username: 'B' });
        });

        const posts = postedBodies();
        // Without this the loop below passes vacuously when no request is made.
        expect(posts.length, 'the messenger made no POST at all').toBeGreaterThan(0);

        for (const { url, body } of posts) {
            const parsed = JSON.parse(body);
            expect(typeof parsed, `${url} sent a ${typeof parsed}, not an object`).toBe('object');
        }
    });
});
