/**
 * Who a message is from, before it can be read.
 *
 * The NEW_MESSAGE frame carries addresses only (backend/routers/messenger.py
 * hand-builds it), so a first message from someone not already in the sidebar
 * showed the literal "New Message" as their name — the same label for every
 * unknown partner — until a reload refetched /messages/conversations. The
 * sender saw it too, because the server echoes the frame back for device sync
 * and the echo can win the race against the POST it came from.
 *
 * These drive real frames through the provider's socket, because the bug lived
 * in the ordering between that socket and the request, not in either alone.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act } from '@testing-library/react';
import { displayName } from '../utils/format';

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

const ME = 'a'.repeat(64);
const BOB = 'b'.repeat(64);

let messenger;
function Probe() {
    messenger = useMessengerContext();
    const { login, isAuthenticated } = useAuth();
    if (!isAuthenticated) login({ username: 'A', address: ME }, 'vault', 'tok');
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

/** Deliver one server frame, exactly as useMessengerSocket receives it. */
const deliver = async (frame) => {
    await act(async () => {
        await socket.onmessage({ data: JSON.stringify(frame) });
        // The directory lookup is fired without being awaited, by design.
        await Promise.resolve();
    });
};

const newMessage = (from, to, id = 1) => ({
    type: 'NEW_MESSAGE',
    message: {
        id,
        sender_address: from,
        recipient_address: to,
        // Undecryptable on purpose: the name must not depend on reading it.
        content: JSON.stringify({ v: 1, sid: 'no-such-session', ct: 'x' }),
        is_read: false,
        created_at: '2026-09-11T10:00:00+00:00',
    },
});

/** URLs of every directory lookup this run made. */
const directoryCalls = () =>
    global.fetch.mock.calls.map(([url]) => String(url)).filter(u => /\/users\/[0-9a-f]{8}/.test(u));

let directoryResponse;

beforeEach(() => {
    directoryResponse = { ok: true, status: 200, json: async () => ({ address: BOB, username: 'Bob' }) };
    global.fetch = vi.fn(async (url) =>
        /\/users\//.test(String(url))
            ? directoryResponse
            : { ok: true, status: 200, json: async () => [] }
    );
    global.WebSocket = class {
        constructor() { this.readyState = 0; socket = this; }
        close() {}
        send() {}
        addEventListener() {}
    };
});
afterEach(() => { vi.restoreAllMocks(); });

describe('a message from someone not yet in the sidebar', () => {
    it('is labelled with the sender name, not a placeholder', async () => {
        await mount();
        await deliver(newMessage(BOB, ME));

        const convo = messenger.conversations.find(c => c.user.address === BOB);
        expect(convo, 'the message opened no conversation').toBeTruthy();
        expect(convo.user.username).toBe('Bob');
        expect(displayName(convo.user)).toBe('Bob');
    });

    it('names the partner without the message being decrypted', async () => {
        await mount();
        await deliver(newMessage(BOB, ME));

        const convo = messenger.conversations.find(c => c.user.address === BOB);
        // The premise of the test above: nothing decrypted, name still there.
        expect(convo.last_message.plainText ?? null).toBeNull();
        expect(convo.user.username).toBe('Bob');
    });

    it("names the recipient on the sender's own echo", async () => {
        await mount();
        // The server sends this same frame back to the sender for device sync.
        await deliver(newMessage(ME, BOB));

        const convo = messenger.conversations.find(c => c.user.address === BOB);
        expect(convo.user.username).toBe('Bob');
    });

    it('asks the directory once per partner, not once per message', async () => {
        await mount();
        await deliver(newMessage(BOB, ME, 1));
        await deliver(newMessage(BOB, ME, 2));
        await deliver(newMessage(BOB, ME, 3));

        expect(directoryCalls()).toHaveLength(1);
    });
});

describe('when the directory cannot be reached', () => {
    it('falls back to the address rather than inventing a name', async () => {
        directoryResponse = { ok: false, status: 503, json: async () => ({}) };
        await mount();
        await deliver(newMessage(BOB, ME));

        const convo = messenger.conversations.find(c => c.user.address === BOB);
        // A short address is a label the user can compare against a contact.
        // "New Message" is the same string for every partner alive.
        expect(convo.user.username).toBeUndefined();
        expect(displayName(convo.user)).toBe(`${BOB.slice(0, 8)}...`);
    });

    it('retries on the next message instead of caching the failure', async () => {
        directoryResponse = { ok: false, status: 503, json: async () => ({}) };
        await mount();
        await deliver(newMessage(BOB, ME, 1));

        directoryResponse = { ok: true, status: 200, json: async () => ({ address: BOB, username: 'Bob' }) };
        await deliver(newMessage(BOB, ME, 2));

        expect(directoryCalls()).toHaveLength(2);
        expect(messenger.conversations.find(c => c.user.address === BOB).user.username).toBe('Bob');
    });
});
