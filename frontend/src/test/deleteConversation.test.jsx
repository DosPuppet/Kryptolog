/**
 * "Delete this conversation" (audit 2026-09-11 M-6), driven through the real
 * providers: hide it for me, and optionally erase my own messages in it first.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act } from '@testing-library/react';
import { conversationEraseBody } from '../utils/crypto';

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

const ME = { address: 'aa'.repeat(48), username: 'me' }; // 96-hex addresses (crypto-core 4.0.0)
const BOB = { address: 'bb'.repeat(48), username: 'bob', encryption_public_key: 'k' };

let messenger;
function Probe() {
    messenger = useMessengerContext();
    const { login, isAuthenticated } = useAuth();
    if (!isAuthenticated) login(ME, 'trustkeys', 'tok');
    return null;
}

let calls;
let presetClears = [];
const json = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });

beforeEach(async () => {
    calls = [];
    global.fetch = vi.fn(async (url, init = {}) => {
        const u = String(url);
        calls.push(`${init.method || 'GET'} ${u.replace(/^https?:\/\/[^/]+/, '').split('?')[0]}`);
        if (u.includes('/messages/conversations')) {
            return json(u.includes('offset=0') ? [{ user: BOB, last_message: { id: 5 }, unread_count: 2 }] : []);
        }
        if (u.includes('/conversations/clears')) return json(u.includes('offset=0') ? presetClears : []);
        if (u.includes('/clear')) return json({ kind: 'dm', conversation: BOB.address, cleared_through_id: 5, cleared_at: '2026-10-12T00:00:00Z' });
        if (u.includes('/redactable-messages')) return json([]);
        if (u.includes('/auth/nonce/')) return json({ nonce: 'ab12', deployment: 'dep-1' });
        if (u.includes('/erase')) return json({ status: 'erased', redacted: 0, deleted: 3, kept: 0 });
        if (u.includes('/messages/history')) {
            return json([4, 5].map((id) => ({
                id, sender_address: BOB.address, recipient_address: ME.address,
                content: 'not a payload', created_at: '2026-10-12T00:00:00Z',
            })));
        }
        return json([]);
    });
    global.WebSocket = class { constructor() { this.readyState = 0; } send() {} close() {} };
    window.trustkeys = { signConversationErase: vi.fn(async () => 'c2ln') };
    await act(async () => {
        render(<AuthProvider><PQCProvider><MessengerProvider><Probe /></MessengerProvider></PQCProvider></AuthProvider>);
    });
    await act(async () => { await new Promise((r) => setTimeout(r, 600)); });
});

afterEach(() => {
    presetClears = [];
    delete window.trustkeys;
    vi.restoreAllMocks();
});

describe('deleting a conversation', () => {
    it('hides it, without erasing anything, by default', async () => {
        expect(messenger.conversations).toHaveLength(1);
        expect(messenger.unreadCount).toBe(2);

        await act(async () => { await messenger.deleteConversation('dm', BOB.address); });

        expect(messenger.conversations).toHaveLength(0);
        expect(messenger.unreadCount).toBe(0);
        expect(calls.some((c) => c.includes('/erase'))).toBe(false);
        expect(window.trustkeys.signConversationErase).not.toHaveBeenCalled();
    });

    it('erases my messages first, under a signature for THIS conversation, then hides it', async () => {
        await act(async () => { await messenger.deleteConversation('dm', BOB.address, { eraseMine: true }); });

        expect(window.trustkeys.signConversationErase).toHaveBeenCalledWith(
            expect.objectContaining({ kind: 'dm', conversation: BOB.address, redactionKeys: [] })
        );
        const erase = calls.findIndex((c) => c.startsWith('POST') && c.includes('/erase'));
        const clear = calls.findIndex((c) => c.startsWith('POST') && c.endsWith('/clear'));
        expect(erase).toBeGreaterThan(-1);
        expect(clear).toBeGreaterThan(erase);
        expect(messenger.conversations).toHaveLength(0);
    });

    it('leaves the conversation visible when the erase fails', async () => {
        window.trustkeys.signConversationErase = vi.fn(async () => { throw new Error('User rejected'); });
        await act(async () => {
            await expect(messenger.deleteConversation('dm', BOB.address, { eraseMine: true })).rejects.toThrow();
        });
        expect(messenger.conversations).toHaveLength(1);
        expect(calls.some((c) => c.endsWith('/clear'))).toBe(false);
    });

    it('signs the same bytes the vault path would', async () => {
        // The vault path signs conversationEraseBody(args) itself; pin that it
        // is a conversation-erase body for the conversation given.
        const body = await conversationEraseBody({
            nonce: 'ab12', kind: 'dm', conversation: BOB.address, origin: 'http://localhost:3000', deployment: 'dep-1',
        });
        expect(body).toContain('context=conversation-erase');
        expect(body).toContain(`conversation=dm:${BOB.address}`);
    });
});

describe('a conversation hidden on another device', () => {
    it('shows only what arrived after the marker, and stays listed because something did', async () => {
        presetClears = [{ kind: 'dm', conversation: BOB.address, cleared_through_id: 4, cleared_at: '2026-10-12T00:00:00Z' }];
        // A second session, as another device would start one: it reads the marker on load.
        await act(async () => {
            render(<AuthProvider><PQCProvider><MessengerProvider><Probe /></MessengerProvider></PQCProvider></AuthProvider>);
        });
        await act(async () => { await new Promise((r) => setTimeout(r, 600)); });
        await act(async () => { await messenger.loadConversation(BOB); });

        expect(messenger.conversations).toHaveLength(1); // newest id 5 > marker 4
        expect(messenger.activeConversation.messages.map((m) => m.id)).toEqual([5]);
    });
});
