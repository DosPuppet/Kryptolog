/**
 * The send side of crypto-core 3.0.0's message format (audit 2026-10-12 K-06,
 * K-07), driven through the real MessengerProvider.
 *
 * Each message carries a signed `seq` — its position in a session this client
 * minted — so receivers can detect replays and gaps; and a session is retired
 * after SESSION_MAX_MESSAGES, so one leaked session key no longer exposes a DM
 * conversation for its whole life. The extension custody path is stubbed with
 * real crypto-core wraps and a placeholder signature: what is under test is
 * which session each message goes out under, not the signature.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act } from '@testing-library/react';
import {
    generateMlDsaKeyPair, generateMlKemKeyPair, attestEncryptionKey,
    generateSessionKey, wrapSessionKey,
} from '../utils/crypto';

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

let me, partner;

const identity = async () => {
    const dsa = await generateMlDsaKeyPair();
    const kem = await generateMlKemKeyPair();
    return {
        address: dsa.publicKey,
        identity_public_key: dsa.publicKey,
        username: 'U',
        encryption_public_key: kem.publicKey,
        encryption_key_attestation: await attestEncryptionKey(kem.publicKey, dsa.privateKey),
    };
};

let messenger;
function Probe() {
    messenger = useMessengerContext();
    const { login, isAuthenticated } = useAuth();
    if (!isAuthenticated) login(me, 'trustkeys', 'tok');
    return null;
}

/** The DM payloads the client POSTed, in order. */
const sentPayloads = () => global.fetch.mock.calls
    .filter(([url, init]) => /\/messages$/.test(String(url)) && init?.method === 'POST')
    .map(([, init]) => JSON.parse(JSON.parse(init.body).content));

let failNextPost;

beforeEach(async () => {
    me ??= await identity();
    partner ??= await identity();
    failNextPost = false;
    let id = 0;
    global.fetch = vi.fn(async (url, init) => {
        if (/\/messages$/.test(String(url)) && init?.method === 'POST') {
            if (failNextPost) {
                failNextPost = false;
                return { ok: false, status: 500, json: async () => ({ detail: 'boom' }) };
            }
            id += 1;
            return {
                ok: true, status: 200,
                json: async () => ({ id, sender_address: me.address, recipient_address: partner.address, created_at: new Date().toISOString() }),
            };
        }
        return { ok: true, status: 200, json: async () => [] };
    });
    global.WebSocket = class {
        constructor() { this.readyState = 0; }
        send() {}
        close() {}
    };
    window.trustkeys = {
        generateSessionKey: () => generateSessionKey(),
        wrapSessionKey: (k, pk) => wrapSessionKey(k, pk),
        signMessage: async () => 'placeholder-signature',
    };
    await act(async () => {
        render(
            <AuthProvider><PQCProvider><MessengerProvider><Probe /></MessengerProvider></PQCProvider></AuthProvider>
        );
    });
    // PQCProvider re-checks for the extension shortly after mount.
    await act(async () => { await new Promise((r) => setTimeout(r, 600)); });
});

afterEach(() => {
    delete window.trustkeys;
    vi.restoreAllMocks();
});

const send = async (text) => {
    await act(async () => { await messenger.sendMessage(text, partner); });
};

describe('DM sessions and positions (crypto-core 3.0.0)', () => {
    it('numbers the messages of a session from 0, and wraps keys only on the first', async () => {
        await send('one');
        await send('two');
        await send('three');
        const [a, b, c] = sentPayloads();

        expect([a.seq, b.seq, c.seq]).toEqual([0, 1, 2]);
        expect(new Set([a.sid, b.sid, c.sid]).size).toBe(1);
        expect(a.keys).toEqual({ recip: expect.any(Object), sender: expect.any(Object) });
        expect(b.keys).toBeNull();
        for (const p of [a, b, c]) {
            expect(Number.isSafeInteger(p.ts)).toBe(true);
            expect(Math.abs(p.ts - Date.now())).toBeLessThan(60_000);
        }
    });

    it('retires a session after 100 messages and starts the next one at seq 0', async () => {
        for (let i = 0; i < 101; i++) await send(`m${i}`);
        const sent = sentPayloads();

        expect(sent[99].seq).toBe(99);
        expect(sent[100].sid).not.toBe(sent[99].sid);
        expect(sent[100].seq).toBe(0);
        expect(sent[100].keys).not.toBeNull();
    }, 60_000);

    it('drops a session whose first message never reached the server', async () => {
        // That message carried the session key, so nobody received it: every
        // later message under that sid would be unreadable to the partner.
        failNextPost = true;
        await send('lost');
        await send('delivered');

        const posted = global.fetch.mock.calls
            .filter(([url, init]) => /\/messages$/.test(String(url)) && init?.method === 'POST')
            .map(([, init]) => JSON.parse(JSON.parse(init.body).content));
        expect(posted).toHaveLength(2);
        expect(posted[1].sid).not.toBe(posted[0].sid);
        expect(posted[1].keys).not.toBeNull();
        expect(posted[1].seq).toBe(0);
    });
});
