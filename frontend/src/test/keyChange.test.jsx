/**
 * A contact's key changed: nothing goes to it until the reader confirms
 * (audit 2026-10-12 K-05), driven through the real MessengerProvider.
 *
 * The TOFU store recorded key changes, but only the share dialog consulted it:
 * a key swapped by the directory kept receiving messages in every conversation.
 * The changed key here is still correctly ATTESTED — the identity signed it —
 * because that is the case attestation cannot catch: it proves whose key it
 * is, not that it is the key the reader last checked.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act } from '@testing-library/react';
import {
    generateEncryptionKeyPair, attestEncryptionKey,
    generateSessionKey, wrapSessionKey, encryptionKeyId,
} from '../utils/crypto';
import { makeSigner } from './identities';
import { toast } from '../utils/toast';
import { trustContactKey, checkContactKey } from '../services/trustedKeys';

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

/** An identity whose encryption key can be replaced, re-attested by the same identity. */
const identity = async () => {
    const signer = makeSigner();
    const id = {
        // What the directory serves NOW; each rekey() replaces it.
        current: null,
        rekey: async () => {
            const kem = generateEncryptionKeyPair();
            id.current = {
                address: signer.address,
                identity_public_key: signer.identityPublicKey,
                username: 'U',
                encryption_public_key: kem.publicKey,
                encryption_key_attestation: await attestEncryptionKey(
                    { address: signer.address, encryptionPublicKey: kem.publicKey }, signer.seed
                ),
            };
            return id.current;
        },
    };
    await id.rekey();
    return id;
};

let me, partner, carol;
let messenger;
function Probe() {
    messenger = useMessengerContext();
    const { login, isAuthenticated } = useAuth();
    if (!isAuthenticated) login(me.current, 'trustkeys', 'tok');
    return null;
}

const posted = (re) => global.fetch.mock.calls
    .filter(([url, init]) => re.test(String(url)) && init?.method === 'POST')
    .map(([, init]) => JSON.parse(JSON.parse(init.body).content));
const dmPosts = () => posted(/\/messages\/?$/).filter((p) => !p.gid);
const groupPosts = () => posted(/\/groups\/group-7\/messages/);

beforeEach(async () => {
    localStorage.clear();
    me ??= await identity();
    partner = await identity();
    carol = await identity();
    let id = 0;
    global.fetch = vi.fn(async (url, init) => {
        if (/messages/.test(String(url)) && init?.method === 'POST') {
            id += 1;
            return {
                ok: true, status: 200,
                json: async () => ({ id, sender_address: me.current.address, created_at: new Date().toISOString() }),
            };
        }
        return { ok: true, status: 200, json: async () => [] };
    });
    global.WebSocket = class { constructor() { this.readyState = 0; } send() {} close() {} };
    window.trustkeys = {
        generateSessionKey: () => generateSessionKey(),
        wrapSessionKey: (k, pk) => wrapSessionKey(k, pk),
        signMessage: async () => 'placeholder-signature',
    };
    vi.spyOn(toast, 'error');
    await act(async () => {
        render(<AuthProvider><PQCProvider><MessengerProvider><Probe /></MessengerProvider></PQCProvider></AuthProvider>);
    });
    await act(async () => { await new Promise((r) => setTimeout(r, 600)); });
});

afterEach(() => {
    delete window.trustkeys;
    vi.restoreAllMocks();
});

const dm = async (text, user) => { await act(async () => { await messenger.sendMessage(text, user); }); };

describe('DM to a contact whose key changed', () => {
    it('pins the key on first contact, without asking', async () => {
        await dm('hello', partner.current);
        expect(dmPosts()).toHaveLength(1);
        expect(checkContactKey(partner.current.address, partner.current.encryption_public_key)).toBe('unchanged');
    });

    it('refuses to send to a changed key, and says why', async () => {
        await dm('hello', partner.current);
        const swapped = await partner.rekey();

        await dm('the code is 4711', swapped);
        expect(dmPosts()).toHaveLength(1); // nothing new left the client
        expect(toast.error).toHaveBeenCalledWith(expect.stringMatching(/encryption key changed/));
    });

    it('sends again once the reader confirms the new key', async () => {
        await dm('hello', partner.current);
        const swapped = await partner.rekey();
        trustContactKey(swapped.address, swapped.encryption_public_key); // KeyTrustPanel's button

        await dm('after checking', swapped);
        expect(dmPosts()).toHaveLength(2);
    });

    it('mints a new session for the new key instead of reusing one wrapped to the old (5.1.0)', async () => {
        // The session minted for the old key is still young; without the
        // binding it would carry on, and its key — wrapped to the retired
        // encryption key — would protect what is sent next.
        await dm('hello', partner.current);
        await dm('again', partner.current);
        const [first, second] = dmPosts();
        expect(second.keys).toBeNull(); // same session, as long as the key is the same
        const swapped = await partner.rekey();
        trustContactKey(swapped.address, swapped.encryption_public_key);

        await dm('after the rotation', swapped);
        const third = dmPosts()[2];
        expect(third.sid).not.toBe(first.sid);
        expect(third.keys.recip.kid).toBe(encryptionKeyId(swapped.encryption_public_key));
    });
});

describe('group with a member whose key changed', () => {
    const channel = () => ({
        id: 'group-7',
        members: [me, partner, carol].map((i) => ({
            user_address: i.current.address, role: 'member', user: i.current,
        })),
    });
    const sendGroup = async (text) => {
        await act(async () => { await messenger.sendGroupMessage(text, channel()); });
    };

    it('wraps to everyone else, excludes that member, and names them', async () => {
        await sendGroup('first');
        await partner.rekey();
        await sendGroup('second');

        const [first, second] = groupPosts();
        expect(Object.keys(first.keys)).toContain(partner.current.address);
        expect(second.keys).not.toBeNull(); // the member set moved, so the session rotated
        expect(Object.keys(second.keys)).not.toContain(partner.current.address);
        expect(Object.keys(second.keys)).toContain(carol.current.address);
        expect(Object.keys(second.keys)).toContain(me.current.address);
        expect(toast.error).toHaveBeenCalledWith(expect.stringMatching(/key changed/));
    });

    it("rotates the session when a member's key changes, once the new key is confirmed (5.1.0)", async () => {
        await sendGroup('first');
        const swapped = await partner.rekey();
        trustContactKey(swapped.address, swapped.encryption_public_key);
        await sendGroup('second');
        const [first, second] = groupPosts();
        expect(second.sid).not.toBe(first.sid); // same members, a different key: a new session
        expect(second.keys[partner.current.address].kid).toBe(encryptionKeyId(swapped.encryption_public_key));
    });

    it('never excludes the sender\'s own row', async () => {
        trustContactKey(me.current.address, 'a key this device saw for me once');
        await sendGroup('mine');
        expect(Object.keys(groupPosts()[0].keys)).toContain(me.current.address);
    });
});
