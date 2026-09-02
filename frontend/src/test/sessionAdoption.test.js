// Session-key adoption gate (audit H-1) + conversation scoping.
//
// The finding: processMessages adopted the session key out of ANY message that
// carried a decryptable `keys` block and made it the conversation's active
// session. Signature verification ran afterwards and only produced a `verified`
// flag for the UI badge, so it gated nothing — a server could inject a message
// wrapping a key it owns, we would adopt it, and the next outbound message went
// out encrypted to the server. That defeats the README's "zero-knowledge relay"
// claim against exactly the adversary it names.
//
// These tests drive the real hook against real ML-DSA signatures and real
// AES-GCM session keys; only the custody-provider unwrap is stubbed.

import { describe, it, expect, beforeAll, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import {
    generateMlDsaKeyPair,
    generateSessionKey,
    encryptWithSessionKey,
    messageSigningBody,
    signMessagePQC,
} from '../utils/crypto';
import { useMessageSessions } from '../context/messenger/useMessageSessions';
import { sessionKeyId, mayAdoptSession } from '../context/messenger/sessionScope';

const CHANNEL = 'cccccccc-0000-4000-8000-000000000001';

let me, alice, bob, mallory;

beforeAll(async () => {
    [me, alice, bob, mallory] = await Promise.all(
        Array.from({ length: 4 }, async () => {
            const { publicKey, privateKey } = await generateMlDsaKeyPair();
            return { address: publicKey.toLowerCase(), privateKey };
        })
    );
}, 60000);

/** A DM row as the server would deliver it. `signWith` defaults to the claimed sender. */
const dmMessage = async ({ id, from, to, sid, sKey, text = 'hello', blob = null, sign = true, signWith }) => {
    const ct = await encryptWithSessionKey(text, sKey);
    const keys = blob ? { recip: blob, sender: null } : null;
    const payload = { v: 1, sid, keys, ct };
    if (sign) {
        const body = await messageSigningBody({ from: from.address, conv: to.address, sid, keys, ct });
        payload.sig = await signMessagePQC(body, (signWith || from).privateKey);
    }
    return { id, sender_address: from.address, recipient_address: to.address, content: JSON.stringify(payload) };
};

const groupMessage = async ({ id, from, sid, sKey, text = 'hi group', wrapFor = [], sign = true, signWith }) => {
    const ct = await encryptWithSessionKey(text, sKey);
    const keys = {};
    for (const [addr, blob] of wrapFor) keys[addr] = blob;
    const payload = { v: 2, sid, gid: CHANNEL, keys, ct };
    if (sign) {
        const body = await messageSigningBody({
            from: from.address, conv: CHANNEL, gid: CHANNEL, sid, keys, ct,
        });
        payload.sig = await signMessagePQC(body, (signWith || from).privateKey);
    }
    return { id, sender_address: from.address, channel_id: CHANNEL, content: JSON.stringify(payload) };
};

/** Mount the hook with a stub custody provider that maps blob strings to keys. */
const setup = (blobToKey = {}) => {
    const unwrapManySessionKeys = vi.fn(async (blobs) => blobs.map(b => blobToKey[b] ?? null));
    const unwrapSessionKey = vi.fn(async (b) => blobToKey[b] ?? null);
    const { result } = renderHook(() => useMessageSessions({
        user: { address: me.address },
        unwrapSessionKey,
        unwrapManySessionKeys,
        activeConversationRef: { current: null },
        setActiveConversation: () => { },
        activeGroupConversationRef: { current: null },
        setActiveGroupConversation: () => { },
    }));
    return { result, unwrapManySessionKeys, unwrapSessionKey };
};

const process = async (result, msgs, mode = 'dm') => {
    let out;
    await act(async () => { out = await result.current.processMessages(msgs, mode); });
    return out;
};

describe('session adoption requires a valid signature (H-1)', () => {
    it('adopts the session from a properly signed partner message', async () => {
        const sid = 'sid-good';
        const sKey = await generateSessionKey();
        const { result, unwrapManySessionKeys } = setup({ 'blob-alice': sKey });
        const msg = await dmMessage({ id: 1, from: alice, to: me, sid, sKey, blob: 'blob-alice' });

        const [out] = await process(result, [msg]);

        expect(out.verified).toBe(true);
        expect(out.plainText).toBe('hello');
        expect(unwrapManySessionKeys).toHaveBeenCalledTimes(1);
        expect(result.current.activeSessionIds[alice.address]).toBe(sid);
        expect(result.current.sessionKeys[sessionKeyId(alice.address, sid)]).toBe(sKey);
    });

    it('refuses a forged message: the key is never unwrapped, let alone adopted', async () => {
        // The audit's scenario. The server claims the message is from Alice and
        // wraps a session key IT owns; the signature is made with its own key,
        // so it does not verify against the claimed sender_address.
        const sid = 'sid-evil';
        const sKey = await generateSessionKey();
        const { result, unwrapManySessionKeys } = setup({ 'blob-evil': sKey });
        const msg = await dmMessage({
            id: 1, from: alice, to: me, sid, sKey, blob: 'blob-evil', signWith: mallory,
        });

        const [out] = await process(result, [msg]);

        expect(out.verified).toBe(false);
        expect(out.plainText).toBeNull();
        // Not merely un-adopted — the blob is never even handed to the custody
        // provider, so no key the attacker chose enters the cache at all.
        expect(unwrapManySessionKeys).not.toHaveBeenCalled();
        expect(result.current.sessionKeys).toEqual({});
        expect(result.current.activeSessionIds).toEqual({});
    });

    it('refuses an unsigned (legacy) message — `verified === null` does not qualify', async () => {
        const sid = 'sid-legacy';
        const sKey = await generateSessionKey();
        const { result, unwrapManySessionKeys } = setup({ 'blob-legacy': sKey });
        const msg = await dmMessage({ id: 1, from: alice, to: me, sid, sKey, blob: 'blob-legacy', sign: false });

        const [out] = await process(result, [msg]);

        expect(out.verified).toBeNull();
        expect(unwrapManySessionKeys).not.toHaveBeenCalled();
        expect(result.current.sessionKeys).toEqual({});
    });

    it('a forged message cannot displace an already-adopted session', async () => {
        // Even with a genuine session in place, an injected later message must
        // not take over `activeSessionIds` — that is what would redirect the
        // next outbound message.
        const goodKey = await generateSessionKey();
        const evilKey = await generateSessionKey();
        const { result } = setup({ 'blob-good': goodKey, 'blob-evil': evilKey });

        const good = await dmMessage({ id: 1, from: alice, to: me, sid: 'sid-good', sKey: goodKey, blob: 'blob-good' });
        const evil = await dmMessage({
            id: 2, from: alice, to: me, sid: 'sid-evil', sKey: evilKey, blob: 'blob-evil', signWith: mallory,
        });

        await process(result, [good, evil]);

        expect(result.current.activeSessionIds[alice.address]).toBe('sid-good');
        expect(result.current.sessionKeys[sessionKeyId(alice.address, 'sid-evil')]).toBeUndefined();
    });

    it('manual decrypt applies the same gate — it is not a way around it', async () => {
        const sid = 'sid-manual';
        const sKey = await generateSessionKey();
        const { result, unwrapSessionKey } = setup({ 'blob-evil': sKey });
        const msg = await dmMessage({
            id: 1, from: alice, to: me, sid, sKey, blob: 'blob-evil', signWith: mallory,
        });

        await act(async () => { await result.current.handleManualDecrypt(msg, 'dm'); });

        expect(unwrapSessionKey).not.toHaveBeenCalled();
        expect(result.current.sessionKeys).toEqual({});
    });
});

describe('the newest session wins (L-1)', () => {
    it('picks the last message in the batch, not the first', async () => {
        // History arrives chronologically ASCENDING and the old code used
        // `.find`, so the OLDEST session in the batch became active — in a
        // variable named `recentMsg`. Combined with H-1 that gave an injected
        // early message priority over every legitimate later one.
        const oldKey = await generateSessionKey();
        const newKey = await generateSessionKey();
        const { result } = setup({ 'blob-old': oldKey, 'blob-new': newKey });

        const older = await dmMessage({ id: 1, from: alice, to: me, sid: 'sid-old', sKey: oldKey, blob: 'blob-old' });
        const newer = await dmMessage({ id: 2, from: alice, to: me, sid: 'sid-new', sKey: newKey, blob: 'blob-new' });

        await process(result, [older, newer]);

        expect(result.current.activeSessionIds[alice.address]).toBe('sid-new');
        // Both keys stay readable — only the SEND session is the newest one.
        expect(result.current.sessionKeys[sessionKeyId(alice.address, 'sid-old')]).toBe(oldKey);
        expect(result.current.sessionKeys[sessionKeyId(alice.address, 'sid-new')]).toBe(newKey);
    });
});

describe('sessions are scoped to their conversation', () => {
    it('a sid adopted from Alice is not reachable from Bob', async () => {
        const sid = 'shared-sid';
        const aliceKey = await generateSessionKey();
        const { result } = setup({ 'blob-alice': aliceKey });

        const fromAlice = await dmMessage({ id: 1, from: alice, to: me, sid, sKey: aliceKey, blob: 'blob-alice' });
        await process(result, [fromAlice]);
        expect(result.current.sessionKeys[sessionKeyId(alice.address, sid)]).toBe(aliceKey);

        // Bob's conversation reuses the same sid. Under the old flat cache this
        // decrypted with Alice's key; scoped, it is simply a different entry.
        const bobKey = await generateSessionKey();
        const fromBob = await dmMessage({ id: 2, from: bob, to: me, sid, sKey: bobKey, blob: 'unknown-blob' });
        const [out] = await process(result, [fromBob]);

        expect(out.plainText).toBeNull();
        expect(result.current.sessionKeys[sessionKeyId(bob.address, sid)]).toBeUndefined();
        expect(result.current.activeSessionIds[bob.address]).toBeUndefined();
    });

    it('keys are stored under (conversation, sid), never the bare sid', async () => {
        const sid = 'sid-scope';
        const sKey = await generateSessionKey();
        const { result } = setup({ 'blob-alice': sKey });
        await process(result, [await dmMessage({ id: 1, from: alice, to: me, sid, sKey, blob: 'blob-alice' })]);

        expect(result.current.sessionKeys[sid]).toBeUndefined();
        expect(Object.keys(result.current.sessionKeys)).toEqual([sessionKeyId(alice.address, sid)]);
    });
});

describe('group messages', () => {
    it('adopts a verified group session for reading, but never as the send key', async () => {
        // Groups deliberately do not adopt a SEND session from history (O-1):
        // each client mints its own per page load. Reading must still work.
        const sid = 'gsid-1';
        const sKey = await generateSessionKey();
        const { result } = setup({ 'blob-me': sKey });
        const msg = await groupMessage({ id: 1, from: alice, sid, sKey, wrapFor: [[me.address, 'blob-me']] });

        const [out] = await process(result, [msg], 'group');

        expect(out.verified).toBe(true);
        expect(out.plainText).toBe('hi group');
        expect(result.current.sessionKeys[sessionKeyId(`group_${CHANNEL}`, sid)]).toBe(sKey);
        expect(result.current.activeSessionIds).toEqual({});
    });

    it('refuses a group message whose signature does not verify', async () => {
        const sid = 'gsid-evil';
        const sKey = await generateSessionKey();
        const { result, unwrapManySessionKeys } = setup({ 'blob-me': sKey });
        const msg = await groupMessage({
            id: 1, from: alice, sid, sKey, wrapFor: [[me.address, 'blob-me']], signWith: mallory,
        });

        const [out] = await process(result, [msg], 'group');

        expect(out.verified).toBe(false);
        expect(unwrapManySessionKeys).not.toHaveBeenCalled();
        expect(result.current.sessionKeys).toEqual({});
    });
});

describe('mayAdoptSession', () => {
    const dm = (from, to) => ({ sender_address: from, recipient_address: to });

    it('accepts a verified message from either end of our own conversation', () => {
        expect(mayAdoptSession(dm(alice.address, me.address), true, 'dm', me.address)).toBe(true);
        expect(mayAdoptSession(dm(me.address, alice.address), true, 'dm', me.address)).toBe(true);
    });

    it('rejects a message between two other parties injected into our history', () => {
        expect(mayAdoptSession(dm(alice.address, bob.address), true, 'dm', me.address)).toBe(false);
    });

    it('rejects anything not strictly verified', () => {
        for (const verdict of [false, null, undefined, 'true', 1]) {
            expect(mayAdoptSession(dm(alice.address, me.address), verdict, 'dm', me.address)).toBe(false);
        }
    });
});
