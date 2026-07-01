import { describe, it, expect } from 'vitest';
import {
    generateDilithiumKeyPair,
    signMessagePQC,
    verifySignaturePQC,
    messageSigningBody,
    MESSAGE_SIGNING_PREFIX,
    SIGNING_CONTEXT,
    domainSeparate,
} from '../utils/crypto';
import { verifyMessageAuthenticity } from '../context/MessengerContext';

// Audit S1: messages are signed end-to-end and verified against the sender's
// ML-DSA public key (== sender_address).
describe('message signing (S1)', () => {
    it('MESSAGE_SIGNING_PREFIX matches an empty message-context domain string', () => {
        expect(MESSAGE_SIGNING_PREFIX).toBe(domainSeparate(SIGNING_CONTEXT.MESSAGE, ''));
        // Every real message body starts with the prefix (the extension's silent
        // signer relies on this to refuse non-message payloads).
        const body = messageSigningBody({ from: 'a', conv: 'b', sid: 's', ct: 'cc' });
        expect(body.startsWith(MESSAGE_SIGNING_PREFIX)).toBe(true);
    });

    it('a sender signature verifies against the sender public key', async () => {
        const { publicKey, privateKey } = await generateDilithiumKeyPair();
        const body = messageSigningBody({ from: publicKey, conv: 'recipient', sid: 'sid1', ct: 'deadbeef' });
        const sig = await signMessagePQC(body, privateKey);
        expect(await verifySignaturePQC(body, sig, publicKey)).toBe(true);
    });

    it('verification fails if the ciphertext is tampered (re-attribution/forgery)', async () => {
        const { publicKey, privateKey } = await generateDilithiumKeyPair();
        const body = messageSigningBody({ from: publicKey, conv: 'recipient', sid: 'sid1', ct: 'deadbeef' });
        const sig = await signMessagePQC(body, privateKey);
        const tampered = messageSigningBody({ from: publicKey, conv: 'recipient', sid: 'sid1', ct: 'deadbe00' });
        expect(await verifySignaturePQC(tampered, sig, publicKey)).toBe(false);
    });

    it('binds the real ciphertext object — a swapped same-session ct does NOT verify', async () => {
        // Production signs over the AES-GCM envelope OBJECT { iv, content }, not a
        // string. Regression for the ct-binding bug: previously the object coerced
        // to the constant "[object Object]", so any ciphertext verified under one
        // signature. The signed bytes must commit to the actual ciphertext.
        const { publicKey, privateKey } = await generateDilithiumKeyPair();
        const ct = { iv: 'aabbccdd', content: '0011223344' };
        const body = messageSigningBody({ from: publicKey, conv: 'recipient', sid: 'sid1', ct });
        const sig = await signMessagePQC(body, privateKey);
        expect(await verifySignaturePQC(body, sig, publicKey)).toBe(true);
        // Server swaps the ciphertext content for another value -> must fail now.
        const swapped = messageSigningBody({ from: publicKey, conv: 'recipient', sid: 'sid1', ct: { iv: 'aabbccdd', content: 'deadbeef99' } });
        expect(await verifySignaturePQC(swapped, sig, publicKey)).toBe(false);
    });

    it("verification fails against a different sender's key (server can't forge as Alice)", async () => {
        const alice = await generateDilithiumKeyPair();
        const mallory = await generateDilithiumKeyPair();
        const body = messageSigningBody({ from: alice.publicKey, conv: 'r', sid: 's', ct: 'cc' });
        const sig = await signMessagePQC(body, alice.privateKey);
        // Server swaps the claimed author to Mallory's key → signature no longer verifies.
        expect(await verifySignaturePQC(body, sig, mallory.publicKey)).toBe(false);
    });

    it('a message signature cannot be replayed as a login signature (domain separation)', async () => {
        const { publicKey, privateKey } = await generateDilithiumKeyPair();
        const ct = 'abcd';
        const body = messageSigningBody({ from: publicKey, conv: 'r', sid: 's', ct });
        const sig = await signMessagePQC(body, publicKey ? privateKey : privateKey);
        const loginBody = domainSeparate(SIGNING_CONTEXT.LOGIN, `from=${publicKey}\nconv=r\nsid=s\nct=${ct}`);
        expect(await verifySignaturePQC(loginBody, sig, publicKey)).toBe(false);
    });
});

// Audit F-1: group message authenticity must bind to the SERVER-ATTESTED channel
// (the delivered row's channel_id), never to the sender/server-supplied gid in
// the content — otherwise a malicious server can re-home a message Alice signed
// for channel A into channel B (which she and the viewer both belong to) and it
// still shows "verified".
describe('group message channel binding (F-1)', () => {
    const channelA = 'aaaaaaaa-0000-4000-8000-000000000001';
    const channelB = 'bbbbbbbb-0000-4000-8000-000000000002';

    // Mirror how MessengerContext.sendGroupMessage signs: conv = channel id.
    const signGroupMessage = async (privateKey, publicKey, channelId, sid, ct) => {
        const body = messageSigningBody({ from: publicKey.toLowerCase(), conv: channelId, sid, ct });
        return signMessagePQC(body, privateKey);
    };

    it('verifies a group message delivered under the channel it was signed for', async () => {
        const { publicKey, privateKey } = await generateDilithiumKeyPair();
        const sid = 's1', ct = 'deadbeef';
        const sig = await signGroupMessage(privateKey, publicKey, channelA, sid, ct);
        const msg = { sender_address: publicKey.toLowerCase(), channel_id: channelA };
        const payload = { v: 2, sid, gid: channelA, ct, sig };
        expect(await verifyMessageAuthenticity(msg, payload, 'group')).toBe(true);
    });

    it('rejects a message re-homed into another channel (server cannot move a signed message)', async () => {
        const { publicKey, privateKey } = await generateDilithiumKeyPair();
        const sid = 's1', ct = 'deadbeef';
        const sig = await signGroupMessage(privateKey, publicKey, channelA, sid, ct);
        // Malicious server serves the channel-A message inside channel B's history.
        const msg = { sender_address: publicKey.toLowerCase(), channel_id: channelB };
        const payload = { v: 2, sid, gid: channelA, ct, sig };
        expect(await verifyMessageAuthenticity(msg, payload, 'group')).toBe(false);
    });

    it('rejects even when the server also rewrites gid to match the new channel', async () => {
        const { publicKey, privateKey } = await generateDilithiumKeyPair();
        const sid = 's1', ct = 'deadbeef';
        const sig = await signGroupMessage(privateKey, publicKey, channelA, sid, ct);
        // gid rewritten to B too — conv now binds to channel_id, so the sig (over
        // conv=A) still fails to verify under channel B.
        const msg = { sender_address: publicKey.toLowerCase(), channel_id: channelB };
        const payload = { v: 2, sid, gid: channelB, ct, sig };
        expect(await verifyMessageAuthenticity(msg, payload, 'group')).toBe(false);
    });

    it('returns null for an unsigned (legacy) message', async () => {
        const msg = { sender_address: 'x', channel_id: channelA };
        expect(await verifyMessageAuthenticity(msg, { v: 2, sid: 's', ct: 'c' }, 'group')).toBeNull();
    });
});
