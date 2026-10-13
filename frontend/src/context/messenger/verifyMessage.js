import { messageSigningBody, verifyIdentitySignature } from '../../utils/crypto';
import { identityKeyFor } from '../../services/identityKeys';

// Verify a message's end-to-end signature (audit S1). Rebuilds the exact bytes
// the sender signed and checks them against the sender's identity key — the
// one its address names, checked by identityKeyFor and again by
// verifyIdentitySignature (crypto-core 3.3.0) — so a server can't forge or
// re-attribute a message. Returns true/false, or null for an unsigned
// (legacy) message.
//
// The conversation binding (`conv`) MUST come from the SERVER-ATTESTED delivery
// context, never from a sender/server-supplied field inside the content (audit
// F-1): DMs bind to the message row's recipient_address; groups bind to the
// row's channel_id — NOT payload.gid, which a malicious server could rewrite to
// re-home a message Alice signed for channel A into channel B (one she and the
// viewer both belong to) while it still showed as "verified".
//
// And the KIND of conversation is bound too (3.3.0): a group message must
// declare the very channel it was delivered under, and a DM must declare
// none. The signed body of a DM is `conv=<recipient>`, `gid=` — which is also
// what a group message with no declared gid in a channel whose id is that
// address would rebuild. Channel ids are minted by the server, so a malicious
// server could mint exactly that id and replay a DM into a group as verified.
// Honest clients always set gid on group messages and never on DMs.
//
// Since v1.4.0 the signed body also covers the key envelope and the declared
// gid (audit M-8), so a relay that drops or substitutes one member's wrapped
// key entry — previously invisible, since the signature only covered `ct` —
// now fails verification for every recipient.
//
// `token` is only for fetching a key no response embedded (a live frame
// carries addresses only).
export const verifyMessageAuthenticity = async (msg, payload, mode, token = null) => {
    if (!payload || !payload.sig) return null;
    try {
        const from = (msg.sender_address || '').toLowerCase();
        let conv;
        if (mode === 'group') {
            if (!payload.gid || payload.gid !== msg.channel_id) return false;
            conv = msg.channel_id;
        } else {
            if (payload.gid) return false;
            conv = (msg.recipient_address || '').toLowerCase();
        }
        const body = await messageSigningBody({
            from,
            conv,
            gid: payload.gid || '',
            sid: payload.sid,
            // The sender's clock and session position (crypto-core 3.0.0,
            // K-06). Signed, so a relay cannot rewrite them to hide a replay.
            ts: payload.ts,
            seq: payload.seq,
            keys: payload.keys ?? null,
            ct: payload.ct,
        });
        const identityPublicKey = await identityKeyFor(from, { hint: msg.sender, token });
        if (!identityPublicKey) return false;
        return await verifyIdentitySignature({
            address: from, identityPublicKey, message: body, signature: payload.sig,
        });
    } catch {
        return false;
    }
};
