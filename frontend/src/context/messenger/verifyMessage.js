import { messageSigningBody, verifySignaturePQC } from '../../utils/crypto';

// Verify a message's end-to-end signature (audit S1). Rebuilds the exact bytes
// the sender signed and checks them against the claimed sender_address (which IS
// the sender's ML-DSA public key), so a server can't forge or re-attribute a
// message. Returns true/false, or null for an unsigned (legacy) message.
//
// The conversation binding (`conv`) MUST come from the SERVER-ATTESTED delivery
// context, never from a sender/server-supplied field inside the content (audit
// F-1): DMs bind to the message row's recipient_address; groups bind to the
// row's channel_id — NOT payload.gid, which a malicious server could rewrite to
// re-home a message Alice signed for channel A into channel B (one she and the
// viewer both belong to) while it still showed as "verified". For groups we also
// reject outright when the payload's self-declared gid disagrees with the
// channel the message was actually delivered under.
export const verifyMessageAuthenticity = async (msg, payload, mode) => {
    if (!payload || !payload.sig) return null;
    try {
        const from = (msg.sender_address || '').toLowerCase();
        let conv;
        if (mode === 'group') {
            if (payload.gid && payload.gid !== msg.channel_id) return false;
            conv = msg.channel_id || '';
        } else {
            conv = (msg.recipient_address || '').toLowerCase();
        }
        const body = messageSigningBody({ from, conv, sid: payload.sid, ct: payload.ct });
        return await verifySignaturePQC(body, payload.sig, msg.sender_address);
    } catch {
        return false;
    }
};
