import { Shield, ShieldAlert, ShieldCheck } from 'lucide-react';

// Per-message authenticity indicator (audit S1 / F-2).
//
// `verified` is the end-to-end signature result for a received message:
//   true   → a valid ML-DSA signature from the claimed author,
//   false  → a signature was present but did NOT verify,
//   null/undefined → the message carried NO signature at all.
//
// Pre-F-2, the unsigned case rendered nothing, so a malicious/compromised server
// could silently strip the `sig` field and the recipient saw no cue at all —
// indistinguishable from a verified message. Unsigned messages now ALWAYS show
// an indicator:
//   • a neutral amber "unsigned" when the conversation has no signed history
//     (a legacy / non-signing peer — benign), and
//   • a loud red "unsigned" warning when `suspicious` is set — i.e. someone in
//     this conversation HAS produced valid signatures, so a missing one is a
//     likely signature-stripping / tampering attempt rather than an old client.
//
// Callers gate on `!isMe` (own messages aren't verified against the peer).
export default function MessageAuthBadge({ verified, suspicious = false }) {
    if (verified === true) {
        return <ShieldCheck className="w-3 h-3 text-emerald-500" title="Signature verified" />;
    }
    if (verified === false) {
        return (
            <span className="flex items-center gap-0.5 text-red-500 font-semibold" title="Signature invalid — author could not be verified">
                <ShieldAlert className="w-3 h-3" /> unverified
            </span>
        );
    }
    // Unsigned (null/undefined): no signature was attached to this message.
    if (suspicious) {
        return (
            <span
                className="flex items-center gap-0.5 text-red-500 font-semibold"
                title="Unsigned message — earlier messages here were signed, so this one's authenticity cannot be verified and it may have been tampered with."
            >
                <ShieldAlert className="w-3 h-3" /> unsigned
            </span>
        );
    }
    return (
        <span
            className="flex items-center gap-0.5 text-amber-500"
            title="Unsigned message — the author could not be cryptographically verified."
        >
            <Shield className="w-3 h-3" /> unsigned
        </span>
    );
}
