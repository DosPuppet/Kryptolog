// Domain separation and the exact bytes each kind of signature covers.
//
// Nothing here signs anything; it produces the STRING that gets signed. Sender
// and receiver must build these identically, byte for byte, which is why they
// live apart from the key handling in pqc.js.

import { sha256Hex, canonicalJson } from './encoding.js';
// The attestation helpers below sign and verify, so this module leans on pqc.js.
// One-directional: pqc.js does not import signing.js, so there is no cycle.
import { signMessage, verifySignature } from './pqc.js';

// --- Domain separation (audit H1) ---
// Every signed payload is wrapped with a context tag *before* it is signed, so a
// signature minted for one purpose (e.g. approving multisig/document content)
// can never be replayed as another (e.g. a login challenge). The context is
// fixed here by the calling code — never drawn from user-supplied content — and
// the header line cannot be reproduced by a content body, so the namespaces are
// disjoint. The server (backend/auth.py `_login_message`) and the Ethereum path
// apply the identical wrapper, so signatures stay interoperable across libs.
export const SIGNING_CONTEXT = Object.freeze({
    LOGIN: 'login',
    CONTENT: 'content',
    MULTISIG_APPROVAL: 'multisig-approval',
    MESSAGE: 'message',
    KEY_ATTESTATION: 'key-attestation',
});
const DS_HEADER = 'Kryptolog Signed Message v1';
export const domainSeparate = (context, body) => `${DS_HEADER}\ncontext=${context}\n${body}`;

// The exact prefix of any `message`-context payload. The extension's silent
// message-signing path checks for this so it will ONLY auto-sign chat messages,
// never a login / multisig / content signature (those use other contexts).
export const MESSAGE_SIGNING_PREFIX = domainSeparate(SIGNING_CONTEXT.MESSAGE, '');

// Canonicalize the ciphertext field for signing. Production passes the AES-GCM
// envelope OBJECT { iv, content } (as returned by encryptWithSessionKey); a bare
// string (an already-serialized ct) is signed as-is. This explicit serialization
// is load-bearing: interpolating the object directly would coerce it to the
// constant "[object Object]", so the signature would NOT commit to the real
// ciphertext and any same-session ciphertext could be swapped under a valid
// signature. iv/content are hex, so a '.' separator is unambiguous.
const canonicalCiphertext = (ct) =>
    (ct && typeof ct === 'object') ? `${ct.iv}.${ct.content}` : ct;

// Canonical bytes a sender signs for one chat message (audit S1: authenticate
// messages end-to-end, not just encrypt them). Binds the author, the
// conversation (DM recipient address or group channel id), the declared group
// id, the session id, the KEY ENVELOPE, and the exact ciphertext, under the
// `message` domain so it can't be replayed as another signature type. Sender and
// every receiver build this identically:
//   from = message.sender_address, conv = recipient_address (DM) | channel_id (group).
//
// `keysh` — digest of the per-recipient wrapped-key map (audit M-8). Without it
// the signature covered `ct` but not `keys`, so a relay could DROP or substitute
// one member's entry and the message still verified for everyone else. It cannot
// read anything that way (wrapping a valid entry needs the session key), but it
// can silently exclude one member from a session epoch — targeted censorship
// that reaches the victim only as "encrypted, key unavailable". Digested rather
// than inlined because the map holds a full ML-KEM envelope per member.
//
// `gid` is signed as well even though `conv` already binds the server-attested
// channel_id: it makes the payload's self-declared group id part of the signed
// statement rather than something only a separate equality check defends.
//
// Async because of the digest — every call site must await it.
export const messageSigningBody = async ({ from, conv, sid, ct, gid = '', keys = null }) =>
    domainSeparate(SIGNING_CONTEXT.MESSAGE,
        `from=${from}\nconv=${conv}\ngid=${gid ?? ''}\nsid=${sid}` +
        `\nkeysh=${await sha256Hex(canonicalJson(keys ?? null))}\nct=${canonicalCiphertext(ct)}`);

// --- Encryption-key attestation (audit M-1) ---
// The address IS the ML-DSA public key (self-certifying), but the ML-KEM
// encryption key is a separate directory field the server could lie about. An
// identity therefore SELF-SIGNS its own ML-KEM key: peers verify the signature
// against the address before wrapping anything to that key, so a malicious
// directory can no longer substitute a KEM key it controls. The message is
// fixed and self-referential (never site- or peer-supplied), and the
// `key-attestation` context keeps it disjoint from login/content/message
// signatures. The server stores + verifies it too (backend
// auth.encryption_key_attestation_message must stay byte-identical).
export const encryptionKeyAttestationBody = (mlkemPublicKeyHex) =>
    domainSeparate(SIGNING_CONTEXT.KEY_ATTESTATION, `mlkem=${mlkemPublicKeyHex}`);

export const attestEncryptionKey = async (mlkemPublicKeyHex, mldsaPrivateKeyHex) =>
    signMessage(encryptionKeyAttestationBody(mlkemPublicKeyHex), mldsaPrivateKeyHex);

export const verifyEncryptionKeyAttestation = async (addressHex, mlkemPublicKeyHex, signatureHex) => {
    if (!addressHex || !mlkemPublicKeyHex || !signatureHex) return false;
    return verifySignature(encryptionKeyAttestationBody(mlkemPublicKeyHex), signatureHex, addressHex);
};

// Safety-number fingerprint of an identity + its encryption key, for manual
// out-of-band comparison (both parties read the SAME number for a contact —
// it's a digest of the contact's keys, not of the pair of participants).
// SHA-256 over the attestation body → 60 decimal digits in 12 groups of 5,
// Signal-style: digits are easier to read aloud / compare than hex.
export const keyFingerprint = async (addressHex, mlkemPublicKeyHex) => {
    const hex = await sha256Hex(`fingerprint\naddr=${addressHex}\nmlkem=${mlkemPublicKeyHex}`);
    const groups = [];
    for (let i = 0; i < 12; i++) {
        // 5 hex chars (20 bits) per group → mod 100000 keeps 5 decimal digits.
        const chunk = parseInt(hex.slice(i * 5, i * 5 + 5), 16) % 100000;
        groups.push(String(chunk).padStart(5, '0'));
    }
    return groups.join(' ');
};

// Server-verifiable multisig approval message (audit M1). A signer approves a
// workflow by signing the SHA-256 of the STORED CIPHERTEXT, bound to the
// workflow + secret id. The server is zero-knowledge (can't see plaintext) but
// can hash the ciphertext it holds, so it can verify this. Must be byte-
// identical to the server's auth.multisig_approval_message().
export const multisigApprovalMessage = (workflowId, secretId, ciphertextSha256Hex) =>
    domainSeparate(
        SIGNING_CONTEXT.MULTISIG_APPROVAL,
        `workflow=${workflowId}\nsecret=${secretId}\nct=${ciphertextSha256Hex}`
    );

// --- Device transfer passphrase ---
// A high-entropy (128-bit) human-transcribable passphrase for one-time
// device-to-device vault transfer. Crockford base32 (no 0/1/O/I ambiguity),
// grouped for readability: e.g. "K7Q4-9F2M-RX83-...". Carried out of band
// (QR / typed) — never sent to the server.
const _B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const generateTransferCode = () => {
    const bytes = crypto.getRandomValues(new Uint8Array(16)); // 128 bits
    let bits = '';
    for (const b of bytes) bits += b.toString(2).padStart(8, '0');
    let out = '';
    for (let i = 0; i < bits.length; i += 5) {
        out += _B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
    }
    // Group into 4-char blocks for legibility.
    return out.match(/.{1,4}/g).join('-');
};
