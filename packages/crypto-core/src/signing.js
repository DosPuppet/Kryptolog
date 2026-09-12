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
    ACCOUNT_DELETION: 'account-deletion',
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
// signature. iv/content are base64 since L-12, and '.' is not in that alphabet
// (A-Za-z0-9+/=), so the separator stays unambiguous — and fromB64 rejects
// non-canonical spellings, so one ciphertext has exactly one signed form.
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
// `redacted=1` — the form an author signs when removing their own content
// (account deletion). The key envelope has to survive the removal: a DM epoch's
// session key lives in the FIRST message under that sid, and the partner's own
// replies reuse it with keys:null, so deleting that message takes the partner's
// authored history with it. Redacting keeps `keys` and drops only `ct`.
//
// It is a DISJOINT branch, not a missing field, and that is the whole point:
//   • `\nct=` is always emitted for a present ciphertext and `\nredacted=`
//     never is, so no ciphertext value can spell a redaction and no redaction
//     can be read as a ciphertext. (A bare `ct=null` would have collided with
//     the literal string ciphertext "null" — one signature valid for two
//     different messages, which is the L-12 defect in a new place.)
//   • Because the author must SIGN this form, a redaction is an authenticated
//     statement rather than an absence: the server cannot strip `ct` from a
//     live message and pass it off as one (the original signature covers
//     `ct=…`), and cannot un-redact one either.
// `ct == null` catches null and undefined alike, so "absent" and "explicitly
// null" cannot diverge between the two languages.
//
// Async because of the digest — every call site must await it.
export const messageSigningBody = async ({ from, conv, sid, ct, gid = '', keys = null }) =>
    domainSeparate(SIGNING_CONTEXT.MESSAGE,
        `from=${from}\nconv=${conv}\ngid=${gid ?? ''}\nsid=${sid}` +
        `\nkeysh=${await sha256Hex(canonicalJson(keys ?? null))}` +
        (ct == null ? '\nredacted=1' : `\nct=${canonicalCiphertext(ct)}`));

// --- Login challenge ---
// The bytes a client signs to prove it holds the identity key, domain-separated
// under `login` (audit H1) so a content or message signature can never be
// replayed as one. When an ML-KEM key is supplied it is folded in, so the
// identity's signature authorizes that key and a network attacker cannot
// substitute their own at login (audit M-2).
//
// This lived inline in the SPA until now, while every other signed body was
// already here. That made it the one string both sides must agree on byte for
// byte with no shared source, no cross-language fixture, and no test that could
// fail on a mismatch — backend/tests/conftest.py stubs the verifier, so a typo
// in either copy would have passed the whole suite and broken every login.
// Must stay byte-identical to backend/auth.py `_login_message`.
export const loginChallengeBody = (nonce, encryptionPublicKeyHex = null) =>
    domainSeparate(
        SIGNING_CONTEXT.LOGIN,
        `Sign in to Kryptolog with nonce: ${nonce}` +
        (encryptionPublicKeyHex ? `\nEncryption key: ${encryptionPublicKeyHex}` : '')
    );

// --- Account deletion ---
// The bytes a client signs to authorize destroying its own account. Its own
// context, so a login signature (which a relay could obtain by other means) can
// never be replayed as one (audit H1) — and, the other way round, the extension
// will not auto-sign this: it silently signs only `message`-context bodies, so
// account deletion surfaces an explicit approval popup.
//
// `mode` is signed because the two modes are not interchangeable: without it a
// relay could downgrade an "erase" into a "leave" (the data the user asked to
// destroy stays) or escalate a "leave" into an "erase" (data destroyed that the
// user asked to keep), under a signature the server accepts either way.
//
// The redaction set is signed for the same class of reason: dropping one entry
// en route turns a redaction into a deletion, which takes the partner's own
// history with it. Digested rather than inlined — same reasoning as `keysh` —
// so the body stays a fixed size for an account with thousands of epochs.
//
// Entries are `"dm:<id>"` / `"group:<id>"`, NOT bare ids: DMs and group
// messages live in tables with independent id sequences, so a bare 412 names
// two different rows and a relay could drop one of them while the set still
// matched. The prefix is what makes the set a set of messages rather than of
// numbers.
//
// Sorted with the DEFAULT comparator on purpose, now that these are strings:
// JS sorts by UTF-16 code unit and Python's sorted() by code point, which agree
// exactly over the ASCII these ids are made of. (Numeric ids would not have
// been safe here — JS's default sort is lexicographic, so [2, 10] would spell
// [10, 2] on one side and [2, 10] on the other.)
export const accountDeletionBody = async (nonce, mode, redactionKeys = []) =>
    domainSeparate(SIGNING_CONTEXT.ACCOUNT_DELETION,
        `nonce=${nonce}\nmode=${mode}\nredactions=${await sha256Hex(
            canonicalJson([...redactionKeys].sort()))}`);

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
