// Domain separation and the exact bytes each kind of signature covers.
//
// Nothing here signs anything; it produces the STRING that gets signed. Sender
// and receiver must build these identically, byte for byte, which is why they
// live apart from the key handling in pqc.js.

import { sha384Hex, canonicalJson } from './encoding.js';
// The attestation helpers below sign and verify, so this module leans on pqc.js.
// One-directional: pqc.js does not import signing.js, so there is no cycle.
import { signMessage } from './pqc.js';
import { verifyIdentitySignature, isAddress } from './identity.js';

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
    CONVERSATION_ERASE: 'conversation-erase',
});
const DS_HEADER = 'Kryptolog Signed Message v1';
export const domainSeparate = (context, body) => `${DS_HEADER}\ncontext=${context}\n${body}`;

// The exact prefix of any `message`-context payload. The extension's silent
// message-signing path checks for this so it will ONLY auto-sign chat messages,
// never a login / multisig / content signature (those use other contexts).
export const MESSAGE_SIGNING_PREFIX = domainSeparate(SIGNING_CONTEXT.MESSAGE, '');

// --- Identifiers inside signed bodies (crypto-core 3.0.0, audit 2026-09-23 Q-6) ---
//
// The bodies are `key=value` lines with no escaping, so they are only injective
// — one body, one meaning — if no interpolated value can contain a line break
// followed by another label. That used to hold by circumstance: honest clients
// generate UUIDs. It holds by construction now: every identifier is checked
// against its alphabet on the way in, by the signer and the verifier alike, and
// the Python mirror applies the same patterns.
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const HEX_RE = /^[0-9a-f]+$/;
// An origin as browsers serialise it: scheme, host, optional port, no path, no
// trailing slash, lowercase. Exactly what `window.location.origin` and Chrome's
// `sender.origin` produce, so the extension can compare them as strings.
const ORIGIN_RE = /^https?:\/\/[a-z0-9.-]+(:[0-9]{1,5})?$/;

export class SignedBodyError extends Error {
    constructor(message) {
        super(message);
        this.name = 'SignedBodyError';
    }
}

const need = (ok, what) => {
    if (!ok) throw new SignedBodyError(`signed body: invalid ${what}`);
};
const isCount = (n) => Number.isSafeInteger(n) && n >= 0;

export const isCanonicalOrigin = (origin) => typeof origin === 'string' && ORIGIN_RE.test(origin);
export const isSignedIdentifier = (id) => typeof id === 'string' && ID_RE.test(id);

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
export const messageSigningBody = async ({ from, conv, sid, ct, gid = '', keys = null, ts, seq }) => {
    // An address, or a channel id (crypto-core 4.0.0): the two alphabets are
    // disjoint — 96 hex characters against at most 64 — so neither can be
    // mistaken for the other on either side.
    need(isAddress(from), 'sender');
    need(isAddress(conv) || isSignedIdentifier(conv), 'conversation');
    need(gid === '' || gid == null || isSignedIdentifier(gid), 'group id');
    need(isSignedIdentifier(sid), 'session id');
    // `ts` and `seq` (crypto-core 3.0.0, audit 2026-10-12 K-06): the sender's
    // clock in ms and its position in the session. Neither existed, so a server
    // could re-deliver an old, perfectly verified message as new, drop one, or
    // reorder them, and every copy still showed "verified". With both signed,
    // the receiver can tell a replay (a seq it has seen, or a ts far from the
    // delivery time), a gap, and a reordering — see messenger/freshness.js.
    need(isCount(ts), 'timestamp');
    need(isCount(seq), 'sequence number');
    return domainSeparate(SIGNING_CONTEXT.MESSAGE,
        `from=${from}\nconv=${conv}\ngid=${gid ?? ''}\nsid=${sid}\nts=${ts}\nseq=${seq}` +
        `\nkeysh=${await sha384Hex(canonicalJson(keys ?? null))}` +
        (ct == null ? '\nredacted=1' : `\nct=${canonicalCiphertext(ct)}`));
};

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
export const loginChallengeBody = ({ nonce, origin, deployment, encryptionKey = null }) => {
    need(typeof nonce === 'string' && HEX_RE.test(nonce), 'nonce');
    // WHERE this login is for (crypto-core 3.0.0, audit 2026-10-12 K-02). The
    // challenge named no server, so any site that could obtain a signature over
    // it — a connected site asking TrustKeys, another Kryptolog deployment the
    // same identity uses — could relay a nonce from the real server and open a
    // session there. The server now refuses an origin it does not serve and a
    // deployment that is not its own; TrustKeys refuses to sign an origin that
    // is not the one the browser says is asking.
    need(isCanonicalOrigin(origin), 'origin');
    need(isSignedIdentifier(deployment), 'deployment');
    need(encryptionKey == null || encryptionKey === '' || HEX_RE.test(encryptionKey), 'encryption key');
    return domainSeparate(
        SIGNING_CONTEXT.LOGIN,
        `Sign in to Kryptolog\norigin=${origin}\ndeployment=${deployment}\nnonce=${nonce}` +
        `\nencryption-key=${encryptionKey || ''}`
    );
};

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
export const accountDeletionBody = async ({ nonce, mode, redactionKeys = [], origin, deployment }) => {
    need(typeof nonce === 'string' && HEX_RE.test(nonce), 'nonce');
    need(mode === 'leave' || mode === 'erase', 'mode');
    // Bound to the server like the login challenge (K-02): destroying an
    // account is not a signature a relay should be able to carry elsewhere.
    need(isCanonicalOrigin(origin), 'origin');
    need(isSignedIdentifier(deployment), 'deployment');
    return domainSeparate(SIGNING_CONTEXT.ACCOUNT_DELETION,
        `origin=${origin}\ndeployment=${deployment}\nnonce=${nonce}\nmode=${mode}` +
        `\nredactions=${await sha384Hex(canonicalJson([...redactionKeys].sort()))}`);
};

// Erasing one's OWN messages in ONE conversation (crypto-core 3.1.0, additive;
// audit 2026-09-11 M-6). The account erase, scoped: the server redacts the
// session carriers this signature names and deletes the rest of the caller's
// messages in that conversation — never the other side's.
//
// Its own context, outside `message`, for the reason the account erase has
// one: TrustKeys signs `message` bodies SILENTLY for a site holding a grant,
// and the per-message redactions are exactly such bodies. Without a separate,
// popup-gated authorization, any connected site could wipe a user's side of
// any conversation. The conversation is named in full — `dm:<partner address>`
// or `group:<channel id>` — so a relay cannot carry an approval for one
// conversation over to another.
export const conversationEraseBody = async ({
    nonce, kind, conversation, redactionKeys = [], origin, deployment,
}) => {
    need(typeof nonce === 'string' && HEX_RE.test(nonce), 'nonce');
    need(
        (kind === 'dm' && isAddress(conversation)) ||
        (kind === 'group' && isSignedIdentifier(conversation)),
        'conversation'
    );
    need(isCanonicalOrigin(origin), 'origin');
    need(isSignedIdentifier(deployment), 'deployment');
    return domainSeparate(SIGNING_CONTEXT.CONVERSATION_ERASE,
        `origin=${origin}\ndeployment=${deployment}\nnonce=${nonce}` +
        `\nconversation=${kind}:${conversation}` +
        `\nredactions=${await sha384Hex(canonicalJson([...redactionKeys].sort()))}`);
};

// --- Encryption-key attestation (audit M-1) ---
// The address names the identity key (self-certifying, identity.js), but the
// encryption key is a separate directory field the server could lie about. An
// identity therefore SELF-SIGNS its own encryption key: peers verify the
// signature, with the key the address names, before wrapping anything to it,
// so a malicious directory cannot substitute a KEM key it controls. The
// message is fixed and self-referential (never site- or peer-supplied), and
// the `key-attestation` context keeps it disjoint from login/content/message
// signatures. The server stores + verifies it too (backend
// auth.encryption_key_attestation_message must stay byte-identical).
//
// Since 4.0.0 it names the ADDRESS as well: the statement is "this encryption
// key is <address>'s", not merely "I hold this key", so an attestation cannot
// be lifted onto another identity's record even by a key that signs for both.
export const encryptionKeyAttestationBody = ({ address, encryptionPublicKey }) => {
    need(isAddress(address), 'address');
    need(typeof encryptionPublicKey === 'string' && HEX_RE.test(encryptionPublicKey), 'encryption key');
    return domainSeparate(
        SIGNING_CONTEXT.KEY_ATTESTATION, `address=${address}\nencryption=${encryptionPublicKey}`
    );
};

export const attestEncryptionKey = async ({ address, encryptionPublicKey }, identitySeedHex) =>
    signMessage(encryptionKeyAttestationBody({ address, encryptionPublicKey }), identitySeedHex);

// Verified as the identity `address`, with the key the address names
// (3.3.0, identity.js): a directory that serves a key under somebody else's
// address does not get an attestation accepted on that key's word.
export const verifyEncryptionKeyAttestation = async ({
    address, identityPublicKey, encryptionPublicKey, attestation,
}) => {
    if (!encryptionPublicKey || !attestation) return false;
    let message;
    try {
        message = encryptionKeyAttestationBody({ address, encryptionPublicKey });
    } catch {
        return false;
    }
    return verifyIdentitySignature({ address, identityPublicKey, message, signature: attestation });
};

// Safety-number fingerprint of an identity + its encryption key, for manual
// out-of-band comparison (both parties read the SAME number for a contact —
// it's a digest of the contact's keys, not of the pair of participants).
// SHA-384 over a labelled, versioned statement of the two → 60 decimal digits
// in 12 groups of 5, Signal-style: digits are easier to read aloud / compare
// than hex. 4.0.0 changed the number for every contact, deliberately: the keys
// it summarises changed too.
export const keyFingerprint = async (address, encryptionPublicKey) => {
    const hex = await sha384Hex(
        `Kryptolog safety number v4\naddress=${address}\nencryption=${encryptionPublicKey}`
    );
    const groups = [];
    for (let i = 0; i < 12; i++) {
        // 5 hex chars (20 bits) per group → mod 100000 keeps 5 decimal digits.
        const chunk = parseInt(hex.slice(i * 5, i * 5 + 5), 16) % 100000;
        groups.push(String(chunk).padStart(5, '0'));
    }
    return groups.join(' ');
};

// Server-verifiable multisig approval message (audit M1). A signer approves a
// workflow by signing the SHA-384 (4.0.0) of the STORED CIPHERTEXT, bound to the
// workflow + secret id. The server is zero-knowledge (can't see plaintext) but
// can hash the ciphertext it holds, so it can verify this. Must be byte-
// identical to the server's auth.multisig_approval_message().
export const multisigApprovalMessage = (workflowId, secretId, ciphertextSha384Hex) =>
    domainSeparate(
        SIGNING_CONTEXT.MULTISIG_APPROVAL,
        `workflow=${workflowId}\nsecret=${secretId}\nct=${ciphertextSha384Hex}`
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
