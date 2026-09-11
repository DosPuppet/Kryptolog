// Hex, digests and canonical JSON — the encodings every other module builds on.
//
// This module has no dependencies of its own, deliberately: everything else
// here imports from it, so a cycle is impossible by construction.

// Helper: Uint8Array/Array <-> Hex. Deliberately Buffer-free so this package
// stays a pure, runtime-agnostic ESM module (Node, browser SPA, MV3 extension)
// with no Node polyfill dependency — that's what lets a single symlinked copy
// build cleanly in both Vite apps. Output is byte-identical to the previous
// Buffer.from(...).toString('hex') (lowercase, two chars per byte).
// Module-level like the _HEX table below: these are stateless and were being
// reallocated on every encrypt, decrypt, digest and canonicalisation.
export const ENC = new TextEncoder();
export const DEC = new TextDecoder();

const _HEX = [];
for (let i = 0; i < 256; i++) _HEX.push(i.toString(16).padStart(2, '0'));
export const toHex = (arr) => {
    const bytes = arr instanceof Uint8Array ? arr : new Uint8Array(arr);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) hex += _HEX[bytes[i]];
    return hex;
};
// Throws rather than guessing (audit L-9). This used to feed every character
// pair to parseInt(_, 16) and store the result, so a non-hex pair became NaN,
// NaN stored into a Uint8Array became 0, and a corrupted public key silently
// decoded to a key of ZEROS instead of raising. An odd-length string quietly
// lost its last character the same way. Both turn "this data is damaged" into
// "this data is valid and different", which is the worst answer a decoder can
// give — every caller here is decoding a key, iv, salt or ciphertext, and none
// of them can act on a silently substituted one. Matches the backend's is_hex.
const _HEX_ONLY = /^[0-9a-fA-F]+$/;
export const fromHex = (hex) => {
    if (typeof hex !== 'string' || hex.length === 0 || hex.length % 2 !== 0 || !_HEX_ONLY.test(hex)) {
        throw new Error('fromHex: expected a non-empty, even-length hex string');
    }
    const len = hex.length >> 1;
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
};

// --- Base64: the encoding for opaque payloads (audit L-12) ---
//
// Hex costs 2 characters per byte; base64 costs 1.33. On the 50 MB file ceiling
// that is 100 MB stored and transferred instead of 67 MB, and it is ~25% off
// every message envelope (a wrapped ML-KEM session key, a 2 420-byte signature).
//
// The split is deliberate and is NOT "base64 everywhere": identifiers stay hex.
// An address IS an ML-DSA public key — a primary key, a URL path segment, and
// part of every signed login body — and the project normalizes addresses to
// lowercase everywhere, which a case-sensitive encoding would quietly destroy.
// Same for the ML-KEM public key (folded into the signed login challenge) and
// for SHA-256 digests, which must keep matching Python's hexdigest(). What moves
// is the opaque stuff: ciphertext, IVs, wrapped keys, signatures, vault blobs.
//
// btoa/atob rather than Buffer, for the same reason toHex is hand-rolled: this
// package has to run unchanged in Node, the browser SPA and an MV3 service
// worker. Standard alphabet with padding (not base64url) — these values live in
// JSON bodies and Postgres text, never in a URL.
const _B64_ONLY = /^[A-Za-z0-9+/]*={0,2}$/;
// 8 KB per btoa call: String.fromCharCode(...bytes) on a 1 MB chunk blows the
// argument limit and crashes, so the binary string is built in slices.
const _B64_SLICE = 8192;
export const toB64 = (arr) => {
    const bytes = arr instanceof Uint8Array ? arr : new Uint8Array(arr);
    let binary = '';
    for (let i = 0; i < bytes.length; i += _B64_SLICE) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + _B64_SLICE));
    }
    return btoa(binary);
};
const _B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const _B64_VALUES = new Uint8Array(128);
for (let i = 0; i < _B64_ALPHABET.length; i++) _B64_VALUES[_B64_ALPHABET.charCodeAt(i)] = i;

// Throws rather than guessing, exactly as fromHex does and for the same reason
// (audit L-9): every caller is decoding a key, iv or ciphertext, and none can
// act on a silently substituted one. atob alone is not enough — it accepts
// whitespace and non-canonical trailing bits, so two different strings could
// decode to the same bytes. That matters beyond tidiness: a message signature
// commits to the ciphertext in its STRING form, so a malleable encoding would
// let the same bytes be presented under a second, equally valid signature.
export const fromB64 = (b64) => {
    if (typeof b64 !== 'string' || b64.length === 0 || b64.length % 4 !== 0 || !_B64_ONLY.test(b64)) {
        throw new Error('fromB64: expected a non-empty, padded, canonical base64 string');
    }
    // Reject non-canonical padding: the bits below the encoded length must be
    // zero, or the value has more than one valid spelling.
    const pad = b64.endsWith('==') ? 2 : b64.endsWith('=') ? 1 : 0;
    if (pad) {
        const last = _B64_VALUES[b64.charCodeAt(b64.length - pad - 1)];
        if (last & (pad === 2 ? 0b1111 : 0b11)) {
            throw new Error('fromB64: non-canonical base64 (unused trailing bits are set)');
        }
    }
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
};

// SHA-256 -> lowercase hex (matches Python hashlib.sha256().hexdigest()).
export const sha256HexBytes = async (bytes) =>
    toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));

// The same over a UTF-8 string. Separate from the bytes form on purpose: which
// one a caller wants is a real decision — hashing a File's contents and hashing
// its name are both plausible and give different answers.
export const sha256Hex = async (str) => sha256HexBytes(ENC.encode(str));

// Deterministic JSON with recursively sorted object keys. JSON.stringify would
// NOT do: it preserves insertion order, so the sender and a verifier that
// rebuilt the object from a re-serialized payload could produce different bytes
// for the same value and the signature would fail for reasons that look random.
// Every party has to derive the identical string from the identical value, so
// key order has to come from the data, not from how it was constructed.
export const canonicalJson = (value) => {
    if (value === null || value === undefined) return 'null';
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
    if (typeof value === 'object') {
        return `{${Object.keys(value).sort()
            .map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
            .join(',')}}`;
    }
    return JSON.stringify(value);
};
