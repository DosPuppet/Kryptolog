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
