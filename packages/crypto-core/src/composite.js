// Composite ML-DSA signatures: id-MLDSA65-Ed25519-SHA512
// (draft-ietf-lamps-pq-composite-sigs-19), the hybrid signature of crypto-core 4.
//
// A composite signature is valid only if BOTH halves verify: forging one needs
// both ML-DSA-65 (FIPS 204, NIST category 3) and Ed25519 to be broken. That is
// ANSSI's hybridization rule (concatenation, valid iff all components are) at
// the level it asks for (category 3 or 5; the ML-DSA-44 of 3.x is category 2),
// and the audit 2026-10-12 K-10 finding. The construction is the IETF one, NOT
// noble's `combineSigners`, which signs the raw message under each key and
// carries no label: a composite signature here is a published, interoperable
// object that the server's OpenSSL verifies from the same specification.
//
// Bytes in, bytes out. The wire encodings (hex keys, base64 signatures) belong
// to the callers in pqc.js, as for every other primitive.

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';

import { ENC } from './encoding.js';

export const COMPOSITE_SIG_ALG = 'MLDSA65-Ed25519-SHA512';

// Fixed by the draft. The prefix is shared by every composite algorithm, the
// label names this one; both are hashed into what each half signs, so a
// component signature cannot be lifted out and presented as a plain ML-DSA or
// Ed25519 signature over the same message, nor moved to another combination.
const PREFIX = ENC.encode('CompositeAlgorithmSignatures2025');
const LABEL = ENC.encode('COMPSIG-MLDSA65-Ed25519-SHA512');

const ML_PK = 1952;
const ML_SIG = 3309;
const ML_SEED = 32;
export const COMPOSITE_LENGTHS = Object.freeze({
    publicKey: ML_PK + 32, // mldsa65PK || ed25519PK
    secretKey: ML_SEED + 32, // mldsa65Seed || ed25519Seed: the draft's serialization
    signature: ML_SIG + 64, // mldsa65Sig || ed25519Sig
});
const EMPTY = new Uint8Array(0);

const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
};

// Realm-independent, as noble's own check is: a Uint8Array made in another
// realm (jsdom's TextEncoder, an iframe) fails `instanceof` while being bytes.
export const isUint8Array = (b) =>
    b instanceof Uint8Array || (ArrayBuffer.isView(b) && b.constructor?.name === 'Uint8Array');
const isBytes = (b, length) => isUint8Array(b) && (length === undefined || b.length === length);

/**
 * M' = Prefix || Label || len(ctx) || ctx || SHA-512(M): what both halves sign.
 * The application context is one length byte, so at most 255 bytes.
 */
export const compositeMessage = (message, ctx = EMPTY) => {
    if (!isBytes(message) || !isBytes(ctx)) throw new TypeError('compositeMessage: bytes expected');
    if (ctx.length > 255) throw new RangeError('compositeMessage: context longer than 255 bytes');
    return concat(PREFIX, LABEL, Uint8Array.of(ctx.length), ctx, sha512(message));
};

const halves = (secretKey) => {
    if (!isBytes(secretKey, COMPOSITE_LENGTHS.secretKey)) {
        throw new RangeError(`composite secret key must be ${COMPOSITE_LENGTHS.secretKey} bytes`);
    }
    // Copies: noble's keygen(seed) keeps a reference to the buffer it is given.
    return { mlSeed: secretKey.slice(0, ML_SEED), edSeed: secretKey.slice(ML_SEED) };
};

/** The composite public key of a 64-byte composite secret key. */
export const compositePublicKey = (secretKey) => {
    const { mlSeed, edSeed } = halves(secretKey);
    return concat(ml_dsa65.keygen(mlSeed).publicKey, ed25519.getPublicKey(edSeed));
};

/**
 * A new key pair. The two halves are drawn INDEPENDENTLY — deriving both from
 * one seed would let a break of whichever derivation is weaker reach the
 * other, which is the dependency a hybrid exists to avoid. `secretKey` may be
 * given (64 bytes) to rebuild a stored key; the secret is that seed pair, so a
 * vault stores 64 bytes instead of ML-DSA's 4 032-byte expanded key.
 */
export const compositeKeygen = (secretKey = crypto.getRandomValues(new Uint8Array(COMPOSITE_LENGTHS.secretKey))) => {
    const copy = secretKey.slice();
    return { publicKey: compositePublicKey(copy), secretKey: copy };
};

/** Sign `message` (bytes). ML-DSA is hedged, so two signatures of one message differ. */
export const compositeSign = (message, secretKey, ctx = EMPTY) => {
    const { mlSeed, edSeed } = halves(secretKey);
    const m = compositeMessage(message, ctx);
    const mlSig = ml_dsa65.sign(m, ml_dsa65.keygen(mlSeed).secretKey, { context: LABEL });
    return concat(mlSig, ed25519.sign(m, edSeed));
};

// Ed25519 as OpenSSL verifies it — the server's library, which the clients
// must never be more lenient than.
//
// noble's `zip215: false` gives RFC 8032 DECODING (canonical encodings only,
// small-order public keys refused), but it still checks the COFACTORED
// equation [8][S]B = [8]R + [8][k]A, where OpenSSL checks the cofactorless
// [S]B = R + [k]A. The two disagree on a signature whose R carries a
// small-order component: noble accepted one built that way and OpenSSL refused
// it (measured 2026-10-13; the vector is in the hybrid test). Requiring R and A
// to be torsion-free makes the two equations coincide, so a client never shows
// as valid a signature the server would have refused — the direction that
// matters for Proof Audit, which must not vouch for an approval the server
// never took. Only the key's owner can build such a signature (it needs the
// secret scalar), so this closes a disagreement, not a forgery.
const ed25519VerifyStrict = (signature, message, publicKey) => {
    if (!ed25519.verify(signature, message, publicKey, { zip215: false })) return false;
    const Point = ed25519.Point;
    return Point.fromBytes(signature.subarray(0, 32)).isTorsionFree()
        && Point.fromBytes(publicKey).isTorsionFree();
};

/**
 * True only if BOTH halves verify, over exactly this message, key and context.
 * Never throws: anything malformed — a wrong length above all, checked before
 * any splitting so a short input cannot shift where one half ends — is false.
 */
export const compositeVerify = (signature, message, publicKey, ctx = EMPTY) => {
    try {
        if (!isBytes(signature, COMPOSITE_LENGTHS.signature)) return false;
        if (!isBytes(publicKey, COMPOSITE_LENGTHS.publicKey)) return false;
        const m = compositeMessage(message, ctx);
        const mlOk = ml_dsa65.verify(
            signature.subarray(0, ML_SIG), m, publicKey.subarray(0, ML_PK), { context: LABEL }
        );
        return mlOk && ed25519VerifyStrict(signature.subarray(ML_SIG), m, publicKey.subarray(ML_PK));
    } catch {
        return false;
    }
};
