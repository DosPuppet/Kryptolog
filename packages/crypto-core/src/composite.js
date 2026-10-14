// Composite ML-DSA signatures (draft-ietf-lamps-pq-composite-sigs-19), behind
// a registry (crypto-core 4.2.0, lot 12; the only suite since 5.0.0):
//
//   MLDSA65-ECDSA-P384-SHA512
//
// A composite signature is valid only if BOTH halves verify: forging one needs
// ML-DSA-65 (FIPS 204, NIST category 3) AND ECDSA on P-384 to be broken. That
// is ANSSI's hybridization rule for signatures — concatenation, valid iff
// every component is (PG-083 v3.00 §2.2) — and the audit 2026-10-12 K-10
// finding. The construction is the IETF one, NOT noble's `combineSigners`,
// which signs the raw message under each key and carries no label: a composite
// signature here is a published, interoperable object that the server's
// OpenSSL verifies from the same specification.
//
// Why P-384 (5.0.0, the ninth cutover). The 4.x identity was ML-DSA-65 +
// Ed25519, and Ed25519 is not among the ECCG Agreed Cryptographic Mechanisms
// v2, which ANSSI accepts for certification (EC-DSA on P-256/384/521 and
// brainpool only), nor among the curves ANSSI's own PG-083 v3.00 names.
// ML-DSA-65 is agreed and stayed; only the traditional half changed, to the
// curve the KEM uses too (kem.js), so the project has one classical curve.
//
// Bytes in, bytes out. The wire encodings (hex keys, base64 signatures) belong
// to the callers in pqc.js, as for every other primitive.

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { p384 } from '@noble/curves/nist.js';
import { sha512 } from '@noble/hashes/sha2.js';

import { ENC } from './encoding.js';

// Fixed by the draft and shared by every composite algorithm. Each suite adds
// its own label; both are hashed into what each half signs, so a component
// signature cannot be lifted out and presented as a plain ML-DSA or
// traditional signature over the same message, nor moved to another
// combination.
const PREFIX = ENC.encode('CompositeAlgorithmSignatures2025');
const ML_PK = 1952;
const ML_SIG = 3309;
const ML_SEED = 32;
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
const messageFor = (label) => (message, ctx = EMPTY) => {
    if (!isBytes(message) || !isBytes(ctx)) throw new TypeError('compositeMessage: bytes expected');
    if (ctx.length > 255) throw new RangeError('compositeMessage: context longer than 255 bytes');
    return concat(PREFIX, label, Uint8Array.of(ctx.length), ctx, sha512(message));
};

// The ML-DSA-65 half: signed over M' under the suite's label as FIPS 204
// context. Hedged, so two signatures of one message
// differ.
const mlSign = (m, mlSeed, label) => ml_dsa65.sign(m, ml_dsa65.keygen(mlSeed).secretKey, { context: label });
const mlVerify = (sig, m, pk, label) => ml_dsa65.verify(sig, m, pk, { context: label });

// --- MLDSA65-ECDSA-P384-SHA512 ---
//
// The traditional half is ECDSA on P-384 with SHA-384 over M' (the draft's
// ecdsa-with-SHA384), its signature a DER Ecdsa-Sig-Value — so a composite
// signature has a VARIABLE length, 3 309 bytes of ML-DSA then 8 to 104 of DER.
//
// Two rules on top of the draft, enforced identically by the server
// (backend/auth.py), because ECDSA alone does not give them:
//
//   • LOW-S. (r, s) and (r, n - s) are both valid ECDSA signatures, and anyone
//     can compute the second from the first without the key: ECDSA is not
//     strongly unforgeable, as PG-083 v3.00 itself warns. A composite inherits
//     that from its weaker half, which RecoSignature.2 asks a hybrid not to
//     do (it should keep the additional properties of both components, and
//     ML-DSA is SUF-CMA). Requiring s <= n/2 leaves one valid s per signature.
//     The draft does not ask for it, and its own vector shows why it matters:
//     sWithContext's ECDSA half is high-S. Our signer always writes low-S.
//   • CANONICAL DER. A second spelling of the same (r, s) would be a second
//     valid signature by the same route; noble's DER decoder is strict
//     (minimal lengths, no superfluous leading zero, nothing trailing), and the
//     server re-encodes and compares.
//
// The secret key is the ML-DSA seed and the P-384 SCALAR, 80 bytes, drawn
// INDEPENDENTLY — deriving both from one seed would let a break of whichever
// derivation is weaker reach the other, which is the dependency a hybrid
// exists to avoid. The draft serializes the scalar as an RFC 5915
// ECPrivateKey; that wrapping says nothing the length does not, so a vault
// stores the 48 bytes, not ML-DSA's 4 032-byte expanded key either.

export const MLDSA65_P384_SIG_ALG = 'MLDSA65-ECDSA-P384-SHA512';
const P384_LABEL = ENC.encode('COMPSIG-MLDSA65-ECDSA-P384-SHA512');
const P384_POINT = 97;
const P384_SCALAR = 48;
const DER_MIN = 8; // 30 06 02 01 r 02 01 s
const DER_MAX = 104; // 30 66 02 31 00||r 02 31 00||s

export const MLDSA65_P384_LENGTHS = Object.freeze({
    publicKey: ML_PK + P384_POINT, // mldsa65PK || P-384 point, SEC1 uncompressed
    secretKey: ML_SEED + P384_SCALAR, // mldsa65Seed || P-384 scalar
    signature: ML_SIG + DER_MAX, // at most: mldsa65Sig || DER(r, s)
});

/** M' for MLDSA65-ECDSA-P384-SHA512. */
export const mldsa65P384Message = messageFor(P384_LABEL);

const p384Halves = (secretKey) => {
    if (!isBytes(secretKey, MLDSA65_P384_LENGTHS.secretKey)) {
        throw new RangeError(`composite secret key must be ${MLDSA65_P384_LENGTHS.secretKey} bytes`);
    }
    const scalar = secretKey.slice(ML_SEED);
    if (!p384.utils.isValidSecretKey(scalar)) throw new RangeError('composite secret key: P-384 scalar out of range');
    return { mlSeed: secretKey.slice(0, ML_SEED), scalar };
};

/** The composite public key of an 80-byte secret key. */
export const mldsa65P384PublicKey = (secretKey) => {
    const { mlSeed, scalar } = p384Halves(secretKey);
    return concat(ml_dsa65.keygen(mlSeed).publicKey, p384.getPublicKey(scalar, false));
};

/** A new key pair, its halves drawn independently, or the one a stored key names. */
export const mldsa65P384Keygen = (secretKey = concat(
    crypto.getRandomValues(new Uint8Array(ML_SEED)), p384.utils.randomSecretKey()
)) => {
    const copy = secretKey.slice();
    return { publicKey: mldsa65P384PublicKey(copy), secretKey: copy };
};

/**
 * Sign `message` (bytes). Both halves are hedged: ML-DSA by default, ECDSA by
 * RFC 6979 §3.6 extra entropy, so a fault or a reused deterministic nonce
 * cannot be steered by repeating a message.
 */
export const mldsa65P384Sign = (message, secretKey, ctx = EMPTY) => {
    const { mlSeed, scalar } = p384Halves(secretKey);
    const m = mldsa65P384Message(message, ctx);
    const ecSig = p384.sign(m, scalar, { format: 'der', lowS: true, extraEntropy: true });
    return concat(mlSign(m, mlSeed, P384_LABEL), ecSig);
};

/**
 * True only if BOTH halves verify, over exactly this message, key and context,
 * with a low-S, canonically DER-encoded ECDSA half. Never throws.
 */
export const mldsa65P384Verify = (signature, message, publicKey, ctx = EMPTY) => {
    try {
        if (!isBytes(signature)) return false;
        if (signature.length < ML_SIG + DER_MIN || signature.length > ML_SIG + DER_MAX) return false;
        if (!isBytes(publicKey, MLDSA65_P384_LENGTHS.publicKey)) return false;
        const point = publicKey.subarray(ML_PK);
        if (point[0] !== 0x04) return false; // one encoding: SEC1 uncompressed
        const m = mldsa65P384Message(message, ctx);
        return mlVerify(signature.subarray(0, ML_SIG), m, publicKey.subarray(0, ML_PK), P384_LABEL)
            && p384.verify(signature.subarray(ML_SIG), m, point, { format: 'der', lowS: true });
    } catch {
        return false;
    }
};

// --- The registry ---
//
// One shape for every suite: `{ alg, lengths, publicKey(sk), keygen(sk?),
// sign(message, sk, ctx?), verify(sig, message, pk, ctx?) }`, where
// `lengths.signature` is a MAXIMUM (a P-384 signature is variable-length).

export const SIGNATURE_SUITES = Object.freeze({
    [MLDSA65_P384_SIG_ALG]: Object.freeze({
        alg: MLDSA65_P384_SIG_ALG,
        lengths: MLDSA65_P384_LENGTHS,
        publicKey: mldsa65P384PublicKey,
        keygen: mldsa65P384Keygen,
        sign: mldsa65P384Sign,
        verify: mldsa65P384Verify,
    }),
});
