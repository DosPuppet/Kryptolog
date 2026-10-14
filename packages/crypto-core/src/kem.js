// The hybrid KEM, behind a registry (crypto-core 4.1.0, lot 12; the only suite
// since 5.0.0):
//
//   HKDFwSHA384_P384_ML-KEM-768_CatKDF   ETSI TS 103 744 V1.2.2 CatKDF over
//                                        P-384 ECDH + ML-KEM-768
//
// It holds while EITHER of its halves does (audit 2026-10-12 K-10), and it is
// what the references ANSSI accepts for certification name. The ECCG Agreed
// Cryptographic Mechanisms v2 (April 2025) agree P-256/384/521 and brainpool
// curves only and ETSI TS 103 744's CatKDF/CasKDF as the combiners; ANSSI's
// PQC FAQ recommends CatKDF/CasKDF by name; PG-083 v3.00 (2026-03-20)
// recommends digests of at least 384 bits once post-quantum security is the
// goal (RecoPQHachage). X-Wing — the 4.x KEM, ML-KEM-768 + X25519 under a
// SHA3-256 combiner — missed all three; ENISA's 2026-04-30 report files its
// combiner as "not allowed" next to CatKDF. The suite here is an ETSI
// parameter set verbatim — §7.7.2 lists HKDFwSHA384_P384_ML-KEM-768, and only
// P-384 goes with SHA-384 there — so nothing is a construction of our own
// beyond the encoding of the transcript, which the standard leaves to the
// application.
//
// A suite is a value, not a code path: `encapsulate(publicKey)` gives
// `{ cipherText, key }` and `decapsulate(cipherText, secretKey)` gives `key`,
// a 256-bit AES-GCM key bound to the suite, so the envelope layer (pqc.js)
// never needs to know which KEM it is talking to. Adding a suite is one entry
// and its vectors — the algorithmic crypto-agility ANSSI's note of 2026-01-19
// asks for first (Rec. 1). Accepting several suites for NEW data is a
// different thing, and this registry does not do it: which suite is written
// and read is decided once, in pqc.js.
//
// Secret keys are SEEDS: the P-384 scalar and the ML-KEM-768 seed side by
// side. Bytes in, bytes out; the wire encodings are pqc.js's.

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { p384 } from '@noble/curves/nist.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha384 } from '@noble/hashes/sha2.js';

import { isUint8Array } from './composite.js';
import { ENC } from './encoding.js';

const EMPTY = new Uint8Array(0);

const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
};

const need = (bytes, length, what) => {
    if (!isUint8Array(bytes) || bytes.length !== length) {
        throw new RangeError(`${what} must be ${length} bytes`);
    }
};

// --- ETSI TS 103 744 V1.2.2 building blocks ---
//
// Exported because the standard's own known-answer test pins each of them
// (tests/fixtures/etsi_catkdf_vectors.json), not because anything outside this
// file should assemble a key exchange from parts.

// [len]32 || val for each value: the length-delimited concatenation both
// context formatting functions (§7.2.2, §7.2.3) and Annex C's m_format share.
const lengthPrefixed = (...values) => concat(...values.flatMap((v) => {
    if (!isUint8Array(v)) throw new TypeError('ETSI formatting: bytes expected');
    const n = v.length;
    return [Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255), v];
}));

/**
 * Annex C's m_format: `cid || [len]32 || val1 || [len]32 || val2 ...`. The
 * standard calls it informative, for its test vectors; it is what MA and MB are
 * here too, so the transcript this suite feeds CatKDF has the exact shape the
 * reference implementation's vectors were computed over.
 */
export const etsiMessage = (cid, ...values) => concat(cid, lengthPrefixed(...values));

/** §7.2.3 cahb_f with SHA-384: the context HKDF-SHA-384 parameter sets use. */
export const etsiContextSha384 = (...values) => sha384(lengthPrefixed(...values));

/**
 * §8.2.3 CatKDF, with the §7.4.2 HKDF-SHA-384 mapping:
 *   secret = psk || k1 || k2, context = cahb_f(info, MA, MB),
 *   key_material = HKDF(secret, salt = label, info = context, length).
 * An absent label is the empty salt, which RFC 5869 treats as HashLen zeros —
 * what §7.4.2 asks for — because HMAC pads both to the same block of zeros.
 */
export const catKdfHkdfSha384 = ({ psk = EMPTY, k1, k2, MA, MB, info = EMPTY, label = EMPTY, length }) =>
    hkdf(sha384, concat(psk, k1, k2), label, etsiContextSha384(info, MA, MB), length);

// --- HKDFwSHA384_P384_ML-KEM-768 with CatKDF, static recipient keys (§8.2.2) ---
//
// The recipient's static keys are P1 (P-384) and P2 (ML-KEM-768); the sender
// answers with R1 (a fresh P-384 key) and R2 (the ML-KEM ciphertext). The
// ORDER is the standard's: §8.2.3 fixes it by the parameter set's name, so the
// ECDH half comes first in every key, ciphertext and secret below.
//
// What the standard leaves to the application, and how it is decided here:
//   • MA and MB are Annex C's m_format with this parameter set's cid (0x2221)
//     and empty label contributions — the cid names the parameter set inside
//     the transcript, and there is no label to agree on: nothing is exchanged
//     interactively, the recipient's keys come attested from the directory.
//   • `info` names the suite and what the key is for, like X-Wing's HKDF info.
//   • Points are SEC1 UNCOMPRESSED (97 bytes), on the wire and in MA/MB alike.
//     The reference harness puts the bare x||y in MA/MB; one encoding
//     everywhere is worth more here than matching a test-only format, and the
//     vector test feeds the harness's encoding to catKdfHkdfSha384 directly.
//   • k1 is the ECDH x-coordinate as a fixed 48-byte string (SP 800-56A Z).
//
// CatKDF is IND-CCA in the random-oracle model as long as either half is
// OW-CCA (Annex B) — which is the property static keys need, and why both
// public keys and both ciphertexts are in the context rather than relying on
// a property of ML-KEM the way X-Wing's combiner does.

export const CATKDF_KEM_ALG = 'HKDFwSHA384_P384_ML-KEM-768_CatKDF';
const CATKDF_CID = Uint8Array.of(0x22, 0x21); // HKDFwSHA384, P-384, ML-KEM-768, CatKDF
const CATKDF_INFO = ENC.encode(`Kryptolog/${CATKDF_KEM_ALG}/AES-GCM/v5`);

const P384_POINT = 97; // 0x04 || x || y
const P384_SCALAR = 48;
const MLKEM_SEED = 64; // d || z (FIPS 203 KeyGen_internal)

export const CATKDF_LENGTHS = Object.freeze({
    publicKey: P384_POINT + 1184, // P-384 point || ML-KEM-768 encapsulation key
    secretKey: P384_SCALAR + MLKEM_SEED, // P-384 scalar || ML-KEM-768 seed
    cipherText: P384_POINT + 1088, // ephemeral P-384 point || ML-KEM-768 ciphertext
    key: 32,
});

const uncompressedPoint = (bytes, what) => {
    // fromBytes also takes the 49-byte compressed form; this suite has one
    // encoding, and a length check alone would let a 0x02/0x03 prefix through.
    if (bytes[0] !== 0x04) throw new RangeError(`${what} must be an uncompressed P-384 point`);
    return bytes;
};

const catkdfHalves = (secretKey) => {
    need(secretKey, CATKDF_LENGTHS.secretKey, 'CatKDF secret key');
    const scalar = secretKey.slice(0, P384_SCALAR); // copies: noble keeps references
    if (!p384.utils.isValidSecretKey(scalar)) throw new RangeError('CatKDF secret key: P-384 scalar out of range');
    return { scalar, mlkemSeed: secretKey.slice(P384_SCALAR) };
};

// The x-coordinate of d·Q: noble validates Q (on the curve, not infinity) and d.
const ecdhX = (scalar, point) => p384.getSharedSecret(scalar, point, true).subarray(1);

const catkdfKey = ({ P1, P2, R1, R2, k1, k2 }) => catKdfHkdfSha384({
    k1, k2,
    MA: etsiMessage(CATKDF_CID, EMPTY, P1, P2),
    MB: etsiMessage(CATKDF_CID, EMPTY, R1, R2),
    info: CATKDF_INFO,
    length: CATKDF_LENGTHS.key,
});

/** The CatKDF public key (P-384 point || ML-KEM-768 key) of a 112-byte secret key. */
export const catkdfPublicKey = (secretKey) => {
    const { scalar, mlkemSeed } = catkdfHalves(secretKey);
    return concat(p384.getPublicKey(scalar, false), ml_kem768.keygen(mlkemSeed).publicKey);
};

/**
 * A new key pair, or the one a stored secret key names. The two halves are
 * drawn INDEPENDENTLY, as the composite identity's are: a break of whichever
 * derivation is weaker must not reach the other half.
 */
export const catkdfKeygen = (secretKey = concat(
    p384.utils.randomSecretKey(), crypto.getRandomValues(new Uint8Array(MLKEM_SEED))
)) => {
    const copy = secretKey.slice();
    return { publicKey: catkdfPublicKey(copy), secretKey: copy };
};

/** Encapsulate to `publicKey`: `{ cipherText, key }`, `key` a 32-byte AES key. */
export const catkdfEncapsulate = (publicKey) => {
    need(publicKey, CATKDF_LENGTHS.publicKey, 'CatKDF public key');
    const P1 = uncompressedPoint(publicKey.subarray(0, P384_POINT), 'CatKDF public key');
    const P2 = publicKey.subarray(P384_POINT);
    const ephemeral = p384.utils.randomSecretKey();
    const k1 = ecdhX(ephemeral, P1);
    const R1 = p384.getPublicKey(ephemeral, false);
    // ML-KEM.Encaps runs the FIPS 203 modulus check on P2 and throws on failure.
    const { cipherText: R2, sharedSecret: k2 } = ml_kem768.encapsulate(P2);
    return { cipherText: concat(R1, R2), key: catkdfKey({ P1, P2, R1, R2, k1, k2 }) };
};

/** The key `cipherText` carries for the holder of `secretKey`. */
export const catkdfDecapsulate = (cipherText, secretKey) => {
    need(cipherText, CATKDF_LENGTHS.cipherText, 'CatKDF ciphertext');
    const { scalar, mlkemSeed } = catkdfHalves(secretKey);
    const R1 = uncompressedPoint(cipherText.subarray(0, P384_POINT), 'CatKDF ciphertext');
    const R2 = cipherText.subarray(P384_POINT);
    const { publicKey: P2, secretKey: dk } = ml_kem768.keygen(mlkemSeed);
    const P1 = p384.getPublicKey(scalar, false);
    const k1 = ecdhX(scalar, R1);
    // ML-KEM decapsulation rejects implicitly: a bad R2 yields an unrelated
    // secret, so a tampered envelope fails its AES-GCM tag, not here.
    const k2 = ml_kem768.decapsulate(R2, dk);
    return catkdfKey({ P1, P2, R1, R2, k1, k2 });
};

// --- The registry ---
//
// One shape for every suite: `{ alg, lengths, publicKey(sk), keygen(sk?),
// encapsulate(pk) -> { cipherText, key }, decapsulate(ct, sk) -> key }`, where
// `key` is always the final 256-bit AES-GCM key.

export const KEM_SUITES = Object.freeze({
    [CATKDF_KEM_ALG]: Object.freeze({
        alg: CATKDF_KEM_ALG,
        lengths: CATKDF_LENGTHS,
        publicKey: catkdfPublicKey,
        keygen: catkdfKeygen,
        encapsulate: catkdfEncapsulate,
        decapsulate: catkdfDecapsulate,
    }),
});
