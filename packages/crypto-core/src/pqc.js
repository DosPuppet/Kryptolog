// The asymmetric layer of crypto-core 5: hybrid signatures and the hybrid KEM
// envelope (audit 2026-10-12 K-10; lot 12, ANSSI 2026).
//
//   identity    composite ML-DSA-65 + ECDSA-P384         (composite.js) — signs
//   encryption  ETSI CatKDF, P-384 ECDH + ML-KEM-768     (kem.js)       — receives
//
// Both are NIST category 3 — the level ANSSI's PG-083 v3.00 prefers to 1
// (ML-KEM-768 "préférable" to 512), and enough on a platform that can change
// algorithm, which is what ANSSI's crypto-agility note asks for before the
// highest parameter set (Rec. 1) — and each holds as long as either of its
// halves does. Every component is in the ECCG Agreed Cryptographic
// Mechanisms v2. Keys are stored as their SEEDS — 80 bytes for the
// composite, 112 for the KEM — and expanded on use: the seed is what FIPS
// 204/203 define as the private key, and what any other library (WebCrypto,
// OpenSSL) can import.

import { SIGNATURE_SUITES, MLDSA65_P384_SIG_ALG } from './composite.js';
import { KEM_SUITES, CATKDF_KEM_ALG } from './kem.js';
import { toHex, fromHex, toB64, fromB64, ENC, DEC, sha384HexBytes } from './encoding.js';

// --- Format markers (crypto-core 3.0.0, audit 2026-10-12 K-10) ---
//
// Every envelope this package writes says what it is: a format version and an
// algorithm id, stored WITH the data, and every decoder refuses anything else
// by name, before touching a key. 4.0.0 is the cutover those markers were the
// hook for: nothing written before it opens after it, and says so.
//
// Since 4.0.0 the two markers are also the AES-GCM associated data of the
// envelope they describe. They were stored beside the ciphertext before, but
// nothing authenticated them: the day a second algorithm exists, a marker an
// attacker can rewrite is a downgrade lever. 5.0.0 adds a third to every KEM
// envelope, the recipient key's id (`kid`, below), bound the same way.
export const FORMAT_VERSION = 5;

// --- The suites in use (the agility seam, 4.3.0; switched in 5.0.0) ---
//
// Which signature identities use and which KEM encryption keys use, by
// registry id — the one place either is named. Everything below goes through
// the registries (composite.js SIGNATURE_SUITES, kem.js KEM_SUITES), so the
// next change of algorithm is these two lines and a format version, not a
// rewrite of every call site. The registries hold more than one suite; this
// package WRITES and ACCEPTS only the ones named here, which is the line
// ANSSI's crypto-agility note draws (Rec. 6): coexisting algorithms must
// never let a negotiation, or an attacker-chosen marker, pick an undesired
// one.
export const SIGNATURE_ALG = MLDSA65_P384_SIG_ALG;
export const KEM_ALG = CATKDF_KEM_ALG;
export const KEM_ENVELOPE_ALG = `${KEM_ALG}-A256GCM`;
export const SIGNATURE_SUITE = SIGNATURE_SUITES[SIGNATURE_ALG];
export const KEM_SUITE = KEM_SUITES[KEM_ALG];

export class FormatError extends Error {
    constructor(message) {
        super(message);
        this.name = 'FormatError';
    }
}

/**
 * Refuse an envelope that is not the current format, naming why. Called by every
 * decoder before it does any cryptography, so old or foreign data is reported
 * as such rather than as a failed tag.
 */
export const assertFormat = (envelope, alg, what) => {
    if (!envelope || typeof envelope !== 'object') {
        throw new FormatError(`${what}: not an envelope`);
    }
    if (envelope.v !== FORMAT_VERSION) {
        throw new FormatError(
            `${what}: format ${envelope.v ?? 'unversioned'} is not supported ` +
            `(this client reads format ${FORMAT_VERSION}). It was written by an ` +
            'older Kryptolog version and cannot be opened.'
        );
    }
    if (envelope.alg !== alg) {
        throw new FormatError(`${what}: unsupported algorithm ${envelope.alg ?? '(none)'}`);
    }
};

/**
 * The associated data binding an envelope's markers to its ciphertext (4.0.0),
 * and since 5.0.0 the recipient key's id for an envelope that has one. The
 * symmetric envelopes have no kid and keep their 4.0.0 shape; their alg is
 * not a KEM envelope's, so the two forms cannot collide.
 */
export const formatAad = (alg, kid) => ENC.encode(
    `Kryptolog envelope\nv=${FORMAT_VERSION}\nalg=${alg}` + (kid === undefined ? '' : `\nkid=${kid}`)
);

// --- Encryption key ids (5.0.0, lot 12) ---
//
// Which key an envelope is sealed to, without the key: the first 128 bits of
// SHA-384 over the key under a prefix naming the format and the suite. Every
// KEM envelope carries it, bound into its associated data.
//
// It is what makes an encryption key REPLACEABLE without replacing the
// identity (5.1.0): an account keeps the keys it has retired, and reads an
// envelope with whichever one its kid names (account.js encryptionKeyFor),
// where 4.x could only try the one key it had. 128 bits: a kid only has to
// tell one account's keys apart, and the AES-GCM tag still fails for any key
// but the one the envelope was sealed to, so even a collision could cost a
// failed decryption, never a wrong one.
export const KEY_ID_HEX_LENGTH = 32;
const KEY_ID_DOMAIN = ENC.encode(`Kryptolog encryption key id v${FORMAT_VERSION}\nalg=${KEM_ALG}\n`);
const KEY_ID_RE = new RegExp(`^[0-9a-f]{${KEY_ID_HEX_LENGTH}}$`);

/** The id of an encryption public key (hex), as envelopes carry it. */
export const encryptionKeyId = (encryptionPublicKeyHex) => {
    const key = fromHex(encryptionPublicKeyHex);
    const input = new Uint8Array(KEY_ID_DOMAIN.length + key.length);
    input.set(KEY_ID_DOMAIN);
    input.set(key, KEY_ID_DOMAIN.length);
    return sha384HexBytes(input).slice(0, KEY_ID_HEX_LENGTH);
};

/** Is `value` shaped like a key id (32 lowercase hex)? */
export const isEncryptionKeyId = (value) => typeof value === 'string' && KEY_ID_RE.test(value);

// The KEM suite hands back the final 256-bit AES-GCM key (kem.js); this only
// imports it, non-extractable, for the one operation it is for.
const importKemKey = (key, usage) => crypto.subtle.importKey('raw', key, 'AES-GCM', false, usage);

// --- Keys ---

/** A fresh identity key pair: `{ publicKey, seed }`, both lowercase hex. */
export const generateIdentityKeyPair = () => {
    const { publicKey, secretKey } = SIGNATURE_SUITE.keygen();
    return { publicKey: toHex(publicKey), seed: toHex(secretKey) };
};

/** A fresh encryption key pair: `{ publicKey, seed }`, both lowercase hex. */
export const generateEncryptionKeyPair = () => {
    const { publicKey, secretKey } = KEM_SUITE.keygen();
    return { publicKey: toHex(publicKey), seed: toHex(secretKey) };
};

/** The identity public key a stored seed names. */
export const identityPublicKeyOf = (seedHex) => toHex(SIGNATURE_SUITE.publicKey(fromHex(seedHex)));

/** The encryption public key a stored seed names. */
export const encryptionPublicKeyOf = (seedHex) => toHex(KEM_SUITE.publicKey(fromHex(seedHex)));

// --- Signatures ---

// A composite signature over the UTF-8 message bytes, base64 (audit L-12).
// The application context is empty: domain separation lives inside the
// message (signing.js), as it always has.
export const signMessage = async (message, identitySeedHex) =>
    toB64(SIGNATURE_SUITE.sign(ENC.encode(message), fromHex(identitySeedHex)));

// The raw primitive: true iff BOTH halves verify over exactly this message
// (audit H4). Application code verifies through identity.js's
// verifyIdentitySignature, which also checks the key against an address.
export const verifySignature = async (message, signatureB64, identityPublicKeyHex) => {
    try {
        return SIGNATURE_SUITE.verify(fromB64(signatureB64), ENC.encode(message), fromHex(identityPublicKeyHex));
    } catch {
        return false;
    }
};

// --- The KEM envelope ---
//
// One sealing path for both envelopes that open with an encryption key: the
// message envelope (`content`, a string) and the wrapped session key
// (`encKey`, key bytes) differ in the NAME of their ciphertext field and in
// nothing else, so they share it — two copies of a format are two chances to
// drift. The markers are the associated data (formatAad).

/** `{ v, alg, kid, kem, iv, [field] }`: `plaintext` (bytes) sealed to one encryption key. */
export const kemSeal = async (plaintext, encryptionPublicKeyHex, field) => {
    const kid = encryptionKeyId(encryptionPublicKeyHex);
    const { cipherText, key } = KEM_SUITE.encapsulate(fromHex(encryptionPublicKeyHex));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const sealed = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: formatAad(KEM_ENVELOPE_ALG, kid) },
        await importKemKey(key, ['encrypt']),
        plaintext
    );
    return {
        v: FORMAT_VERSION,
        alg: KEM_ENVELOPE_ALG,
        kid,
        kem: toB64(cipherText),
        iv: toB64(iv),
        [field]: toB64(new Uint8Array(sealed)),
    };
};

/**
 * The plaintext bytes of a kemSeal envelope, for the holder of the seed it was
 * sealed to. Which seed that is, among an account's keys, is the envelope's
 * `kid` to say (account.js encryptionKeyFor); a wrong one fails the tag.
 */
export const kemOpen = async (envelope, encryptionSeedHex, field, what) => {
    assertFormat(envelope, KEM_ENVELOPE_ALG, what);
    if (!isEncryptionKeyId(envelope.kid)) throw new FormatError(`${what}: missing or malformed key id`);
    const key = KEM_SUITE.decapsulate(fromB64(envelope.kem), fromHex(encryptionSeedHex));
    return new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromB64(envelope.iv), additionalData: formatAad(KEM_ENVELOPE_ALG, envelope.kid) },
        await importKemKey(key, ['decrypt']),
        fromB64(envelope[field])
    ));
};

export const encryptMessage = (message, encryptionPublicKeyHex) =>
    kemSeal(ENC.encode(message), encryptionPublicKeyHex, 'content');

export const decryptMessage = async (encryptedData, encryptionSeedHex) =>
    DEC.decode(await kemOpen(encryptedData, encryptionSeedHex, 'content', 'KEM envelope'));
