// The asymmetric layer of crypto-core 4: hybrid signatures and the hybrid KEM
// envelope (audit 2026-10-12 K-10).
//
//   identity    composite ML-DSA-65 + Ed25519 (composite.js) — signs
//   encryption  X-Wing, ML-KEM-768 + X25519   (kem.js)       — receives
//
// Both are NIST category 3, the level ANSSI asks for, and each holds as long
// as either of its two halves does. Keys are stored as their SEEDS — 64 bytes
// for the composite, 32 for X-Wing — and expanded on use: the seed is what
// FIPS 204/203 and the IETF drafts define as the private key, and what any
// other library (WebCrypto, OpenSSL) can import.

import { compositeKeygen, compositePublicKey, compositeSign, compositeVerify, COMPOSITE_SIG_ALG } from './composite.js';
import { xwingKeygen, xwingPublicKey, xwingEncapsulate, xwingDecapsulate } from './kem.js';
import { toHex, fromHex, toB64, fromB64, ENC, DEC } from './encoding.js';

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
// attacker can rewrite is a downgrade lever.
export const FORMAT_VERSION = 4;
export const KEM_ENVELOPE_ALG = 'XWING-HKDF384-A256GCM';
export const SIGNATURE_ALG = COMPOSITE_SIG_ALG;

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

/** The associated data binding an envelope's markers to its ciphertext (4.0.0). */
export const formatAad = (alg) => ENC.encode(`Kryptolog envelope\nv=${FORMAT_VERSION}\nalg=${alg}`);

// The AES key from an X-Wing shared secret: HKDF-SHA-384 under a label that
// names the KEM and the version (audit S5 introduced the HKDF step; 4.0.0 moved
// it to SHA-384 with the rest of the format). X-Wing's secret is already a
// SHA3-256 output, so this is domain binding, not a fix for a weakness.
const KEM_KDF_INFO = 'Kryptolog/X-Wing/AES-GCM/v4';
export const kemAesKey = async (sharedSecret, usage) => {
    const ikm = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-384', salt: new Uint8Array(0), info: ENC.encode(KEM_KDF_INFO) },
        ikm,
        { name: 'AES-GCM', length: 256 },
        false,
        usage
    );
};

// --- Keys ---

/** A fresh identity key pair: `{ publicKey, seed }`, both lowercase hex. */
export const generateIdentityKeyPair = () => {
    const { publicKey, secretKey } = compositeKeygen();
    return { publicKey: toHex(publicKey), seed: toHex(secretKey) };
};

/** A fresh encryption key pair: `{ publicKey, seed }`, both lowercase hex. */
export const generateEncryptionKeyPair = () => {
    const { publicKey, secretKey } = xwingKeygen();
    return { publicKey: toHex(publicKey), seed: toHex(secretKey) };
};

/** The identity public key a stored seed names. */
export const identityPublicKeyOf = (seedHex) => toHex(compositePublicKey(fromHex(seedHex)));

/** The encryption public key a stored seed names. */
export const encryptionPublicKeyOf = (seedHex) => toHex(xwingPublicKey(fromHex(seedHex)));

// --- Signatures ---

// A composite signature over the UTF-8 message bytes, base64 (audit L-12).
// The application context is empty: domain separation lives inside the
// message (signing.js), as it always has.
export const signMessage = async (message, identitySeedHex) =>
    toB64(compositeSign(ENC.encode(message), fromHex(identitySeedHex)));

// The raw primitive: true iff BOTH halves verify over exactly this message
// (audit H4). Application code verifies through identity.js's
// verifyIdentitySignature, which also checks the key against an address.
export const verifySignature = async (message, signatureB64, identityPublicKeyHex) => {
    try {
        return compositeVerify(fromB64(signatureB64), ENC.encode(message), fromHex(identityPublicKeyHex));
    } catch {
        return false;
    }
};

// --- The KEM envelope ---

export const encryptMessage = async (message, encryptionPublicKeyHex) => {
    const { cipherText, sharedSecret } = xwingEncapsulate(fromHex(encryptionPublicKeyHex));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await kemAesKey(sharedSecret, ["encrypt"]);
    const content = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: formatAad(KEM_ENVELOPE_ALG) },
        key,
        ENC.encode(message)
    );
    return {
        v: FORMAT_VERSION,
        alg: KEM_ENVELOPE_ALG,
        kem: toB64(cipherText),
        iv: toB64(iv),
        content: toB64(new Uint8Array(content)),
    };
};

export const decryptMessage = async (encryptedData, encryptionSeedHex) => {
    assertFormat(encryptedData, KEM_ENVELOPE_ALG, 'KEM envelope');
    const sharedSecret = xwingDecapsulate(fromB64(encryptedData.kem), fromHex(encryptionSeedHex));
    const key = await kemAesKey(sharedSecret, ["decrypt"]);
    const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromB64(encryptedData.iv), additionalData: formatAad(KEM_ENVELOPE_ALG) },
        key,
        fromB64(encryptedData.content)
    );
    return DEC.decode(plain);
};
