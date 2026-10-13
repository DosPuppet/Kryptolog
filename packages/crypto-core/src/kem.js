// X-Wing: ML-KEM-768 + X25519 (draft-connolly-cfrg-xwing-kem-10), the hybrid
// KEM of crypto-core 4.
//
// The shared secret is SHA3-256 over both component secrets, the X25519
// ciphertext and public key, and a fixed label, so it stays secret while
// EITHER component holds (audit 2026-10-12 K-10). ML-KEM-768 is NIST category
// 3, ANSSI's acceptable level. ANSSI's FAQ names the ETSI CatKDF / CasKDF
// combiners; X-Wing is neither — it is a fixed instance with its own published
// proof — and THREAT_MODEL.md says so rather than overstate the fit.
//
// noble ships it as `ml_kem768_x25519` (its `XWing` export is a legacy alias of
// the same object). The secret key IS the 32-byte seed — X-Wing re-expands it
// with SHAKE256 on every decapsulation — so a vault stores 32 bytes, not
// ML-KEM's 2 400-byte expanded key.
//
// Bytes in, bytes out, like composite.js; the envelope format is pqc.js's.

import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';

import { isUint8Array } from './composite.js';

export const XWING_LENGTHS = Object.freeze({
    publicKey: 1216, // ML-KEM-768 pk (1184) || X25519 pk (32)
    secretKey: 32,
    cipherText: 1120, // ML-KEM-768 ct (1088) || X25519 ephemeral pk (32)
    sharedSecret: 32,
});

const need = (bytes, length, what) => {
    if (!isUint8Array(bytes) || bytes.length !== length) {
        throw new RangeError(`X-Wing ${what} must be ${length} bytes`);
    }
};

/** The X-Wing public key of a 32-byte secret key (seed). */
export const xwingPublicKey = (secretKey) => {
    need(secretKey, XWING_LENGTHS.secretKey, 'secret key');
    return ml_kem768_x25519.getPublicKey(secretKey.slice());
};

/** A new key pair, or the one a stored 32-byte secret key (seed) names. */
export const xwingKeygen = (secretKey = crypto.getRandomValues(new Uint8Array(XWING_LENGTHS.secretKey))) => {
    const copy = secretKey.slice(); // noble's keygen(seed) keeps a reference to its argument
    return { publicKey: xwingPublicKey(copy), secretKey: copy };
};

// Deliberately no way to pass the encapsulation randomness: a caller that
// could would sooner or later pass a constant. The draft's vectors pin
// encapsulation through decapsulation instead (see test/hybrid.test.js).
/** Encapsulate to `publicKey`: `{ cipherText, sharedSecret }`. */
export const xwingEncapsulate = (publicKey) => {
    need(publicKey, XWING_LENGTHS.publicKey, 'public key');
    return ml_kem768_x25519.encapsulate(publicKey);
};

/** The shared secret `cipherText` carries for the holder of `secretKey`. */
export const xwingDecapsulate = (cipherText, secretKey) => {
    need(cipherText, XWING_LENGTHS.cipherText, 'ciphertext');
    need(secretKey, XWING_LENGTHS.secretKey, 'secret key');
    return ml_kem768_x25519.decapsulate(cipherText, secretKey.slice());
};
