// AES-GCM: session keys, envelopes, and file chunks.
//
// The session-key and envelope pairs are the same primitive under two wire
// names for the ciphertext property. Chunk encryption is separate because its
// associated data is mandatory (audit M-2).

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import { toHex, fromHex, toB64, fromB64, ENC, DEC } from './encoding.js';
import { kemAesKey } from './pqc.js';

// --- AES-GCM: session keys, envelopes, and chunks ---
//
// Encoding split (audit L-12): the KEY HANDLES passed in and out of this module
// stay hex — they are in-memory values and the extension's IPC contract, never
// stored or transferred. What goes on the wire — iv, ciphertext, the wrapped-key
// envelope — is base64.

/** Import a hex AES-256 key. One helper, so every call site agrees on the algorithm. */
const importAesKey = async (keyHex) =>
    crypto.subtle.importKey("raw", fromHex(keyHex), "AES-GCM", false, ["encrypt", "decrypt"]);

/** A fresh 256-bit AES key, hex-encoded (a handle, not a wire value). */
export const generateSessionKey = async () => toHex(crypto.getRandomValues(new Uint8Array(32)));

/**
 * AES-GCM a string under a hex key, returning { iv, [field] } — both base64.
 *
 * `field` names the ciphertext property because two callers disagree about it:
 * the message envelope calls it `content`, the file envelope `ciphertext`. Both
 * shapes are on the wire already, so they stay — but the bytes are produced
 * here, once, rather than by two functions that must not drift.
 */
const aeadEncrypt = async (plaintext, keyHex, field) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await importAesKey(keyHex);
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        ENC.encode(plaintext)
    );
    return { iv: toB64(iv), [field]: toB64(new Uint8Array(encrypted)) };
};

/** Inverse of aeadEncrypt, reading the ciphertext from `field`. */
const aeadDecrypt = async (envelope, keyHex, field) => {
    const key = await importAesKey(keyHex);
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromB64(envelope.iv) },
        key,
        fromB64(envelope[field])
    );
    return DEC.decode(decrypted);
};

export const wrapSessionKey = async (sessionKeyHex, publicKeyHex) => {
    // 1. Encapsulate a shared secret for the receiver (ML-KEM-768)
    const publicKey = fromHex(publicKeyHex);
    const { cipherText: ct, sharedSecret: ss } = ml_kem768.encapsulate(publicKey);

    // 2. Use Shared Secret (HKDF-derived, audit S5) to encrypt the Session Key
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const kek = await kemAesKey(new Uint8Array(ss), ["encrypt"]);

    const sessKeyBytes = fromHex(sessionKeyHex);
    const encryptedKey = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        kek,
        sessKeyBytes
    );

    return {
        kem: toB64(ct),
        iv: toB64(iv),
        encKey: toB64(new Uint8Array(encryptedKey))
    };
};

export const unwrapSessionKey = async (wrappedKey, privateKeyHex) => {
    // wrappedKey: { kem, iv, encKey } — all base64
    const privateKey = fromHex(privateKeyHex);
    const ct = fromB64(wrappedKey.kem);

    // 1. Decapsulate Shared Secret (ML-KEM-768)
    const ss = ml_kem768.decapsulate(ct, privateKey);

    // 2. Decrypt Session Key
    const iv = fromB64(wrappedKey.iv);
    const encryptedKey = fromB64(wrappedKey.encKey);

    const kek = await kemAesKey(new Uint8Array(ss), ["decrypt"]); // HKDF (audit S5)

    const decryptedKeyBytes = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        kek,
        encryptedKey
    );

    return toHex(new Uint8Array(decryptedKeyBytes));
};

export const encryptWithSessionKey = (message, sessionKeyHex) =>
    aeadEncrypt(message, sessionKeyHex, "content");

export const decryptWithSessionKey = (encryptedData, sessionKeyHex) =>
    aeadDecrypt(encryptedData, sessionKeyHex, "content");

// The envelope/large-file pair. Same primitive as the session-key pair above,
// differing only in what the ciphertext property is called on the wire.

/** Alias of generateSessionKey: both are a 256-bit AES key and always were. */
export const generateSymmetricKey = generateSessionKey;

export const encryptSymmetric = (content, keyHex) =>
    aeadEncrypt(content, keyHex, "ciphertext");

export const decryptSymmetric = (encryptedObject, keyHex) =>
    aeadDecrypt(encryptedObject, keyHex, "ciphertext");

// --- Binary Chunk Encryption (for chunked file uploads) ---

// Associated data binding a chunk to its position (audit M-2).
//
// Every chunk of a secret is encrypted under the SAME fileKey, and AES-GCM was
// used with no AAD — so a server could swap chunk 3 for chunk 7, both decrypt
// cleanly, and the reassembled file is silently wrong. Nothing catches it: the
// message signature layer covers metadata, not file bytes. Binding (secret,
// index) into the AEAD makes a misplaced chunk fail its tag instead.
//
// Not a substitute for the DB's uq_file_chunk_secret_index constraint — that
// stops a duplicate index being stored at all; this stops a stored chunk being
// served under the wrong index.
export const chunkAad = (secretId, chunkIndex) =>
    `Kryptolog/chunk/v1\nsecret=${secretId}\nindex=${chunkIndex}`;

// AAD is REQUIRED, not defaulted: falling back to "no AAD" would silently write
// the old, swappable format, which is exactly the downgrade path the
// clean-cutover stance exists to avoid.
const aadBytes = (aad, fn) => {
    if (typeof aad !== 'string' || aad === '') {
        throw new Error(`${fn}: aad is required — build it with chunkAad(secretId, chunkIndex) (audit M-2)`);
    }
    return ENC.encode(aad);
};

/**
 * Encrypt a binary chunk (Uint8Array) with AES-GCM.
 * @param {string} aad - from chunkAad(secretId, chunkIndex); required.
 * Returns { iv: base64, ciphertext: base64 }
 */
export const encryptChunk = async (chunkBytes, keyHex, aad) => {
    const additionalData = aadBytes(aad, 'encryptChunk');
    const key = await importAesKey(keyHex);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData }, key, chunkBytes
    );
    return { iv: toB64(iv), ciphertext: toB64(new Uint8Array(encrypted)) };
};

/**
 * Decrypt a binary chunk. Returns Uint8Array (raw bytes).
 * @param {string} aad - must be byte-identical to the one used at encrypt time.
 * Throws (AES-GCM tag failure) if the chunk was served under a different index.
 */
export const decryptChunk = async (ivB64, ciphertextB64, keyHex, aad) => {
    const additionalData = aadBytes(aad, 'decryptChunk');
    const key = await importAesKey(keyHex);
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromB64(ivB64), additionalData }, key, fromB64(ciphertextB64)
    );
    return new Uint8Array(decrypted);
};
