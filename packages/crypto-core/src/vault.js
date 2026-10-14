// Vault encryption: the Argon2id KDF, the AES-GCM wrapping around it, and the
// rule for the password that feeds it.
//
// crypto-core 3.0.0 (audit 2026-10-12 K-08): PBKDF2-SHA-512 → Argon2id. PBKDF2
// at 600k iterations is cheap to parallelise on GPUs because it needs no memory;
// a vault blob or a `.kvault` backup that leaves the device is attacked offline,
// where that is exactly the property that matters. Argon2id makes each guess
// cost 46 MiB of memory.
//
// The KDF parameters now travel IN the blob, as a descriptor
// `{ alg, m, t, p, salt }` that replaces the bare salt. Raising them later is
// then a matter of writing new blobs with new numbers, not another cutover:
// every reader takes them from the data. Nothing derives with parameters it was
// not handed except `newVaultKdf()`, which is where new ones are chosen.

import { argon2idAsync } from '@noble/hashes/argon2.js';

import { toB64, fromB64, ENC, DEC, canonicalJson } from './encoding.js';
import { FORMAT_VERSION, FormatError } from './pqc.js';

export const VAULT_KDF_ALG = 'argon2id';

// OWASP Password Storage Cheat Sheet, first Argon2id configuration: 46 MiB,
// one pass, one lane. Measured at ~0.4 s in V8 — the same engine as the SPA and
// the extension's service worker — which is what PBKDF2 600k cost before, on a
// phone as much as a desktop. Memory-hardness is the gain, not more seconds.
export const VAULT_KDF_PARAMS = Object.freeze({ m: 46 * 1024, t: 1, p: 1 });

// A decoded descriptor must fall inside these before anything is derived with
// it: the parameters come from a blob, which may come from anywhere (an
// imported backup, a device transfer), and an absurd `m` is a memory bomb.
const KDF_BOUNDS = { m: [8 * 1024, 1024 * 1024], t: [1, 16], p: [1, 4] };
const VAULT_KEY_BITS = 256;

/** A fresh KDF descriptor: current parameters, new random salt. */
export const newVaultKdf = () => ({
    alg: VAULT_KDF_ALG,
    ...VAULT_KDF_PARAMS,
    salt: toB64(crypto.getRandomValues(new Uint8Array(16))),
});

const checkKdf = (kdf) => {
    if (!kdf || kdf.alg !== VAULT_KDF_ALG) {
        throw new FormatError(`vault KDF: unsupported algorithm ${kdf?.alg ?? '(none)'}`);
    }
    for (const [name, [lo, hi]] of Object.entries(KDF_BOUNDS)) {
        const value = kdf[name];
        if (!Number.isInteger(value) || value < lo || value > hi) {
            throw new FormatError(`vault KDF: parameter ${name}=${value} is out of range`);
        }
    }
    const salt = fromB64(kdf.salt);
    if (salt.length < 16) throw new FormatError('vault KDF: salt too short');
    return salt;
};

/**
 * The vault key as RAW BYTES, derived with the parameters in `kdf`.
 *
 * Exists so a session can be resumed without keeping the PASSWORD anywhere
 * (audit M-4): a non-extractable CryptoKey cannot survive an MV3 service-worker
 * restart, so the extension caches these bytes, together with the descriptor
 * that produced them.
 */
export const deriveVaultKeyBits = async (password, kdf) => {
    const salt = checkKdf(kdf);
    return argon2idAsync(ENC.encode(password), salt, {
        m: kdf.m,
        t: kdf.t,
        p: kdf.p,
        dkLen: VAULT_KEY_BITS / 8,
        // Yield to the event loop while hashing, so an unlock does not freeze
        // the page (or the service worker's message handling) for its duration.
        asyncTick: 10,
    });
};

/** Import raw vault-key bytes as a non-extractable AES-GCM key. */
export const importVaultKey = async (keyBytes) => crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM", length: VAULT_KEY_BITS },
    false,
    ["encrypt", "decrypt"]
);

/** The CryptoKey for `kdf`. Composed from the two above: one KDF in the file. */
export async function deriveKey(password, kdf) {
    return importVaultKey(await deriveVaultKeyBits(password, kdf));
}

/** The KDF descriptor a stored blob was written with, after checking its format. */
export const vaultKdfOf = (blob) => {
    assertVaultFormat(blob);
    return blob.kdf;
};

/**
 * Does this look like an encrypted vault blob at all — current OR older format?
 *
 * The import screens use it to decide "ask for a password" vs "plain JSON". It
 * deliberately accepts the pre-3.0.0 shape too, so such a file reaches
 * decryptVault and gets its readable "older format" refusal instead of being
 * mistaken for something else.
 */
export const isEncryptedVaultBlob = (obj) =>
    !!obj && typeof obj === 'object' && !Array.isArray(obj.accounts) &&
    typeof obj.iv === 'string' && typeof obj.data === 'string' &&
    (obj.kdf !== undefined || typeof obj.salt === 'string');

const assertVaultFormat = (blob) => {
    if (!blob || typeof blob !== 'object') throw new FormatError('vault: not a vault blob');
    if (blob.v !== FORMAT_VERSION) {
        throw new FormatError(
            'This vault or backup was created by an older Kryptolog version ' +
            `(format ${blob.v ?? '< 3'}) and cannot be opened by this one.`
        );
    }
};

// The blob's own markers — its format version and the KDF descriptor that
// produced its key — are its AES-GCM associated data (5.0.0). The 4.0.0
// changelog said every envelope's markers were; the vault's were not, so a
// blob's `kdf` could be rewritten (to cheaper parameters, say, for whoever
// re-derives next) without the tag noticing. Canonical JSON, so the bytes do
// not depend on the order the descriptor's fields were written in.
const vaultAad = (kdf) => ENC.encode(`Kryptolog vault\nv=${FORMAT_VERSION}\nkdf=${canonicalJson(kdf)}`);

const seal = async (data, key, kdf) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv, additionalData: vaultAad(kdf) },
        key,
        ENC.encode(JSON.stringify(data))
    );
    return {
        v: FORMAT_VERSION,
        kdf,
        iv: toB64(iv),
        data: toB64(new Uint8Array(encryptedContent))
    };
};

export const encryptVault = async (data, password) => {
    const kdf = newVaultKdf();
    return seal(data, await deriveKey(password, kdf), kdf);
};

export const decryptVault = async (encryptedVault, password) => {
    const key = await deriveKey(password, vaultKdfOf(encryptedVault));
    try {
        return await openSealed(encryptedVault, key);
    } catch {
        throw new Error("Incorrect password or corrupted data");
    }
};

const openSealed = async (blob, key) => {
    const decryptedContent = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromB64(blob.iv), additionalData: vaultAad(blob.kdf) },
        key,
        fromB64(blob.data)
    );
    return JSON.parse(DEC.decode(decryptedContent));
};

/**
 * Encrypt with a pre-derived key. `kdf` is the descriptor that key came from:
 * it is written into the blob so the next reader derives the same key.
 * IV is random per call — safe to reuse the same key.
 */
export const encryptVaultWithKey = async (data, key, kdf) => {
    checkKdf(kdf);
    return seal(data, key, kdf);
};

export const decryptVaultWithKey = async (encryptedVault, key) => {
    assertVaultFormat(encryptedVault);
    try {
        return await openSealed(encryptedVault, key);
    } catch {
        throw new Error("Decryption failed with cached key");
    }
};

// --- Vault password rule (audit 2026-10-12 K-08, 2026-09-11 M-5) ---
//
// The vault password is the only thing between a stolen blob or backup and the
// identity keys inside it, and the attack is offline: no rate limit, no lockout.
// The floor was 4 characters in the extension and 6 in the SPA. One rule now,
// in the package both clients share, so they cannot drift apart again.
//
// Deliberately simple and explainable: length first, then the patterns a
// cracker tries before anything else. Not an entropy estimator — a long
// passphrase of ordinary words passes, which is the advice worth giving.
export const VAULT_PASSWORD_MIN_LENGTH = 12;

const COMMON = new Set([
    'passwordpassword', 'password1234', 'password12345', 'password123456',
    '123456789012', '1234567890123', '12345678901234', 'qwertyuiopas',
    'azertyuiopqs', 'qwertyqwerty', 'azertyazerty', 'iloveyouiloveyou',
    'motdepasse123', 'motdepassemotdepasse', 'administrator', 'letmeinletmein',
]);

const isSequence = (pw) => {
    let step = null;
    for (let i = 1; i < pw.length; i++) {
        const d = pw.charCodeAt(i) - pw.charCodeAt(i - 1);
        if (Math.abs(d) > 1) return false;
        if (step === null) step = d;
        else if (d !== step) return false;
    }
    return true;
};

/**
 * Why this password is not acceptable for a vault or backup, or null if it is.
 * The message is user-facing.
 */
export const vaultPasswordProblem = (password) => {
    const pw = typeof password === 'string' ? password : '';
    if (pw.length < VAULT_PASSWORD_MIN_LENGTH) {
        return `Use at least ${VAULT_PASSWORD_MIN_LENGTH} characters — a short phrase of several words is ideal.`;
    }
    if (new Set(pw).size < 5) {
        return 'Use more varied characters: this password repeats too few of them.';
    }
    if (COMMON.has(pw.toLowerCase()) || isSequence(pw.toLowerCase())) {
        return 'This password is among the first an attacker would try. Choose another.';
    }
    return null;
};
