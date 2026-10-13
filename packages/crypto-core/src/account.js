// What a vault holds for one identity, in crypto-core 4 (audit 2026-10-12 K-10):
//
//   { id, name, createdAt,
//     identity:   { seed, publicKey },   composite ML-DSA-65 + Ed25519, 64-byte seed
//     encryption: { seed, publicKey } }  X-Wing, 32-byte seed
//
// `id` IS the address, in both apps. The extension used random UUIDs and the
// SPA the ML-DSA key, which made an account exported from one and imported in
// the other a different account; one rule, here, ends that.
//
// The seeds are the secret; everything else is derived from them. `parseAccount`
// re-derives it all on every load and refuses an account whose stored public
// key or id disagrees with its seeds — so a vault, a backup or a device
// transfer cannot carry a key pair that does not belong together, and nothing
// downstream ever has to wonder whether `publicKey` is the seed's.

import { FormatError, generateIdentityKeyPair, generateEncryptionKeyPair, identityPublicKeyOf, encryptionPublicKeyOf } from './pqc.js';
import { addressOf } from './identity.js';

const SEED_RE = { identity: /^[0-9a-f]{128}$/, encryption: /^[0-9a-f]{64}$/ };
const LEGACY_FIELDS = ['mldsa', 'mlkem', 'dilithium', 'kyber'];

/** A new account: fresh, independent identity and encryption seeds. */
export const generateAccount = (name) => {
    const identity = generateIdentityKeyPair();
    const encryption = generateEncryptionKeyPair();
    return {
        id: addressOf(identity.publicKey),
        name,
        createdAt: Date.now(),
        identity,
        encryption,
    };
};

const halfOf = (account, field, derive) => {
    const half = account[field];
    if (!half || typeof half !== 'object' || !SEED_RE[field].test(half.seed ?? '')) {
        throw new FormatError(`account: missing or malformed ${field} seed`);
    }
    const publicKey = derive(half.seed);
    if (half.publicKey !== undefined && half.publicKey !== publicKey) {
        throw new FormatError(`account: the stored ${field} public key is not its seed's`);
    }
    return { seed: half.seed, publicKey };
};

/**
 * Validate a stored account and return it in canonical form. Throws
 * FormatError for anything else — by name for an account an older Kryptolog
 * wrote, which holds ML-DSA-44 / ML-KEM-768 keys that no longer verify or
 * decrypt anything.
 */
export const parseAccount = (account) => {
    if (!account || typeof account !== 'object') throw new FormatError('account: not an account');
    if (LEGACY_FIELDS.some((f) => f in account)) {
        throw new FormatError(
            'This identity was created by an older Kryptolog version (ML-DSA-44 / ML-KEM-768 keys) ' +
            'and cannot be used by this one.'
        );
    }
    const identity = halfOf(account, 'identity', identityPublicKeyOf);
    const encryption = halfOf(account, 'encryption', encryptionPublicKeyOf);
    const id = addressOf(identity.publicKey);
    if (account.id !== undefined && account.id !== id) {
        throw new FormatError("account: the stored id is not its identity key's address");
    }
    return {
        id,
        name: typeof account.name === 'string' ? account.name : '',
        createdAt: Number.isFinite(account.createdAt) ? account.createdAt : Date.now(),
        identity,
        encryption,
    };
};
