// What a vault holds for one identity, in crypto-core 5 (lot 12):
//
//   { id, name, createdAt,
//     identity:          { seed, publicKey },          composite ML-DSA-65 + ECDSA-P384, 80-byte seed
//     encryption:        { alg, kid, seed, publicKey,  the CURRENT encryption key:
//                          createdAt },                 ETSI CatKDF P-384 + ML-KEM-768, 112-byte seed
//     retiredEncryption: [ { ...same, retiredAt } ] }  keys it replaced, kept to READ with
//
// `id` IS the address, in both apps. The extension used random UUIDs and the
// SPA the ML-DSA key, which made an account exported from one and imported in
// the other a different account; one rule, here, ends that.
//
// The seeds are the secret; everything else is derived from them. `parseAccount`
// re-derives it all on every load and refuses an account whose stored public
// key, key id or address disagrees with its seeds — so a vault, a backup or a
// device transfer cannot carry a key pair that does not belong together, and
// nothing downstream ever has to wonder whether `publicKey` is the seed's.
//
// Why a list of retired keys (5.0.0, used from 5.1.0). An identity is its
// address and cannot change without becoming someone else; an encryption key
// can, and must be able to — to move to another KEM without wiping the server
// (the ANSSI crypto-agility note's Rec. 3: old keys have to be handled, not
// stranded), or simply after a suspected leak. A retired key is never written
// to again: senders only ever see the current one, through its attestation.
// It is kept so the account can still OPEN what was sealed to it, which every
// KEM envelope names by `kid` — until its owner destroys it.

import {
    FormatError, generateIdentityKeyPair, generateEncryptionKeyPair, identityPublicKeyOf, encryptionPublicKeyOf,
    encryptionKeyId, SIGNATURE_SUITE, KEM_SUITE, KEM_ALG,
} from './pqc.js';
import { addressOf } from './identity.js';

// A seed is as long as its suite's secret key, in hex, taken from the
// registries so it follows the suites in use.
const seedPattern = (suite) => new RegExp(`^[0-9a-f]{${suite.lengths.secretKey * 2}}$`);
const SEED_RE = { identity: seedPattern(SIGNATURE_SUITE), encryption: seedPattern(KEM_SUITE) };
// How many retired encryption keys an account keeps. A rotation is a rare,
// deliberate act; this bounds what a hostile backup can make a device derive.
export const MAX_RETIRED_ENCRYPTION_KEYS = 32;
const LEGACY_FIELDS = ['mldsa', 'mlkem', 'dilithium', 'kyber'];

const now = () => Date.now();

/** The current-key record for a fresh or given key pair. */
const encryptionRecord = ({ seed, publicKey }, createdAt = now()) => ({
    alg: KEM_ALG,
    kid: encryptionKeyId(publicKey),
    seed,
    publicKey,
    createdAt,
});

/** A new account: fresh, independent identity and encryption seeds. */
export const generateAccount = (name) => {
    const identity = generateIdentityKeyPair();
    return {
        id: addressOf(identity.publicKey),
        name,
        createdAt: now(),
        identity,
        encryption: encryptionRecord(generateEncryptionKeyPair()),
        retiredEncryption: [],
    };
};

const checkPair = (half, what, pattern, derive) => {
    if (!half || typeof half !== 'object' || !pattern.test(half.seed ?? '')) {
        throw new FormatError(`account: missing or malformed ${what} seed`);
    }
    const publicKey = derive(half.seed);
    if (half.publicKey !== undefined && half.publicKey !== publicKey) {
        throw new FormatError(`account: the stored ${what} public key is not its seed's`);
    }
    return { seed: half.seed, publicKey };
};

const checkEncryptionKey = (record, what) => {
    const { seed, publicKey } = checkPair(record, what, SEED_RE.encryption, encryptionPublicKeyOf);
    if (record.alg !== KEM_ALG) throw new FormatError(`account: ${what} is not a ${KEM_ALG} key`);
    const kid = encryptionKeyId(publicKey);
    if (record.kid !== undefined && record.kid !== kid) {
        throw new FormatError(`account: the stored ${what} id is not its key's`);
    }
    return {
        alg: KEM_ALG,
        kid,
        seed,
        publicKey,
        createdAt: Number.isFinite(record.createdAt) ? record.createdAt : 0,
    };
};

const OLDER = (what) => new FormatError(
    `This identity was created by an older Kryptolog version (${what}) and cannot be used by this one.`
);

/**
 * Validate a stored account and return it in canonical form. Throws
 * FormatError for anything else — by name for an account an older Kryptolog
 * wrote, whose keys no longer verify or decrypt anything.
 */
export const parseAccount = (account) => {
    if (!account || typeof account !== 'object') throw new FormatError('account: not an account');
    if (LEGACY_FIELDS.some((f) => f in account)) throw OLDER('ML-DSA-44 / ML-KEM-768 keys');
    // 4.x: a 64-byte composite seed and an alg-less X-Wing key.
    if (account.encryption && typeof account.encryption === 'object' && !('alg' in account.encryption)) {
        throw OLDER('ML-DSA-65 + Ed25519 / X-Wing keys');
    }
    const identity = checkPair(account.identity, 'identity', SEED_RE.identity, identityPublicKeyOf);
    const encryption = checkEncryptionKey(account.encryption, 'encryption key');

    const retiredInput = account.retiredEncryption ?? [];
    if (!Array.isArray(retiredInput) || retiredInput.length > MAX_RETIRED_ENCRYPTION_KEYS) {
        throw new FormatError('account: malformed list of retired encryption keys');
    }
    const kids = new Set([encryption.kid]);
    const retiredEncryption = retiredInput.map((record) => {
        const key = checkEncryptionKey(record, 'retired encryption key');
        if (kids.has(key.kid)) throw new FormatError('account: an encryption key appears twice');
        kids.add(key.kid);
        return { ...key, retiredAt: Number.isFinite(record.retiredAt) ? record.retiredAt : 0 };
    });

    const id = addressOf(identity.publicKey);
    if (account.id !== undefined && account.id !== id) {
        throw new FormatError("account: the stored id is not its identity key's address");
    }
    return {
        id,
        name: typeof account.name === 'string' ? account.name : '',
        createdAt: Number.isFinite(account.createdAt) ? account.createdAt : now(),
        identity,
        encryption,
        retiredEncryption,
    };
};

/**
 * The account's encryption key — current or retired — whose id is `kid`, or
 * null. Every decryption picks its seed through this, from the `kid` of the
 * envelope it is opening.
 */
export const encryptionKeyFor = (account, kid) =>
    [account?.encryption, ...(account?.retiredEncryption ?? [])].find((key) => key?.kid === kid) ?? null;

export class MissingKeyError extends Error {
    constructor(kid) {
        super(`This was encrypted to a key (${kid}) this account no longer holds.`);
        this.name = 'MissingKeyError';
        this.kid = kid;
    }
}

/** The seed that opens `envelope`, or a MissingKeyError naming its kid. */
export const encryptionSeedFor = (account, envelope) => {
    const key = encryptionKeyFor(account, envelope?.kid);
    if (!key) throw new MissingKeyError(envelope?.kid ?? '(none)');
    return key.seed;
};
