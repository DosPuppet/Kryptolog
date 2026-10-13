// An identity's ADDRESS versus its identity PUBLIC KEY — the seam the hybrid
// cutover needs (audit 2026-10-12 K-10).
//
// Until crypto-core 4 the two are the same string: an address IS an ML-DSA-44
// public key, and every verifier was handed the address as the key. 4.0.0
// makes the identity key a 1 984-byte composite and the address a SHA-384 of
// it, so a verifier needs the KEY and must check that it is the one the
// address names. This module introduces that shape while the answer is still
// trivial: `addressOf` is the identity function in 3.x, pinned as such, and
// every caller already goes through it. The cutover then changes what an
// address is in one place instead of at every verification.
//
// The binding is checked by the VERIFIER, never trusted from whoever supplied
// the key: a key comes from the directory, i.e. from the server, and a server
// that could serve any key for an address could forge any author.

import { verifySignature } from './pqc.js';

const HEX_RE = /^(?:[0-9a-f]{2})+$/;

/**
 * The address an identity public key (lowercase hex) is known by.
 * crypto-core 3.x: the key itself. 4.0.0: a hash of it.
 */
export const addressOf = (identityPublicKey) => {
    if (typeof identityPublicKey !== 'string' || !HEX_RE.test(identityPublicKey)) {
        throw new TypeError('addressOf: an identity public key is lowercase hex');
    }
    return identityPublicKey;
};

/** Does `identityPublicKey` belong to `address`? Never throws. */
export const isAddressOf = (address, identityPublicKey) => {
    try {
        return typeof address === 'string' && addressOf(identityPublicKey) === address;
    } catch {
        return false;
    }
};

/**
 * Verify `signature` (base64) over `message` as the identity `address`, using
 * `identityPublicKey` — which must be that address's key. A key that belongs
 * to another address is a refusal, not a verification against the wrong key.
 */
export const verifyIdentitySignature = async ({ address, identityPublicKey, message, signature }) => {
    if (!isAddressOf(address, identityPublicKey)) return false;
    return verifySignature(message, signature, identityPublicKey);
};
