// An identity's ADDRESS versus its identity PUBLIC KEY (audit 2026-10-12 K-10).
//
// crypto-core 4: the identity key is a composite ML-DSA-65 + Ed25519 key
// (1 984 bytes, composite.js), and the address that names it is
//
//     hex(SHA-384("Kryptolog address v4\nalg=MLDSA65-Ed25519-SHA512\n" || key))
//
// — 96 lowercase hex characters. Short enough to be a primary key, a URL
// segment and a line in every signed body, where 3.x carried a 2 624-character
// ML-DSA-44 key in each. The prefix names the version and the algorithm, so an
// address can never be read as the hash of a key of another kind, and the
// hash is SHA-384 because ANSSI asks for at least that level next to
// category-3 primitives.
//
// 3.3.0 introduced this seam with `addressOf` as the identity function, so
// every verifier already took the KEY and checked it against the address; this
// is the one place that changed meaning.
//
// The binding is checked by the VERIFIER, never trusted from whoever supplied
// the key: a key comes from the directory, i.e. from the server, and a server
// that could serve any key for an address could forge any author.

import { COMPOSITE_LENGTHS, compositeVerify } from './composite.js';
import { ENC, fromHex, fromB64, sha384HexBytes } from './encoding.js';

const ADDRESS_DOMAIN = ENC.encode('Kryptolog address v4\nalg=MLDSA65-Ed25519-SHA512\n');
export const ADDRESS_HEX_LENGTH = 96;
export const IDENTITY_KEY_HEX_LENGTH = COMPOSITE_LENGTHS.publicKey * 2;

const ADDRESS_RE = new RegExp(`^[0-9a-f]{${ADDRESS_HEX_LENGTH}}$`);
const IDENTITY_KEY_RE = new RegExp(`^[0-9a-f]{${IDENTITY_KEY_HEX_LENGTH}}$`);

/** Is `value` shaped like an address (96 lowercase hex)? */
export const isAddress = (value) => typeof value === 'string' && ADDRESS_RE.test(value);

/** The address of a composite identity public key (lowercase hex). */
export const addressOf = (identityPublicKey) => {
    if (typeof identityPublicKey !== 'string' || !IDENTITY_KEY_RE.test(identityPublicKey)) {
        throw new TypeError(
            `addressOf: an identity public key is ${IDENTITY_KEY_HEX_LENGTH} lowercase hex characters`
        );
    }
    const key = fromHex(identityPublicKey);
    const input = new Uint8Array(ADDRESS_DOMAIN.length + key.length);
    input.set(ADDRESS_DOMAIN);
    input.set(key, ADDRESS_DOMAIN.length);
    return sha384HexBytes(input);
};

/** Does `identityPublicKey` belong to `address`? Never throws. */
export const isAddressOf = (address, identityPublicKey) => {
    try {
        return isAddress(address) && addressOf(identityPublicKey) === address;
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
    try {
        return compositeVerify(fromB64(signature), ENC.encode(message), fromHex(identityPublicKey));
    } catch {
        return false;
    }
};
