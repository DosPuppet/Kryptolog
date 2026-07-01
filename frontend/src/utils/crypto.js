// SPA crypto shim.
//
// All wire/storage primitives live in @kryptolog/crypto-core — the single source
// of truth shared with the TrustKeys extension. Byte-compatibility between the two
// builds is structural (one source) and enforced by that package's
// test/byte-compat.test.js, NOT by a hand-maintained "KEEP IN SYNC" comment.
//
// This file only adds SPA-local glue:
//   • `*PQC`-suffixed aliases — historical artifact from when the app also had
//     `*Eth` variants (web3.js); the suffix disambiguates at the call sites.
//   • generateAccount() — the SPA uses the ML-DSA public key as the account id
//     (it doubles as the on-wire identity/address), which differs from the
//     extension's local-UUID policy, so it cannot live in the shared core.
export * from '@kryptolog/crypto-core';

import {
    generateKyberKeyPair,
    generateDilithiumKeyPair,
} from '@kryptolog/crypto-core';

// PQC-suffixed aliases for the SPA's call sites (see note above).
export {
    signMessage as signMessagePQC,
    verifySignature as verifySignaturePQC,
    encryptMessage as encryptMessagePQC,
    decryptMessage as decryptMessagePQC,
} from '@kryptolog/crypto-core';

export const generateAccount = async (name) => {
    const kyber = await generateKyberKeyPair();
    const dilithium = await generateDilithiumKeyPair();

    return {
        id: dilithium.publicKey, // Use Public Key as ID for consistency
        name,
        kyber,
        dilithium,
        createdAt: Date.now(),
    };
};
