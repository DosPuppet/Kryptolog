// TrustKeys extension crypto shim.
//
// All wire/storage primitives live in @kryptolog/crypto-core — the single source
// of truth shared with the SPA. Byte-compatibility between the two builds is
// structural (one source) and enforced by that package's
// test/byte-compat.test.js, NOT by a hand-maintained "KEEP IN SYNC" comment.
//
// This file only adds extension-local glue: generateAccount() uses a random UUID
// as the local account id (used for the wallet's account list / activeAccountId),
// which differs from the SPA's public-key-as-id policy, so it cannot live in the
// shared core. The extension signs the exact bytes the page hands it, so the H1
// domain-separation wrapper is applied at the SPA's call sites, not here.
export * from '@kryptolog/crypto-core';

import {
    generateKyberKeyPair,
    generateDilithiumKeyPair,
} from '@kryptolog/crypto-core';

export const generateAccount = async (name) => {
    const kyber = await generateKyberKeyPair();
    const dilithium = await generateDilithiumKeyPair();

    return {
        id: crypto.randomUUID(),
        name,
        kyber,
        dilithium,
        createdAt: Date.now(),
    };
};
