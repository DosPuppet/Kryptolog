// TrustKeys extension crypto shim.
//
// All wire/storage primitives live in @kryptolog/crypto-core — the single source
// of truth shared with the SPA. Byte-compatibility between the two builds is
// structural (one source) and enforced by that package's
// test/byte-compat.test.js, NOT by a hand-maintained "KEEP IN SYNC" comment.
//
// Nothing extension-local is left here. generateAccount() used to be: the
// extension gave an account a random UUID where the SPA used its key, so one
// identity was two different accounts depending on which app had exported it.
// Since crypto-core 4.0.0 an account's id is its address in both, and the one
// generateAccount lives in crypto-core.
export * from '@kryptolog/crypto-core';
