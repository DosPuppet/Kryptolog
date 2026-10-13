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
// generateAccount() moved into crypto-core with 4.0.0: an account's id is its
// address in both apps now, so the one policy lives in the one package.
export * from '@kryptolog/crypto-core';


// PQC-suffixed aliases for the SPA's call sites (see note above).
export {
    signMessage as signMessagePQC,
    encryptMessage as encryptMessagePQC,
    decryptMessage as decryptMessagePQC,
} from '@kryptolog/crypto-core';
