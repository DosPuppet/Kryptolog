// @kryptolog/crypto-core — the single source of truth for client-side crypto.
//
// crypto-core 5 is HYBRID throughout (audit 2026-10-12 K-10), at NIST category
// 3, and every component is in the ECCG Agreed Cryptographic Mechanisms v2
// that ANSSI accepts for certification (lot 12) — each primitive holds while
// either half does:
//   identity    composite ML-DSA-65 + ECDSA-P384, id-MLDSA65-ECDSA-P384-SHA512
//               (draft-ietf-lamps-pq-composite-sigs-19)             — composite.js
//   encryption  ETSI TS 103 744 CatKDF, HKDFwSHA384_P384_ML-KEM-768  — kem.js
//   address     SHA-384 of the identity key                          — identity.js
// Both sit behind registries (SIGNATURE_SUITES, KEM_SUITES) and pqc.js names
// the one in use of each, so the next change of algorithm is an entry and a
// cutover, not a rewrite. Both are pinned to their specifications' own vectors
// and checked against the server's OpenSSL in both directions
// (test/hybrid.test.js).
//
// The primitives come from @noble/post-quantum and @noble/curves: pure JS, no
// WASM. noble is NOT independently audited (post-quantum self-audited at 0.6.1)
// and does not claim constant-time execution; it stays because no
// production-grade replacement runs in all three browsers yet (see CLAUDE.md,
// "liboqs -> pyca/cryptography"). Keys are stored as SEEDS, which is what any
// other library — WebCrypto's ML-DSA/ML-KEM once it ships, OpenSSL — imports.
//
// This package is consumed by BOTH the SPA (frontend/) and the TrustKeys
// extension (trustkeys/) via their respective Vite builds. There is exactly ONE
// copy of every wire/storage primitive here, so the "produced here, consumed
// there (and vice-versa)" byte-compatibility that used to be guarded by a
// hand-maintained "KEEP IN SYNC" comment is now structural. The guarantee is
// enforced by test/byte-compat.test.js (golden vectors + version guard), not by
// a comment. Each app's src/utils/crypto.js is a thin shim that re-exports this
// module and adds only its app-local glue (the `*PQC` aliases in the SPA).
// Accounts are generated here too since 4.0.0 (account.js): the two apps used
// to give an account different ids.
//
// The implementation is split across the modules re-exported below, cut at the
// section boundaries this file used to carry as banner comments. The public
// surface is unchanged: everything is still imported from the package root, and
// the split is invisible to both apps. It exists so the WebAuthn block — which
// needs `window` and is used only by the SPA — is no longer in the same file a
// service worker has to read to find the chunk cipher.

// Bumped whenever a wire/storage format or shared primitive changes; the
// per-version history is in CHANGELOG.md next to this file.
export const CRYPTO_CORE_VERSION = '5.1.0';

export * from './encoding.js';
export * from './signing.js';
export * from './pqc.js';
export * from './identity.js';
export * from './account.js';
export * from './composite.js';
export * from './kem.js';
export * from './aead.js';
export * from './vault.js';
export * from './webauthn.js';
