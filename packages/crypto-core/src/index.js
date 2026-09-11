// @kryptolog/crypto-core — the single source of truth for client-side crypto.
//
// NIST FIPS post-quantum primitives (audited, pure-TS, no WASM):
//   ML-KEM-768  (FIPS 203) — key encapsulation, replaces Kyber768
//   ML-DSA-44   (FIPS 204) — signatures,        replaces Dilithium2
// ML-DSA byte encoding is interop-verified against the server's liboqs.
//
// This package is consumed by BOTH the SPA (frontend/) and the TrustKeys
// extension (trustkeys/) via their respective Vite builds. There is exactly ONE
// copy of every wire/storage primitive here, so the "produced here, consumed
// there (and vice-versa)" byte-compatibility that used to be guarded by a
// hand-maintained "KEEP IN SYNC" comment is now structural. The guarantee is
// enforced by test/byte-compat.test.js (golden vectors + version guard), not by
// a comment. Each app's src/utils/crypto.js is a thin shim that re-exports this
// module and adds only its app-local glue (the `*PQC` aliases in the SPA, and
// each app's own generateAccount() id policy).
//
// The implementation is split across the modules re-exported below, cut at the
// section boundaries this file used to carry as banner comments. The public
// surface is unchanged: everything is still imported from the package root, and
// the split is invisible to both apps. It exists so the WebAuthn block — which
// needs `window` and is used only by the SPA — is no longer in the same file a
// service worker has to read to find the chunk cipher.

// Bumped whenever a wire/storage format or shared primitive changes; the
// per-version history is in CHANGELOG.md next to this file.
export const CRYPTO_CORE_VERSION = '2.0.0';

export * from './encoding.js';
export * from './signing.js';
export * from './pqc.js';
export * from './aead.js';
export * from './vault.js';
export * from './webauthn.js';
