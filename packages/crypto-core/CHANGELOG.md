# @kryptolog/crypto-core — changelog

Bumped whenever a wire/storage format or shared primitive changes.
`test/byte-compat.test.js` asserts both app builds resolve the same
version, so a re-duplicated or version-skewed copy fails CI loudly.

## 1.1.0

messageSigningBody now binds the actual ciphertext (the AES-GCM envelope object is serialized canonically instead of coercing to the constant "[object Object]"), so message signatures change.

## 1.2.0

account keypair fields renamed to their FIPS names — kyber → mlkem (ML-KEM-768), dilithium → mldsa (ML-DSA-44). New vaults/backups write the new fields; normalizeAccount() maps legacy fields on load so older vaults and exported backups still open.

## 1.3.0

encryption-key attestation (audit M-1) — an identity self-signs its ML-KEM key under the `key-attestation` context so peers can verify the directory's key binding offline; keyFingerprint() renders the pair as a Signal-style safety number for out-of-band comparison.

## 1.4.0

two wire-format breaks, landed together so there is ONE incompatibility boundary rather than two.

- encryptChunk/decryptChunk now REQUIRE an AAD binding the chunk to its (secret, index) — audit M-2. Chunks written before this no longer decrypt.
- messageSigningBody now also covers `gid` and a digest of the key envelope (`keysh`), and is async — audit M-8. Signatures produced before this no longer verify.

## 1.5.0

ADDITIVE — no wire or storage format change. deriveVaultKeyBits() / importVaultKey() expose the vault KDF's raw output so the extension can resume a session without keeping the password anywhere (audit M-4). deriveKey() is now composed from them and produces the identical key; the byte-compat suite pins the KDF output as a golden vector so that equivalence cannot regress silently.

## 1.6.0

ADDITIVE/hardening — no wire or storage format change. fromHex() now THROWS on malformed input (audit L-9) instead of decoding non-hex to zero bytes and truncating odd-length strings, which turned a corrupted key into a valid-looking different one.

## 1.7.0

WIRE-FORMAT BREAK. unwrapSessionKey no longer accepts the pre-standardization
`ct` field name for the wrapped key; it reads `encKey` only. wrapSessionKey has
written `encKey` since that name was standardized, and neither app writes `ct`,
so this affects only wrapped keys stored by a client older than that change —
those no longer unwrap.

Removed because it is the downgrade path the clean-cutover stance exists to
avoid, and this file states that rule a few functions above where it was being
broken.
