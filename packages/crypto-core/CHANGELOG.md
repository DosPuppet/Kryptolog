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

## 2.0.0

WIRE-FORMAT AND STORAGE BREAK, and the widest one so far: every opaque payload
moves from hex to base64 (audit L-12). Hex cost 2 characters per byte where
base64 costs 1.33 — at the schema's 50 MB file ceiling that is 67 MB stored and
transferred instead of 100 MB, plus roughly 25% off every message envelope.

Base64 now, hex before:

- AES-GCM envelopes — `iv` and the ciphertext field (`content` / `ciphertext`).
- The wrapped session key `{kem, iv, encKey}`, and the KEM envelope `{kem, iv, content}`.
- File chunks: `iv` and `ciphertext`.
- ML-DSA detached signatures, including the encryption-key attestation.
- The vault blob `{salt, iv, data}` — so existing local vaults and any exported
  `.kvault` backup no longer open. This is the break a user feels: it is key
  custody, not just wire format.

Deliberately NOT moved, because they are identifiers rather than payloads:

- Addresses (an address IS an ML-DSA public key — a primary key, a URL path
  segment, and part of every signed login body) and ML-KEM public keys. Base64
  is case-sensitive; the project normalizes addresses to lowercase everywhere,
  and that convention would not survive the move.
- SHA-256 digests, which must keep matching Python's `hexdigest()`.
- Safety numbers, which humans read aloud.
- Key handles passed in and out of this package (`generateSessionKey`,
  `unwrapSessionKey`): in-memory values and the extension's IPC contract, never
  stored or transferred.

`toHex`/`fromHex` therefore stay, and are still the right tool for the above.

Note on counting cutovers: the HKDF-SHA-256 derivation of the AES key from the
ML-KEM shared secret (audit S5, `KEM_KDF_INFO` in pqc.js) was a wire break too,
and it landed before this file existed, so it carries no version of its own. Any
statement of how many incompatible formats this package has been through should
count it — the honest count to 2.0.0 is six, not five.
