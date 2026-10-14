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

## 2.1.0

ADDITIVE — **existing message signatures are unaffected**, and nothing stored
stops verifying. Two additions, both for account deletion.

- `messageSigningBody` gains a `redacted=1` branch, taken when `ct` is absent.
  A message with a ciphertext still produces byte-identical output to 2.0.0
  (the byte-compat suite asserts exactly that), so this is not a cutover. The
  branch exists so an author can remove their own content without destroying
  anyone else's: a DM epoch's session key lives in the FIRST message under that
  sid and the partner's own replies reuse it with `keys:null`, so deleting that
  message takes the partner's authored history with it. Redaction keeps `keys`
  and drops only `ct`.

  The two forms are structurally disjoint — `\nct=` is always emitted for a
  present ciphertext and `\nredacted=` never is — so no ciphertext value can
  spell a redaction and no redaction can be read as a ciphertext. This is not
  the "compatibility fallback" the project bans: nothing accepts an old form
  *instead of* a new one, and each value still has exactly one signed spelling.

  Because the author signs it, a redaction is an authenticated act rather than
  an absence. A server can neither forge one on a live message nor un-redact one.

- `accountDeletionBody(nonce, mode, redactedMessageIds)` under a new
  `account-deletion` context, so a login signature can never be replayed as an
  account deletion and the extension will not silently auto-sign one (it signs
  only `message`-context bodies without prompting). `mode` and the redaction id
  set are both signed: without them a relay could downgrade an erase into a
  leave, escalate a leave into an erase, or drop one id and turn a redaction
  into a deletion.

## 3.0.0

WIRE AND STORAGE FORMAT BREAK — the seventh cutover. Every change below lands in
this one version so there is a single incompatibility boundary (audit 2026-10-12
lot 4). Nothing written before it opens or verifies after it: wipe, do not migrate.

- **Every envelope carries `v: 3` and an `alg` id** (K-10): KEM envelopes and
  wrapped keys `MLKEM768-HKDF-A256GCM`, symmetric envelopes `A256GCM`, the vault
  blob a KDF descriptor. Decoders refuse anything else with a `FormatError` that
  says "written by an older version", instead of failing as a bad tag. This is
  also the hook the hybrid cutover (4.0.0) will hang off.
- **Vault KDF: PBKDF2-SHA-512 600k → Argon2id** (m = 46 MiB, t = 1, p = 1,
  OWASP's first configuration; K-08). The blob is
  `{ v, kdf: { alg, m, t, p, salt }, iv, data }`: parameters travel with the data,
  so raising them later needs no cutover. `deriveVaultKeyBits`, `deriveKey` and
  `encryptVaultWithKey` take that descriptor where they took a salt.
- **`vaultPasswordProblem(password)`**: one rule for both clients — at least 12
  characters, at least 5 distinct, not a sequence or a well-known password
  (K-08, 2026-09-11 M-5). The floor was 4 in the extension and 6 in the SPA.
- **`loginChallengeBody({ nonce, origin, deployment, encryptionKey })`** names the
  SPA origin and the server deployment (K-02). The server refuses an origin it
  does not serve and a deployment that is not its own.
- **`accountDeletionBody({ nonce, mode, redactionKeys, origin, deployment })`**:
  bound to the server the same way.
- **`messageSigningBody`** signs `ts` (sender clock, ms) and `seq` (position in
  the session) (K-06), so replays, gaps and reordering are detectable.
- Every identifier interpolated into a signed body is checked against its
  alphabet by signer and verifier alike (`SignedBodyError`), which makes the
  bodies injective by construction rather than by the habits of honest clients
  (2026-09-23 Q-6).

## 3.1.0

ADDITIVE — nothing stored or signed before it changes. Every 3.0.0 vector is
unchanged, which is the proof; if one ever needs regenerating for this, it was
a cutover.

- **`conversationEraseBody({ nonce, kind, conversation, redactionKeys, origin,
  deployment })`** under a new `conversation-erase` context: the authorization
  for erasing one's own messages in one conversation (audit 2026-09-11 M-6).
  Separate from `message` so the extension never signs it silently, and naming
  the conversation in full so an approval cannot be carried to another one.

## 3.2.0

ADDITIVE — nothing stored or signed before it changes, and nothing uses the new
primitives yet. Every 3.x vector is unchanged. The hybrid primitives that 4.0.0
moves every format to (audit 2026-10-12 K-10), landed first so the cutover
itself only switches callers:

- **`composite.js`: composite ML-DSA-65 + Ed25519**, the IETF
  `id-MLDSA65-Ed25519-SHA512` (draft-ietf-lamps-pq-composite-sigs-19) —
  `compositeKeygen`, `compositePublicKey`, `compositeSign`, `compositeVerify`,
  `compositeMessage`. Valid only if BOTH halves verify. The secret key is the
  draft's 64-byte seed pair, drawn as two independent halves. ML-DSA-65 is NIST
  category 3, the level ANSSI asks for; 3.x signs with ML-DSA-44 (category 2).
- **`kem.js`: X-Wing**, ML-KEM-768 + X25519 (draft-connolly-cfrg-xwing-kem-10) —
  `xwingKeygen`, `xwingPublicKey`, `xwingEncapsulate`, `xwingDecapsulate`, over
  noble's `ml_kem768_x25519`. The secret key is the 32-byte seed.
- **Ed25519 is verified no more leniently than OpenSSL.** noble's strict mode
  still checks the cofactored equation where OpenSSL checks the cofactorless
  one, so it accepted a hand-built signature with a torsion component that the
  server refuses. `compositeVerify` also requires R and A to be torsion-free,
  which makes the two coincide.
- **`@noble/curves` is a direct dependency** (of the two apps too, which
  resolve this package's imports from their own `node_modules`), at `~2.2.0`:
  the range `@noble/post-quantum` 0.6.1 pins, so one copy serves both.
- Pinned by the specifications' own vectors, copied verbatim with their
  provenance into `tests/fixtures/composite_mldsa65_ed25519_vectors.json` and
  `tests/fixtures/xwing_vectors.json` (`test/hybrid.test.js`).

## 3.3.0

ADDITIVE on the wire — nothing stored or signed changes, every vector is
unchanged — but an API break for callers, and the HTTP API breaks with it:
deploy the SPA, the extension and the server together. The identity-key seam
4.0.0 needs (audit 2026-10-12 K-10), introduced while it is still trivial.

- **`identity.js`**: `addressOf(identityPublicKey)`, `isAddressOf(address,
  key)`, `verifyIdentitySignature({ address, identityPublicKey, message,
  signature })`. In 3.x an address IS its ML-DSA-44 key, so `addressOf` is the
  identity function, pinned as such; 4.0.0 makes it a hash. A verifier checks
  the binding itself and refuses a key that is not the address's — the key
  comes from the server, and a server free to serve any key for an address
  could forge any author.
- **`verifyEncryptionKeyAttestation({ address, identityPublicKey,
  encryptionPublicKey, attestation })`**: the positional form is gone; the
  attestation verifies through the same binding.
- The server stores the key apart from the address (`users.identity_public_key`),
  checks the binding at login before the signature, verifies every signature
  against the stored key, and embeds the key in every user record it serves.
  Deleted identities keep it, so their messages still verify.
- The SPA's message verifier also binds the KIND of conversation: a group
  message must declare the channel it was delivered under, a DM none. Channel
  ids are server-minted, so a server could otherwise mint one equal to an
  address and replay a DM into a group as verified, or the reverse.

## 4.0.0

CUTOVER — the eighth, and the one the 3.0.0 format markers were the hook for
(audit 2026-10-12 K-10). Nothing written before it opens or verifies after it,
and every decoder says so by name: wrapped keys, envelopes, vaults, `.kvault`
backups, extension vaults, stored accounts, signatures, proofs and the server's
identities. Deploy the SPA, the extension and the server together, on an empty
database (the backend's migration b4c5d6e7f8a9 refuses one that holds
identities).

Hybrid throughout, at NIST category 3 — the level ANSSI asks for; each
primitive holds while either of its halves does:

- **Signatures are composite ML-DSA-65 + Ed25519** (`id-MLDSA65-Ed25519-SHA512`,
  composite.js from 3.2.0). ML-DSA-44 is gone. `signMessage(message,
  identitySeedHex)`; `verifySignature` is the raw primitive, and applications
  verify through `verifyIdentitySignature`.
- **Encryption is X-Wing** (ML-KEM-768 + X25519, kem.js from 3.2.0):
  `KEM_ENVELOPE_ALG` = `XWING-HKDF384-A256GCM`, the AES key from HKDF-SHA-384
  under `Kryptolog/X-Wing/AES-GCM/v4`.
- **`FORMAT_VERSION` 4, and the markers are authenticated**: every envelope's
  `v` and `alg` are its AES-GCM associated data (`formatAad`), where before they
  sat beside the ciphertext unauthenticated. Pinned by decrypt-side golden
  envelopes (test/golden-envelopes.json), since no round-trip can catch a
  change both sides make together.
- **An address is SHA-384 of the identity key**, under
  `Kryptolog address v4\nalg=MLDSA65-Ed25519-SHA512\n` — 96 hex characters,
  where it was the 2 624-character ML-DSA-44 key. `addressOf`, `isAddress`,
  `isAddressOf` (identity.js). A golden address is pinned against the server's
  computation (tests/fixtures/hybrid_interop.json).
- **Every digest in a signed body is SHA-384**: `keysh`, the redaction-set
  digests, the multisig ciphertext digest (`ciphertextSha384`), and the safety
  number, now over `Kryptolog safety number v4\naddress=…\nencryption=…`.
- **Signed bodies take addresses**: a sender and a DM conversation must be 96
  hex. A channel id is at most 64 characters, so the two can no longer be
  confused — a group named after an address cannot be signed at all.
- **The key attestation names the address**:
  `encryptionKeyAttestationBody({ address, encryptionPublicKey })`.
- **Accounts are seeds** (account.js): `{ id, name, createdAt, identity: { seed,
  publicKey }, encryption: { seed, publicKey } }`, with `id` the ADDRESS in both
  apps (`generateAccount` moved here; the extension used UUIDs). `parseAccount`
  re-derives every public value from the seeds and refuses a stored key or id
  that disagrees, and a 3.x account by name. `normalizeAccount`,
  `generateMlDsaKeyPair` and `generateMlKemKeyPair` are gone, as are the
  `ml_dsa44` / `ml_kem768` paths.

Measured on this development machine: an X-Wing unwrap costs 2.6 ms in the
client, a composite signature ~10 ms to make and ~4 ms to verify; the server
verifies 1 000 composite signatures (a full erase round) in 0.17 s.

## 4.1.0

ADDITIVE — nothing on the wire or in storage changes, and every vector is
unchanged as the proof. The first step of lot 12 (ANSSI 2026 alignment): the
KEM 5.0.0 will switch to, added beside X-Wing behind a registry.

- **`KEM_SUITES`**, keyed by KEM id. Every suite has one shape —
  `keygen`, `publicKey`, `encapsulate(pk) -> { cipherText, key }`,
  `decapsulate(ct, sk) -> key` — where `key` is the final 256-bit AES-GCM key.
  The X-Wing entry (`XWING_KEM_ALG` = `XWING-HKDF384`) carries the
  HKDF-SHA-384 step under `Kryptolog/X-Wing/AES-GCM/v4` that pqc.js applies
  today, byte for byte. Nothing uses the registry yet.
- **`HKDFwSHA384_P384_ML-KEM-768_CatKDF`**: ETSI TS 103 744 V1.2.2's CatKDF
  over P-384 ECDH and ML-KEM-768 with static recipient keys (§8.2.2), a
  parameter set the standard lists (§7.7.2). `catkdfKeygen`, `catkdfPublicKey`,
  `catkdfEncapsulate`, `catkdfDecapsulate`, `CATKDF_LENGTHS`: a 1 281-byte
  public key (SEC1 uncompressed point || ML-KEM key), a 112-byte secret key
  (P-384 scalar || ML-KEM seed, drawn independently), a 1 185-byte ciphertext.
  MA/MB are Annex C's m_format with cid 0x2221 and empty label contributions;
  `info` is `Kryptolog/HKDFwSHA384_P384_ML-KEM-768_CatKDF/AES-GCM/v5`.
- **The standard's building blocks**, exported because its known-answer test
  pins each one: `etsiMessage` (Annex C), `etsiContextSha384` (cahb_f, §7.2.3),
  `catKdfHkdfSha384` (§8.2.3 with the §7.4.2 HKDF mapping). The vector — the
  reference implementation's cid 2221 case, ECDH and derandomized ML-KEM
  included — is copied verbatim into `tests/fixtures/etsi_catkdf_vectors.json`
  with its provenance.

Why (sources checked 2026-10-14): the ECCG Agreed Cryptographic Mechanisms v2,
which ANSSI accepts for certification, agree no X25519 and agree only
CatKDF/CasKDF as hybrid combiners; ANSSI's PQC FAQ recommends the two by name;
PG-083 v3.00 recommends ≥ 384-bit digests for post-quantum security. X-Wing's
SHA3-256 combiner misses all three.

## 4.2.0

ADDITIVE — nothing on the wire or in storage changes; every vector is
unchanged. Lot 12b: the identity signature 5.0.0 will switch to, beside the
current one behind a registry.

- **`SIGNATURE_SUITES`**, keyed by algorithm id, one shape for every suite:
  `keygen`, `publicKey`, `sign(message, sk, ctx?)`, `verify(sig, message, pk,
  ctx?)`, with `lengths.signature` a maximum.
- **`MLDSA65-ECDSA-P384-SHA512`** (draft-ietf-lamps-pq-composite-sigs-19, now
  in the RFC Editor queue): `mldsa65P384Keygen`, `mldsa65P384PublicKey`,
  `mldsa65P384Sign`, `mldsa65P384Verify`, `mldsa65P384Message`,
  `MLDSA65_P384_LENGTHS`. A 2 049-byte public key (ML-DSA-65 key || SEC1
  uncompressed P-384 point), an 80-byte secret key (ML-DSA seed || P-384
  scalar, drawn independently), a signature of 3 317 to 3 413 bytes (ML-DSA-65
  || DER ECDSA-with-SHA-384). ML-DSA-65 stays: it is ECCG-agreed. Ed25519 is
  not, nor named by ANSSI's PG-083 v3.00, and P-384 is the curve the 4.1.0 KEM
  uses too.
- **Low-S and canonical DER are required**, beyond the draft: ECDSA is not
  strongly unforgeable ((r, n-s) is a second valid signature anyone can make),
  PG-083 warns about it, and RecoSignature.2 asks a hybrid to keep the
  properties of both halves — ML-DSA is SUF-CMA. The draft's own vector shows
  the case: `sWithContext` has a high s, valid under the draft and refused
  here, while its low-S twin verifies. The signer always writes low-S, and
  both halves are hedged (ECDSA with RFC 6979 §3.6 extra entropy).
- Pinned by the draft's vector, copied verbatim into
  `tests/fixtures/composite_mldsa65_ecdsa_p384_vectors.json`. Its ECDSA is
  randomized upstream, so M' is pinned by verifying upstream's signatures.

## 4.3.0

NO WIRE CHANGE — every golden envelope, signed body and vector is unchanged,
and that is the proof this release is a seam and nothing more (lot 12d). The
envelope layer stops naming algorithms and goes through the 4.1.0/4.2.0
registries, so the 5.0.0 cutover is a change of WHICH suites, not of HOW
envelopes are built.

- **`SIGNATURE_ALG` and `KEM_ALG`** (pqc.js) name the suites in use, and
  **`SIGNATURE_SUITE` / `KEM_SUITE`** are those registry entries. Every key,
  signature and envelope operation uses them; `KEM_ENVELOPE_ALG` is spelled
  `${KEM_ALG}-A256GCM`, which is the 4.0.0 `XWING-HKDF384-A256GCM` exactly.
  Only the named suites are written or accepted: a registry entry is not a
  fallback (ANSSI crypto-agility note, Rec. 6).
- **`kemSeal` / `kemOpen`**: one sealing path for the two KEM envelopes,
  which differed only in their ciphertext field's name (`content` for
  `encryptMessage`, `encKey` for `wrapSessionKey`). `kemAesKey` is gone: the
  KEM suite now returns the final AES key (4.1.0), and nothing outside this
  package called it.
- The address prefix is spelled from `FORMAT_VERSION` and `SIGNATURE_ALG`
  (`Kryptolog address v4\nalg=MLDSA65-Ed25519-SHA512\n`, unchanged), and the
  account seed patterns from the suites' secret-key lengths.
- The backend mirrors the seam: `auth.SIGNATURE_VERIFIERS[SIG_ALG]` is what
  every verification path calls.

## 5.0.0

CUTOVER — the ninth, and meant to be the last that needs an empty database
(lot 12, ANSSI 2026 alignment). Nothing 4.x wrote opens or verifies after it,
and every decoder says so by name: wrapped keys, envelopes, vaults, `.kvault`
backups, extension vaults, stored accounts, signatures, multisig proofs, and
the server's identities (its migration c5d6e7f8a9b0 refuses a database that
holds any). Deploy the SPA, the extension and the server together.

Why: the 4.x suites missed the references ANSSI accepts for certification.
The ECCG Agreed Cryptographic Mechanisms v2 agree neither Ed25519 nor X25519,
and only ETSI TS 103 744's CatKDF/CasKDF as hybrid KEM combiners — X-Wing's
SHA3-256 combiner is filed as "not allowed" next to them by ENISA's
2026-04-30 report; ANSSI's PG-083 v3.00 names neither curve and recommends
≥ 384-bit digests for post-quantum security. Every component of 5.0.0 is
ECCG-agreed, at the level PG-083 prefers (ML-KEM-768, ML-DSA-65); ANSSI's
crypto-agility note puts algorithmic agility — which 4.1.0–4.3.0 built — ahead
of the highest parameter set.

- **Identity: `MLDSA65-ECDSA-P384-SHA512`** (4.2.0). Addresses are SHA-384
  under `Kryptolog address v5\nalg=MLDSA65-ECDSA-P384-SHA512\n`. Signatures
  are 3 317..3 413 bytes, low-S and canonical DER required on both sides.
  The Ed25519 composite, its torsion rule and the server's subgroup check are
  gone.
- **Encryption: `HKDFwSHA384_P384_ML-KEM-768_CatKDF`** (4.1.0); envelopes are
  `{ v: 5, alg: 'HKDFwSHA384_P384_ML-KEM-768_CatKDF-A256GCM', kid, kem, iv, … }`.
  X-Wing is gone.
- **Key ids**: every KEM envelope carries `kid`, the first 128 bits of
  SHA-384 over the recipient key under `Kryptolog encryption key id v5\n
  alg=…\n` (`encryptionKeyId`), and the associated data binds it with `v` and
  `alg`. Decryption picks its seed by kid (`encryptionSeedFor`, which throws
  `MissingKeyError` for a key the account no longer holds).
- **Accounts** keep the current encryption key with its `alg`, `kid` and
  `createdAt`, and a `retiredEncryption` list (empty until 5.1.0's rotation),
  each entry re-derived and checked on load; a 4.x account is refused by name.
- **Signed bodies name the encryption key's suite**: the login challenge gains
  `encryption-key-alg=`, the key attestation `encryption-alg=`, and the safety
  number is v5 over both. A key is only ever authorized as a key of the suite
  named.
- **The vault blob's markers are its associated data**: `v` and the KDF
  descriptor (canonical JSON) — the 4.0.0 entry claimed this for "every
  envelope", and the vault was not one of them.
- **The last SHA-256 on a signed path is gone**: a signed document's file
  digest is SHA-384 (`sha384HexOfFile`, WebCrypto); `sha256Hex` and
  `sha256HexBytes` are removed. Multisig proofs are format 3.0.
- Sizes: identity key 2 049 bytes, encryption key 1 281, a wrap ~1 790 JSON
  characters (`WRAPPED_KEY_CHARS` 1 850 on the server), a signature at most
  4 552 base64 characters. The golden envelopes and the signed-bodies fixture
  were regenerated once, deliberately, for this release.

Measured on this development machine (Intel Mac, Node 24): a composite
signature costs ~12 ms to make and ~9.5 ms to verify in the client, a wrap or
an unwrap ~11 ms (X-Wing unwrapped in 2.6 ms: noble's pure-JS P-384 is slower
than its X25519); the server verifies 1 000 composite signatures — a full
erase round — in 0.69 s (0.17 s for the Ed25519 composite). WebCrypto's
native P-384 ECDH is the lever if unwrap cost ever shows; the registry is
where it would go.

## 5.1.0

ADDITIVE — no wire or storage format change for anything that exists. Every
5.0.0 golden envelope and signed-body vector is unchanged, which is the proof;
the fixture only GAINS a `key_rotation` body. An identity can now replace its
encryption key without becoming someone else, which is what makes 5.0.0's
registry an agility mechanism rather than a list of one (ANSSI's crypto-agility
note, Rec. 1 and 3: change the algorithm, and handle the old keys).

- **`rotateAccountEncryptionKey(account, now)`** makes a fresh key current and
  moves the old one to `retiredEncryption`, newest first, at most
  `MAX_RETIRED_ENCRYPTION_KEYS` (32). A retired key only ever DEcrypts:
  `encryptionSeedFor` finds it by the envelope's kid; nothing encrypts to it.
- **`revertAccountEncryptionKeyRotation(account, newKid, now)`** undoes a
  rotation the server refused — and RETIRES the unpublished key rather than
  dropping it, so an undo run at the wrong moment (the server took the key
  after all) destroys nothing.
- **`destroyRetiredEncryptionKey(account, kid)`**: whatever was sealed to that
  key and never re-wrapped becomes unreadable for good. The user's decision,
  and the only coarse forward secrecy a static-key design has.
- **A signed rotation**, context `key-rotation`:
  `address=…\nold-kid=…\nnew-kid=…\nnew-alg=…\nts=…` (`keyRotationBody`,
  `signKeyRotation`, `verifyKeyRotation`). Its own context so the extension
  never signs it silently; kids rather than keys so it stays short. The server
  builds the body from the kid it HOLDS, so a recorded rotation cannot be
  replayed to roll a key back.
- **`rotationChain`** walks verified records from a pinned kid to a current
  one. Clients use it to say "X replaced their key on <date>" instead of "X's
  key changed" — and still stop the send until the new safety number is
  confirmed: the rotation is signed by the identity key, like the
  attestation, so it explains a change but cannot vouch for one.
