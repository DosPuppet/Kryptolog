# Threat model

What Kryptolog protects, against whom, and — as plainly — what it does not.
Components and flows are described in [ARCHITECTURE.md](ARCHITECTURE.md).

Status as of crypto-core 5.1.0 (October 2026), after the remediation of the
2026-10-12 audit and lot 12, which aligned the primitives with ANSSI's 2026
guidance and added key rotation. That audit's own table is
the starting point; the "Then" column is what it found, "Now" is what holds
today.

## Adversaries

| Adversary | Then | Now | Why, and what remains |
|---|---|---|---|
| Network eavesdropper (Wi-Fi, ISP) | Protected | Protected | TLS, then end-to-end encryption underneath it. |
| "Harvest now, decrypt later" with a quantum computer | Content protected | Content protected | ML-KEM-768 + ECDH P-384 (ETSI CatKDF) for every wrap. Metadata stays with the server. |
| A break of the new post-quantum algorithms, or of their implementation | Not protected | **Protected while the classical half holds** | Hybrid since crypto-core 4.0.0, on ECCG-agreed curves since 5.0.0: a signature verifies only if both ML-DSA-65 and ECDSA P-384 accept it, and a wrapped key stays secret while either ML-KEM-768 or ECDH P-384 does. See "Cryptographic conformity" below for what that does and does not claim. |
| Honest-but-curious server operator | Content yes, metadata no | Content yes, metadata no | The server sees who talks to whom, when, how much, group membership. Retention can bound how long it keeps messages. |
| Malicious operator or compromised server | Not protected | **Partly** | It can no longer substitute a contact's key unnoticed (attestation is mandatory, and a changed key stops sending until the user confirms it), replay or reorder messages undetected (signed `ts`/`seq`), or make an unverifiable message read as genuine (hidden until revealed). **It still serves the SPA's code**, so it can ship a client that leaks keys — the one thing no server-side control fixes (code integrity, postponed). It also sees all metadata. |
| Access to PostgreSQL or Redis | Partly protected | Better protected | Both listen on loopback with generated passwords. With the database, an attacker reads ciphertext and metadata and can still try key substitution, which clients now refuse. |
| Theft of a device or a `.kvault` backup | Depended on the password | Offline cost is real | Argon2id at 46 MiB per guess, and a 12-character, non-trivial password floor in both clients. A weak-but-allowed passphrase can still fall. |
| Later compromise of a private encryption key | Not protected for the past | **Bounded, not solved** | Sessions rotate after 100 messages or 24 h, which limits a leaked *session* key. A leaked encryption key still opens every wrap sent to it while it was current: there is no ratchet, so no forward secrecy (postponed). Since 5.1.0 a key can be **rotated** — what the account holds is re-wrapped to the new key — and the retired one destroyed, after which its later leak opens nothing re-wrapped; that bounds exposure by the rotation period, it is not forward secrecy. Retention, if configured, removes old ciphertext. |
| Malicious site connected to TrustKeys | Not protected | Protected for the reserved operations | A page can no longer have a login, account deletion, conversation erase or multisig approval signed blind: the extension builds those bodies itself, with the origin the browser reports, and says what each does. A site can still ask to sign a document (`content`) and to decrypt — both behind approval windows. |
| XSS in the SPA | Not protected | Not protected | Script in the page can use whatever the page can: the local vault's unlocked keys, the session, and the extension's calls (still behind its windows). The CSP and self-hosted assets narrow the routes in; they do not change the consequence. |
| A stranger with an account | — | Limited | Rate limits, per-account quotas, a search-only directory, 404s that do not reveal what exists, and admins who cannot take a group from its owner. |

## What is deliberately out of scope

- **Code delivery integrity.** The server that stores the ciphertext also
  serves the code that encrypts it. Closing this means shipping the UI inside
  the extension or having the extension check published hashes. Postponed.
- **Forward secrecy.** Needs a ratchet (Double Ratchet or similar). Postponed;
  session rotation is the interim bound.
- **Metadata privacy.** The server knows the social graph by design.
- **Availability against a determined attacker.** Rate limits, quotas and body
  limits bound abuse by one account; they are not DDoS protection.

## Cryptographic conformity (crypto-core 5.1.0)

Checked on 2026-10-14 against ANSSI's **PG-083 v3.00** (*Règles et
recommandations concernant le choix et le dimensionnement des mécanismes
cryptographiques*, 2026-03-20), ANSSI's **views on crypto-agility**
(2026-01-19), the **ECCG Agreed Cryptographic Mechanisms v2**, which ANSSI
accepts beside PG-083, and **ETSI TS 103 744 v1.2.2**. The 4.0.0 choices were
argued from ANSSI's December 2023 position paper, which these superseded:
X-Wing failed twice (X25519 is not an agreed curve, and its SHA3-256 combiner is
not CatKDF/CasKDF, which ENISA's 2026-04-30 report files as "not allowed"), and
the Ed25519 half of the identity once. 5.0.0 replaced both.

| Requirement | Source | What Kryptolog does | What remains |
|---|---|---|---|
| Hybridize post-quantum asymmetric mechanisms | PG-083 | Every signature is the composite `MLDSA65-ECDSA-P384-SHA512` (draft-ietf-lamps-pq-composite-sigs-19, in the RFC Editor queue); every key encapsulation is ML-KEM-768 + ECDH P-384. | The composite is still a draft until it is published; a change would be a further cutover. |
| Post-quantum level | PG-083 (ML-KEM-768 "préférable"), ECCG ACM v2 | ML-KEM-768 and ML-DSA-65, NIST category 3. | Category 5 is not used. With the registries below it is one suite entry plus a rotation, not a redesign. |
| Classical half on an agreed curve | PG-083, ECCG ACM v2 | P-384 for both halves. X25519 and Ed25519 are gone. | — |
| KEM combiner | ANSSI PQC FAQ (CatKDF/CasKDF), ECCG ACM v2 | ETSI TS 103 744 **CatKDF**, parameter set `HKDFwSHA384_P384_ML-KEM-768`, its context over both public keys and both ciphertexts. Pinned to ETSI's own test vectors in JavaScript and Python, and checked noble ↔ OpenSSL both ways. | Used with **static** recipient keys (§8.2.2), as a KEM to a published key — not the ephemeral exchange most of the specification describes. That is what makes the next row unmet. |
| Hybrid keeps both components' properties | RecoSignature.2, RecoConfidentialitéAsym.2 | A signature is valid only if both halves verify; a wrap holds while either KEM does. | — |
| ECDSA is not strongly unforgeable | PG-083 (explicit warning) | Low-S and canonical DER are required when signing and when verifying, on both sides, so a signature has exactly one encoding — a second valid one would be the L-12 defect again, since signatures commit to strings. | — |
| Digests of at least 384 bits | RecoPQHachage | Addresses, key ids, every digest inside a signed body (session-key envelopes, redaction sets, multisig ciphertexts, signed-document files), the safety number and the KEM's KDF are SHA-384. The composite's prehash is SHA-512 by specification. | The server's own session tokens are HMAC-SHA-256 (HS256): a symmetric MAC it both issues and checks, never a signed path. |
| Algorithmic agility | Agility note, Rec. 1 | `KEM_SUITES` and `SIGNATURE_SUITES` registries; every envelope names its `alg` and its recipient key's `kid`, both in its associated data; every key is bound to its suite where it is authorized (attestation, login body, safety number). | **An identity suite cannot be rotated**: an address is the hash of the identity key, so a new signature suite is a new identity. Encryption keys can be. |
| Handle old keys, do not strand them | Rec. 3 | Encryption-key rotation (5.1.0): a signed record, then every **mutable** wrap the account holds (grants, multisig keys) re-wrapped to the new key. Retired keys stay on the device, decrypt only, found by kid; the user destroys them when ready. | **Message sessions** sit inside signed payloads and cannot be re-wrapped: they stay readable only while the retired key is kept. Group-name wraps move at the next rename or membership change. |
| No undesired suite; authenticated configuration | Rec. 6 | One active suite for everything written; decoders refuse another `v`/`alg` by name; the suite is inside what the identity signs. **No fallback**: a retired key can open what was sealed to it, never be written to. | — |
| Forward secrecy | RecoConfidentialitéPersistante, RecoPQConfidentialitéPersistante | **Not met.** Session keys rotate (100 messages / 24 h), and rotating then destroying an encryption key bounds what a later leak opens by the rotation period. | Needs ephemeral keys or a ratchet. Postponed (out of scope above). |
| Implementation assurance | — | The server verifies with OpenSSL (pyca/cryptography). | The clients use @noble, which is not independently audited and does not claim constant-time execution; noble's P-384 is pure JavaScript. |

None of this is a certification or an evaluation: it is the project's own
reading of the references, kept here so the next change can be checked
against the same list.

## Fit for purpose

Suitable for demonstration, research, teaching post-quantum cryptography, and
personal use between people who trust each other, on a server they administer.
**Not** suitable, as it stands, for real sensitive or regulated data, or where
the server operator may be an adversary: that needs the two postponed items
above — code delivery integrity and forward secrecy — and an independent
third-party audit.
