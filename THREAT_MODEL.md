# Threat model

What Kryptolog protects, against whom, and — as plainly — what it does not.
Components and flows are described in [ARCHITECTURE.md](ARCHITECTURE.md).

Status as of crypto-core 4.0.0 (October 2026), after the remediation of the
2026-10-12 audit, its hybridization lot included. That audit's own table is
the starting point; the "Then" column is what it found, "Now" is what holds
today.

## Adversaries

| Adversary | Then | Now | Why, and what remains |
|---|---|---|---|
| Network eavesdropper (Wi-Fi, ISP) | Protected | Protected | TLS, then end-to-end encryption underneath it. |
| "Harvest now, decrypt later" with a quantum computer | Content protected | Content protected | X-Wing (ML-KEM-768 + X25519) for every wrap. Metadata stays with the server. |
| A break of the new post-quantum algorithms, or of their implementation | Not protected | **Protected while the classical half holds** | Hybrid since crypto-core 4.0.0: a signature verifies only if both ML-DSA-65 and Ed25519 accept it, and a wrapped key stays secret while either ML-KEM-768 or X25519 does. See "Hybridization" below for what that does and does not claim. |
| Honest-but-curious server operator | Content yes, metadata no | Content yes, metadata no | The server sees who talks to whom, when, how much, group membership. Retention can bound how long it keeps messages. |
| Malicious operator or compromised server | Not protected | **Partly** | It can no longer substitute a contact's key unnoticed (attestation is mandatory, and a changed key stops sending until the user confirms it), replay or reorder messages undetected (signed `ts`/`seq`), or make an unverifiable message read as genuine (hidden until revealed). **It still serves the SPA's code**, so it can ship a client that leaks keys — the one thing no server-side control fixes (code integrity, postponed). It also sees all metadata. |
| Access to PostgreSQL or Redis | Partly protected | Better protected | Both listen on loopback with generated passwords. With the database, an attacker reads ciphertext and metadata and can still try key substitution, which clients now refuse. |
| Theft of a device or a `.kvault` backup | Depended on the password | Offline cost is real | Argon2id at 46 MiB per guess, and a 12-character, non-trivial password floor in both clients. A weak-but-allowed passphrase can still fall. |
| Later compromise of a private encryption key | Not protected for the past | **Bounded, not solved** | Sessions rotate after 100 messages or 24 h, which limits a leaked *session* key. A leaked X-Wing key still opens every wrap ever sent to it: there is no ratchet, so no forward secrecy (postponed). Retention, if configured, removes old ciphertext. |
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

## Hybridization (crypto-core 4.0.0)

What it claims, against ANSSI's December 2023 follow-up position paper on
post-quantum cryptography:

- **Signatures** are the IETF composite `id-MLDSA65-Ed25519-SHA512`
  (draft-ietf-lamps-pq-composite-sigs, at the time of writing an Internet-Draft
  in IESG review): both halves sign a prefixed, labelled digest of the message
  and both must verify — ANSSI's "concatenation, valid iff all components are
  valid". ML-DSA-65 is NIST category 3; ANSSI asks for 3 or 5, and ML-DSA-44,
  used until 3.x, was category 2.
- **Key encapsulation** is X-Wing (draft-connolly-cfrg-xwing-kem), ML-KEM-768
  with X25519. ANSSI's FAQ names the ETSI CatKDF / CasKDF combiners; **X-Wing
  is neither**. It is a fixed instance with its own published security proof,
  and the fit with ANSSI's combiner guidance is an argument, not a match.
- **Hashes** introduced or redefined by the cutover — addresses, the KDF, the
  digests inside signed bodies, the safety number — are SHA-384, ANSSI's
  minimum next to category-3 primitives. The composite's internal SHA-512 and
  X-Wing's SHA3-256 are fixed by their specifications.
- **One deliberate difference between the two libraries is closed.** The
  clients' noble verifies Ed25519 with the cofactored equation, the server's
  OpenSSL with the cofactorless one; they disagree on signatures whose points
  carry a small-order component, which only the key's owner can build. The
  clients additionally require torsion-free points, and the server refuses at
  login any identity key whose Ed25519 half is not of prime order, so the two
  accept exactly the same signatures.

What it does not claim: the client libraries (@noble) are not independently
audited and do not claim constant-time execution; the drafts may still change
before they become RFCs, which would be a further cutover; and none of this
addresses the postponed items above.

## Fit for purpose

Suitable for demonstration, research, teaching post-quantum cryptography, and
personal use between people who trust each other, on a server they administer.
**Not** suitable, as it stands, for real sensitive or regulated data, or where
the server operator may be an adversary: that needs the two postponed items
above — code delivery integrity and forward secrecy — and an independent
third-party audit.
