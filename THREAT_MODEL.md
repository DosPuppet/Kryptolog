# Threat model

What Kryptolog protects, against whom, and — as plainly — what it does not.
Components and flows are described in [ARCHITECTURE.md](ARCHITECTURE.md).

Status as of crypto-core 3.1.0 (October 2026), after the remediation of the
2026-10-12 audit. That audit's own table is the starting point; the "Then"
column is what it found, "Now" is what holds today.

## Adversaries

| Adversary | Then | Now | Why, and what remains |
|---|---|---|---|
| Network eavesdropper (Wi-Fi, ISP) | Protected | Protected | TLS, then end-to-end encryption underneath it. |
| "Harvest now, decrypt later" with a quantum computer | Content protected | Content protected | ML-KEM-768 and ML-DSA-44. Metadata stays with the server. Not yet hybrid with a classical algorithm (postponed, see below). |
| Honest-but-curious server operator | Content yes, metadata no | Content yes, metadata no | The server sees who talks to whom, when, how much, group membership. Retention can bound how long it keeps messages. |
| Malicious operator or compromised server | Not protected | **Partly** | It can no longer substitute a contact's key unnoticed (attestation is mandatory, and a changed key stops sending until the user confirms it), replay or reorder messages undetected (signed `ts`/`seq`), or make an unverifiable message read as genuine (hidden until revealed). **It still serves the SPA's code**, so it can ship a client that leaks keys — the one thing no server-side control fixes (code integrity, postponed). It also sees all metadata. |
| Access to PostgreSQL or Redis | Partly protected | Better protected | Both listen on loopback with generated passwords. With the database, an attacker reads ciphertext and metadata and can still try key substitution, which clients now refuse. |
| Theft of a device or a `.kvault` backup | Depended on the password | Offline cost is real | Argon2id at 46 MiB per guess, and a 12-character, non-trivial password floor in both clients. A weak-but-allowed passphrase can still fall. |
| Later compromise of a private ML-KEM key | Not protected for the past | **Bounded, not solved** | Sessions rotate after 100 messages or 24 h, which limits a leaked *session* key. A leaked ML-KEM key still opens every wrap ever sent to it: there is no ratchet, so no forward secrecy (postponed). Retention, if configured, removes old ciphertext. |
| Malicious site connected to TrustKeys | Not protected | Protected for the reserved operations | A page can no longer have a login, account deletion, conversation erase or multisig approval signed blind: the extension builds those bodies itself, with the origin the browser reports, and says what each does. A site can still ask to sign a document (`content`) and to decrypt — both behind approval windows. |
| XSS in the SPA | Not protected | Not protected | Script in the page can use whatever the page can: the local vault's unlocked keys, the session, and the extension's calls (still behind its windows). The CSP and self-hosted assets narrow the routes in; they do not change the consequence. |
| A stranger with an account | — | Limited | Rate limits, per-account quotas, a search-only directory, 404s that do not reveal what exists, and admins who cannot take a group from its owner. |

## What is deliberately out of scope

- **Code delivery integrity.** The server that stores the ciphertext also
  serves the code that encrypts it. Closing this means shipping the UI inside
  the extension or having the extension check published hashes. Postponed.
- **Forward secrecy.** Needs a ratchet (Double Ratchet or similar). Postponed;
  session rotation is the interim bound.
- **Hybrid post-quantum + classical cryptography** (crypto-core 4.0.0). ANSSI
  requires it for regulated use. Postponed; every envelope already carries a
  version and an algorithm id, which is the hook.
- **Metadata privacy.** The server knows the social graph by design.
- **Availability against a determined attacker.** Rate limits, quotas and body
  limits bound abuse by one account; they are not DDoS protection.

## Fit for purpose

Suitable for demonstration, research, teaching post-quantum cryptography, and
personal use between people who trust each other, on a server they administer.
**Not** suitable, as it stands, for real sensitive or regulated data, or where
the server operator may be an adversary: that needs the three postponed items
above and an independent third-party audit.
