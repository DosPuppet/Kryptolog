# Architecture

How Kryptolog is put together, for someone about to change it. What is
protected against whom is in [THREAT_MODEL.md](THREAT_MODEL.md); how to run it
in production is in [DEPLOYMENT.md](DEPLOYMENT.md); the history of every
decision below is in [CLAUDE.md](CLAUDE.md).

## The one idea

The server stores and relays ciphertext it cannot read. Every key that opens
content lives on a user's device, in one of two custodians, and every
cryptographic format is defined once, in `packages/crypto-core`, shared by both
clients and mirrored byte for byte in the backend where the server has to check
a signature.

## Components

| Component | Path | Role |
|---|---|---|
| SPA | `frontend/` | React 19. The whole user interface; encrypts, decrypts, signs — directly with a local vault, or through TrustKeys. |
| TrustKeys | `trustkeys/` | MV3 browser extension. A key custodian: holds identities in its own vault, signs and decrypts for connected sites, behind approval windows. |
| crypto-core | `packages/crypto-core/` | Every primitive and wire format, once. A `file:` dependency of both clients; golden vectors pin its bytes. |
| Backend | `backend/` | FastAPI + SQLAlchemy on PostgreSQL. Directory, storage, access control, relay. Verifies signatures; never decrypts. |
| Redis | — | Shared rate limits, WebSocket fan-out between workers, presence. Optional for a single process. |
| Reverse proxy | `nginx.conf.example`, `DEPLOYMENT.md` | TLS, the SPA's CSP, serving `frontend/dist`. |

Two trust zones: the **device** (SPA + custodian), which holds keys, and the
**server side** (backend, PostgreSQL, Redis, proxy), which holds ciphertext,
public keys and metadata.

## Identity and custody

An identity is an **ML-DSA-44 key pair**; its public key, lowercase hex, *is*
the address. Each identity also has an **ML-KEM-768** encryption key, which it
**attests** — signs with its identity key — so a client can check that the
directory is serving the key the identity chose. A login submitting a key
without its attestation is refused.

Keys live in one of two custodians:

- **Local vault** — in the SPA, `localStorage`, sealed with AES-GCM under an
  **Argon2id** key (m = 46 MiB, t = 1, p = 1; parameters travel in the blob).
  Asks for the password on each custody call unless a key cache is configured.
- **TrustKeys** — the extension's own Argon2id vault. A connected site gets
  typed calls (`signLogin`, `signAccountDeletion`, `signConversationErase`,
  `signMultisigApproval`, `decrypt…`); the extension builds the signed bodies
  itself, with the origin Chrome reports, and shows what each one does. Only
  chat-message signatures may be silent, and only for a site granted it.

## Formats (crypto-core 3.1.0)

- **Signed bodies** are domain-separated: `Kryptolog Signed Message v1`, a
  `context=` line (`login`, `message`, `account-deletion`,
  `conversation-erase`, `multisig-approval`, `key-attestation`, `content`),
  then `key=value` lines whose interpolated identifiers are checked against
  their alphabet on both sides, so a body has exactly one meaning. Login and
  deletion bodies name the SPA **origin** and the server **deployment**.
- **Envelopes** carry `v: 3` and an algorithm id; decoders refuse anything else
  by name.
- **Session keys**: AES-256-GCM, wrapped per recipient with ML-KEM-768 + HKDF.
- **Opaque payloads are base64, identifiers are hex.**

The backend mirrors exactly the bodies it verifies (`backend/auth.py`), pinned
against crypto-core by `tests/fixtures/signed_bodies.json`.

## Flows

**Login.** `GET /auth/nonce/{address}` issues a single-use challenge and the
deployment id; the custodian signs the login body (origin, deployment, nonce,
encryption key); `POST /auth/login` claims the nonce, checks origin and
deployment, verifies the signature and the attestation, and returns a 30-minute
JWT. The token lives in memory only. Logging out bumps `token_version`, which
kills every token and hangs up every socket of that account.

**Direct and group messages.** The sender mints a session key per conversation
(rotated after 100 messages or 24 h, never adopted from the other side), wraps
it for every recipient whose attestation verifies and whose key the reader has
not seen change, encrypts, and signs the body — author, conversation, group,
session, timestamp, sequence number, key envelope, ciphertext. The server
stores the payload and relays it over the WebSocket; the reader verifies the
signature, the position (`seq`) and the clock before showing it, and hides an
unverifiable message behind an explicit reveal.

**Secrets and files.** The content is encrypted under a fresh key, wrapped for
the owner; sharing adds one wrapped copy per grantee (`access_grants`, one per
grantee, optionally expiring). Files are chunked; each chunk's AEAD binds its
secret and index.

**Multisig.** A workflow wraps the secret's key for each signer (who must be
able to read what they approve) and for each recipient; the server withholds
the recipients' keys until `threshold` signers have signed the SHA-256 of the
stored ciphertext.

**Deletion.** An account can *leave* (reversible) or *erase* (final); a
conversation can be *hidden* for one user and the user's own messages in it
*erased*. Erasing redacts — never deletes — any message that carries a session
key, under signatures from its author, and is authorized by a separate,
explicitly approved signature. `security/authorization.py` decides what each
deletion may touch.

## Backend layout

- `routers/` — one module per area; handlers are synchronous `def`s (database
  work off the event loop) that hand WebSocket frames to background tasks.
- `security/` — every authorization rule (`authorization.py`), input and crypto
  validation, the SSRF guard for push endpoints, quotas, the body-size limit,
  and the audit trail (`audit_log.py`, `request_audit.py`). A rule written
  inline in a router is a bug waiting for its second copy.
- `websocket_manager.py` — sockets, presence, and the Redis fan-out, with a
  supervised listener and local delivery while it is down.
- `utils/push.py` — Web Push on its own bounded worker pool, off the request.
- `retention.py`, `account_deletion.py` — the two things that delete history.
- `alembic/` — every schema change; `alembic check` fails CI on drift.

## Tests

| Suite | What it pins |
|---|---|
| `backend/tests` (pytest, real PostgreSQL) | Rules, storage invariants, the signed-body mirror, real ML-DSA on the signature-gated paths |
| `packages/crypto-core/test` | Golden vectors: the bytes a peer receives |
| `frontend/src/test` (vitest + jsdom) | Providers driven end to end against a stubbed server |
| `trustkeys/test` (vitest, mocked `chrome.*`) | Sender gating, approvals, typed signing |
| `e2e/` (Playwright, real Chromium + the extension) | The critical path across both custody modes |

Every gate is mutation-tested when it is added: a test that does not fail when
its rule is removed is not counted.
