# Kryptolog — Transversal Audit

**Date:** 2026-06-10
**Scope:** backend (FastAPI), frontend (React SPA), TrustKeys (MV3 extension)
**Method:** static review of all source (no runtime execution). Severity is *my* estimate; nothing here has been exploited.
**Reviewer:** Claude (Opus 4.8)

This is a scratch/working document (git-ignored under `.tempdoc/`).

---

## 0. Executive summary

The codebase is in good shape. The PQC migration (@noble/post-quantum on clients, in-process liboqs on the server, Node sidecar deleted) is clean, well-documented, and the zero-knowledge envelope model is sound: the server only ever holds ciphertext and per-recipient wrapped keys. Many audit items from the prior round are genuinely fixed (key-bound login challenge, PRF-only biometrics, token revocation via `token_version`, strict CSP, removal of the unsigned public-key setter).

The **one finding that deserves real attention is H1 (cross-context signature reuse / blind-signing)** — a single ML-DSA identity key signs login challenges, multisig content, and documents with **no domain separation**, and the multisig path signs *attacker-influenceable* text. That yields a plausible account-takeover path. Everything else is medium-or-below hardening and cleanup.

| # | Severity | Area | Finding |
|---|----------|------|---------|
| H1 | **High** | Crypto/Auth | One signing key, no domain separation → multisig blind-sign can be replayed as a login |
| M1 | Medium | Multisig | Signatures never verified server-side; any signer can overwrite recipient keys |
| M2 | Medium | WebSocket | No Origin allowlist / no connect rate-limit on `/ws` |
| M3 | Medium | Extension | Vault password held in `chrome.storage.session` plaintext (≤1h) |
| M4 | Medium | Extension | `sender.origin || request.origin` fallback weakens the permission trust boundary |
| M5 | Medium | Transport | No HSTS header (already flagged pending in CLAUDE.md) |
| L1–L9 | Low | various | logging, alg-header check, SQLite/worker scaling, rate-limit gaps, N+1, loose schema bounds |

---

## 1. Security findings

### H1 — No domain separation across signing contexts (blind-signing → login replay) — **High** — ✅ FIXED (2026-06-10)

> **Resolution:** Introduced explicit domain separation. Every signed payload is now
> wrapped as `Kryptolog Signed Message v1\ncontext=<login|content>\n<body>` before
> signing, with the context fixed by code (never by user-supplied content). Login uses
> the `login` context (backend `_login_message` + `PQCContext`/`Web3Context`); all
> multisig approvals and document signatures use the `content` context (sign + verify
> sites in `MultisigCreateModal`, `MultisigWorkflow`, `useSecrets`, `ProofAudit`,
> `SecretItem`). A `content`-domain signature can no longer reproduce the `login`-domain
> bytes, so the multisig→login replay is blocked. New regression tests:
> `test_content_signature_cannot_be_replayed_as_login` / `test_login_challenge_is_domain_separated`
> (backend) and the `domain separation (audit H1)` block in `frontend/src/test/pqc.test.js`.
> The TrustKeys extension signs whatever bytes the page hands it, so wrapping at the
> frontend call sites covers it with no extension change.


**Where:** [auth.py:86-126](backend/auth.py#L86) (`_login_message`/`verify_signature`), [Login/PQCContext.jsx:115](frontend/src/context/PQCContext.jsx#L115), [MultisigWorkflow.jsx:502-513](frontend/src/components/MultisigWorkflow.jsx#L502), [crypto.js signMessagePQC](frontend/src/utils/crypto.js#L60).

The same ML-DSA-44 identity key signs three different kinds of payload:

1. **Login challenge:** `Sign in to Kryptolog with nonce: <N>\nEncryption key: <K>`
2. **Multisig content:** `dataToSign = creatorSignedContent || contentToSign` — i.e. **the raw decrypted secret content**, which is chosen by the *workflow creator*.
3. **Documents:** a content hash.

Only the login string has a distinguishing prefix; the multisig path signs arbitrary creator-controlled text with **no prefix and no structural wrapper**. Because the multisig signature and the login signature are both "ML-DSA over these exact UTF-8 bytes," a multisig signature whose content equals a login string *is* a valid login signature.

**Attack path (account takeover):**
1. Attacker calls the public `GET /auth/nonce/{victim}` ([routers/auth.py:13](backend/routers/auth.py#L13)) → nonce `N`.
2. Attacker reads the victim's `encryption_public_key` via the auth-gated `GET /users/{victim}`.
3. Attacker creates a multisig workflow naming the victim as a signer, with the secret content set to exactly `Sign in to Kryptolog with nonce: N\nEncryption key: <victim_key>`.
4. Victim signs the workflow (the TrustKeys SIGN popup shows the raw message; local-vault `vaultService.sign` signs raw too).
5. The server stores `signer.signature` and returns it to workflow participants; the attacker is the owner and reads it.
6. Attacker `POST /auth/login` with `{address: victim, nonce: N, signature: <stolen>, encryption_public_key: <victim_key>}` → server verifies ML-DSA over the identical bytes → issues a JWT **for the victim**.

**Mitigants that lower (not remove) practicality:** 5-minute nonce TTL; the victim might notice the content looks like a login string; requires luring the victim into signing. It's still a legitimate cross-protocol reuse bug.

**Fix:** introduce collision-free domain separation for every signed context and enforce it on the verifying side:
- Login: sign/verify `KRYPTOLOG-LOGIN-v1\n<nonce>\n<enc_key>` (server prepends the tag in `_login_message`; reject anything without it).
- Multisig: never sign raw content. Sign `KRYPTOLOG-MULTISIG-v1\n<workflow_id>\n<sha256(content)>`.
- Documents: `KRYPTOLOG-DOC-v1\n<hash>`.
- Make the TrustKeys SIGN popup render the *structured, labeled* request, not an opaque blob, so users can tell login from approval.

This also makes the multisig signature meaningful (binds to a specific workflow), which ties into M1.

---

### M1 — Multisig signatures are not verified server-side; recipient keys overwritable — **Medium** — ✅ FIXED (2026-06-10)

> **Resolution (ciphertext-bound approval):** Because the server is zero-knowledge it
> can't verify a signature over plaintext it never sees — so signers now sign the
> **SHA-256 of the stored ciphertext**, bound to the workflow + secret id, under a new
> `multisig-approval` domain (`auth.multisig_approval_message` ↔ `multisigApprovalMessage`).
> The server recomputes that hash from the ciphertext it holds and verifies the signature
> against the signer's identity key (`auth.verify_message_signature`, PQC + Eth) before
> setting `has_signed` — so completion now requires the actual signing key, not merely a
> session JWT. Single signature, no extra prompt. In-app (`SignerVerificationBadge`) and
> offline (`ProofAudit`, proof v1.1 now carries `secret_id` + `ciphertext_sha256`)
> verification updated to match; the creator's plaintext signature is unchanged.
> **Recipient-key hardening:** `/sign` now rejects `recipient_keys` on any non-completing
> signature, so only the final signer can (re)write them. Tests: backend
> `test_verify_message_signature_pqc`, `test_multisig_approval_message_is_domain_separated`,
> `test_sign_rejected_when_signature_invalid`, `TestRecipientKeyRelease` (×2); frontend
> `multisig ciphertext-bound approval` block. Gate: 123 backend, 21 frontend — all green.


**Where:** [routers/multisig.py:191-258](backend/routers/multisig.py#L191).

- Completion is gated purely on the `has_signed` boolean (`all(s.has_signed for s in all_signers)`). The stored `signature` is never verified by the server — it's decorative from the backend's perspective. Verification only happens client-side in `SignerVerificationBadge`. In a zero-knowledge design that's a defensible choice, but it means the server's notion of "completed" carries no cryptographic weight; a bug or a malicious client that sets `has_signed` (via the normal sign endpoint with any bytes) advances the workflow.
- `recipient_keys` can be supplied on **any** sign call, not just the last signer's, and each overwrites `recipient.encrypted_key` unconditionally. A malicious signer can overwrite recipient keys with garbage → recipients get an undecryptable key once the workflow completes (integrity/DoS on key release). They can't learn the secret, but they can break delivery.

**Fix:** verify each signature server-side against the domain-separated multisig digest (depends on H1's wrapper) before accepting `has_signed`; restrict `recipient_keys` writes to the final signer and reject overwrites of already-set keys.

---

### M2 — WebSocket `/ws` has no Origin allowlist or connect rate-limit — **Medium** — ✅ FIXED (2026-06-10)

> **Resolution:** `/ws` now reads `websocket.headers["origin"]` and rejects the
> connection (close `1008`) unless it matches `config.get_allowed_origins()`
> ([messenger.py:175-178](backend/routers/messenger.py#L175)), and a pre-auth timeout
> closes sockets that don't send a valid bearer token within the grace window — so an
> attacker can no longer hold unbounded pre-auth sockets open. (commit `315a99e`)

**Where:** [routers/messenger.py:164-219](backend/routers/messenger.py#L164).

The handshake `accept()`s before auth and performs no `Origin` check. CSWSH is **not** directly exploitable because auth is a bearer token in the first app message (pulled from localStorage, not an auto-sent cookie) — good design. But there's no origin allowlist and no rate limit on connection establishment, so an attacker can open unbounded pre-auth sockets (each waits on `receive_text`) → resource exhaustion. `slowapi` limits HTTP routes but not this WS.

**Fix:** validate `websocket.headers["origin"]` against `ALLOWED_ORIGINS` before/right after accept; add a connection cap or short auth-timeout (close sockets that don't authenticate within N seconds).

---

### M3 — Extension stores the vault password in `chrome.storage.session` (plaintext, ≤1h) — **Medium**

**Where:** [background/handlers/auth.js:36-48](trustkeys/src/background/handlers/auth.js#L36), [background/index.js:13-28](trustkeys/src/background/index.js#L13).

`unlockWithSession` persists the raw password to `chrome.storage.session` for up to an hour of inactivity-extended life. `chrome.storage.session` is memory-only and not exposed to content scripts, so this is the conventional "stay unlocked" tradeoff — but the password (which derives the at-rest vault key) lives in service-worker memory/session storage, broadening the window for a compromised-extension or memory-dump scenario. Note the positive: external `getActiveAccount` returns **only public keys** ([accounts.js:46-50](trustkeys/src/background/handlers/accounts.js#L46)), so private material never crosses the page boundary.

**Fix (optional):** cache a derived non-extractable `CryptoKey` instead of the password (mirrors the frontend `vaultService` key-cache approach), so the password itself isn't retained; shorten/adjust the 1h idle window.

---

### M4 — `sender.origin || request.origin` fallback in permission checks — **Medium** — ✅ FIXED (2026-06-10)

> **Resolution:** Permission gates now use Chrome's `sender.origin` exclusively; the
> message-supplied `request.origin` fallback was removed
> ([crypto.js:19](trustkeys/src/background/handlers/crypto.js#L19) and the SIGN/DECRYPT/
> wrap paths). Absence of `sender.origin` is treated as "deny," not "trust the
> caller-supplied value," closing the spoofed-origin path. (commit `0afbee6`)

**Where:** [handlers/crypto.js:20,78,99,127](trustkeys/src/background/handlers/crypto.js#L20), [index.js:165](trustkeys/src/background/index.js#L165).

Security decisions (`state.vault.permissions[checkOrigin]`) use `sender.origin || request.origin`. `sender.origin` is set by Chrome and trustworthy; `request.origin` is message-supplied. The content script is currently the only sender and doesn't pass `origin` for SIGN/DECRYPT, so this is presently safe — but a message-supplied origin should never be a fallback for an authorization gate. If any future path lets `sender.origin` be undefined, a crafted message asserts an arbitrary trusted origin.

**Fix:** use `sender.origin` exclusively for permission decisions; treat its absence as "deny," not "fall back to caller-supplied value."

---

### M5 — No HSTS — **Medium** — ✅ ALREADY ADDRESSED

> **Resolution:** HSTS is set at the TLS-terminating layer:
> [nginx.conf.example:50](nginx.conf.example#L50) emits
> `Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`
> alongside the rest of the security headers and CSP. nginx is the correct layer —
> the backend runs plain HTTP behind the proxy, so an app-level HSTS header would be
> meaningless. The finding stands only against the app middleware, which the audit
> reviewed without accounting for the (pre-existing, tracked) nginx config.

[main.py:20-29](backend/main.py#L20) sets `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, but not `Strict-Transport-Security`. Add it (at nginx or in the middleware) for any HTTPS deployment.

---

### Low / hardening

- ✅ **L1 — `print()` logging in auth path.** [auth.py](backend/auth.py) prints token-decode and signature-verification errors. Use structured logging at appropriate levels; avoid logging anything attacker-controlled at info. (CLAUDE.md lists structured logging as pending.) *(Resolved — `logging` module logger; attacker-triggerable verify/decode failures at `debug`, server faults at `error`. Raw tokens/signatures are not logged.)*
- ✅ **L2 — JWT `alg` header not validated.** [auth.py:157-186](backend/auth.py#L157) ignores the header `alg` and always verifies with ML-DSA, so alg-confusion/`none` doesn't apply — but defensively reject tokens whose header `alg` ≠ `ML-DSA-44`. *(Resolved — PyJWT `decode(..., algorithms=["HS256"])` enforces an alg whitelist, so `none`/alg-confusion is rejected structurally.)*
- ✅ **L3 — Inconsistent default expiry.** `create_access_token` default branch uses 15 min ([auth.py:137](backend/auth.py#L137)) while `ACCESS_TOKEN_EXPIRE_MINUTES = 30` is what login passes. Harmless but confusing; unify. *(Resolved — default unified to `ACCESS_TOKEN_EXPIRE_MINUTES` in the PyJWT rewrite.)*
- **L4 — Public nonce minting.** `GET /auth/nonce/{address}` lets anyone mint a nonce for any address (enables H1 step 1). Rate-limited 10/min; acceptable in isolation, but fixing H1 neutralizes the leverage.
- **L5 — SQLite + `check_same_thread=False` won't scale to multiple uvicorn workers.** [database.py:4-8](backend/database.py#L4). The ephemeral-key warning, in-memory slowapi limiter, and alembic-on-import all assume a single process. Multi-worker deployment needs a real DB + shared rate-limit store (Redis) + externalized signing key (already env-based ✓).
- **L6 — Alembic upgrade on import with broad fallback.** [main.py:52-64](backend/main.py#L52) falls back to `create_all + stamp` on *any* exception — can silently paper over a real migration failure in production. Consider failing closed in production.
- **L7 — `list_users` `LIKE '%term%'`** is a non-indexable scan ([routers/users.py:68](backend/routers/users.py#L68)); fine at small scale, watch as the directory grows.
- **L8 — Rate-limit coverage gaps.** Several mutating/reading routes lack `@limiter.limit` (e.g. `GET /secrets`, `PUT/DELETE /secrets/{id}`, `POST /documents`). Most sensitive ones are covered; tighten for completeness.
- **L9 — Loose schema bounds.** `address: max_length=20000` and several `Text` fields ([schemas.py](backend/schemas.py)) are far larger than any real value (PQC pubkey hex ≈ 2624). Tighten to realistic caps to shrink the storage-DoS surface.

---

## 2. Code quality

> **Progress (2026-06-11):** §2 cleared. The `handleSign` SoC comment and the
> `getActiveAccount` dead code were already cleaned up during the H1/M1 fixes. The
> `groups.list_groups` N+1 is fixed (batched to two queries). `print()` logging is
> replaced with a `logging`-based module logger (`kryptolog.*`) across `auth.py`,
> `main.py`, `messenger.py`, `websocket_manager.py` — verification/decode failures at
> `debug`, server faults at `error`/`warning` (addresses L1 too); CLI scripts keep
> `print`. Hand-rolled JWT → **classical HS256 via PyJWT** (also closes L2/L3; retired
> the ML-DSA server keypair, liboqs kept for login-challenge verify). Crypto-module
> duplication addressed by **align + document** (behavior verified identical; mirrored
> sync-contract header in both files) rather than a riskier shared-package extraction.
> Kyber/Dilithium naming kept (intentional, documented). 130 backend + 14 frontend green.

- ✅ **`MultisigWorkflow.jsx handleSign` (lines 404-513) is unfinished thinking left in the file.** A long stream-of-consciousness comment block (L413-432) literally debates *what should be signed* ("A) The Original Content? B) The Creator's Signed Struct?... Let's stick to signing what we See"). The signing contract was never nailed down — which is exactly the root of H1/M1. This needs to be replaced with an explicit, documented "what we sign and why" and the domain-separated digest.
- ✅ **Duplicated crypto module.** [frontend/src/utils/crypto.js](frontend/src/utils/crypto.js) and [trustkeys/src/utils/crypto.js](trustkeys/src/utils/crypto.js) are ~90% identical but have drifted (`signMessagePQC`/`verifySignaturePQC` vs `signMessage`/`verifySignature`; frontend has extra vault/biometric/chunk helpers). Divergence risk for security-critical code. Extract a shared, versioned package and import it in both. *(Resolved via **align + document** rather than a shared package: confirmed the security-critical behavior already matches byte-for-byte — KDF (PBKDF2-600k-SHA-512→AES-GCM-256), AEAD (12-byte IV), ML-KEM-768/ML-DSA-44, and the KEM/session-wrap/vault envelope shapes — and added a mirrored "SHARED CRYPTO CORE — KEEP IN SYNC" header to both files documenting the wire-format invariants, the `*PQC`-vs-bare naming map, and the intentional frontend-only extras. The remaining drift is naming + frontend extras, neither a correctness issue; a full shared-package extraction across the two Vite builds was judged higher-risk than its benefit.)*
- ✅ **Dead code in `accounts.js getActiveAccount`** ([accounts.js:37-40](trustkeys/src/background/handlers/accounts.js#L37)): `return {success:false...}` immediately followed by an unreachable `throw`. Pick one behavior. *(Resolved — `getActiveAccount` is now a clean permission-check + return; no unreachable code.)*
- ✅ **Hand-rolled JWT.** [auth.py:132-186](backend/auth.py#L132) reimplements JWT encode/decode (manual b64url + sign/verify). PyJWT is already a dependency. Hand-rolled JOSE is a classic source of subtle bugs — see also L2. (Discussed under §3.) *(Resolved — replaced with PyJWT **HS256**. The token is server-issued/verified only, so a symmetric secret (`KRYPTOLOG_JWT_SECRET`) is correct and small; PyJWT validates the alg whitelist + exp (closes L2), and the expiry default was unified (L3). The ML-DSA server keypair is retired; liboqs stays for login-challenge verification. See §3.)*
- ✅ **`groups.list_groups` N+1** ([routers/groups.py:114-136](backend/routers/groups.py#L114)): one "latest message" query per channel in a Python loop, plus unread_count is hardcoded to 0 (TODO). Batch it; finish read tracking or remove the field. *(Resolved — batched to two queries via `max(id)` grouped subquery + a single sender-eager-loaded fetch. unread_count still 0; per-user read tracking remains a TODO.)*
- **Naming debt:** "Kyber"/"Dilithium" identifiers persist for ML-KEM/ML-DSA. Intentional for storage-schema stability and documented — acceptable, but a future rename pass would reduce confusion.
- ✅ **Broad `except Exception` + `print` swallowing** appears in several places (push loop, ws handler, alembic). Fine for resilience, but log at warning/error with context rather than `print`. *(Resolved — `print` replaced with `logging` module loggers across `auth.py`/`main.py`/`messenger.py`/`websocket_manager.py`, with appropriate levels. Also closes L1.)*

---

## 3. Pertinence / architecture

- ✅ **Does the JWT even need PQC?** (CLAUDE.md already asks this — I agree it's worth acting on.) The JWT is a server-issued, server-verified token; nothing about it crosses a quantum-threat boundary that a classical MAC wouldn't cover. ML-DSA JWTs are big (~2.4 KB signature) and pull liboqs into the JWT path. Switching to PyJWT HS256/EdDSA would be smaller, standard, and remove the hand-rolled JOSE (L2). liboqs stays required server-side regardless, to verify client **login challenges** — that part genuinely needs PQC. Net: keep liboqs for challenge verification; consider classical JWTs. *(Done 2026-06-11 — JWTs are now HS256 (PyJWT); liboqs retained only for login-challenge verification; the ML-DSA server keypair is retired.)*
- **Zero-knowledge envelope model is sound.** Server stores only ciphertext + per-recipient wrapped keys; ML-KEM is browser-internal; ML-DSA interop (noble↔liboqs) is the only cross-wire crypto and is test-covered. Good separation.
- **Multisig is strictly N-of-N**, with weak server-side signature meaning (M1). If the product ever wants M-of-N thresholds or auditable approvals, the current model needs the signature to actually bind to the workflow (H1 fix is a prerequisite).
- **Rate limiting is in-process (slowapi).** Resets per worker and doesn't coordinate across processes — fine for a single-process deploy, insufficient for horizontal scaling (pair with L5).
- **Extension permission model** (per-origin grants, dynamic content-script registration, `<all_urls>` host permission) is broad but coherent for a "user authorizes arbitrary sites" wallet. The `<all_urls>` host permission and MAIN-world API injection are the cost of that model; acceptable, worth a line in the store listing / threat model.
- **Biometric vault is PRF-only with no software fallback** — a deliberate, correct hardening (a non-hardware-bound key would have to sit in JS-readable storage). Good.

---

## 4. What looks genuinely solid (so it isn't re-litigated)

- Key-bound login challenge (encryption key folded into the signed message) — closes the M-2 KEM-substitution concern.
- Token revocation via `token_version` honored on both HTTP and WS ([dependencies.py:40-57](backend/dependencies.py#L40)).
- Fail-closed server signing key in production ([auth.py:42-50](backend/auth.py#L42)), validated at boot ([main.py:70-71](backend/main.py#L70)).
- Strict CSP with templated `connect-src`, `object-src 'none'`, no `unsafe-eval` ([frontend/index.html](frontend/index.html), [vite.config.js](frontend/vite.config.js)).
- Trusted-proxy-aware rate-limit keying ([dependencies.py:22-33](backend/dependencies.py#L22)).
- PBKDF2-SHA-512 @ 600k iterations for the vault KDF; AES-GCM throughout; per-call random IVs.
- File-size enforcement via SQL aggregation before insert ([routers/secrets.py:306-315](backend/routers/secrets.py#L306)).

---

## 5. Suggested priority order

1. **H1** — domain-separate all signed contexts + render structured sign requests. (Also unlocks a meaningful M1 fix.)
2. **M1** — verify multisig signatures server-side against the workflow-bound digest; lock down `recipient_keys` writes.
3. **M2** — WS origin allowlist + connect throttle.
4. **M4** — drop the `request.origin` fallback in permission gates.
5. **M3 / M5 / L-series** — as hardening passes.
6. **Quality:** clean up `handleSign`, de-duplicate the crypto module, reconsider PQC-vs-classical JWTs.

*Not executed:* I reviewed statically and did not run the test suite; CLAUDE.md reports the gate green (87 backend + 8 pqc + 9 frontend). Note that no current test exercises the H1 cross-context reuse or the M1 recipient-key-overwrite path — worth adding alongside the fixes.
