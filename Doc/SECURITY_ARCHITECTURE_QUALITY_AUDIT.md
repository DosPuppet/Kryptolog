# SafeLog — Security, Architecture & Quality Audit

**Date:** 2026-05-29
**Scope:** Backend (FastAPI + Node PQC sidecar), Frontend (React 19 SPA), TrustKeys extension (referenced)
**Audit type:** Static review of source code, configuration, and design. No dynamic/penetration testing or cryptographic library verification was performed.

---

## 1. Executive Summary

SafeLog is an end-to-end-encrypted (E2EE) secret-management and document-signing platform whose headline feature is **post-quantum cryptography** (Kyber KEM + Dilithium signatures), delivered through a browser extension or an in-browser "local vault."

The **core architecture is sound**: the server is a zero-knowledge store that only ever holds ciphertext and per-recipient wrapped keys (envelope encryption). Private keys never leave the client. Authentication is challenge/response with anti-replay nonces. This is a genuinely good E2EE design and the strongest aspect of the project.

However, the project is best characterized as an **advanced prototype / portfolio project, not production-ready**. The principal concerns are:

1. **The post-quantum primitives rely on unaudited pure-JavaScript libraries** — the central security claim rests on code with no formal guarantees, no constant-time assurance, and no third-party audit.
2. **A live secret (VAPID private key) is committed to the repository.**
3. **Biometric "fallback" mode stores a key in plaintext `localStorage`**, defeating vault encryption for affected users.
4. **Every authenticated request makes a synchronous HTTP round-trip to a Node sidecar** to verify the token — a coupling, latency, and availability problem that exists only because the chosen crypto library is JS-only.
5. **SQLite** as the datastore for a multi-user, sharing-heavy, group-chat product.

Overall risk rating: **MEDIUM-HIGH** for any real deployment; **acceptable** for a local/demo/educational context, which appears to be the intent.

---

## 2. Application Overview

| Aspect | Detail |
|--------|--------|
| Purpose | E2EE vault for secrets/files, secure sharing, signed documents, N-of-N multisig, E2EE messenger + group chat |
| Trust model | Zero-knowledge server; client-side encryption; keys held in extension or password-protected browser vault |
| Auth | Dual: MetaMask (ECDSA `personal_sign`) **or** TrustKeys (Dilithium-signed challenge) |
| Processes | 3 local: FastAPI API (`:8000`), Node PQC sidecar (`:3002`), Vite frontend (`:5173`) |
| Storage | SQLite (`sql_app.db`), stores only ciphertext + wrapped keys |

The design intent — *the server should learn nothing* — is implemented consistently: [models.py](../backend/models.py) stores `encrypted_data`, `encrypted_key`, and per-grantee `AccessGrant.encrypted_key` blobs, never plaintext or raw keys.

---

## 3. Architecture Audit

### 3.1 Strengths

- **Envelope / hybrid encryption done right.** A random symmetric session key encrypts content; that key is wrapped per-recipient with the recipient's Kyber public key (`wrapSessionKey`/`unwrapSessionKey` in [crypto.js](../frontend/src/utils/crypto.js)). Sharing re-wraps the key without re-encrypting content, and Eth↔PQC recipients are supported.
- **Clean router separation** ([backend/routers/](../backend/routers/)) by domain (auth, secrets, multisig, messenger, groups, notifications).
- **Schema-level input validation** with explicit `max_length` on every field ([schemas.py](../backend/schemas.py)).
- **Migrations** via Alembic with a `create_all` + `stamp` fallback ([main.py](../backend/main.py)).
- **Chunked uploads** with server-side cumulative size enforcement computed in SQL ([secrets.py:307](../backend/routers/secrets.py#L307)).

### 3.2 Architectural weaknesses

**A1 — The Node PQC sidecar is an architectural liability (MEDIUM).**
The backend is Python but `dilithium-crystals-js` is JS-only, so a separate Node HTTP service exists solely to sign/verify. Consequences:
- **Every authenticated request** calls `auth.decode_access_token`, which performs a synchronous `httpx.post(.../verify)` to the sidecar ([auth.py:133](../backend/auth.py#L133)). This is a per-request network hop, a hard availability dependency (sidecar down ⇒ all auth fails), and a latency/throughput ceiling.
- Token *creation* also round-trips ([auth.py:104](../backend/auth.py#L104)).
- It is a second deployable, with its own secret, port, and failure mode.

A Python PQC binding (e.g. `liboqs-python`/`pqcrypto`) would eliminate the process, the network hop, and the per-request coupling, and would use vetted C implementations instead of pure JS — a strict improvement on both axes.

**A2 — SQLite for a multi-user, real-time product (MEDIUM).**
[database.py](../backend/database.py) uses `sqlite:///./sql_app.db` with `check_same_thread=False`. SQLite is single-writer; with WebSocket fan-out, group chat, and push, write contention and `database is locked` errors are likely under concurrency. There is no backup/durability story. E2EE means a DB leak does not expose plaintext (good), but availability and scaling are real concerns. PostgreSQL is the natural target.

**A3 — Hand-rolled JWT instead of a vetted library (MEDIUM).**
`PyJWT` is a declared dependency ([requirements.txt](../backend/requirements.txt)) but unused for the main flow. [auth.py](../backend/auth.py) manually assembles `header.payload.signature`. Issues:
- The `alg` header is *not validated* on decode — verification always uses the server's Dilithium key, so algorithm-confusion is not currently exploitable, but the construction is fragile and easy to break in future edits.
- No `iat`/`nbf`, no `jti`, no revocation list, no refresh token. Sessions are 30 min ([auth.py:85-92](../backend/auth.py#L85) sets a 15-min default but login passes 30) with hard re-login.
- A **single global signing keypair** is derived deterministically from `SAFELOG_SECRET_KEY` ([pqc_service.js:18-31](../backend/pqc_service.js#L18)). Leakage of that one secret allows forging tokens for any user.

**A4 — Auth type discrimination by string length (LOW).**
`verify_signature` decides Eth vs PQC via `len(address) > 42` ([auth.py:72](../backend/auth.py#L72)). Functional but brittle; an explicit `auth_type` field would be clearer and safer.

---

## 4. Security Audit

Findings are ordered by severity. Severity reflects impact in a *real* deployment.

### HIGH

**H1 — Live secret committed to the repository.**
[backend/.env.example](../backend/.env.example) contains a real-looking VAPID **private** key:
```
VAPID_PRIVATE_KEY=ev5VTB79IqNGDuk9wV3Z9reX5-u4y-aKDygsCIMRs1E
```
Even as an "example," a private key in version control must be treated as compromised. Anyone with the repo can send push notifications as this VAPID identity. (Note also `PQC_SERVICE_URL=http://localhost:8000` in the example is wrong — the sidecar is `:3002`.)
**Fix:** purge the key, rotate VAPID keys, replace example values with obvious placeholders, and scrub git history.

**H2 — Biometric "fallback" mode stores a key in plaintext `localStorage`.**
In [crypto.js:721-723](../frontend/src/utils/crypto.js#L721), the Android/no-PRF path generates a 32-byte key and writes it **unencrypted** to `localStorage['safelog_bio_fallback_key']`. The vault password is then encrypted with that key and *also* stored in `localStorage` ([vault.js:449-460](../frontend/src/services/vault.js#L449)). Anyone with `localStorage` access — via **XSS**, a malicious extension, or local machine access — obtains both the key and the encrypted password, recovers the vault password, and decrypts the entire vault. This **negates** the 600k-iteration PBKDF2 protection for fallback-mode users. The code comments acknowledge the risk, but it is shipped, not gated. **Fix:** do not offer non-hardware-bound biometrics; require PRF, or treat fallback as "convenience only, no security guarantee" with explicit consent and no password storage.

**H3 — Core PQC relies on unaudited, pure-JS implementations.**
The entire post-quantum value proposition rests on `crystals-kyber` and `dilithium-crystals-js` (npm, pure JS/WASM) used in [crypto.js](../frontend/src/utils/crypto.js) and [pqc_service.js](../backend/pqc_service.js). These are **not** the NIST reference implementations, are **not** formally verified, and offer **no constant-time guarantees** (timing side-channels on key operations). For a product whose differentiator is quantum resistance, the primitive itself is the weakest link. **Fix:** migrate to vetted implementations (liboqs and its bindings) and clearly document the limitation until then.

**H4 — Permissive signature verification with prefix-match fallback.**
`verifySignaturePQC` ([crypto.js:152-235](../frontend/src/utils/crypto.js#L152)) tries three strategies; Strategy 3 extracts the signed message *from the signature blob itself*, verifies the blob against its own extracted content, then accepts if the expected message is merely a **prefix** of the extracted content (trailing bytes ignored). This makes "what was signed" ambiguous and means a signature can be accepted for a message that is only a substring of the actually-signed content. In document/proof verification (ProofAudit), integrity claims should be exact-match only. **Fix:** verify a single canonical encoding with exact equality; remove the heuristic fallbacks.

### MEDIUM

**M1 — Per-request auth depends on the sidecar (see A1).** Synchronous verify round-trip on every request: availability SPOF, latency, and a DoS amplification vector (each request forces an HTTP call + Dilithium verify). At minimum, cache verification results for the token's lifetime, or verify locally.

**M2 — No CSP, no HSTS; legacy XSS header.** [main.py:19-26](../backend/main.py#L19) sets `X-Frame-Options`, `nosniff`, `Referrer-Policy`, and the **deprecated** `X-XSS-Protection: 1; mode=block` (modern guidance is `0`). There is **no `Content-Security-Policy`** and **no `Strict-Transport-Security`**. Because keys live in `localStorage` (H2), an XSS is catastrophic — a strong CSP is the single highest-value hardening here.

**M3 — Rate limiting keyed on raw remote address.** `Limiter(key_func=get_remote_address)` ([dependencies.py:10](../backend/dependencies.py#L10)). Behind the documented Nginx reverse proxy, all clients may share the proxy IP (mass over-throttling) unless `X-Forwarded-For` is correctly trusted — and naïvely trusting it enables bypass. Configure proxy-aware client IP extraction explicitly.

**M4 — Multisig trust model is client-enforced.** During `/sign`, any signer may overwrite recipient `encrypted_key`s ([multisig.py:216-223](../backend/routers/multisig.py#L216)). The server cannot validate these blobs (it has no keys), so correctness depends entirely on honest clients. This is inherent to E2EE but should be documented as an explicit threat-model assumption (a malicious last signer can release a wrong/garbage key to recipients).

**M5 — Non-constant-time API-key comparison on sidecar.** `apiKey !== validKey` ([pqc_service.js:59](../backend/pqc_service.js#L59)) is a timing comparison of the shared secret. Low risk (service binds `127.0.0.1`), but use `crypto.timingSafeEqual`.

**M6 — CORS allows credentials with wildcard methods/headers.** [main.py:41-47](../backend/main.py#L41) sets `allow_credentials=True` with `allow_methods=["*"]`/`allow_headers=["*"]`. Origins are explicit (good, and fail-closed when unset), but the app uses Bearer tokens, so `allow_credentials` is unnecessary and broadens exposure. Tighten to the methods/headers actually used.

### LOW

- **L1 — Logging via `print()` only.** Exceptions (including token-decode failures) are printed ([auth.py:162](../backend/auth.py#L162)); there is no structured logging and no security audit trail. ProofAudit is now offline-only (per recent commit), so there is no server-side record of signing events.
- **L2 — Session ergonomics.** 30-min tokens with no refresh force frequent re-login and re-unlock.
- **L3 — Frontend crypto is under-tested.** README cites 87 backend tests but only 7 frontend tests, none meaningfully covering the most complex and security-critical code (`crypto.js`, `vault.js`). The convoluted `verifySignaturePQC` is exactly the kind of code that needs exhaustive tests.
- **L4 — Loose dependency pinning on bleeding-edge stack.** `fastapi>=0.128`, `sqlalchemy>=2.0.46`, React 19, Tailwind 4, Vite 7. `>=` ranges can silently pull breaking/risky versions; pin or use a lockfile-enforced range. Cutting-edge majors increase churn and supply-chain surface.
- **L5 — Hex-encoded blobs in SQLite.** File chunks and ciphertext are stored as hex `Text` ([models.py:132](../backend/models.py#L132)), doubling storage vs. binary `BLOB` and bloating the single-file DB.

### Notable strengths (security)

- **True zero-knowledge server** — only ciphertext and wrapped keys persisted.
- **Strong local-vault KDF** — PBKDF2-SHA-512, 600k iterations ([crypto.js:498-520](../frontend/src/utils/crypto.js#L498)).
- **Private keys stripped from in-memory vault copy** (`_sanitize` in [vault.js:63](../frontend/src/services/vault.js#L63)); decrypt-on-demand pattern.
- **Anti-replay login** — single-use nonces with 5-min expiry, deleted on consumption ([auth.py router](../backend/routers/auth.py), [auth router:53](../backend/routers/auth.py#L53)).
- **Authenticated WebSocket** — token verified before connect ([messenger.py:182](../backend/routers/messenger.py#L182)).
- **AES-GCM everywhere** for symmetric encryption with random 12-byte IVs.

---

## 5. Code Quality Audit

| Area | Assessment |
|------|------------|
| Readability | Good. Clear module boundaries, descriptive names, helpful comments. |
| Backend consistency | High. Routers follow a uniform pattern; dependency injection used well. |
| Frontend crypto | **Mixed.** `crypto.js` is large and mostly clear, but `verifySignaturePQC` (H4) is convoluted, comment-heavy "trial-and-error" code — a maintainability and correctness smell. |
| Error handling | Backend swallows exceptions into `print` + generic returns; loses observability. |
| Tests | Backend reasonable (87); frontend minimal (7) and absent on the riskiest code. |
| Config hygiene | Weak — secret in `.env.example` (H1), wrong URL in example, no central settings object ([config.py](../backend/config.py) holds only a file-size constant). |
| Dead/disabled code | MPC recovery and Google OAuth are present but "currently disabled," adding surface and confusion. |

**Recommendations:** centralize configuration (e.g., `pydantic-settings`) and fail fast on missing required env vars; replace `print` with structured logging; add property-based tests for all crypto round-trips (encrypt→decrypt, sign→verify, wrap→unwrap); remove or clearly fence disabled features.

---

## 6. Pertinence of Usage & Technology Choices

### 6.1 Is the problem worth solving this way?
A client-side-encrypted secret/credential manager with secure sharing is a legitimate and useful product class (1Password/Bitwarden territory). The **E2EE-with-envelope-sharing** approach is the right architecture for it, and SafeLog implements it credibly.

### 6.2 Is post-quantum cryptography pertinent here?
**Partially.** The "harvest-now, decrypt-later" threat is real for long-lived secrets, so PQC for the *confidentiality* layer (Kyber KEM wrapping session keys) has genuine forward-looking value. **But** the benefit is undermined by:
- **Unaudited JS implementations** (H3) — quantum resistance on paper, unverified in practice, with side-channel exposure.
- **The server's classical trust anchor** — auth integrity rests on one Dilithium key derived from one env secret; PQC does not help if that leaks.
- **MetaMask path uses classical ECDSA/x25519**, so half the user base gets no PQC at all.

Net: PQC is a defensible *differentiator* and learning vehicle, but currently more **marketing-grade than assurance-grade**. It should be framed honestly until backed by vetted libraries.

### 6.3 Technology choices

| Choice | Verdict |
|--------|---------|
| FastAPI + SQLAlchemy + Alembic | **Good.** Idiomatic, well-suited. |
| **Node PQC sidecar** | **Questionable.** Exists only to bridge a JS-only library; introduces a per-request hop and a second process. A Python PQC binding removes it entirely. (See A1.) |
| **SQLite** | **Inadequate for the advertised multi-user/real-time feature set.** Fine for single-user/self-host/demo. (See A2.) |
| Hand-rolled Dilithium JWT | **Questionable.** Reinvents a solved problem; `PyJWT` already present. (See A3.) |
| React 19 / Vite 7 / Tailwind 4 | **Acceptable but bleeding-edge.** Modern and capable; expect churn and ensure dependency pinning. |
| `crystals-kyber` / `dilithium-crystals-js` | **Risky for a security product** (H3). Prefer audited C implementations via bindings. |
| MetaMask + WebAuthn/PRF + browser extension | **Good UX/security breadth**, though it multiplies code paths and edge cases. |
| Web Push (VAPID) | Reasonable; just don't commit the keys (H1). |

---

## 7. Prioritized Recommendations

**Immediate (do before any real use):**
1. **Purge and rotate the committed VAPID private key** (H1); scrub history; placeholder all example secrets.
2. **Remove plaintext-key biometric fallback** or strip its security claim (H2).
3. **Add a strict Content-Security-Policy** and HSTS; set `X-XSS-Protection: 0` (M2).

**Short term:**
4. **Replace the JS PQC libraries** with audited implementations (liboqs bindings) and, in doing so, **eliminate the Node sidecar** by moving PQC into the Python backend (H3, A1).
5. **Cache or localize token verification** so requests don't each hit the sidecar (M1).
6. **Harden `verifySignaturePQC`** to exact-match, single-encoding verification (H4).
7. **Centralize config**, fail fast on missing secrets, replace `print` with structured logging + an audit log.

**Medium term:**
8. **Migrate to PostgreSQL** before multi-user/real-time load (A2).
9. **Adopt a standard JWT library**, add refresh tokens + revocation (A3).
10. **Expand frontend crypto test coverage** with round-trip/property tests (L3).
11. **Document the multisig/E2EE threat model** explicitly (M4).

---

## 8. Conclusion

SafeLog is an ambitious, well-organized E2EE platform with a genuinely correct zero-knowledge core and several strong security primitives (envelope encryption, hardened local-vault KDF, anti-replay auth). It is held back from production readiness by a committed secret, a localStorage key-storage flaw, a per-request dependency on an avoidable crypto sidecar, SQLite as the datastore, and — most fundamentally — a post-quantum value proposition built on unaudited JavaScript cryptography.

As an **educational / portfolio / demonstration** project it is impressive and largely coherent. As a **production secrets manager** it should not be deployed until at least the HIGH findings (H1–H4) and the sidecar/database architecture (A1–A2) are addressed. The fastest path to credibility is to swap in audited PQC libraries, collapse the sidecar into the backend, and treat configuration secrets with the rigor the rest of the design already demonstrates.
