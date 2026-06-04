# Kryptolog (PQC fork) — Project Context

> This file is auto-loaded into context each session. It exists to let a fresh Claude
> pick up the post-quantum crypto migration without re-deriving the analysis. The full
> security/architecture/quality audit is in `Doc/SECURITY_ARCHITECTURE_QUALITY_AUDIT.md`.

## What this is

A **clean-state fork** of `dozpupp/kryptolog` (original local copy at `/home/bakaneko/kryptolog`),
created 2026-05-29 to migrate the post-quantum cryptography off unaudited JavaScript
libraries onto NIST FIPS algorithms. Fresh git history (single initial commit); existing
data/identities are intentionally **not** carried over.

Kryptolog is an **end-to-end-encrypted** secret-management + document-signing platform:
secrets/files vault, secure sharing (per-recipient key wrapping), signed documents,
N-of-N multisig workflows, E2EE messenger + group chat, web-push notifications.

- **Backend:** FastAPI + SQLAlchemy + Alembic, SQLite (`backend/sql_app.db`). Zero-knowledge:
  stores only ciphertext and per-recipient wrapped keys, never plaintext or private keys.
- **Frontend:** React 19 + Vite 7 + Tailwind 4 SPA.
- **TrustKeys:** Chrome/Brave MV3 extension (key custody) — **also uses the PQC libs**, so it
  is in scope for the migration.
- **PQC sidecar (to be removed):** a Node service (`backend/pqc_service.js`) that exists only
  because the Dilithium lib is JS-only; the Python backend HTTP-calls it to sign/verify.

## Status: migration IMPLEMENTED (committed to `main`)

The lib swap is **done and tested**, not pending. Clients use `@noble/post-quantum`
0.6.1 (ML-KEM-768 + ML-DSA-44); the backend uses in-process `oqs` (ML-DSA-44) and the
Node sidecar is deleted. noble↔liboqs ML-DSA-44 interop is proven **both directions**.
Test gate green: `backend/tests/test_pqc.py` (8) + `frontend/src/test/pqc.test.js` (9)
+ the existing backend suite (87). Server signing key is now
`KRYPTOLOG_ML_DSA_PUBLIC_KEY` / `KRYPTOLOG_ML_DSA_SECRET_KEY` (generate via
`backend/generate_server_keys.py`; unset ⇒ ephemeral key + warning). The sections
below are retained as the rationale of record.

## The migration — decisions locked in

| Decision | Choice |
|----------|--------|
| Migration stance | **Clean cutover** — wipe existing vaults/identities/DB, no dual-support, no lazy re-keying |
| Git history | **Fresh start** — initial commit only |
| Algorithms | **ML-KEM-768** (replaces Kyber768) + **ML-DSA-44** (replaces Dilithium2 / `kind=2`) |
| Browser + extension lib | **`@noble/post-quantum`** (audited, pure TS, no WASM) |
| Server lib | **`liboqs-python`** (`oqs`) — in-process |
| Node PQC sidecar | **Delete it** — fold signing/verification into the Python backend (closes audit A1/M1) |

Note: ML-KEM/ML-DSA (FIPS 203/204) are **NOT wire-compatible** with the round-3 Kyber/Dilithium
used today — hence the clean cutover.

## Key constraint shaping the work

Crypto runs in two places, but only **ML-DSA crosses the wire**:
- **Browser/extension** (E2EE, must stay client-side): ML-KEM encaps/decaps + ML-DSA sign/verify.
- **Server**: ML-DSA only — signs JWTs, verifies login challenges.
- **ML-KEM is browser-internal** (server never touches it) → only clients must agree.
- **ML-DSA must interoperate** between noble (browser/extension) and liboqs (server). Both emit
  FIPS 204 byte encodings so they *should* match — **prove it with tests, don't assume.**

## Phased plan

0. *(Optional with clean cutover)* lightweight `alg`/version tag on crypto envelopes for future agility.
1. **Provider seam:** wrap the ~27 client crypto call sites behind one `PQCProvider` interface so the lib swap is localized.
2. **Swap implementations:**
   - Frontend + extension: `npm rm crystals-kyber dilithium-crystals-js`; remove the `postinstall`
     hook + `scripts/patch-kyber.cjs`, delete `public/dilithium.wasm`, remove the
     `window.chrome.runtime.getURL` polyfill (`crypto.js:10-17`). `npm i @noble/post-quantum`.
     Rewrite sign/verify (delete the 3-strategy `verifySignaturePQC` heuristic — audit H4) and
     KEM wrap/unwrap (AES-GCM plumbing stays unchanged).
   - Backend: delete `pqc_service.js`; drop it from `start_all.sh`, `run_dev.sh`,
     `ecosystem.config.cjs`; add `oqs` to `requirements.txt`; rewrite `backend/auth.py` to use
     `oqs.Signature("ML-DSA-44")` locally.
3. **Test gate (mandatory):** NIST KAT vectors for both libs; cross-interop noble↔liboqs
   sign/verify; KEM wrap→unwrap round-trip.

## Gotchas / snags

- **`@noble/post-quantum` argument order** (`sign(secretKey, msg)` vs `(msg, secretKey)`) has changed
  between releases — pin the version and follow the installed README, don't trust memory.
- **`liboqs-python` is not a pure wheel** — it compiles liboqs C (needs cmake + a compiler). Document in README install steps.
- **No seeded keygen in liboqs:** today the server key is derived deterministically from
  `KRYPTOLOG_SECRET_KEY` (in `pqc_service.js`). liboqs has no public seeded-keygen → instead
  **generate the server signing keypair once and store the secret key** in env / a secret manager
  (better practice anyway). Revisit whether the JWT even needs PQC signing vs. PyJWT (HS256/EdDSA);
  liboqs is still required server-side to verify client login challenges regardless.
- Don't forget the **extension** — miss it and extension-based login breaks server-side verification.

## Audit highlights already addressed in this fork

- **H1 (leaked secret):** removed the real VAPID private key from `backend/.env.example` and fixed
  the wrong `PQC_SERVICE_URL` (now `:3002`). The original repo still needs its key rotated + history scrubbed.

Remaining high-value hardening from the audit (not yet done): strict CSP + HSTS, the localStorage
biometric-fallback key issue (H2), exact-match signature verification (H4), structured logging.

## Conventions

- Markdown file references use clickable links, e.g. `[auth.py](backend/auth.py)`.
- Git commits end with the `Co-Authored-By: Claude Opus 4.8` trailer; branch before committing on `main`.
