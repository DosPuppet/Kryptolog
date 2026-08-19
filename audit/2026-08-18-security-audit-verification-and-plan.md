# Security Audit — Verification and Correction Plan

**Date:** 2026-08-18
**Scope:** Verification of the external static audit (KRY-001 … KRY-012) against the
actual code at `main` (`ee84b9e`), plus a prioritised correction plan.

Every finding below was checked against the source. Line references point at the
code as of the commit above.

---

## 1. Verdict on the audit

The audit is substantially accurate. All five P0/P1 findings are real and
reproducible. Two claims need correction, and verification surfaced two issues
the audit did not report.

### 1.1 Confirmed exactly as described

#### KRY-001 — HIGH — Expired AccessGrants remain valid for file chunks

`_check_secret_access()` at `backend/routers/secrets.py:268-273` queries
`AccessGrant` filtering only on `secret_id` and `grantee_address`, with no
`expires_at` condition:

```python
grant = db.query(models.AccessGrant).filter(
    models.AccessGrant.secret_id == secret_id,
    models.AccessGrant.grantee_address == user_address
).first()
if grant:
    return secret
```

Meanwhile `backend/routers/secrets.py:206` and `backend/routers/secrets.py:222`
*do* purge expired grants, but only in the listing endpoints
(`GET /secrets/{id}/access` and `GET /secrets/shared-with-me`).

The expiry policy is therefore enforced on the pages a user browses, but not on
the two chunk-download endpoints that call `_check_secret_access()`:

- `GET /secrets/{secret_id}/chunks` (`backend/routers/secrets.py:334`)
- `GET /secrets/{secret_id}/chunks/{chunk_index}` (`backend/routers/secrets.py:348`)

**Amplifying detail the audit missed:** because purging is lazy and only happens
on those two listing endpoints, an expired grant survives indefinitely as long as
neither party opens a listing page. The attack window is unbounded, not the
60 seconds the audit's scenario implies.

#### KRY-002 — HIGH (upgraded from "potential") — SSRF via Web Push endpoint

`PushSubscriptionCreate` at `backend/schemas.py:291-294` has no validators at
all — not even `max_length`:

```python
class PushSubscriptionCreate(BaseModel):
    endpoint: str
    p256dh: str
    auth: str
```

The endpoint flows unvalidated into `webpush()` at `backend/utils/push.py:28`.

**Dynamic confirmation (resolves the audit's caveat):** the installed pywebpush
calls `self.requests_method.post(endpoint, timeout=timeout, **params)` with no
`allow_redirects=False`. `requests` follows redirects by default, so both the
direct internal-address variant *and* the redirect / DNS-rebinding variants work.
This is exploitable, not merely potential.

#### KRY-003 — MEDIUM/HIGH — Key transfer is not truly single-use

`backend/routers/transfers.py:57-71` is a textbook SELECT-then-DELETE. Two
concurrent claims on the same id both read `row.ciphertext` before either
`db.delete(row)` commits.

#### KRY-004 — MEDIUM — Login nonce not consumed atomically

`backend/routers/auth.py:35-64` fetches the nonce, runs the ML-DSA verification,
then deletes. The verification is comparatively slow, which widens the race
window considerably beyond a simple read-then-write.

#### KRY-005 — MEDIUM — Multisig quorum race

`backend/routers/multisig.py:265-271` computes `already_signed` from an unlocked
read of all signer rows.

### 1.2 Where the audit is wrong or incomplete

#### KRY-005's stated impact is misleading

The audit frames the risk as an inconsistent quorum count. The more serious
consequence is different: with quorum=2 and two concurrent signers, *both*
compute `is_completing = True`, so both are allowed past the guard at
`backend/routers/multisig.py:272-276`. That guard exists specifically to enforce
"only the completing signer may release recipient keys" — the race breaks that
invariant, letting a non-final signer overwrite recipient keys with garbage.

#### NEW — Non-atomic completion in the same function (not in the audit)

`backend/routers/multisig.py` commits twice:

- line 289 — `db.commit()` persists the signature
- lines 303-305 — `wf.status = "completed"` is set and committed separately

A crash or dropped connection between those two commits leaves a workflow with a
full quorum permanently stuck in `pending`. The secret is never released and
there is no recovery path.

#### NEW — HIGH — Push subscription IDOR (not in the audit)

`backend/routers/notifications.py:16-27` looks up an existing `PushSubscription`
by `endpoint` alone, then reassigns ownership with no check:

```python
existing = db.query(models.PushSubscription).filter(
    models.PushSubscription.endpoint == sub.endpoint
).first()
if existing:
    existing.user_address = current_user.address   # no ownership check
```

Any authenticated user who learns or guesses another user's endpoint string can
steal that subscription row and redirect the victim's push notifications — which
carry sender names and secret titles — to their own device. `unsubscribe` has the
same class of problem. This pairs badly with KRY-002.

### 1.3 Findings to downgrade

#### KRY-009 (CSP) — real, but lower priority than stated

A grep across `frontend/src/` and `trustkeys/src/` found **zero** `innerHTML` /
`dangerouslySetInnerHTML` sinks. CSP here is defense-in-depth, not a live hole.
Still worth adding; not urgent.

#### KRY-011 (`len(key) < 500`) — not a vulnerability

The checks at `backend/routers/groups.py:46`, `backend/routers/groups.py:311`,
`backend/routers/messenger.py:33` and `backend/routers/users.py:79` are UX
capability filters ("does this user have a PQC key we can encrypt to?"), not
security gates. The actual security boundary is `bytes.fromhex()` plus liboqs
verification in `backend/auth.py:125-135`, which correctly rejects malformed
keys. Worth tightening for clarity and auditability; it is not exploitable.

### 1.4 Environment constraint affecting all fixes

`backend/database.py:9-21` defaults to PostgreSQL but explicitly supports SQLite
(`connect_args` branch on the URL scheme). `backend/tests/conftest.py` runs
against real PostgreSQL. **All SQL-level fixes must be portable across both** —
so Postgres-only `DELETE ... RETURNING` is not acceptable as the sole mechanism,
and `with_for_update()` needs a documented SQLite fallback (it is a no-op there).

---

## 2. Correction plan

### P0 — the four exploitable bugs, plus the one the audit missed

**1. Centralised authorization layer (fixes KRY-001)**

Add `backend/security/authorization.py` exposing `can_read_secret()`,
`can_write_secret()` and `can_manage_grant()`, where the grant query carries
`(expires_at IS NULL OR expires_at > now())`. Rewrite `_check_secret_access()` to
delegate, so the rule exists in exactly one place.

This is the audit's own recommendation and it is the right call: the bug exists
precisely *because* the rule was duplicated between the listing endpoints and the
chunk endpoints.

**2. SSRF guard for push endpoints (fixes KRY-002)**

Add `backend/security/url_guard.py`:

- HTTPS-only
- resolve the hostname, reject loopback / private / link-local / multicast /
  reserved ranges
- pin the connection to the validated IP so DNS rebinding cannot swap it after
  the check
- set `allow_redirects=False` on the pywebpush call

Validate at **subscribe time and at send time** — stored rows predate the check.
Add `max_length` to the three `PushSubscriptionCreate` fields.

**3. Fix the push subscription IDOR (new finding)**

Scope the `existing` lookup in `subscribe` to
`user_address == current_user.address`; make `unsubscribe` equally scoped.

**4. Atomic transfer claim (fixes KRY-003)**

Conditional `DELETE ... WHERE id = :id AND expires_at > now()`, checking
`rowcount` before returning the ciphertext, with the row read in the same
transaction. Must work on both PostgreSQL and SQLite, so use a locked read plus a
guarded delete rather than a Postgres-only `RETURNING`.

**5. Atomic nonce consumption (fixes KRY-004)**

Consume the nonce with a conditional delete **before** the ML-DSA verification,
holding the value in memory for the comparison. This both closes the race and
shrinks the window that the slow signature check currently opens.

### P1

**6. Multisig locking and atomicity (fixes KRY-005 + the new completion bug)**

- Lock the workflow row with `SELECT ... FOR UPDATE` (documented SQLite
  fallback, since `with_for_update()` is a no-op there)
- Compute the quorum inside that transaction
- Collapse the two commits into one so the signature and the `completed` status
  land atomically
- Add `UNIQUE(workflow_id, user_address)` on both the signer and recipient
  tables, with an Alembic migration

**7. Strict public-key validation (addresses KRY-011)**

Replace the `len(key) < 500` heuristics with a shared
`is_usable_encryption_key()` helper doing hex validation plus exact-length check
against the ML-KEM-768 constant.

### P2 — hardening

**8. HTTP headers (KRY-009)** — replace `X-XSS-Protection` (obsolete; its legacy
auditor had its own bypasses) with CSP, `Permissions-Policy`,
`Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy` in
`backend/main.py:37-45`. Leave HSTS to nginx, as the audit correctly notes.

**9. Input limits (KRY-010)** — addresses to the exact ML-DSA-44 hex length;
group names to a sane bound. The current 500 KB group name limit
(`backend/schemas.py:218`, `backend/schemas.py:270`) is indefensible.

**10. Supply chain / CI (KRY-007, KRY-008)** — pin GitHub Actions by SHA, add
`permissions: contents: read` at workflow level, add pip-audit / npm audit /
Gitleaks / CodeQL, generate a hash-pinned Python lockfile.

Flipping `continue-on-error: true` (`.github/workflows/ci.yml:73`, `:98`) to
blocking depends on how much lint debt exists — measure first rather than
breaking CI.

**11. Attack tests (audit §19)**

- expired grant → chunk download returns 403
- concurrent transfer claims → exactly one success
- concurrent logins on one nonce → exactly one success
- concurrent multisig approvals → quorum honoured, keys released once
- SSRF address matrix (localhost, 127.0.0.1, ::1, 10/8, 172.16/12, 192.168/16,
  169.254.169.254, redirect-to-internal)

Group membership authorization was checked and is already correctly enforced
(`backend/routers/groups.py:172`, `:201`, `:260`, `:298`, `:373`, `:382`,
`:478`, `:540`, `:578`), so the audit's suggested group tests should pass as-is —
worth adding as regression guards.

### Deliberately deferred

**KRY-006 (structured AAD)** — adding AAD changes the wire format and breaks every
stored ciphertext. It needs a versioned envelope and a migration path; that is a
project of its own, not a fix.

**KRY-012 (service layer refactor)** — a large mechanical change that would make
reviewing the security fixes above significantly harder if bundled in.

Both are worth doing. Neither belongs in the same change as the P0 work.

---

## 3. Recommended sequencing

Land **P0 (items 1-5)** as one focused change with its regression tests. Those
five — four from the audit plus the push IDOR — are the only issues an attacker
can use today.

---

## 4. P0 implementation status — DONE (2026-08-18)

All five P0 items are implemented and covered by regression tests.
Suite: **225 passing**, up from 171, no regressions. (`tests/test_ws_fanout.py`
still fails on a pre-existing missing `fakeredis` dev dependency — unrelated,
identical before and after.)

| Item | Status | Where |
|---|---|---|
| 1. Authorization layer (KRY-001) | done | `backend/security/authorization.py` |
| 2. SSRF guard (KRY-002) | done | `backend/security/url_guard.py` |
| 3. Push IDOR (new finding) | done | `backend/routers/notifications.py` |
| 4. Atomic transfer claim (KRY-003) | done | `backend/routers/transfers.py` |
| 5. Atomic nonce consumption (KRY-004) | done | `backend/routers/auth.py` |

### Verification by mutation testing

Each fix was reverted in place to confirm the new tests actually detect the
original defect rather than merely passing:

- **KRY-001** — dropping the expiry predicate from `find_live_grant` failed
  exactly the two chunk-access tests.
- **KRY-003** — restoring SELECT-then-DELETE handed the same ciphertext to
  multiple concurrent claimants.
- **KRY-004** — restoring SELECT→verify→DELETE (with a sleep standing in for
  ML-DSA verification) minted **9 valid tokens from a single nonce** under 24
  concurrent requests. Post-fix: exactly 1.

All mutations were reverted; `grep -rn MUTATION backend/routers backend/security`
returns nothing.

### Implementation notes worth carrying forward

**Naive-UTC convention.** `expires_at` columns are `DateTime` without
`timezone=True`, so rows read back are naive, but several call sites were
writing *aware* datetimes into them and comparing aware-to-naive. That
inconsistency was latent in `transfers.py` and `auth.py` and would have made the
new expiry predicates unreliable, so it was normalised as part of the fix.
`security.authorization.as_naive_utc()` is the shared helper; new code touching
these columns should use it.

**`DELETE ... RETURNING` was not used**, despite the audit recommending it —
it is Postgres-only and `backend/database.py` still supports SQLite. Both
atomic consumers instead use a conditional `DELETE` guarded on `rowcount`,
which gives the same exactly-once guarantee portably.

**Nonce is now consumed before signature verification.** This is the change
that closes KRY-004: the expensive ML-DSA check no longer sits inside the race
window. A consequence worth knowing — a failed login attempt burns the nonce,
so the client must request a fresh one to retry. That is the intended
anti-replay behaviour, not a bug.

**SSRF defence is layered, and layer 3 is the important one.** Scheme/port
validation plus resolve-and-check is a TOCTOU race on its own: the name can be
re-pointed between validation and the actual request. `_PinnedHostAdapter`
re-resolves at connect time and requires the result to still intersect the
validated addresses, which is what actually closes DNS rebinding. Redirects are
refused separately (`requests` follows them by default — that was the original
exploit path). Endpoints are validated at **both** subscribe time and send time,
because stored rows predate the check.

**Push subscription conflicts drop the stale row rather than reassigning it.**
When an endpoint is already registered to a different account, the old row is
deleted and a new one created, so no subscription history crosses an account
boundary and no row id is inherited.

### New test files

- `backend/tests/test_authorization.py` — expired/revoked grant vs. chunk
  endpoints, NULL-expiry still valid, owner unaffected, push IDOR.
- `backend/tests/test_ssrf_guard.py` — the audit's full address matrix
  (loopback, RFC1918, link-local/metadata, CGNAT, multicast, IPv6, IPv4-mapped),
  scheme/port/credential/control-char rejection, redirect refusal, rebinding.
- `backend/tests/test_concurrency.py` — 24-way concurrent transfer claims and
  concurrent logins on one nonce, asserting *exactly one* success.

`backend/tests/test_notifications.py` gained an autouse fixture stubbing only
the DNS step, since its placeholder hostnames are deliberately unresolvable and
would otherwise be (correctly) rejected by the new guard.

### Still open after P0

P2 (headers, input limits, supply chain, CI) is unchanged from the plan above.
KRY-006 (AAD) and KRY-012 (service layer) remain deliberately deferred.

---

## 5. P1 implementation status — DONE (2026-08-19)

Both P1 items are implemented and covered by regression tests.
Suite: **251 passing**, up from 225, no regressions. (`test_ws_fanout.py`'s 5
failures remain the pre-existing missing `fakeredis` dev dependency.)

| Item | Status | Where |
|---|---|---|
| 6. Multisig locking + atomicity (KRY-005 + new bug) | done | `backend/routers/multisig.py`, migration `c3d4e5f6a7b2` |
| 7. Strict PQC key validation (KRY-011) | done | `backend/security/crypto_validation.py` |

### KRY-005 is worse than the audit reported

Mutation testing settled this. Removing the row lock and restoring the split
commits, then firing four signers concurrently at a **2-of-4** workflow:

```
AssertionError: 4 signatures recorded for a 2-of-4 quorum
```

All four signatures land. The quorum is not merely miscounted — it is bypassed
entirely, because every signer reads `already_signed == 0` before any of them
commits. The audit framed this as an inconsistency at "certain thresholds"; it
is a complete failure of the N-of-M policy under concurrent signing. With
`with_for_update()` the count is exactly 2 and the workflow ends `completed`.

### Fixes

**Row lock + single commit.** `sign_multisig_workflow` takes
`SELECT ... FOR UPDATE` on the workflow, computes the quorum under that lock,
and commits the signature, recipient keys, and `status = "completed"` in one
transaction. This also fixes the non-atomic completion bug found during
verification (fully-signed workflow stranded in `pending`). Push notifications
were moved after the commit deliberately — a push failure must never roll back
a recorded signature. `FOR UPDATE` is a no-op on SQLite, which serialises
writes at the file level anyway; PostgreSQL is where it matters.

**UNIQUE(workflow_id, user_address)** on both participant tables, via Alembic
`c3d4e5f6a7b2`. The duplicate-collapsing step is written as a correlated
subquery rather than `DELETE ... USING`, so it runs on SQLite too. Verified on
a populated database: seeded duplicates collapse 2 -> 1, the constraint then
applies, and downgrade is clean.

**Strict key validation.** `security/crypto_validation.py` replaces the four
`len(key) < 500` checks with exact-length hex validation against the FIPS
constants (ML-KEM-768 = 2368 hex chars, ML-DSA-44 = 2624, signature = 4840).

### A limit worth recording: ML-KEM has no cheap validity check

The audit's remediation step 3 — "decode via the PQC implementation" — buys
nothing here. Verified directly:

```
liboqs ACCEPTED garbage key -> no cheap semantic check available
```

liboqs will happily encapsulate against 1184 bytes of `AA`, so the audit's own
`"AAAA..."` example is structurally indistinguishable from a real key. Format
validation is the ceiling for a standalone key check. What actually binds a
key to an identity is the **ML-DSA key attestation**, which the project already
implements — the audit correctly praised it in §15.2 without noticing it is
the answer to its own §13.

### Compatibility decision: strict on write, lenient on read

Strict validation is enforced where keys are **written** (login), not where
they are **read**. Accounts whose stored key predates this check keep working
until their client sends a new one; `is_usable_encryption_key(strict=False)`
retains the length floor as a fallback for those rows. Enforcing strictly at
read time would have locked existing users out of the messenger — a validation
tightening should not be a denial of service against your own users.

This did require updating test fixtures: the placeholder keys
(`"enc_pub_key_" + "c" * 600`) are not valid hex and are now correctly
rejected at login, so they were replaced with well-formed ML-KEM-768-shaped
values across `conftest.py`, `test_auth.py`, and `test_key_attestation.py`.

### New test files

- `backend/tests/test_multisig_concurrency.py` — concurrent signing against a
  2-of-4 quorum, the recipient-key release guard under race, completion
  atomicity, signing closed after completion, and DB-level duplicate rejection.
- `backend/tests/test_crypto_validation.py` — hex/length validation, the
  audit's "600 arbitrary chars" case, and strict-vs-legacy behaviour.

### Still open after P1

P2 only: HTTP headers, input limits (KRY-010), Python lockfile (KRY-007), and
CI hardening (KRY-008). KRY-006 and KRY-012 remain deferred.

---

## 6. P2 implementation status — DONE (2026-08-19)

Suite: **274 backend tests passing** (up from 251), frontend 53 passing,
crypto-core 22 passing, all builds green.

| Item | Status | Where |
|---|---|---|
| 8-10. HTTP headers (KRY-009) | done | `backend/main.py` |
| 11. Python lockfile (KRY-007) | done | `backend/requirements.lock` |
| 12. SAST / dependency scanning (KRY-008) | done | `.github/workflows/security.yml` |
| 13. Actions pinned by SHA (KRY-008) | done | both workflows |
| 14. Lint gate (KRY-008) | partial — frontend blocking, extension advisory | `.github/workflows/ci.yml` |
| 9 (KRY-010). Input limits | done | `backend/schemas.py` |

### The scanner immediately earned its place

Adding `pip-audit` surfaced a real problem on its first run: **`pyjwt` 2.10.1
carried 12 known advisories**, and it was the one *hard-pinned* dependency
(`pyjwt==2.10.1`) in `requirements.txt`.

Exposure was limited — `auth.py` uses HS256 only, passes an explicit
`algorithms=[JWT_ALG]` allowlist, and never touches `PyJWKClient` — so the
headline advisories (PYSEC-2026-179 JWK/HMAC confusion, PYSEC-2026-175
`PyJWKClient` URL handling) did not apply. But running the JWT library with a
dozen open CVEs is not a defensible position for a project whose entire session
model rests on it. Upgraded to `pyjwt>=2.13.0`; `pip-audit` now reports **no
known vulnerabilities**, and the auth tests pass with no code changes.

`npm audit` likewise found 2 high-severity issues in `packages/crypto-core`
(`nanoid`, `postcss` — both build-time). Fixed non-breaking; crypto-core's 22
byte-compat tests still pass. The `elliptic` chain in `trustkeys` was
deliberately **not** force-upgraded: it arrives via `vite-plugin-node-polyfills`
as a devDependency and does not appear in the built bundle, so a breaking
toolchain upgrade buys nothing.

### Two corrections to the audit's §11 and §10

**Most of the headers the audit called missing were already present.** It
reviewed the FastAPI middleware in isolation and concluded CSP, HSTS and
Permissions-Policy were absent. `nginx.conf.example` already sets all three,
plus a well-built SPA CSP that closely matches the audit's own recommendation.
The genuine gap was the *API* surface: a deployment reaching FastAPI directly,
or bypassing the proxy, got only four headers.

So the split is now explicit: nginx owns the SPA's headers (HSTS belongs to the
TLS terminator; the SPA's CSP describes assets FastAPI never serves), and the
middleware sets an API-appropriate policy — `default-src 'none'` is available
here precisely because the API returns JSON and never markup. HSTS is emitted
only when the request actually arrived over TLS, so dev over plaintext doesn't
pin localhost to https. `X-XSS-Protection` was removed rather than kept.

**The audit also reported CI as lacking `permissions: contents: read`.** It was
already there at workflow level in `ci.yml`.

### Lint gate: honest, not aspirational

The audit asked for lint to stop being `continue-on-error`. Measuring first was
the right call:

- **frontend** — already clean. Now a **blocking** gate.
- **trustkeys** — 96 errors, of which **70 were a config gap**: `eslint.config.js`
  loaded `globals.browser` but not `globals.webextensions`, so every `chrome.*`
  call in an MV3 extension reported as `no-undef`. Adding that one line took it
  to 26. The remaining 26 are real but unrelated cleanups (unused catch
  bindings, case-block declarations, two hook-ordering issues), so this job
  stays advisory with a note naming exactly what must be fixed to flip it.

Making trustkeys blocking today would have meant either failing every build or
bundling unrelated code churn into a security change.

### Supply chain

`backend/requirements.lock` pins all 56 resolved packages with artifact hashes
(`pip-compile --generate-hashes`). Verified it installs in a clean venv under
`pip install --require-hashes`. The CI job audits the lock (so it reflects what
production installs, not just the floors) **and** regenerates it to prove it
hasn't drifted from `requirements.txt` — a stale lock silently reverts the
whole guarantee.

All 8 action references across both workflows are pinned to immutable commit
SHAs with the tag retained as a trailing comment; every SHA was verified to
resolve. `.github/dependabot.yml` covers all five ecosystems including
`github-actions`, which is what keeps SHA pins from rotting — a pin never
updates itself.

### Note on the pre-existing `fakeredis` failures

The 5 `test_ws_fanout.py` failures reported throughout P0 and P1 were a **local
environment gap, not a project defect**: `fakeredis` is correctly declared in
`requirements-dev.txt` and CI installs it. Installing it locally makes all 7
pass. Backend totals in this document are now the true full-suite count.

### Still open

Only the deliberately deferred items remain: **KRY-006** (structured AAD — needs
a versioned envelope and a ciphertext migration) and **KRY-012** (service-layer
refactor). Neither is a fix; both are projects.
