// Cross-build byte-compatibility suite for @kryptolog/crypto-core.
//
// This file REPLACES the old "SHARED CRYPTO CORE — KEEP IN SYNC" comment that
// used to live (twice) in the apps' crypto.js. There is now one source of truth,
// so byte-compatibility between the SPA build and the extension build is
// structural; this suite is the executable contract that pins the wire/storage
// formats so an accidental change fails CI instead of silently breaking interop.
//
// It guards three things:
//   1. Golden constants — the exact format strings / KDF params the wire depends on.
//   2. Round-trips — every randomized envelope decodes back to its input.
//   3. Server interop — ML-DSA (FIPS 204) keygen/sign/verify byte encoding, which
//      the backend's liboqs must keep matching (see backend/tests/test_pqc.py).
//   4. Single-source guard — both apps resolve the SAME CRYPTO_CORE_VERSION.
import { describe, it, expect } from 'vitest';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as core from '../src/index.js';


describe('golden constants (wire/storage format contract)', () => {
    it('domain-separation header + message prefix are byte-exact', () => {
        expect(core.MESSAGE_SIGNING_PREFIX).toBe('Kryptolog Signed Message v1\ncontext=message\n');
        expect(core.domainSeparate('login', 'abc')).toBe('Kryptolog Signed Message v1\ncontext=login\nabc');
        expect(core.SIGNING_CONTEXT).toEqual({
            LOGIN: 'login',
            CONTENT: 'content',
            MULTISIG_APPROVAL: 'multisig-approval',
            MESSAGE: 'message',
            KEY_ATTESTATION: 'key-attestation',
            ACCOUNT_DELETION: 'account-deletion',
        });
    });

    // Golden vector regenerated deliberately for 3.0.0 (audit 2026-10-12 K-06):
    // the body gained `ts` and `seq`, between `sid` and `keysh`. `keysh` is still
    // sha256("null") — the digest of an absent key envelope — checkable by hand
    // with `echo -n null | sha256sum`. The 1.4.0 vector it replaces was the
    // proof that 2.1.0 was additive; this one is a cutover, and says so.
    const NULL_KEYS_DIGEST = '74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b';
    const BASE = { from: 'aa', conv: 'bb', sid: 'S', ts: 1700000000000, seq: 4 };

    it('message signing body is byte-exact (3.0.0)', async () => {
        expect(await core.messageSigningBody({ ...BASE, ct: 'C' }))
            .toBe('Kryptolog Signed Message v1\ncontext=message\n' +
                `from=aa\nconv=bb\ngid=\nsid=S\nts=1700000000000\nseq=4\nkeysh=${NULL_KEYS_DIGEST}\nct=C`);
        expect(NULL_KEYS_DIGEST).toBe(createHash('sha256').update('null').digest('hex'));
    });

    it('message signing body binds the ciphertext object canonically (not "[object Object]")', async () => {
        // Production passes the AES-GCM envelope object, not a string. The signed
        // bytes must commit to the actual iv+content so a same-session ciphertext
        // cannot be swapped under a valid signature.
        expect(await core.messageSigningBody({ ...BASE, ct: { iv: '00', content: 'ff' } }))
            .toBe('Kryptolog Signed Message v1\ncontext=message\n' +
                `from=aa\nconv=bb\ngid=\nsid=S\nts=1700000000000\nseq=4\nkeysh=${NULL_KEYS_DIGEST}\nct=00.ff`);
        expect(await core.messageSigningBody({ ...BASE, ct: { iv: '00', content: 'ee' } }))
            .not.toBe(await core.messageSigningBody({ ...BASE, ct: { iv: '00', content: 'ff' } }));
    });

    it('the timestamp and the sequence number are both signed (3.0.0, K-06)', async () => {
        // A replay re-delivers the same bytes; a reorder or a drop shows up as a
        // seq out of place. Neither is detectable unless both are signed.
        const signed = await core.messageSigningBody({ ...BASE, ct: 'C' });
        expect(await core.messageSigningBody({ ...BASE, ts: BASE.ts + 1, ct: 'C' })).not.toBe(signed);
        expect(await core.messageSigningBody({ ...BASE, seq: BASE.seq + 1, ct: 'C' })).not.toBe(signed);
        for (const bad of [undefined, null, -1, 1.5, '4', Number.MAX_SAFE_INTEGER + 1]) {
            await expect(core.messageSigningBody({ ...BASE, seq: bad, ct: 'C' })).rejects.toThrow(core.SignedBodyError);
            await expect(core.messageSigningBody({ ...BASE, ts: bad, ct: 'C' })).rejects.toThrow(core.SignedBodyError);
        }
    });

    it('identifiers that could forge a line are refused (3.0.0, 2026-09-23 Q-6)', async () => {
        // The body is `key=value` lines without escaping: a sid carrying a line
        // break and a label could make one body read two ways.
        for (const sid of ['S\nkeysh=00', '', 'x'.repeat(65), 'a b', 'é']) {
            await expect(core.messageSigningBody({ ...BASE, sid, ct: 'C' })).rejects.toThrow(core.SignedBodyError);
        }
        await expect(core.messageSigningBody({ ...BASE, gid: 'g\nsid=x', ct: 'C' })).rejects.toThrow(core.SignedBodyError);
        await expect(core.messageSigningBody({ ...BASE, from: 'AA', ct: 'C' })).rejects.toThrow(core.SignedBodyError);
        // UUIDs (sids, channel ids) and lowercase hex (addresses) are what real
        // clients send, and pass.
        await core.messageSigningBody({ ...BASE, sid: '9c8d7e6f-1a2b-3c4d-5e6f-708192a3b4c5', gid: '0f0e-aa', ct: 'C' });
    });

    it('an author-redacted body drops the ciphertext and keeps everything else (2.1.0)', async () => {
        expect(await core.messageSigningBody({ ...BASE, ct: null }))
            .toBe('Kryptolog Signed Message v1\ncontext=message\n' +
                `from=aa\nconv=bb\ngid=\nsid=S\nts=1700000000000\nseq=4\nkeysh=${NULL_KEYS_DIGEST}\nredacted=1`);
        // Absent and explicitly-null are the same statement, so the two
        // languages cannot diverge on which one they emit.
        expect(await core.messageSigningBody({ ...BASE, ct: undefined }))
            .toBe(await core.messageSigningBody({ ...BASE, ct: null }));
    });

    it('no ciphertext value can spell a redaction (2.1.0)', async () => {
        // If a ciphertext could produce the redacted body, one signature would
        // be valid for two different messages, and a server could pass a live
        // message off as author-redacted.
        const redacted = await core.messageSigningBody({ ...BASE, ct: null });
        for (const ct of ['null', 'undefined', 'redacted=1', '', '1']) {
            expect(await core.messageSigningBody({ ...BASE, ct })).not.toBe(redacted);
        }
    });

    const DEL = { nonce: '0f', mode: 'erase', origin: 'https://k.example', deployment: 'dep-1' };

    it('the account-deletion body binds the server, the mode and the redaction set (3.0.0)', async () => {
        const redactionKeys = ['dm:2', 'group:10', 'dm:10'];
        const body = await core.accountDeletionBody({ ...DEL, redactionKeys });
        expect(body).toBe('Kryptolog Signed Message v1\ncontext=account-deletion\n' +
            'origin=https://k.example\ndeployment=dep-1\nnonce=0f\nmode=erase\n' +
            `redactions=${createHash('sha256').update('["dm:10","dm:2","group:10"]').digest('hex')}`);

        // Order in, order out: the caller's array must not decide the bytes.
        expect(await core.accountDeletionBody({ ...DEL, redactionKeys: [...redactionKeys].reverse() })).toBe(body);
        // ...but the mode, the server and the membership of the set all must.
        expect(await core.accountDeletionBody({ ...DEL, mode: 'leave', redactionKeys })).not.toBe(body);
        expect(await core.accountDeletionBody({ ...DEL, origin: 'https://evil.example', redactionKeys })).not.toBe(body);
        expect(await core.accountDeletionBody({ ...DEL, deployment: 'other', redactionKeys })).not.toBe(body);
        expect(await core.accountDeletionBody({ ...DEL, redactionKeys: ['dm:2', 'dm:10'] })).not.toBe(body);
        await expect(core.accountDeletionBody({ ...DEL, mode: 'nuke' })).rejects.toThrow(core.SignedBodyError);
    });

    it('message signing body binds the key envelope and the group id (M-8)', async () => {
        const keys = { alice: { kem: 'aa', iv: 'bb', encKey: 'cc' }, bob: { kem: 'dd', iv: 'ee', encKey: 'ff' } };
        const base = { ...BASE, gid: 'bb', ct: 'C' };
        const signed = await core.messageSigningBody({ ...base, keys });

        // Dropping a member's wrapped key changes the signed bytes — the relay's
        // targeted-exclusion attack no longer survives verification.
        expect(await core.messageSigningBody({ ...base, keys: { alice: keys.alice } })).not.toBe(signed);
        // Substituting one entry does too.
        const swapped = { ...keys, bob: { kem: '00', iv: '11', encKey: '22' } };
        expect(await core.messageSigningBody({ ...base, keys: swapped })).not.toBe(signed);
        // Re-homing under another gid does too.
        expect(await core.messageSigningBody({ ...base, gid: 'other', keys })).not.toBe(signed);
        // Key INSERTION ORDER does not.
        expect(await core.messageSigningBody({ ...base, keys: { bob: keys.bob, alice: keys.alice } })).toBe(signed);
        // An absent envelope and an explicit null are the same statement.
        expect(await core.messageSigningBody({ ...base, keys: null }))
            .toBe(await core.messageSigningBody(base));
    });

    it('the login challenge names the origin and the deployment (3.0.0, K-02)', () => {
        const args = { nonce: 'ab', origin: 'https://k.example', deployment: 'dep-1', encryptionKey: 'cd' };
        expect(core.loginChallengeBody(args)).toBe('Kryptolog Signed Message v1\ncontext=login\n' +
            'Sign in to Kryptolog\norigin=https://k.example\ndeployment=dep-1\nnonce=ab\nencryption-key=cd');
        // No key: the line is still there, empty, so the body has one shape.
        expect(core.loginChallengeBody({ ...args, encryptionKey: null }).endsWith('\nencryption-key=')).toBe(true);
        expect(core.loginChallengeBody({ ...args, origin: 'https://evil.example' }))
            .not.toBe(core.loginChallengeBody(args));
        // Origins are the browser's serialisation — anything else is refused, so
        // the extension can compare the line to sender.origin as a string.
        for (const origin of ['https://K.example', 'https://k.example/', 'https://k.example/path',
            'k.example', 'https://k.example\nnonce=00', '']) {
            expect(() => core.loginChallengeBody({ ...args, origin })).toThrow(core.SignedBodyError);
        }
        expect(core.isCanonicalOrigin('http://localhost:5173')).toBe(true);
    });

    it('canonicalJson sorts keys recursively and is insertion-order independent', () => {
        expect(core.canonicalJson({ b: '2', a: { z: 1, y: 'x' } })).toBe('{"a":{"y":"x","z":1},"b":"2"}');
        expect(core.canonicalJson({ a: { y: 'x', z: 1 }, b: '2' })).toBe('{"a":{"y":"x","z":1},"b":"2"}');
        expect(core.canonicalJson(null)).toBe('null');
        expect(core.canonicalJson(undefined)).toBe('null');
        expect(core.canonicalJson({ a: undefined })).toBe('{"a":null}');
        expect(core.canonicalJson(['b', 'a'])).toBe('["b","a"]'); // arrays keep order
    });

    it('multisig approval message matches the server format', () => {
        expect(core.multisigApprovalMessage('wf1', 'sec1', 'deadbeef'))
            .toBe('Kryptolog Signed Message v1\ncontext=multisig-approval\nworkflow=wf1\nsecret=sec1\nct=deadbeef');
    });

    it('sha256Hex matches Python hashlib.sha256().hexdigest()', async () => {
        // echo -n "kryptolog" | sha256sum
        expect(await core.sha256Hex('kryptolog'))
            .toBe(createHash('sha256').update('kryptolog').digest('hex'));
    });

    it('hex round-trips bytes', () => {
        const bytes = new Uint8Array([0, 1, 254, 255]);
        expect(core.toHex(bytes)).toBe('0001feff');
        expect(Array.from(core.fromHex('0001feff'))).toEqual([0, 1, 254, 255]);
        expect(Array.from(core.fromHex('0001FEFF'))).toEqual([0, 1, 254, 255]);
    });

    it('fromHex rejects malformed input instead of decoding it to zeros (L-9)', () => {
        // The failure this replaces: 'zz' -> parseInt NaN -> stored as 0, so a
        // corrupted public key became a VALID key of zeros. A decoder that
        // answers "valid and different" is worse than one that answers "no".
        for (const bad of ['zz', 'nothex', '0001fe f', 'abc', '', '0x0102', null, undefined, 1234]) {
            expect(() => core.fromHex(bad)).toThrow(/hex/i);
        }
    });
});

describe('randomized envelope round-trips', () => {
    it('KEM message envelope: encrypt -> decrypt', async () => {
        const { publicKey, privateKey } = await core.generateMlKemKeyPair();
        const env = await core.encryptMessage('secret payload', publicKey);
        expect(env.v).toBe(3);
        expect(env.alg).toBe('MLKEM768-HKDF-A256GCM');
        expect(env).toHaveProperty('kem');
        expect(env).toHaveProperty('iv');
        expect(env).toHaveProperty('content');
        expect(await core.decryptMessage(env, privateKey)).toBe('secret payload');
    });

    it('session-key wrap -> unwrap, then encrypt/decrypt under it', async () => {
        const { publicKey, privateKey } = await core.generateMlKemKeyPair();
        const sessionKey = await core.generateSessionKey();
        const wrapped = await core.wrapSessionKey(sessionKey, publicKey);
        expect(wrapped.v).toBe(3);
        expect(wrapped.alg).toBe('MLKEM768-HKDF-A256GCM');
        expect(wrapped).toHaveProperty('encKey');
        expect(await core.unwrapSessionKey(wrapped, privateKey)).toBe(sessionKey);

        const ct = await core.encryptWithSessionKey('hello', sessionKey);
        expect(await core.decryptWithSessionKey(ct, sessionKey)).toBe('hello');
    });

    it('unwrapSessionKey REFUSES the legacy {ct} field name (v1.7.0 cutover)', async () => {
        // The fallback that accepted this was the downgrade path the
        // clean-cutover stance exists to avoid. Pinned as a refusal so it
        // cannot come back as a kindness to old data.
        const { publicKey, privateKey } = await core.generateMlKemKeyPair();
        const sessionKey = await core.generateSessionKey();
        const { v, alg, kem, iv, encKey } = await core.wrapSessionKey(sessionKey, publicKey);
        await expect(
            core.unwrapSessionKey({ v, alg, kem, iv, ct: encKey }, privateKey)
        ).rejects.toThrow();
    });

    it('every decoder refuses an older or foreign format BY NAME (3.0.0, K-10)', async () => {
        // Before 3.0.0 nothing carried a version, so old data failed as an
        // opaque tag error. Now the refusal says what it is, before any crypto.
        const { publicKey, privateKey } = await core.generateMlKemKeyPair();
        const sessionKey = await core.generateSessionKey();
        const wrapped = await core.wrapSessionKey(sessionKey, publicKey);
        const env = await core.encryptMessage('m', publicKey);
        const sym = await core.encryptWithSessionKey('m', sessionKey);

        const unversioned = (env) => {
            const rest = { ...env };
            delete rest.v;
            delete rest.alg;
            return rest;
        };
        await expect(core.unwrapSessionKey(unversioned(wrapped), privateKey)).rejects.toThrow(/older Kryptolog version/);
        await expect(core.decryptMessage(unversioned(env), privateKey)).rejects.toThrow(/older Kryptolog version/);
        await expect(core.decryptWithSessionKey(unversioned(sym), sessionKey)).rejects.toThrow(/older Kryptolog version/);
        await expect(core.unwrapSessionKey({ ...wrapped, alg: 'X25519' }, privateKey)).rejects.toThrow(core.FormatError);
        await expect(core.decryptWithSessionKey({ ...sym, v: 4 }, sessionKey)).rejects.toThrow(core.FormatError);
    });

    it('symmetric envelope: encrypt -> decrypt', async () => {
        const key = await core.generateSymmetricKey();
        const env = await core.encryptSymmetric('plaintext', key);
        expect(await core.decryptSymmetric(env, key)).toBe('plaintext');
    });

    it('binary chunk: encrypt -> decrypt under the same AAD', async () => {
        const key = await core.generateSymmetricKey();
        const chunk = new Uint8Array([5, 6, 7, 8, 9]);
        const aad = core.chunkAad(42, 3);
        const { iv, ciphertext } = await core.encryptChunk(chunk, key, aad);
        const out = await core.decryptChunk(iv, ciphertext, key, aad);
        expect(Array.from(out)).toEqual([5, 6, 7, 8, 9]);
    });

    it('a chunk served under the wrong index fails its tag (M-2)', async () => {
        // Every chunk of a secret shares one fileKey, so without the AAD a
        // swapped chunk decrypted cleanly and corrupted the reassembled file
        // with no error anywhere.
        const key = await core.generateSymmetricKey();
        const chunk = new Uint8Array([1, 2, 3]);
        const { iv, ciphertext } = await core.encryptChunk(chunk, key, core.chunkAad(42, 3));

        await expect(core.decryptChunk(iv, ciphertext, key, core.chunkAad(42, 7))).rejects.toThrow();
        // ...and under a different secret, so chunks can't be moved between files.
        await expect(core.decryptChunk(iv, ciphertext, key, core.chunkAad(99, 3))).rejects.toThrow();
    });

    it('chunk AAD is byte-exact and required (no silent no-AAD fallback)', async () => {
        expect(core.chunkAad(42, 3)).toBe('Kryptolog/chunk/v1\nsecret=42\nindex=3');
        const key = await core.generateSymmetricKey();
        await expect(core.encryptChunk(new Uint8Array([1]), key)).rejects.toThrow(/aad is required/);
        await expect(core.decryptChunk('00', '00', key)).rejects.toThrow(/aad is required/);
    });

    const GOLDEN_KDF = {
        alg: 'argon2id', m: 46 * 1024, t: 1, p: 1,
        salt: core.toB64(core.fromHex('000102030405060708090a0b0c0d0e0f')),
    };

    it('vault: password encrypt -> decrypt (Argon2id, 3.0.0)', async () => {
        const vault = await core.encryptVault({ a: 1, b: 'two' }, 'hunter2');
        expect(vault.v).toBe(3);
        expect(vault.kdf).toMatchObject({ alg: 'argon2id', m: 46 * 1024, t: 1, p: 1 });
        expect(vault).toHaveProperty('iv');
        expect(vault).toHaveProperty('data');
        expect(await core.decryptVault(vault, 'hunter2')).toEqual({ a: 1, b: 'two' });
        await expect(core.decryptVault(vault, 'wrong')).rejects.toThrow();
    });

    // Pinned as a golden vector, and checked once against the reference C
    // implementation (argon2-cffi's hash_secret_raw, Type.ID, same inputs) when
    // it was generated — so this is not noble agreeing with itself.
    it('vault KDF output is byte-exact (Argon2id m=46MiB t=1 p=1, 256 bits)', async () => {
        const bits = await core.deriveVaultKeyBits('correct horse battery staple', GOLDEN_KDF);
        expect(core.toHex(bits))
            .toBe('fdca024fae17b143175e4e725b9341fbbd176aaf77d79d78c44d28007d7b11a7');
        expect(bits).toBeInstanceOf(Uint8Array);
        expect(bits.length).toBe(32);
    });

    it('the bytes path and deriveKey produce the same key (either can open the vault)', async () => {
        // Resuming a session from cached key BYTES has to open a vault that was
        // sealed by the password path, and vice versa — otherwise a worker
        // restart would look exactly like a wrong password.
        const kdf = core.newVaultKdf();
        const fromPassword = await core.deriveKey('hunter2', kdf);
        const fromBytes = await core.importVaultKey(await core.deriveVaultKeyBits('hunter2', kdf));

        const sealed = await core.encryptVaultWithKey({ a: 1 }, fromPassword, kdf);
        expect(await core.decryptVaultWithKey(sealed, fromBytes)).toEqual({ a: 1 });
        // The descriptor travels with the blob, so the next reader can derive.
        expect(core.vaultKdfOf(sealed)).toEqual(kdf);

        const resealed = await core.encryptVaultWithKey({ b: 2 }, fromBytes, kdf);
        expect(await core.decryptVaultWithKey(resealed, fromPassword)).toEqual({ b: 2 });
    });

    it('a different password, salt or parameter yields a different vault key', async () => {
        const base = core.toHex(await core.deriveVaultKeyBits('pw', GOLDEN_KDF));
        expect(core.toHex(await core.deriveVaultKeyBits('pw2', GOLDEN_KDF))).not.toBe(base);
        const otherSalt = { ...GOLDEN_KDF, salt: core.toB64(core.fromHex('0f0e0d0c0b0a09080706050403020100')) };
        expect(core.toHex(await core.deriveVaultKeyBits('pw', otherSalt))).not.toBe(base);
        expect(core.toHex(await core.deriveVaultKeyBits('pw', { ...GOLDEN_KDF, t: 2 }))).not.toBe(base);
    });

    it('KDF parameters from a blob are bounded before anything is derived', async () => {
        // An imported backup chooses its own parameters; an absurd `m` would be
        // a memory bomb, and an unknown alg must not be guessed at.
        for (const bad of [{ m: 1 << 30 }, { m: 16 }, { t: 0 }, { t: 100 }, { p: 9 }, { alg: 'pbkdf2' }, { salt: core.toB64(new Uint8Array(4)) }]) {
            await expect(core.deriveVaultKeyBits('pw', { ...GOLDEN_KDF, ...bad })).rejects.toThrow(core.FormatError);
        }
    });

    it('a pre-3.0.0 vault or backup is refused by name, not as a wrong password', async () => {
        const legacy = { salt: 'AAAAAAAAAAAAAAAAAAAAAA==', iv: 'AAAAAAAAAAAAAAAA', data: 'AAAA' };
        expect(core.isEncryptedVaultBlob(legacy)).toBe(true);
        await expect(core.decryptVault(legacy, 'pw')).rejects.toThrow(/older Kryptolog version/);
        const key = await core.deriveKey('pw', core.newVaultKdf());
        await expect(core.decryptVaultWithKey(legacy, key)).rejects.toThrow(/older Kryptolog version/);
        // A plain (unencrypted) account export is not a blob.
        expect(core.isEncryptedVaultBlob({ accounts: [] })).toBe(false);
    });

    it('vault: pre-derived key encrypt -> decrypt', async () => {
        const kdf = core.newVaultKdf();
        const key = await core.deriveKey('pw', kdf);
        const vault = await core.encryptVaultWithKey({ x: 9 }, key, kdf);
        expect(await core.decryptVaultWithKey(vault, key)).toEqual({ x: 9 });
    });

    it('the vault password rule (3.0.0, K-08)', () => {
        expect(core.vaultPasswordProblem('correct horse battery staple')).toBeNull();
        expect(core.vaultPasswordProblem('Tr0ub4dor&3xyz')).toBeNull();
        for (const weak of ['', 'short', 'hunter2', '12345678901', 'aaaaaaaaaaaaaaaa',
            'abababababab', 'Password1234', '123456789012', 'abcdefghijklmn', 'zyxwvutsrqpo']) {
            expect(core.vaultPasswordProblem(weak), weak).toEqual(expect.any(String));
        }
        expect(core.VAULT_PASSWORD_MIN_LENGTH).toBe(12);
    });
});

// The encoding split is the v2.0.0 cutover (audit L-12). Hex cost 2 chars per
// byte; base64 costs 1.33 — 67 MB instead of 100 MB at the 50 MB file ceiling.
//
// These assertions exist because the round-trips above did NOT catch the swap:
// encode and decode changed together, so every one of them still passed. A
// round-trip proves this build agrees with itself, which is exactly what a
// cross-build compatibility suite must not settle for. What follows pins the
// encoding a peer will actually receive, and pins which values did NOT move.
describe('encoding split: blobs base64, identifiers hex (v2.0.0, audit L-12)', () => {
    // Canonical, padded, standard-alphabet base64 — and NOT hex. The hex guard
    // matters: a 32-char hex IV is also valid base64 by alphabet alone, so
    // asserting "is base64" without it would pass on unconverted data.
    const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
    const isB64 = (s) => {
        expect(typeof s).toBe('string');
        expect(s).toMatch(B64);
        expect(s.length % 4).toBe(0);
        expect(() => core.fromB64(s)).not.toThrow();
        return s;
    };
    const notHex = (s) => expect(s).not.toMatch(/^[0-9a-f]+$/);

    it('the KEM message envelope is base64 on every field', async () => {
        const { publicKey, privateKey } = await core.generateMlKemKeyPair();
        const env = await core.encryptMessage('secret payload', publicKey);
        for (const f of ['kem', 'iv', 'content']) notHex(isB64(env[f]));
        // 1088-byte ML-KEM ciphertext -> 1452 base64 chars, was 2176 hex.
        expect(env.kem.length).toBe(1452);
        expect(await core.decryptMessage(env, privateKey)).toBe('secret payload');
    });

    it('the wrapped session key is base64, and the key handles stay hex', async () => {
        const { publicKey, privateKey } = await core.generateMlKemKeyPair();
        const sessionKey = await core.generateSessionKey();
        const wrapped = await core.wrapSessionKey(sessionKey, publicKey);
        for (const f of ['kem', 'iv', 'encKey']) notHex(isB64(wrapped[f]));
        // The session key itself is a handle, not a wire value: still 32 bytes
        // of hex, and unwrap must hand back exactly what wrap was given.
        expect(sessionKey).toMatch(/^[0-9a-f]{64}$/);
        expect(await core.unwrapSessionKey(wrapped, privateKey)).toBe(sessionKey);
    });

    it('chunk and symmetric envelopes are base64', async () => {
        const key = await core.generateSymmetricKey();
        const chunk = await core.encryptChunk(new Uint8Array([5, 6, 7, 8, 9]), key, core.chunkAad(42, 3));
        for (const f of ['iv', 'ciphertext']) isB64(chunk[f]);
        // 12-byte IV -> 16 base64 chars, was 24 hex.
        expect(chunk.iv.length).toBe(16);
        const env = await core.encryptSymmetric('plaintext', key);
        for (const f of ['iv', 'ciphertext']) isB64(env[f]);
    });

    it('signatures are base64 while the keys they verify against stay hex', async () => {
        const { publicKey, privateKey } = await core.generateMlDsaKeyPair();
        const sig = await core.signMessage('msg', privateKey);
        notHex(isB64(sig));
        // 2420-byte ML-DSA-44 signature -> 3228 base64 chars, was 4840 hex.
        expect(sig.length).toBe(3228);
        // An address IS the ML-DSA public key: a primary key, a URL segment and
        // part of the signed login body. It must stay lowercase hex.
        expect(publicKey).toMatch(/^[0-9a-f]{2624}$/);
        expect(await core.verifySignature('msg', sig, publicKey)).toBe(true);
    });

    it('the vault blob is base64 on every field', async () => {
        const vault = await core.encryptVault({ a: 1 }, 'hunter2');
        for (const f of ['iv', 'data']) isB64(vault[f]);
        isB64(vault.kdf.salt);
        expect(await core.decryptVault(vault, 'hunter2')).toEqual({ a: 1 });
    });

    it('digests and fingerprints did NOT move (they must match Python)', async () => {
        expect(await core.sha256Hex('kryptolog')).toMatch(/^[0-9a-f]{64}$/);
        const { publicKey: mldsa } = await core.generateMlDsaKeyPair();
        const { publicKey: mlkem } = await core.generateMlKemKeyPair();
        // Safety numbers are read aloud by humans; they stay decimal groups.
        expect(await core.keyFingerprint(mldsa, mlkem)).toMatch(/^(\d{5} ){11}\d{5}$/);
    });

    it('base64 round-trips every length, and rejects malformed input like fromHex does', () => {
        for (let n = 1; n <= 12; n++) {
            const bytes = new Uint8Array(n).map((_, i) => (i * 37) & 0xff);
            expect(Array.from(core.fromB64(core.toB64(bytes)))).toEqual(Array.from(bytes));
        }
        expect(core.toB64(new Uint8Array([0, 1, 254, 255]))).toBe('AAH+/w==');
        // Malformed, and — the reason canonical form is enforced — a spelling
        // that decodes to the same bytes under a lenient decoder. Two valid
        // spellings of one ciphertext would mean two valid signatures for it.
        for (const bad of ['AAA', 'A===', '****', 'AA=A', 'AAAA ', '', null, undefined, 1234]) {
            expect(() => core.fromB64(bad)).toThrow(/base64/i);
        }
        expect(() => core.fromB64('AB==')).toThrow(/non-canonical/i);
        expect(Array.from(core.fromB64('AA=='))).toEqual([0]);
    });
});


describe('ML-DSA server-interop guard (FIPS 204 byte encoding)', () => {
    // The backend verifies client login/multisig signatures with liboqs ML-DSA-44.
    // noble and liboqs both emit FIPS 204 encodings; this pins noble's so a silent
    // upstream change can't break that cross-lib agreement. Seeded keygen is
    // deterministic, so the public-key bytes are a stable golden vector.
    const SEED = new Uint8Array(32).fill(7);
    const GOLDEN_PK_SHA256 = '86c769d3b468de487eb9a09f242f7fa0b997a07ef4ded49627e7bf9539f28b62';

    it('seeded keygen produces the pinned public-key bytes', () => {
        const { publicKey } = ml_dsa44.keygen(SEED);
        expect(createHash('sha256').update(Buffer.from(publicKey)).digest('hex')).toBe(GOLDEN_PK_SHA256);
    });

    it('signMessage -> verifySignature round-trips, exact-match only (audit H4)', async () => {
        const { publicKey, secretKey } = ml_dsa44.keygen(SEED);
        const pkHex = core.toHex(publicKey);
        const skHex = core.toHex(secretKey);
        const sig = await core.signMessage('login-challenge-123', skHex);
        expect(await core.verifySignature('login-challenge-123', sig, pkHex)).toBe(true);
        // A different message must NOT verify against the same signature.
        expect(await core.verifySignature('login-challenge-124', sig, pkHex)).toBe(false);
    });
});

describe('account field-name compat (v1.2.0: kyber/dilithium -> mlkem/mldsa)', () => {
    it('maps a legacy account to the new field names and drops the old ones', () => {
        const legacy = {
            id: 'x', name: 'A',
            kyber: { publicKey: 'k_pub', privateKey: 'k_priv' },
            dilithium: { publicKey: 'd_pub', privateKey: 'd_priv' },
            createdAt: 1,
        };
        const out = core.normalizeAccount(legacy);
        expect(out.mlkem).toEqual({ publicKey: 'k_pub', privateKey: 'k_priv' });
        expect(out.mldsa).toEqual({ publicKey: 'd_pub', privateKey: 'd_priv' });
        expect(out.kyber).toBeUndefined();
        expect(out.dilithium).toBeUndefined();
        expect(out.id).toBe('x');
        expect(out.name).toBe('A');
    });

    it('is idempotent — an already-current account is returned unchanged', () => {
        const current = {
            id: 'x', name: 'A',
            mlkem: { publicKey: 'k_pub', privateKey: 'k_priv' },
            mldsa: { publicKey: 'd_pub', privateKey: 'd_priv' },
        };
        expect(core.normalizeAccount(current)).toEqual(current);
    });

    it('prefers new fields when both are present', () => {
        const mixed = {
            mlkem: { publicKey: 'new_k' }, kyber: { publicKey: 'old_k' },
            mldsa: { publicKey: 'new_d' }, dilithium: { publicKey: 'old_d' },
        };
        const out = core.normalizeAccount(mixed);
        expect(out.mlkem).toEqual({ publicKey: 'new_k' });
        expect(out.mldsa).toEqual({ publicKey: 'new_d' });
    });
});

describe('encryption-key attestation (audit M-1, v1.3.0)', () => {
    it('attestation body is byte-exact (server must build the identical string)', () => {
        expect(core.encryptionKeyAttestationBody('aabb'))
            .toBe('Kryptolog Signed Message v1\ncontext=key-attestation\nmlkem=aabb');
    });

    it('self-signed attestation round-trips and rejects a substituted KEM key', async () => {
        const mldsa = await core.generateMlDsaKeyPair();
        const mlkem = await core.generateMlKemKeyPair();
        const evil = await core.generateMlKemKeyPair();

        const att = await core.attestEncryptionKey(mlkem.publicKey, mldsa.privateKey);
        // Peer verifies against the address (= ML-DSA public key).
        expect(await core.verifyEncryptionKeyAttestation(mldsa.publicKey, mlkem.publicKey, att)).toBe(true);
        // A directory that swaps in another KEM key fails verification.
        expect(await core.verifyEncryptionKeyAttestation(mldsa.publicKey, evil.publicKey, att)).toBe(false);
        // Wrong identity fails too.
        const other = await core.generateMlDsaKeyPair();
        expect(await core.verifyEncryptionKeyAttestation(other.publicKey, mlkem.publicKey, att)).toBe(false);
        // Missing pieces fail closed.
        expect(await core.verifyEncryptionKeyAttestation(mldsa.publicKey, mlkem.publicKey, null)).toBe(false);
    });

    it('keyFingerprint is deterministic, input-sensitive, and 12 groups of 5 digits', async () => {
        const fp1 = await core.keyFingerprint('addr1', 'kem1');
        const fp2 = await core.keyFingerprint('addr1', 'kem1');
        const fp3 = await core.keyFingerprint('addr1', 'kem2');
        expect(fp1).toBe(fp2);
        expect(fp1).not.toBe(fp3);
        expect(fp1).toMatch(/^\d{5}( \d{5}){11}$/);
    });
});

describe('single-source / version guard', () => {
    it('exports a version both app builds can assert against', () => {
        expect(core.CRYPTO_CORE_VERSION).toBe('3.0.0');
    });
});

// The other half of backend/tests/test_signed_bodies.py: the SAME fixture file,
// asserted from the producing side. A signature is over a string, so if the two
// languages spell it differently every signature of that kind fails — and a
// wrong message is indistinguishable from a forgery to a verifier.
//
// Reading a shared file rather than re-declaring the expected strings here is
// the point. Two copies of a golden vector agree until someone updates one.
describe('signed bodies match the server, byte for byte', () => {
    const vectors = JSON.parse(
        readFileSync(new URL('../../../tests/fixtures/signed_bodies.json', import.meta.url), 'utf8')
    );

    const login = (encryptionKey = null) => core.loginChallengeBody({
        nonce: vectors.nonce, origin: vectors.origin, deployment: vectors.deployment, encryptionKey,
    });

    it('login challenge', () => {
        expect(login()).toBe(vectors.bodies.login);
    });

    it('login challenge with the encryption key bound in (M-2)', () => {
        expect(login(vectors.mlkem_public_key)).toBe(vectors.bodies.login_with_encryption_key);
    });

    it('key attestation', () => {
        expect(core.encryptionKeyAttestationBody(vectors.mlkem_public_key))
            .toBe(vectors.bodies.key_attestation);
    });

    it('multisig approval', () => {
        expect(core.multisigApprovalMessage(
            vectors.workflow_id, vectors.secret_id, vectors.ciphertext_sha256
        )).toBe(vectors.bodies.multisig_approval);
    });

    it('message body', async () => {
        expect(await core.messageSigningBody({
            from: vectors.message_from, conv: vectors.message_conv, gid: vectors.message_gid,
            sid: vectors.message_sid, ts: vectors.message_ts, seq: vectors.message_seq,
            ct: vectors.message_ct, keys: vectors.message_keys,
        })).toBe(vectors.bodies.message);
    });

    it('author-redacted message body', async () => {
        expect(await core.messageSigningBody({
            from: vectors.message_from, conv: vectors.message_conv, gid: vectors.message_gid,
            sid: vectors.message_sid, ts: vectors.message_ts, seq: vectors.message_seq,
            ct: null, keys: vectors.message_keys,
        })).toBe(vectors.bodies.message_redacted);
    });

    it('account deletion', async () => {
        expect(await core.accountDeletionBody({
            nonce: vectors.nonce, mode: vectors.deletion_mode, redactionKeys: vectors.redaction_keys,
            origin: vectors.origin, deployment: vectors.deployment,
        })).toBe(vectors.bodies.account_deletion);
    });

    it('the fixture is what we think it is, not just what both sides produce', () => {
        // Guards the vectors themselves: agreement with a file both sides could
        // regenerate would pass for any value, including a broken one. keysh is
        // recomputed here from node's own crypto, independent of sha256Hex.
        const canon = core.canonicalJson(vectors.message_keys);
        expect(vectors.bodies.message).toContain(
            `keysh=${createHash('sha256').update(canon).digest('hex')}`);

        // The redaction differs from the live body in its LAST LINE ONLY — same
        // author, conversation, gid, sid and key envelope.
        const cut = (b) => b.slice(0, b.lastIndexOf('\n'));
        expect(cut(vectors.bodies.message_redacted)).toBe(cut(vectors.bodies.message));
        expect(vectors.bodies.message_redacted.endsWith('\nredacted=1')).toBe(true);
        expect(vectors.bodies.message.endsWith('\nct=AAAAAAAAAAAAAAAA.3q2+7w==')).toBe(true);
    });

    it('a login signature verifies against the body the server would rebuild', async () => {
        // End to end on this side: sign the shared body, verify it back. The
        // server half needs liboqs, so it lives in backend/tests/test_pqc.py.
        const { publicKey, privateKey } = await core.generateMlDsaKeyPair();
        const sig = await core.signMessage(vectors.bodies.login_with_encryption_key, privateKey);
        expect(await core.verifySignature(login(vectors.mlkem_public_key), sig, publicKey)).toBe(true);
        // ...and not against the challenge without the key bound in.
        expect(await core.verifySignature(vectors.bodies.login, sig, publicKey)).toBe(false);
    });
});
