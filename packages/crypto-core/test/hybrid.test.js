// The hybrid primitives of crypto-core 5 against their specifications' own
// vectors (audit 2026-10-12 K-10, lot 12): composite ML-DSA-65 + ECDSA-P384
// (draft-ietf-lamps-pq-composite-sigs-19) and ETSI TS 103 744 CatKDF over
// P-384 + ML-KEM-768.
//
// Both vector files are copied verbatim from upstream, with provenance in their
// `_source`. The backend runs the same files through OpenSSL
// (backend/tests/test_hybrid_primitives.py), so neither library is the one that
// is right: the specification is.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { p384 } from '@noble/curves/nist.js';
import * as core from '../src/index.js';

const fixture = (name) => JSON.parse(
    readFileSync(new URL(`../../../tests/fixtures/${name}`, import.meta.url), 'utf8')
);
const b64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const hex = (s) => new Uint8Array(Buffer.from(s, 'hex'));
const flip = (bytes, at) => { const c = bytes.slice(); c[at] ^= 1; return c; };

// The identity signature since 5.0.0 (lot 12b). ECDSA is randomized
// upstream, so the vector pins M' by VERIFYING the published signatures: a
// wrong prefix, label, context byte or digest would make upstream's ECDSA half
// fail under our message as surely as its ML-DSA half.
describe('composite ML-DSA-65 + ECDSA-P384 (draft-ietf-lamps-pq-composite-sigs-19)', () => {
    const V = fixture('composite_mldsa65_ecdsa_p384_vectors.json');
    const [m, ctx, pk, skDraft, s, sCtx] = [V.m, V.ctx, V.pk, V.sk, V.s, V.sWithContext].map(b64);
    // The draft's secret key carries the scalar inside an RFC 5915 ECPrivateKey;
    // ours is the ML-DSA seed and the bare scalar.
    const sk = Uint8Array.from([...skDraft.subarray(0, 32), ...skDraft.subarray(32 + 7, 32 + 7 + 48)]);
    const ML_SIG = 3309;
    const N = p384.Point.Fn.ORDER;
    const P384_LABEL = 'CompositeAlgorithmSignatures2025COMPSIG-MLDSA65-ECDSA-P384-SHA512';

    // A composite signature with its ECDSA half rebuilt from (r, s) — to make
    // the high-S twin of a valid signature, or a non-canonical spelling of it.
    const derParts = (sig) => p384.Signature.fromBytes(sig.subarray(ML_SIG), 'der');
    const withEcdsa = (sig, der) => Uint8Array.from([...sig.subarray(0, ML_SIG), ...der]);
    const der = (r, sv) => new p384.Signature(r, sv).toBytes('der');

    it('has the sizes the formats are built on', () => {
        expect(core.MLDSA65_P384_LENGTHS).toEqual({ publicKey: 2049, secretKey: 80, signature: 3413 });
        expect(core.MLDSA65_P384_SIG_ALG).toBe('MLDSA65-ECDSA-P384-SHA512');
        expect(pk.length).toBe(2049);
        expect(Buffer.from(skDraft.subarray(32, 39)).toString('hex')).toBe('303e0201010430'); // where the scalar sits
    });

    it('derives the published public key from the published secret', () => {
        expect(core.mldsa65P384PublicKey(sk)).toEqual(pk);
        expect(core.mldsa65P384Keygen(sk).publicKey).toEqual(pk);
    });

    it('verifies the low-S published signature, under its own context only', () => {
        expect(core.mldsa65P384Verify(s, m, pk)).toBe(true);
        expect(core.mldsa65P384Verify(s, m, pk, ctx)).toBe(false);
        expect(core.mldsa65P384Verify(s, flip(m, 0), pk)).toBe(false);
    });

    it("refuses the draft's own high-S signature, and accepts its low-S twin", () => {
        // Valid under the draft (noble with lowS:false agrees), refused here
        // ONLY for its s: the same r with n - s, every other byte unchanged,
        // verifies — which is also what proves M' for the context case.
        const { r, s: high } = derParts(sCtx);
        expect(high > N / 2n).toBe(true);
        const M = core.mldsa65P384Message(m, ctx);
        expect(p384.verify(sCtx.subarray(ML_SIG), M, pk.subarray(1952), { format: 'der', lowS: false })).toBe(true);
        expect(core.mldsa65P384Verify(sCtx, m, pk, ctx)).toBe(false);
        expect(core.mldsa65P384Verify(withEcdsa(sCtx, der(r, N - high)), m, pk, ctx)).toBe(true);
    });

    it('turning a valid signature high-S is a refusal: one valid s per signature', () => {
        const { r, s: low } = derParts(s);
        expect(core.mldsa65P384Verify(withEcdsa(s, der(r, N - low)), m, pk)).toBe(false);
    });

    it('refuses a non-canonical DER spelling of the same (r, s)', () => {
        const canonical = s.subarray(ML_SIG);
        // A superfluous leading zero on r: same integer, longer encoding.
        const rLen = canonical[3];
        const r = canonical.subarray(4, 4 + rLen);
        const rest = canonical.subarray(4 + rLen);
        const padded = Uint8Array.from([0x30, canonical[1] + 1, 0x02, rLen + 1, 0x00, ...r, ...rest]);
        expect(core.mldsa65P384Verify(withEcdsa(s, padded), m, pk)).toBe(false);
        // A trailing byte after a valid encoding.
        expect(core.mldsa65P384Verify(Uint8Array.from([...s, 0]), m, pk)).toBe(false);
        // A long-form length where the short form fits.
        const longForm = Uint8Array.from([0x30, 0x81, canonical[1], ...canonical.subarray(2)]);
        expect(core.mldsa65P384Verify(withEcdsa(s, longForm), m, pk)).toBe(false);
    });

    it("pins M' byte for byte", () => {
        const empty = core.mldsa65P384Message(new Uint8Array(0));
        expect(Buffer.from(empty.subarray(0, P384_LABEL.length)).toString('latin1')).toBe(P384_LABEL);
        expect(empty[P384_LABEL.length]).toBe(0);
        expect(Buffer.from(empty.subarray(P384_LABEL.length + 1)).toString('hex'))
            .toBe(createHash('sha512').update('').digest('hex'));
    });

    it('needs BOTH halves, and the uncompressed key form', () => {
        expect(core.mldsa65P384Verify(flip(s, 10), m, pk)).toBe(false); // ML-DSA half
        expect(core.mldsa65P384Verify(flip(s, ML_SIG + 20), m, pk)).toBe(false); // ECDSA half
        expect(core.mldsa65P384Verify(s, m, flip(pk, 10))).toBe(false);
        expect(core.mldsa65P384Verify(s, m, flip(pk, 2000))).toBe(false);
        const compressedPrefix = pk.slice(); compressedPrefix[1952] = 0x02;
        expect(core.mldsa65P384Verify(s, m, compressedPrefix)).toBe(false);
    });

    it('refuses wrong lengths and junk without throwing', () => {
        expect(core.mldsa65P384Verify(s.subarray(0, ML_SIG + 7), m, pk)).toBe(false);
        expect(core.mldsa65P384Verify(new Uint8Array(ML_SIG + 105), m, pk)).toBe(false);
        expect(core.mldsa65P384Verify(s, m, pk.subarray(1))).toBe(false);
        expect(core.mldsa65P384Verify('not bytes', m, pk)).toBe(false);
        expect(core.mldsa65P384Verify(s, m, pk, new Uint8Array(256))).toBe(false);
        expect(() => core.mldsa65P384Sign(m, sk, new Uint8Array(256))).toThrow(/255/);
        expect(() => core.mldsa65P384Sign(m, sk.subarray(1))).toThrow(/80 bytes/);
        expect(() => core.mldsa65P384PublicKey(new Uint8Array(80))).toThrow(/out of range/);
    });

    it('signs low-S, hedged, with a fresh key whose halves are independent', () => {
        const a = core.mldsa65P384Keygen();
        const b = core.mldsa65P384Keygen();
        for (let i = 0; i < 8; i++) {
            const sig = core.mldsa65P384Sign(m, a.secretKey);
            expect(core.mldsa65P384Verify(sig, m, a.publicKey)).toBe(true);
            expect(core.mldsa65P384Verify(sig, m, b.publicKey)).toBe(false);
            expect(derParts(sig).s <= N / 2n).toBe(true);
        }
        // Hedged: the same message twice gives two different ECDSA halves.
        const one = core.mldsa65P384Sign(m, a.secretKey).subarray(ML_SIG);
        const two = core.mldsa65P384Sign(m, a.secretKey).subarray(ML_SIG);
        expect(one).not.toEqual(two);
        expect(a.secretKey.subarray(32)).not.toEqual(b.secretKey.subarray(32));
        expect(core.mldsa65P384PublicKey(a.secretKey)).toEqual(a.publicKey);
    });
});

describe('signature registry', () => {
    it('holds the composite in use, under its own id', () => {
        expect(Object.keys(core.SIGNATURE_SUITES)).toEqual([core.MLDSA65_P384_SIG_ALG]);
        expect(core.SIGNATURE_SUITES[core.SIGNATURE_ALG]).toBe(core.SIGNATURE_SUITE);
        expect(core.SIGNATURE_SUITE.alg).toBe('MLDSA65-ECDSA-P384-SHA512');
        expect(Object.isFrozen(core.SIGNATURE_SUITES)).toBe(true);
    });

    it('signs and verifies within its maximum length', () => {
        const suite = core.SIGNATURE_SUITE;
        const { publicKey, secretKey } = suite.keygen();
        expect(suite.publicKey(secretKey)).toEqual(publicKey);
        const message = new TextEncoder().encode('hello');
        const sig = suite.sign(message, secretKey);
        expect(sig.length).toBeLessThanOrEqual(suite.lengths.signature);
        expect(suite.verify(sig, message, publicKey)).toBe(true);
    });
});

// ETSI TS 103 744 V1.2.2 CatKDF, parameter set HKDFwSHA384_P384_ML-KEM-768
// (lot 12a). The standard's own known-answer test pins every building block;
// the suite's composition — which halves, in which order, under which
// transcript — is then pinned by decapsulating the vector's own ciphertext.
describe('CatKDF HKDFwSHA384_P384_ML-KEM-768 (ETSI TS 103 744 V1.2.2)', () => {
    const V = fixture('etsi_catkdf_vectors.json');
    const enc = (s) => new TextEncoder().encode(s);
    const xor = (a, b) => a.map((byte, i) => byte ^ b[i]);
    const u32 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
    const cat = (...p) => Uint8Array.from(p.flatMap((a) => [...a]));
    const point = (raw) => cat([4], hex(raw)); // the harness's x||y as SEC1 uncompressed
    // Our secret key for the vector's recipient: its P-384 scalar, then its ML-KEM seed.
    const vectorSecretKey = () => cat(hex(V.ecdh_private_a), hex(V.mlkem_keygen_seed));
    const vectorCipherText = () => cat(hex(V.ecdh_public_b), hex(V.pb2));

    it('has the sizes the formats are built on, and the parameter set the standard names', () => {
        expect(core.CATKDF_LENGTHS).toEqual({ publicKey: 1281, secretKey: 112, cipherText: 1185, key: 32 });
        expect(core.CATKDF_KEM_ALG).toBe('HKDFwSHA384_P384_ML-KEM-768_CatKDF');
        expect(V.cid).toBe('2221');
    });

    it('formats MA as Annex C does: cid, then each value behind its 32-bit length', () => {
        const MA = core.etsiMessage(hex(V.cid), hex(V.labelA), hex(V.pa1), hex(V.pa2));
        expect(MA.subarray(0, 2)).toEqual(hex('2221'));
        expect(MA.subarray(2, 6)).toEqual(u32(48));
        expect(MA.subarray(54, 58)).toEqual(u32(96));
        expect(MA.length).toBe(2 + 4 + 48 + 4 + 96 + 4 + 1184);
    });

    it("reproduces the standard's key material from its k1, k2, MA, MB, info and label", () => {
        const km = core.catKdfHkdfSha384({
            k1: hex(V.k1),
            k2: hex(V.k2),
            MA: core.etsiMessage(hex(V.cid), hex(V.labelA), hex(V.pa1), hex(V.pa2)),
            MB: core.etsiMessage(hex(V.cid), hex(V.labelB), hex(V.pb1), hex(V.pb2)),
            info: enc(V.info),
            label: xor(hex(V.labelA), hex(V.labelB)),
            length: 24,
        });
        expect(Buffer.from(km).toString('hex')).toBe(V.key_material);
    });

    it("cahb_f is SHA-384 over the length-prefixed values, as §7.2.3 defines it", () => {
        const a = enc('a'); const bc = enc('bc');
        const expected = createHash('sha384').update(Buffer.from(cat(u32(1), a, u32(2), bc))).digest();
        expect(Buffer.from(core.etsiContextSha384(a, bc))).toEqual(expected);
    });

    it("derives the vector's public keys from its secrets: P1 from the scalar, P2 from the seed", () => {
        const pk = core.catkdfPublicKey(vectorSecretKey());
        expect(pk.subarray(0, 97)).toEqual(point(V.pa1));
        expect(pk.subarray(97)).toEqual(hex(V.pa2));
    });

    it("decapsulates the vector's ciphertext into CatKDF over the vector's own k1 and k2", () => {
        // k1 and k2 are pinned by the standard; what this pins is the
        // composition around them: the ECDH half first, SEC1 points in the
        // transcript, empty label contributions, and this suite's info.
        const P1 = point(V.pa1); const R1 = hex(V.ecdh_public_b);
        const expected = core.catKdfHkdfSha384({
            k1: hex(V.k1),
            k2: hex(V.k2),
            MA: core.etsiMessage(hex('2221'), new Uint8Array(0), P1, hex(V.pa2)),
            MB: core.etsiMessage(hex('2221'), new Uint8Array(0), R1, hex(V.pb2)),
            info: enc('Kryptolog/HKDFwSHA384_P384_ML-KEM-768_CatKDF/AES-GCM/v5'),
            length: 32,
        });
        expect(core.catkdfDecapsulate(vectorCipherText(), vectorSecretKey())).toEqual(expected);
    });

    it('round-trips, and a different key recovers a different key without throwing', () => {
        const alice = core.catkdfKeygen();
        const eve = core.catkdfKeygen();
        const { cipherText, key } = core.catkdfEncapsulate(alice.publicKey);
        expect(cipherText).toHaveLength(1185);
        expect(key).toHaveLength(32);
        expect(core.catkdfDecapsulate(cipherText, alice.secretKey)).toEqual(key);
        expect(core.catkdfDecapsulate(cipherText, eve.secretKey)).not.toEqual(key);
        // Fresh randomness on every encapsulation, in both halves.
        const again = core.catkdfEncapsulate(alice.publicKey);
        expect(again.cipherText.subarray(0, 97)).not.toEqual(cipherText.subarray(0, 97));
        expect(again.cipherText.subarray(97)).not.toEqual(cipherText.subarray(97));
    });

    it('needs BOTH halves: replacing either half of the ciphertext changes the key', () => {
        const alice = core.catkdfKeygen();
        const one = core.catkdfEncapsulate(alice.publicKey);
        const two = core.catkdfEncapsulate(alice.publicKey);
        const mixed = (ecdhFrom, mlkemFrom) => cat(ecdhFrom.cipherText.subarray(0, 97), mlkemFrom.cipherText.subarray(97));
        expect(core.catkdfDecapsulate(mixed(one, two), alice.secretKey)).not.toEqual(one.key);
        expect(core.catkdfDecapsulate(mixed(two, one), alice.secretKey)).not.toEqual(one.key);
        // A flipped bit in the ML-KEM half is implicitly rejected: a key, but not this one.
        expect(core.catkdfDecapsulate(flip(one.cipherText, 600), alice.secretKey)).not.toEqual(one.key);
    });

    it('draws the two halves independently', () => {
        const a = core.catkdfKeygen();
        const b = core.catkdfKeygen();
        expect(a.secretKey.subarray(0, 48)).not.toEqual(b.secretKey.subarray(0, 48));
        expect(a.secretKey.subarray(48)).not.toEqual(b.secretKey.subarray(48));
        expect(core.catkdfKeygen(a.secretKey).publicKey).toEqual(a.publicKey);
    });

    it('refuses malformed keys and ciphertexts by name', () => {
        const { publicKey, secretKey } = core.catkdfKeygen();
        const { cipherText } = core.catkdfEncapsulate(publicKey);
        expect(() => core.catkdfEncapsulate(publicKey.subarray(1))).toThrow(/public key must be 1281/);
        expect(() => core.catkdfDecapsulate(cipherText.subarray(1), secretKey)).toThrow(/ciphertext must be 1185/);
        expect(() => core.catkdfDecapsulate(cipherText, secretKey.subarray(1))).toThrow(/secret key must be 112/);
        // A compressed prefix on an otherwise right-length key or ciphertext.
        const compressed = (b) => { const c = b.slice(); c[0] = 0x02; return c; };
        expect(() => core.catkdfEncapsulate(compressed(publicKey))).toThrow(/uncompressed P-384/);
        expect(() => core.catkdfDecapsulate(compressed(cipherText), secretKey)).toThrow(/uncompressed P-384/);
        // A point that is not on the curve, in the key and in the ciphertext.
        expect(() => core.catkdfEncapsulate(flip(publicKey, 50))).toThrow();
        expect(() => core.catkdfDecapsulate(flip(cipherText, 50), secretKey)).toThrow();
        // An ML-KEM key that fails the FIPS 203 modulus check.
        const bad = publicKey.slice(); bad[97] = 0xff; bad[98] = 0xff;
        expect(() => core.catkdfEncapsulate(bad)).toThrow(/modulus/);
        // A P-384 scalar of zero, and one equal to the group order.
        expect(() => core.catkdfPublicKey(new Uint8Array(112))).toThrow(/out of range/);
        const order = hex(p384.Point.Fn.ORDER.toString(16));
        expect(() => core.catkdfPublicKey(cat(order, secretKey.subarray(48)))).toThrow(/out of range/);
    });
});

// The registry (4.1.0): one shape for every suite, whatever its KEM.
describe('KEM registry', () => {
    it('holds the suite in use, under its own id', () => {
        expect(Object.keys(core.KEM_SUITES)).toEqual([core.CATKDF_KEM_ALG]);
        expect(core.KEM_SUITES[core.KEM_ALG]).toBe(core.KEM_SUITE);
        expect(core.KEM_ENVELOPE_ALG).toBe('HKDFwSHA384_P384_ML-KEM-768_CatKDF-A256GCM');
        expect(Object.isFrozen(core.KEM_SUITES)).toBe(true);
    });

    it('encapsulates and decapsulates to a 256-bit key', () => {
        const suite = core.KEM_SUITE;
        const { publicKey, secretKey } = suite.keygen();
        expect(suite.publicKey(secretKey)).toEqual(publicKey);
        const { cipherText, key } = suite.encapsulate(publicKey);
        expect(cipherText).toHaveLength(suite.lengths.cipherText);
        expect(key).toHaveLength(32);
        expect(suite.decapsulate(cipherText, secretKey)).toEqual(key);
    });
});

// The other half of backend/tests/test_hybrid_primitives.py, over the same
// file: what OpenSSL produced must open here, as what noble produced opens
// there. Generated once by hand, never by a script in the repo.
describe('noble <-> OpenSSL interop (tests/fixtures/hybrid_interop.json)', () => {
    const V = fixture('hybrid_interop.json');
    const message = new TextEncoder().encode(V.message);
    const pk = hex(V.p384_composite_public_key);

    it('gives the composite key the same address as the server (the golden address, 5.0.0)', () => {
        expect(core.addressOf(V.p384_composite_public_key)).toBe(V.p384_composite_address);
    });

    it('derives the same CatKDF and composite keys from the same secrets', () => {
        expect(core.catkdfPublicKey(hex(V.catkdf_secret_key))).toEqual(hex(V.catkdf_public_key));
        expect(core.mldsa65P384PublicKey(hex(V.p384_composite_secret_key))).toEqual(pk);
    });

    it('opens what OpenSSL encapsulated with CatKDF, to the same key', () => {
        const key = core.catkdfDecapsulate(b64(V.openssl_catkdf_cipher_text), hex(V.catkdf_secret_key));
        expect(key).toEqual(b64(V.openssl_catkdf_key));
    });

    it.each(['noble', 'openssl'])('verifies the %s composite signature', (who) => {
        const sig = b64(V[`${who}_p384_composite_signature`]);
        expect(core.mldsa65P384Verify(sig, message, pk)).toBe(true);
        expect(core.mldsa65P384Verify(sig, new TextEncoder().encode('another message'), pk)).toBe(false);
    });
});

// The identity seam (3.3.0) with its 5.0.0 meaning: an address is the SHA-384
// of the composite identity key under a versioned, algorithm-naming prefix.
describe('identity keys and addresses (5.0.0)', () => {
    it('addressOf is the SHA-384 of the key under its domain, and refuses what is not a key', () => {
        const { publicKey } = core.generateIdentityKeyPair();
        const expected = createHash('sha384')
            .update(Buffer.concat([
                Buffer.from('Kryptolog address v5\nalg=MLDSA65-ECDSA-P384-SHA512\n'),
                Buffer.from(publicKey, 'hex'),
            ]))
            .digest('hex');
        expect(core.addressOf(publicKey)).toBe(expected);
        expect(core.isAddress(expected)).toBe(true);
        expect(() => core.addressOf(publicKey.toUpperCase())).toThrow(TypeError);
        expect(() => core.addressOf(publicKey.slice(2))).toThrow(TypeError);
        expect(() => core.addressOf('cd'.repeat(1312))).toThrow(TypeError); // a 3.x key
        expect(() => core.addressOf('cd'.repeat(1984))).toThrow(TypeError); // a 4.x key
        expect(() => core.addressOf(null)).toThrow(TypeError);
    });

    it('verifyIdentitySignature needs the address and the key to agree', async () => {
        const me = core.generateAccount('me');
        const other = core.generateAccount('other');
        const signature = await core.signMessage('hello', me.identity.seed);
        const verify = (address, identityPublicKey, message = 'hello') =>
            core.verifyIdentitySignature({ address, identityPublicKey, message, signature });
        expect(await verify(me.id, me.identity.publicKey)).toBe(true);
        expect(await verify(me.id, me.identity.publicKey, 'hellO')).toBe(false);
        // The right key under another address: the binding refuses it.
        expect(await verify(other.id, me.identity.publicKey)).toBe(false);
        expect(await verify(me.id, other.identity.publicKey)).toBe(false);
        // The key itself is not an address.
        expect(await verify(me.identity.publicKey, me.identity.publicKey)).toBe(false);
        expect(core.isAddressOf(me.id, undefined)).toBe(false);
        expect(core.isAddressOf(undefined, me.identity.publicKey)).toBe(false);
    });
});
