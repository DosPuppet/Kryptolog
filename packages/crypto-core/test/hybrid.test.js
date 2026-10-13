// The hybrid primitives of crypto-core 4 against their specifications' own
// vectors (audit 2026-10-12 K-10): composite ML-DSA-65 + Ed25519 and X-Wing.
//
// Both vector files are copied verbatim from upstream, with provenance in their
// `_source`. The backend runs the same files through OpenSSL
// (backend/tests/test_hybrid_primitives.py), so neither library is the one that
// is right: the specification is.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import * as core from '../src/index.js';

const fixture = (name) => JSON.parse(
    readFileSync(new URL(`../../../tests/fixtures/${name}`, import.meta.url), 'utf8')
);
const b64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const hex = (s) => new Uint8Array(Buffer.from(s, 'hex'));
const flip = (bytes, at) => { const c = bytes.slice(); c[at] ^= 1; return c; };

describe('composite ML-DSA-65 + Ed25519 (draft-ietf-lamps-pq-composite-sigs-19)', () => {
    const V = fixture('composite_mldsa65_ed25519_vectors.json');
    const [m, ctx, pk, sk, s, sCtx] = [V.m, V.ctx, V.pk, V.sk, V.s, V.sWithContext].map(b64);
    const ML_SIG = 3309;

    it('has the sizes the formats are built on', () => {
        expect(core.COMPOSITE_LENGTHS).toEqual({ publicKey: 1984, secretKey: 64, signature: 3373 });
        expect([pk.length, sk.length, s.length]).toEqual([1984, 64, 3373]);
        expect(core.COMPOSITE_SIG_ALG).toBe('MLDSA65-Ed25519-SHA512');
    });

    it('derives the published public key from the published secret key', () => {
        expect(core.compositePublicKey(sk)).toEqual(pk);
        expect(core.compositeKeygen(sk).publicKey).toEqual(pk);
    });

    it('verifies both published signatures, each under its own context only', () => {
        expect(core.compositeVerify(s, m, pk)).toBe(true);
        expect(core.compositeVerify(sCtx, m, pk, ctx)).toBe(true);
        expect(core.compositeVerify(s, m, pk, ctx)).toBe(false);
        expect(core.compositeVerify(sCtx, m, pk)).toBe(false);
        expect(core.compositeVerify(s, flip(m, 0), pk)).toBe(false);
    });

    it("pins M' byte for byte: the deterministic Ed25519 half re-produces upstream's", () => {
        // The ML-DSA half is hedged and differs on every signature; the Ed25519
        // half is a pure function of M' and the key. Matching upstream's bytes
        // therefore proves the prefix, label, context length byte and SHA-512
        // digest are exactly the draft's — a mistake in any of them that the
        // verifier ALSO made would still pass the verification test above.
        expect(core.compositeSign(m, sk).subarray(ML_SIG)).toEqual(s.subarray(ML_SIG));
        expect(core.compositeSign(m, sk, ctx).subarray(ML_SIG)).toEqual(sCtx.subarray(ML_SIG));
        const empty = core.compositeMessage(new Uint8Array(0));
        const label = 'CompositeAlgorithmSignatures2025COMPSIG-MLDSA65-Ed25519-SHA512';
        expect(Buffer.from(empty.subarray(0, label.length)).toString('latin1')).toBe(label);
        expect(empty[label.length]).toBe(0); // len(ctx)
        expect(Buffer.from(empty.subarray(label.length + 1)).toString('hex'))
            .toBe(createHash('sha512').update('').digest('hex'));
    });

    it('needs BOTH halves: one flipped byte in either is a refusal', () => {
        expect(core.compositeVerify(flip(s, 10), m, pk)).toBe(false); // ML-DSA half
        expect(core.compositeVerify(flip(s, ML_SIG + 10), m, pk)).toBe(false); // Ed25519 half
        expect(core.compositeVerify(s, m, flip(pk, 10))).toBe(false);
        expect(core.compositeVerify(s, m, flip(pk, 1960))).toBe(false);
    });

    it('refuses wrong lengths and junk without throwing', () => {
        const extended = new Uint8Array(s.length + 1); extended.set(s);
        expect(core.compositeVerify(s.subarray(1), m, pk)).toBe(false);
        expect(core.compositeVerify(extended, m, pk)).toBe(false);
        expect(core.compositeVerify(s, m, pk.subarray(1))).toBe(false);
        expect(core.compositeVerify('not bytes', m, pk)).toBe(false);
        expect(core.compositeVerify(s, m, pk, new Uint8Array(256))).toBe(false);
        expect(() => core.compositeSign(m, sk, new Uint8Array(256))).toThrow(/255/);
        expect(() => core.compositeSign(m, sk.subarray(1))).toThrow(/64 bytes/);
    });

    it('signs and verifies with a fresh key, whose halves are independent', () => {
        const a = core.compositeKeygen();
        const b = core.compositeKeygen();
        const sig = core.compositeSign(m, a.secretKey);
        expect(core.compositeVerify(sig, m, a.publicKey)).toBe(true);
        expect(core.compositeVerify(sig, m, b.publicKey)).toBe(false);
        // The two seeds are drawn separately, not one seed split in two.
        expect(a.secretKey.subarray(0, 32)).not.toEqual(a.secretKey.subarray(32));
        expect(core.compositePublicKey(a.secretKey)).toEqual(a.publicKey);
    });

    // Ed25519 edges where noble's strict mode and the server's OpenSSL disagree.
    // noble checks the cofactored equation, OpenSSL the cofactorless one, so a
    // torsion component in R or A that cancels under [8] is accepted by the
    // first and refused by the second. Built by hand from a known scalar, which
    // is the point: only a key's OWNER can make these.
    describe('Ed25519 half: never more lenient than OpenSSL', () => {
        const { Point } = ed25519;
        const L = Point.Fn.ORDER;
        const T = Point.fromHex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'); // y = -1, order 2
        const le = (b) => b.reduceRight((x, byte) => (x << 8n) | BigInt(byte), 0n);
        const toLE = (x) => Uint8Array.from({ length: 32 }, (_, i) => Number((x >> BigInt(8 * i)) & 255n));
        const base = core.compositeKeygen(new Uint8Array(64).fill(3));
        const edSeed = base.secretKey.subarray(32);
        const { scalar: a, point: A } = ed25519.utils.getExtendedPublicKey(edSeed);

        // A composite signature whose ML-DSA half is honest and whose Ed25519
        // half is (R, S) built by hand, with optional order-2 components.
        const craft = ({ torsionInR = false, torsionInA = false } = {}) => {
            const Apt = torsionInA ? A.add(T) : A;
            const pub = Uint8Array.from([...base.publicKey.subarray(0, 1952), ...Apt.toBytes()]);
            const M = core.compositeMessage(m);
            for (let r = 1n; ; r += 1n) {
                const R = torsionInR ? Point.BASE.multiply(r).add(T) : Point.BASE.multiply(r);
                const k = le(sha512(Uint8Array.from([...R.toBytes(), ...Apt.toBytes(), ...M]))) % L;
                // With torsion in A, an EVEN k cancels it even cofactorless and
                // OpenSSL accepts too; an odd one is the disagreement.
                if (torsionInA && k % 2n === 0n) continue;
                const edSig = Uint8Array.from([...R.toBytes(), ...toLE((r + k * a) % L)]);
                const mlHalf = core.compositeSign(m, base.secretKey).subarray(0, 3309);
                return { pub, sig: Uint8Array.from([...mlHalf, ...edSig]), M, edSig, edPub: Apt.toBytes() };
            }
        };

        it('the hand-built signature is accepted when there is no torsion', () => {
            const { pub, sig } = craft();
            expect(core.compositeVerify(sig, m, pub)).toBe(true);
        });

        it.each([
            ['R', { torsionInR: true }],
            ['A', { torsionInA: true }],
        ])('a torsion component in %s is refused, though noble strict alone accepts it', (_, opts) => {
            const { pub, sig, M, edSig, edPub } = craft(opts);
            // Without this the test could pass for the wrong reason.
            expect(ed25519.verify(edSig, M, edPub, { zip215: false })).toBe(true);
            expect(core.compositeVerify(sig, m, pub)).toBe(false);
        });

        it('a small-order public key is refused', () => {
            const pub = Uint8Array.from([...base.publicKey.subarray(0, 1952), ...T.toBytes()]);
            const M = core.compositeMessage(m);
            const edSig = Uint8Array.from([...Point.ZERO.toBytes(), ...new Uint8Array(32)]);
            expect(ed25519.verify(edSig, M, T.toBytes(), { zip215: true })).toBe(true); // ZIP215 takes it
            const mlHalf = core.compositeSign(m, base.secretKey).subarray(0, 3309);
            expect(core.compositeVerify(Uint8Array.from([...mlHalf, ...edSig]), m, pub)).toBe(false);
        });
    });
});

describe('X-Wing (draft-connolly-cfrg-xwing-kem-10)', () => {
    const { vectors } = fixture('xwing_vectors.json');

    it('has the sizes the formats are built on', () => {
        expect(core.XWING_LENGTHS).toEqual({ publicKey: 1216, secretKey: 32, cipherText: 1120, sharedSecret: 32 });
        expect(vectors).toHaveLength(3);
    });

    it.each(vectors.map((v, i) => [i, v]))('vector %i: seed -> key pair, ciphertext -> shared secret', (_, v) => {
        const { publicKey, secretKey } = core.xwingKeygen(hex(v.seed));
        expect(secretKey).toEqual(hex(v.sk));
        expect(publicKey).toEqual(hex(v.pk));
        expect(core.xwingPublicKey(hex(v.sk))).toEqual(hex(v.pk));
        expect(core.xwingDecapsulate(hex(v.ct), hex(v.sk))).toEqual(hex(v.ss));
    });

    it("pins the library's encapsulation too, with the vectors' randomness", () => {
        // xwingEncapsulate deliberately takes no randomness. With decapsulation
        // pinned above, the round trip below is what proves our encapsulation;
        // this pins the noble preset it calls.
        for (const v of vectors) {
            const { cipherText, sharedSecret } = ml_kem768_x25519.encapsulate(hex(v.pk), hex(v.eseed));
            expect(cipherText).toEqual(hex(v.ct));
            expect(sharedSecret).toEqual(hex(v.ss));
        }
    });

    it('round-trips, and a different key recovers a different secret without throwing', () => {
        const alice = core.xwingKeygen();
        const eve = core.xwingKeygen();
        const { cipherText, sharedSecret } = core.xwingEncapsulate(alice.publicKey);
        expect(cipherText).toHaveLength(1120);
        expect(core.xwingDecapsulate(cipherText, alice.secretKey)).toEqual(sharedSecret);
        expect(core.xwingDecapsulate(cipherText, eve.secretKey)).not.toEqual(sharedSecret);
    });

    it('refuses wrong lengths by name', () => {
        const { publicKey, secretKey } = core.xwingKeygen();
        expect(() => core.xwingEncapsulate(publicKey.subarray(1))).toThrow(/public key must be 1216/);
        expect(() => core.xwingDecapsulate(new Uint8Array(1119), secretKey)).toThrow(/ciphertext must be 1120/);
        expect(() => core.xwingDecapsulate(new Uint8Array(1120), secretKey.subarray(1))).toThrow(/secret key must be 32/);
    });
});

// The other half of backend/tests/test_hybrid_primitives.py, over the same
// file: what OpenSSL produced must open here, as what noble produced opens
// there. Generated once by hand, never by a script in the repo.
describe('noble <-> OpenSSL interop (tests/fixtures/hybrid_interop.json)', () => {
    const V = fixture('hybrid_interop.json');
    const message = new TextEncoder().encode(V.message);
    const pk = hex(V.composite_public_key);

    it('derives the same composite and X-Wing keys from the same seeds', () => {
        expect(core.compositePublicKey(hex(V.composite_secret_key))).toEqual(pk);
        expect(core.xwingPublicKey(hex(V.xwing_secret_key))).toEqual(hex(V.xwing_public_key));
    });

    it.each(['noble', 'openssl'])('verifies the %s composite signature', (who) => {
        const sig = b64(V[`${who}_composite_signature`]);
        expect(core.compositeVerify(sig, message, pk)).toBe(true);
        expect(core.compositeVerify(sig, new TextEncoder().encode('another message'), pk)).toBe(false);
    });

    it('decapsulates what OpenSSL encapsulated', () => {
        const ss = core.xwingDecapsulate(b64(V.openssl_xwing_cipher_text), hex(V.xwing_secret_key));
        expect(ss).toEqual(b64(V.openssl_xwing_shared_secret));
    });

    // OpenSSL accepts mixed_order_A_even_k's signature; the server refuses its
    // KEY where it enters. The clients refuse all four on the signature alone.
    it.each(Object.keys(V.ed25519_edges))('refuses the %s edge', (edge) => {
        const e = V.ed25519_edges[edge];
        expect(core.compositeVerify(b64(e.signature), message, hex(e.public_key))).toBe(false);
    });

    it.each(Object.keys(V.prime_order_points))('agrees on whether %s has order L', (name) => {
        const { point, in_prime_order_subgroup: expected } = V.prime_order_points[name];
        let actual;
        try {
            const p = ed25519.Point.fromBytes(hex(point));
            actual = !p.is0() && p.isTorsionFree();
        } catch {
            actual = false;
        }
        expect(actual).toBe(expected);
    });
});

// The identity seam (3.3.0). In 3.x an address IS the identity key, so the
// binding is the identity function — pinned here so that 4.0.0, which makes
// the address a hash of the key, is visibly the change that moves it.
describe('identity keys and addresses (3.3.0)', () => {
    it('addressOf is the identity on 3.x keys, and refuses what is not lowercase hex', async () => {
        const { publicKey } = await core.generateMlDsaKeyPair();
        expect(core.addressOf(publicKey)).toBe(publicKey);
        expect(() => core.addressOf(publicKey.toUpperCase())).toThrow(TypeError);
        expect(() => core.addressOf('abc')).toThrow(TypeError);
        expect(() => core.addressOf(null)).toThrow(TypeError);
    });

    it('verifyIdentitySignature needs the address and the key to agree', async () => {
        const me = await core.generateMlDsaKeyPair();
        const other = await core.generateMlDsaKeyPair();
        const signature = await core.signMessage('hello', me.privateKey);
        const verify = (address, identityPublicKey, message = 'hello') =>
            core.verifyIdentitySignature({ address, identityPublicKey, message, signature });
        expect(await verify(me.publicKey, me.publicKey)).toBe(true);
        expect(await verify(me.publicKey, me.publicKey, 'hellO')).toBe(false);
        // The right key under another address: the binding refuses it.
        expect(await verify(other.publicKey, me.publicKey)).toBe(false);
        expect(await verify(me.publicKey, other.publicKey)).toBe(false);
        expect(core.isAddressOf(me.publicKey, undefined)).toBe(false);
        expect(core.isAddressOf(undefined, me.publicKey)).toBe(false);
    });
});
