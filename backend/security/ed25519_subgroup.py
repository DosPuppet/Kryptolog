"""Is an Ed25519 public key in the prime-order subgroup?

The one question about Ed25519 that pyca/cryptography cannot answer, and the
one the composite identity key of crypto-core 4 needs answered (audit
2026-10-12 K-10).

Why it matters: the server verifies Ed25519 with OpenSSL, which checks the
cofactorless equation [S]B = R + [k]A; the clients' noble checks the cofactored
one, [8][S]B = [8]R + [8][k]A, and additionally requires R and A to be
torsion-free (packages/crypto-core/src/composite.js). For a key A with a
small-order component the two disagree: OpenSSL accepts the signatures whose
challenge k happens to cancel the component, every client refuses them all.
That is a key OWNER's construction — it needs the secret scalar — but its
effect is a multisig approval the server takes as consent while Proof Audit
calls it invalid, i.e. a signer who can deny an approval that counted. Refusing
such a key where it enters closes that: with A in the prime-order subgroup the
two equations accept exactly the same signatures, and OpenSSL alone suffices on
every verification after.

Plain RFC 8032 arithmetic over public data, so nothing here needs to be
constant-time. About 1 ms per key; it runs once per key, not per signature.
Cross-checked against noble's `isTorsionFree` on the same points
(tests/test_hybrid_primitives.py, tests/fixtures/hybrid_interop.json).
"""

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493  # the prime subgroup's order
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1, 1, 0)


def _decode(encoded: bytes) -> tuple[int, int, int, int] | None:
    """RFC 8032 5.1.3, strictly: a non-canonical y (>= p), a y with no x, and
    x = 0 with the sign bit set are all refused, as OpenSSL refuses them."""
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    sign = encoded[31] >> 7
    if y >= _P:
        return None
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P) % _P
    if v * x * x % _P == u:
        pass
    elif v * x * x % _P == (-u) % _P:
        x = x * _SQRT_M1 % _P
    else:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def _add(p1, p2):
    """RFC 8032 5.1.4, extended coordinates; complete, so it also doubles."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _multiply(k: int, point):
    acc = _IDENTITY
    while k:
        if k & 1:
            acc = _add(acc, point)
        point = _add(point, point)
        k >>= 1
    return acc


def _is_identity(point) -> bool:
    x, y, z, _ = point
    return x % _P == 0 and (y - z) % _P == 0


def in_prime_order_subgroup(encoded: bytes) -> bool:
    """True iff `encoded` is a canonical Ed25519 point of order exactly L:
    [L]A is the identity and A is not. Small-order points, points with a
    torsion component, and anything that does not decode are all False."""
    point = _decode(encoded)
    if point is None or _is_identity(point):
        return False
    return _is_identity(_multiply(_L, point))
