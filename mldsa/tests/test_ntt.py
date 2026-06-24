import random

import pytest

from mldsa.ntt import ZETAS, intt, multiply_ntts, ntt
from mldsa.params import N, Q


def _poly_mul_naive(a, b):
    """Multiplication in ℤ_q[X]/(X²⁵⁶ + 1)."""
    c = [0] * N
    for i in range(N):
        if a[i] == 0:
            continue
        for j in range(N):
            k = i + j
            v = a[i] * b[j]
            if k < N:
                c[k] = (c[k] + v) % Q
            else:
                c[k - N] = (c[k - N] - v) % Q
    return [v % Q for v in c]


def test_zetas_basic():
    assert len(ZETAS) == 256
    assert ZETAS[0] == 1
    assert all(0 <= z < Q for z in ZETAS)


def test_zeta_is_primitive_512th_root():
    # ζ = 1753, ζ²⁵⁶ ≡ −1 (mod q), so ζ⁵¹² ≡ 1 and ζ²⁵⁶ ≠ 1.
    z256 = pow(1753, 256, Q)
    assert z256 == Q - 1
    assert pow(1753, 512, Q) == 1


def test_zetas_table_known_values():
    # ZETAS[1] = ζ^{BitRev_8(1)} = ζ^128. ζ²⁵⁶ = −1 ⇒ ζ¹²⁸ is a square root of −1.
    # Verify by squaring.
    assert (ZETAS[1] * ZETAS[1]) % Q == Q - 1


@pytest.mark.parametrize("seed", [1, 7, 42, 1337])
def test_ntt_roundtrip(seed):
    rng = random.Random(seed)
    f = [rng.randrange(Q) for _ in range(N)]
    assert intt(ntt(f)) == f


def test_ntt_zero():
    assert ntt([0] * N) == [0] * N
    assert intt([0] * N) == [0] * N


@pytest.mark.parametrize("seed", [0, 1, 99])
def test_multiply_homomorphism(seed):
    rng = random.Random(seed)
    f = [rng.randrange(Q) for _ in range(N)]
    g = [rng.randrange(Q) for _ in range(N)]
    assert intt(multiply_ntts(ntt(f), ntt(g))) == _poly_mul_naive(f, g)


def test_multiply_with_constant_one():
    one = [0] * N
    one[0] = 1
    rng = random.Random(11)
    f = [rng.randrange(Q) for _ in range(N)]
    assert intt(multiply_ntts(ntt(f), ntt(one))) == f
