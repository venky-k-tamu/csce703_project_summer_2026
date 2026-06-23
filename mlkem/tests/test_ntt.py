import random

import pytest

from mlkem.ntt import GAMMAS, ZETAS, intt, multiply_ntts, ntt
from mlkem.params import N, Q


def _poly_mul_naive(a, b):
    """Multiplication in ℤ_q[X]/(X^256 + 1)."""
    c = [0] * N
    for i in range(N):
        ai = a[i]
        if ai == 0:
            continue
        for j in range(N):
            k = i + j
            v = ai * b[j]
            if k < N:
                c[k] = (c[k] + v) % Q
            else:
                c[k - N] = (c[k - N] - v) % Q
    return [v % Q for v in c]


def test_zetas_table_spec_values():
    # FIPS 203 Appendix A, Table 4: first few precomputed zetas.
    assert ZETAS[0] == 1
    assert ZETAS[1] == 1729
    assert ZETAS[2] == 2580
    assert ZETAS[3] == 3289
    assert ZETAS[4] == 2642
    assert ZETAS[5] == 630
    assert ZETAS[6] == 1897
    assert ZETAS[7] == 848
    assert len(ZETAS) == 128
    assert all(0 <= z < Q for z in ZETAS)


def test_gammas_relate_to_zetas():
    # γ_i = ζ^{2·BitRev_7(i)+1} = ζ · (ζ^{BitRev_7(i)})^2 = 17 · ZETAS[i]^2
    for i in range(128):
        assert GAMMAS[i] == (17 * ZETAS[i] * ZETAS[i]) % Q


@pytest.mark.parametrize("seed", [1, 2, 42, 1337])
def test_ntt_roundtrip(seed):
    rng = random.Random(seed)
    f = [rng.randrange(Q) for _ in range(N)]
    assert intt(ntt(f)) == f


def test_ntt_zero_is_zero():
    assert ntt([0] * N) == [0] * N
    assert intt([0] * N) == [0] * N


@pytest.mark.parametrize("seed", [0, 1, 99])
def test_multiply_homomorphism(seed):
    rng = random.Random(seed)
    f = [rng.randrange(Q) for _ in range(N)]
    g = [rng.randrange(Q) for _ in range(N)]
    expected = _poly_mul_naive(f, g)
    got = intt(multiply_ntts(ntt(f), ntt(g)))
    assert got == expected


def test_multiply_with_identity():
    # The polynomial 1 + 0·X + ... has NTT representation (1, 1, ..., 1) in the
    # base-case-multiplication layout (each quadratic factor sees the constant 1).
    one = [0] * N
    one[0] = 1
    rng = random.Random(7)
    f = [rng.randrange(Q) for _ in range(N)]
    assert intt(multiply_ntts(ntt(f), ntt(one))) == f
