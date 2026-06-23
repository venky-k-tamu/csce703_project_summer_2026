import random

import pytest

from mldsa.params import D, GAMMA_2, Q
from mldsa.rounding import (
    _mod_pm,
    decompose,
    high_bits,
    low_bits,
    make_hint,
    power2round,
    use_hint,
)

M = (Q - 1) // (2 * GAMMA_2)  # 16 for ML-DSA-65


def test_mod_pm_basic():
    assert _mod_pm(0, 8) == 0
    assert _mod_pm(4, 8) == 4
    assert _mod_pm(5, 8) == -3
    assert _mod_pm(7, 8) == -1


@pytest.mark.parametrize("seed", [0, 1, 42, 12345])
def test_power2round_identity(seed):
    rng = random.Random(seed)
    half = 1 << (D - 1)
    for _ in range(200):
        r = rng.randrange(Q)
        r1, r0 = power2round(r)
        assert -half < r0 <= half
        assert ((r1 << D) + r0) % Q == r


@pytest.mark.parametrize("seed", [0, 1, 42, 12345])
def test_decompose_identity(seed):
    rng = random.Random(seed)
    for _ in range(200):
        r = rng.randrange(Q)
        r1, r0 = decompose(r)
        assert -GAMMA_2 < r0 <= GAMMA_2
        assert 0 <= r1 < M
        assert (r1 * 2 * GAMMA_2 + r0) % Q == r


def test_high_low_bits_consistent_with_decompose():
    for r in (0, 1, 1234567, Q - 1):
        assert (high_bits(r), low_bits(r)) == decompose(r)


@pytest.mark.parametrize("seed", [0, 1, 42])
def test_hint_roundtrip(seed):
    # The defining property of hints: for |z| ≤ γ2, UseHint(MakeHint(z, r), r)
    # must recover HighBits(r + z).
    rng = random.Random(seed)
    for _ in range(200):
        r = rng.randrange(Q)
        z = rng.randint(-GAMMA_2, GAMMA_2)
        h = make_hint(z, r)
        assert h in (0, 1)
        recovered = use_hint(h, r)
        assert recovered == high_bits((r + z) % Q)


def test_decompose_wraparound_boundary():
    # The (q - 1) wraparound case: r near q-1 should still produce r1 ∈ [0, m).
    for r in (Q - 1, Q - 2, Q - GAMMA_2, Q - 2 * GAMMA_2):
        r1, r0 = decompose(r)
        assert 0 <= r1 < M
        assert (r1 * 2 * GAMMA_2 + r0) % Q == r
