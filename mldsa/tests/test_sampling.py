import pytest

from mldsa.params import ETA, GAMMA_1, K, L, LAMBDA, N, Q, TAU
from mldsa.sampling import (
    expand_a,
    expand_mask,
    expand_s,
    rej_bounded_poly,
    rej_ntt_poly,
    sample_in_ball,
)


def _signed(x):
    return x - Q if x > Q // 2 else x


# ----- rej_ntt_poly / rej_bounded_poly ---------------------------------------


def test_rej_ntt_poly_deterministic_and_in_range():
    seed = b"a-34-byte-seed-for-rej-ntt!!!!!!\x00\x01"
    a = rej_ntt_poly(seed)
    b = rej_ntt_poly(seed)
    assert a == b
    assert len(a) == N
    assert all(0 <= v < Q for v in a)


def test_rej_ntt_poly_different_seeds():
    assert rej_ntt_poly(b"a" * 34) != rej_ntt_poly(b"b" * 34)


def test_rej_bounded_poly_in_eta_range():
    seed = b"b" * 66
    p = rej_bounded_poly(seed)
    assert len(p) == N
    for v in p:
        signed = _signed(v)
        assert -ETA <= signed <= ETA


def test_rej_bounded_poly_deterministic():
    seed = b"x" * 66
    assert rej_bounded_poly(seed) == rej_bounded_poly(seed)


def test_rej_ntt_poly_rejects_wrong_seed_size():
    with pytest.raises(ValueError):
        rej_ntt_poly(b"\x00" * 33)


def test_rej_bounded_poly_rejects_wrong_seed_size():
    with pytest.raises(ValueError):
        rej_bounded_poly(b"\x00" * 65)


# ----- ExpandA / ExpandS / ExpandMask ---------------------------------------


def test_expand_a_dimensions():
    A = expand_a(b"\x00" * 32)
    assert len(A) == K
    assert all(len(row) == L for row in A)
    assert all(len(A[r][s]) == N for r in range(K) for s in range(L))


def test_expand_a_deterministic():
    rho = bytes(range(32))
    assert expand_a(rho) == expand_a(rho)


def test_expand_s_dimensions_and_range():
    s1, s2 = expand_s(b"\x11" * 64)
    assert len(s1) == L
    assert len(s2) == K
    for poly in s1 + s2:
        assert len(poly) == N
        assert all(-ETA <= _signed(v) <= ETA for v in poly)


def test_expand_mask_dimensions_and_range():
    y = expand_mask(b"\x22" * 64, mu=0)
    assert len(y) == L
    for poly in y:
        assert len(poly) == N
        for v in poly:
            signed = _signed(v)
            assert -(GAMMA_1 - 1) <= signed <= GAMMA_1


def test_expand_mask_mu_changes_output():
    rho = b"\x33" * 64
    assert expand_mask(rho, 0) != expand_mask(rho, 1)


# ----- SampleInBall ----------------------------------------------------------


def test_sample_in_ball_shape():
    c = sample_in_ball(b"\x44" * (LAMBDA // 4))
    assert len(c) == N
    nonzero = [v for v in c if v != 0]
    assert len(nonzero) == TAU
    # All nonzero entries are ±1 (with −1 ≡ q − 1).
    for v in nonzero:
        assert v == 1 or v == Q - 1


def test_sample_in_ball_deterministic():
    rho = bytes(range(LAMBDA // 4))
    assert sample_in_ball(rho) == sample_in_ball(rho)


def test_sample_in_ball_rejects_wrong_seed_size():
    with pytest.raises(ValueError):
        sample_in_ball(b"\x00" * (LAMBDA // 4 - 1))
