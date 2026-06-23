import os
import random

import pytest

from mldsa.encoding import (
    bit_pack,
    bit_unpack,
    hint_bit_pack,
    hint_bit_unpack,
    pk_decode,
    pk_encode,
    sig_decode,
    sig_encode,
    simple_bit_pack,
    simple_bit_unpack,
    sk_decode,
    sk_encode,
    w1_encode,
)
from mldsa.params import (
    BITLEN_T1,
    BITLEN_W1,
    D,
    DK_SIZE,
    EK_SIZE,
    ETA,
    GAMMA_1,
    K,
    L,
    LAMBDA,
    N,
    OMEGA,
    SIG_SIZE,
)


def _rng(seed):
    return random.Random(seed)


# ----- low-level bit-packers --------------------------------------------------


@pytest.mark.parametrize("b", [1, 7, 15, 1023, (1 << 13) - 1])
def test_simple_bit_pack_roundtrip(b):
    rng = _rng(b)
    poly = [rng.randint(0, b) for _ in range(N)]
    packed = simple_bit_pack(poly, b)
    assert len(packed) == 32 * b.bit_length()
    assert simple_bit_unpack(packed, b) == poly


@pytest.mark.parametrize("a,b", [(4, 4), (1, 0), (4095, 4096), (GAMMA_1 - 1, GAMMA_1)])
def test_bit_pack_roundtrip(a, b):
    rng = _rng((a << 4) | b)
    poly = [rng.randint(-a, b) for _ in range(N)]
    packed = bit_pack(poly, a, b)
    assert len(packed) == 32 * (a + b).bit_length()
    assert bit_unpack(packed, a, b) == poly


def test_simple_bit_pack_rejects_out_of_range():
    with pytest.raises(ValueError):
        simple_bit_pack([8] + [0] * (N - 1), 7)


def test_bit_pack_rejects_out_of_range():
    with pytest.raises(ValueError):
        bit_pack([ETA + 1] + [0] * (N - 1), ETA, ETA)


# ----- hint vector packer -----------------------------------------------------


def _random_hint(seed, weight):
    rng = _rng(seed)
    h = [[0] * N for _ in range(K)]
    positions = sorted(rng.sample(range(K * N), weight))
    for p in positions:
        h[p // N][p % N] = 1
    return h


@pytest.mark.parametrize("weight", [0, 1, 17, OMEGA])
def test_hint_pack_roundtrip(weight):
    h = _random_hint(weight, weight)
    packed = hint_bit_pack(h)
    assert len(packed) == OMEGA + K
    assert hint_bit_unpack(packed) == h


def test_hint_pack_rejects_over_weight():
    h = _random_hint(0, OMEGA + 1)
    with pytest.raises(ValueError):
        hint_bit_pack(h)


def test_hint_unpack_rejects_bad_length():
    assert hint_bit_unpack(b"\x00" * (OMEGA + K - 1)) is None


def test_hint_unpack_rejects_nonmonotonic_counts():
    # Tampered: cumulative count goes down between rows.
    h = _random_hint(0, 4)
    packed = bytearray(hint_bit_pack(h))
    # Swap the per-row counts so they decrease.
    packed[OMEGA], packed[OMEGA + 1] = packed[OMEGA + 1], packed[OMEGA]
    # ...actually that may still be monotonic; force decrease.
    packed[OMEGA + 1] = 0
    packed[OMEGA] = 4
    assert hint_bit_unpack(bytes(packed)) is None


def test_hint_unpack_rejects_nonzero_trailing_bytes():
    h = _random_hint(1, 2)
    packed = bytearray(hint_bit_pack(h))
    # Insert garbage into a trailing position that should be zero.
    last_used = packed[OMEGA + K - 1]
    if last_used < OMEGA:
        packed[last_used] = 17
        assert hint_bit_unpack(bytes(packed)) is None


# ----- high-level encoders ----------------------------------------------------


def _rand_poly(rng, lo, hi):
    return [rng.randint(lo, hi) for _ in range(N)]


def test_pk_roundtrip():
    rng = _rng(1)
    rho = os.urandom(32)
    bound = (1 << BITLEN_T1) - 1
    t1 = [_rand_poly(rng, 0, bound) for _ in range(K)]
    pk = pk_encode(rho, t1)
    assert len(pk) == EK_SIZE == 1952
    rho2, t1_2 = pk_decode(pk)
    assert rho2 == rho
    assert t1_2 == t1


def test_sk_roundtrip():
    rng = _rng(2)
    rho = os.urandom(32)
    K_seed = os.urandom(32)
    tr = os.urandom(64)
    s1 = [_rand_poly(rng, -ETA, ETA) for _ in range(L)]
    s2 = [_rand_poly(rng, -ETA, ETA) for _ in range(K)]
    half = 1 << (D - 1)
    t0 = [_rand_poly(rng, -(half - 1), half) for _ in range(K)]
    sk = sk_encode(rho, K_seed, tr, s1, s2, t0)
    assert len(sk) == DK_SIZE == 4032
    rho2, K2, tr2, s1_2, s2_2, t0_2 = sk_decode(sk)
    assert (rho2, K2, tr2) == (rho, K_seed, tr)
    assert s1_2 == s1
    assert s2_2 == s2
    assert t0_2 == t0


def test_sig_roundtrip():
    rng = _rng(3)
    c_tilde = os.urandom(LAMBDA // 4)
    z = [_rand_poly(rng, -(GAMMA_1 - 1), GAMMA_1) for _ in range(L)]
    h = _random_hint(4, 17)
    sig = sig_encode(c_tilde, z, h)
    assert len(sig) == SIG_SIZE == 3309
    c2, z2, h2 = sig_decode(sig)
    assert c2 == c_tilde
    assert z2 == z
    assert h2 == h


def test_w1_encode_size():
    rng = _rng(5)
    bound = (1 << BITLEN_W1) - 1
    w1 = [_rand_poly(rng, 0, bound) for _ in range(K)]
    out = w1_encode(w1)
    assert len(out) == 32 * BITLEN_W1 * K
