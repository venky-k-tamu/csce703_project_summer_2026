import statistics

import pytest

from mlkem.params import N, Q
from mlkem.sampling import sample_ntt, sample_poly_cbd


def _signed(x):
    return x - Q if x > Q // 2 else x


def test_sample_ntt_is_deterministic_and_in_range():
    seed = b"some-32-byte-seed-for-sampling!!" + b"\x00\x01"
    out1 = sample_ntt(seed)
    out2 = sample_ntt(seed)
    assert out1 == out2
    assert len(out1) == N
    assert all(0 <= v < Q for v in out1)


def test_sample_ntt_distinct_seeds_distinct_outputs():
    assert sample_ntt(b"a" * 34) != sample_ntt(b"b" * 34)


def test_sample_poly_cbd_eta2_range():
    # With η=2, the CBD output (as a signed integer) lies in {-2,-1,0,1,2}.
    out = sample_poly_cbd(2, b"\xaa" * (64 * 2))
    assert len(out) == N
    signed = [_signed(v) for v in out]
    assert all(-2 <= v <= 2 for v in signed)


def test_sample_poly_cbd_eta3_range():
    out = sample_poly_cbd(3, b"\x55" * (64 * 3))
    assert len(out) == N
    signed = [_signed(v) for v in out]
    assert all(-3 <= v <= 3 for v in signed)


def test_sample_poly_cbd_all_zero_bits_is_zero_poly():
    assert sample_poly_cbd(2, b"\x00" * 128) == [0] * N


def test_sample_poly_cbd_all_one_bits_is_zero_poly():
    # Every bit set means each (x, y) pair has x = y = η, so x - y = 0.
    assert sample_poly_cbd(2, b"\xff" * 128) == [0] * N
    assert sample_poly_cbd(3, b"\xff" * 192) == [0] * N


def test_sample_poly_cbd_rejects_wrong_size():
    with pytest.raises(ValueError):
        sample_poly_cbd(2, b"\x00" * 127)
    with pytest.raises(ValueError):
        sample_poly_cbd(4, b"\x00" * 256)


def test_sample_poly_cbd_distribution_sanity():
    # Pull many samples from distinct PRF outputs and check mean ≈ 0, var ≈ η/2.
    import hashlib

    samples = []
    for k in range(40):
        B = hashlib.shake_256(bytes([k])).digest(64 * 2)
        samples.extend(_signed(v) for v in sample_poly_cbd(2, B))
    mean = statistics.mean(samples)
    var = statistics.pvariance(samples)
    # 40 · 256 = 10240 samples; loose bounds.
    assert abs(mean) < 0.05
    assert abs(var - 1.0) < 0.1  # η=2 → variance η/2 = 1
