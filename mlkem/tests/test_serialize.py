import random

import pytest

from mlkem.params import N, Q
from mlkem.serialize import byte_decode, byte_encode, compress, decompress


@pytest.mark.parametrize("d", [1, 4, 10, 12])
def test_byte_encode_decode_roundtrip(d):
    rng = random.Random(d * 1000 + 7)
    m = (1 << d) if d < 12 else Q
    f = [rng.randrange(m) for _ in range(N)]
    encoded = byte_encode(d, f)
    assert len(encoded) == 32 * d
    assert byte_decode(d, encoded) == f


@pytest.mark.parametrize("d", [1, 4, 10, 11])
def test_compress_decompress_recovers_small_value(d):
    # FIPS 203 §4.2.1: Compress_d(Decompress_d(y)) == y for y in [0, 2^d).
    for y in range(1 << d):
        assert compress(d, decompress(d, y)) == y


def test_compress_decompress_is_lossy_but_bounded():
    # |Decompress_d(Compress_d(x)) - x| <= round(q / 2^(d+1)) per spec §4.2.1.
    d = 10
    bound = (Q + (1 << (d + 1)) - 1) // (1 << (d + 1)) + 1
    for x in range(Q):
        recovered = decompress(d, compress(d, x))
        diff = min((recovered - x) % Q, (x - recovered) % Q)
        assert diff <= bound


def test_byte_decode_d12_reduces_modulo_q():
    # FIPS 203 §4.2.1 note: ByteDecode_12 may receive 12-bit fields with values
    # in [q, 2^12), which must be reduced mod q.
    from mlkem.bytes_bits import bits_to_bytes

    bits = [0] * (N * 12)
    for j in range(12):
        bits[j] = 1  # first 12-bit field = 0xFFF = 4095
    raw = bits_to_bytes(bits)
    decoded = byte_decode(12, raw)
    assert decoded[0] == 4095 % Q
    assert all(v == 0 for v in decoded[1:])


def test_byte_encode_d_lt_12_modular_reduction():
    # For d < 12 the encoder reduces inputs modulo 2^d (spec Algorithm 5).
    d = 4
    m = 1 << d
    f = [m + i for i in range(N)]  # exceeds modulus
    encoded = byte_encode(d, f)
    decoded = byte_decode(d, encoded)
    assert decoded == [(m + i) % m for i in range(N)]
