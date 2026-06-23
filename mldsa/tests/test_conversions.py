import pytest

from mldsa.conversions import bits_to_integer, integer_to_bits, integer_to_bytes


@pytest.mark.parametrize("alpha", [1, 4, 8, 13, 20, 23])
def test_integer_to_bits_roundtrip(alpha):
    for x in (0, 1, (1 << alpha) - 1, ((1 << alpha) - 1) // 3):
        bits = integer_to_bits(x, alpha)
        assert len(bits) == alpha
        assert all(b in (0, 1) for b in bits)
        assert bits_to_integer(bits, alpha) == x


def test_integer_to_bits_lsb_first():
    # 5 = 0b101 → LSB-first bits = [1, 0, 1, 0]
    assert integer_to_bits(5, 4) == [1, 0, 1, 0]


@pytest.mark.parametrize("alpha,x,expected", [
    (1, 0xAB, b"\xab"),
    (2, 0x1234, b"\x34\x12"),
    (4, 0xDEADBEEF, b"\xef\xbe\xad\xde"),
])
def test_integer_to_bytes(alpha, x, expected):
    assert integer_to_bytes(x, alpha) == expected
