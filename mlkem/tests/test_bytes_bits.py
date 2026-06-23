import os

import pytest

from mlkem.bytes_bits import bits_to_bytes, bytes_to_bits


def test_bytes_to_bits_known():
    # byte 0xA5 = 10100101; bit order is little-endian within each byte (spec §4.2.1).
    assert bytes_to_bits(b"\xa5") == [1, 0, 1, 0, 0, 1, 0, 1]


def test_bits_to_bytes_known():
    assert bits_to_bytes([1, 0, 1, 0, 0, 1, 0, 1]) == b"\xa5"


@pytest.mark.parametrize("n", [0, 1, 8, 32, 1024])
def test_roundtrip(n):
    data = os.urandom(n)
    assert bits_to_bytes(bytes_to_bits(data)) == data


def test_bits_to_bytes_rejects_non_multiple_of_8():
    with pytest.raises(ValueError):
        bits_to_bytes([1, 0, 1])
