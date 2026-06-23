import hashlib

import pytest

from mlkem.hashes import G, H, J, XOF, prf


def test_H_matches_sha3_256():
    assert H(b"hello") == hashlib.sha3_256(b"hello").digest()
    assert len(H(b"")) == 32


def test_J_matches_shake256_32():
    assert J(b"hello") == hashlib.shake_256(b"hello").digest(32)
    assert len(J(b"x")) == 32


def test_G_splits_sha3_512():
    a, b = G(b"input")
    raw = hashlib.sha3_512(b"input").digest()
    assert a == raw[:32]
    assert b == raw[32:]
    assert len(a) == len(b) == 32


@pytest.mark.parametrize("eta", [2, 3])
def test_prf_length(eta):
    s = b"\x00" * 32
    out = prf(eta, s, b"\x05")
    assert len(out) == 64 * eta


def test_prf_rejects_wrong_sizes():
    with pytest.raises(ValueError):
        prf(2, b"\x00" * 31, b"\x00")
    with pytest.raises(ValueError):
        prf(2, b"\x00" * 32, b"\x00\x01")


def test_xof_read_matches_shake128_prefix():
    seed = b"the quick brown fox"
    xof = XOF(seed)
    out = xof.read(3) + xof.read(7) + xof.read(100) + xof.read(2000)
    expected = hashlib.shake_128(seed).digest(len(out))
    assert out == expected


def test_xof_grows_buffer_on_demand():
    seed = b"seed"
    xof = XOF(seed)
    # Force several growth rounds.
    chunks = b"".join(xof.read(1000) for _ in range(5))
    expected = hashlib.shake_128(seed).digest(5000)
    assert chunks == expected
