import hashlib

import pytest

from mldsa.hashes import G, H, XOF128, XOF256


def test_H_matches_shake256():
    assert H(b"abc", 64) == hashlib.shake_256(b"abc").digest(64)


def test_G_matches_shake128():
    assert G(b"abc", 100) == hashlib.shake_128(b"abc").digest(100)


@pytest.mark.parametrize("xof_cls,shake", [(XOF128, hashlib.shake_128), (XOF256, hashlib.shake_256)])
def test_xof_prefix_consistent(xof_cls, shake):
    seed = b"the quick brown fox jumps over the lazy dog"
    xof = xof_cls(seed)
    out = xof.read(7) + xof.read(13) + xof.read(101) + xof.read(2300)
    assert out == shake(seed).digest(len(out))


def test_xof_grows_buffer():
    seed = b"seed"
    xof = XOF128(seed)
    chunks = b"".join(xof.read(1000) for _ in range(5))
    assert chunks == hashlib.shake_128(seed).digest(5000)
