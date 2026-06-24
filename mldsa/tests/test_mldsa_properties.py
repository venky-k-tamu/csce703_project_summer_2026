import hashlib
import os

import pytest

from mldsa.mldsa import _keygen_internal, _sign_internal, _verify_internal
from mldsa.params import DK_SIZE, EK_SIZE, SIG_SIZE


def _seed(label: bytes, n: int = 32) -> bytes:
    return hashlib.shake_256(label).digest(n)


# ----- KeyGen ----------------------------------------------------------------


def test_keygen_sizes():
    pk, sk = _keygen_internal(_seed(b"kg-1"))
    assert len(pk) == EK_SIZE == 1952
    assert len(sk) == DK_SIZE == 4032


def test_keygen_deterministic():
    xi = _seed(b"kg-det")
    assert _keygen_internal(xi) == _keygen_internal(xi)


def test_keygen_distinct_seeds_distinct_keys():
    pk1, _ = _keygen_internal(_seed(b"a"))
    pk2, _ = _keygen_internal(_seed(b"b"))
    assert pk1 != pk2


# ----- Sign ------------------------------------------------------------------


def test_sign_size_and_determinism():
    _, sk = _keygen_internal(_seed(b"sign-det"))
    M = b"hello world"
    rnd = b"\x00" * 32
    sig1 = _sign_internal(sk, M, rnd)
    sig2 = _sign_internal(sk, M, rnd)
    assert sig1 == sig2
    assert len(sig1) == SIG_SIZE == 3309


def test_sign_rnd_changes_output_when_hedged():
    _, sk = _keygen_internal(_seed(b"sign-rnd"))
    M = b"msg"
    sig0 = _sign_internal(sk, M, b"\x00" * 32)
    sig1 = _sign_internal(sk, M, b"\x11" * 32)
    assert sig0 != sig1


# ----- Verify ----------------------------------------------------------------


@pytest.mark.parametrize("label", [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"])
def test_sign_verify_roundtrip(label):
    pk, sk = _keygen_internal(_seed(b"rt-" + label))
    M = b"the quick brown fox: " + label
    rnd = _seed(b"rnd-" + label)
    sig = _sign_internal(sk, M, rnd)
    assert _verify_internal(pk, M, sig)


def test_verify_random_seeds():
    for _ in range(5):
        pk, sk = _keygen_internal(os.urandom(32))
        M = os.urandom(100)
        sig = _sign_internal(sk, M, os.urandom(32))
        assert _verify_internal(pk, M, sig)


def test_verify_rejects_tampered_message():
    pk, sk = _keygen_internal(_seed(b"tamper-msg"))
    M = b"original message"
    sig = _sign_internal(sk, M, _seed(b"rnd"))
    assert _verify_internal(pk, b"original messagX", sig) is False


def test_verify_rejects_tampered_signature():
    pk, sk = _keygen_internal(_seed(b"tamper-sig"))
    M = b"msg"
    sig = bytearray(_sign_internal(sk, M, _seed(b"rnd")))
    sig[100] ^= 0x01  # flip a bit in the z section
    assert _verify_internal(pk, M, bytes(sig)) is False


def test_verify_rejects_wrong_pk():
    pk1, sk1 = _keygen_internal(_seed(b"pk-1"))
    pk2, _ = _keygen_internal(_seed(b"pk-2"))
    M = b"msg"
    sig = _sign_internal(sk1, M, _seed(b"rnd"))
    assert _verify_internal(pk1, M, sig) is True
    assert _verify_internal(pk2, M, sig) is False


def test_verify_rejects_wrong_sized_inputs():
    pk, sk = _keygen_internal(_seed(b"size"))
    sig = _sign_internal(sk, b"m", b"\x00" * 32)
    assert _verify_internal(pk[:-1], b"m", sig) is False
    assert _verify_internal(pk, b"m", sig[:-1]) is False
