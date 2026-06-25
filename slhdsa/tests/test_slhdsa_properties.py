"""Property and integration tests for SLH-DSA-SHAKE-128s (slhdsa/slhdsa.py)."""

import hashlib
import os

import pytest

from slhdsa.params import PK_SIZE, SIG_SIZE, SK_SIZE
from slhdsa.slhdsa import _keygen_internal, _sign_internal, _verify_internal, keygen, sign, verify


def _seed(tag: bytes, n: int = 16) -> bytes:
    return hashlib.shake_256(tag).digest(n)


# ---------------------------------------------------------------------------
# KeyGen
# ---------------------------------------------------------------------------


def test_keygen_sizes():
    pk, sk = _keygen_internal(_seed(b"sk"), _seed(b"prf"), _seed(b"pkseed"))
    assert len(pk) == PK_SIZE == 32
    assert len(sk) == SK_SIZE == 64


def test_keygen_deterministic():
    args = (_seed(b"sk-d"), _seed(b"prf-d"), _seed(b"pkseed-d"))
    assert _keygen_internal(*args) == _keygen_internal(*args)


def test_keygen_distinct_seeds_give_distinct_keys():
    pk1, _ = _keygen_internal(_seed(b"s1"), _seed(b"s1"), _seed(b"s1"))
    pk2, _ = _keygen_internal(_seed(b"s2"), _seed(b"s2"), _seed(b"s2"))
    assert pk1 != pk2


def test_keygen_public_api_sizes():
    pk, sk = keygen()
    assert len(pk) == PK_SIZE
    assert len(sk) == SK_SIZE


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------


def test_sign_size():
    pk, sk = _keygen_internal(_seed(b"sk-sz"), _seed(b"prf-sz"), _seed(b"pkseed-sz"))
    opt_rand = _seed(b"rnd-sz")
    m_prime = b"\x00\x00" + b"hello"
    sig = _sign_internal(m_prime, sk, opt_rand)
    assert len(sig) == SIG_SIZE == 7856


def test_sign_deterministic_with_fixed_opt_rand():
    pk, sk = _keygen_internal(_seed(b"sk-det"), _seed(b"prf-det"), _seed(b"pkseed-det"))
    opt_rand = _seed(b"r-det")
    m_prime = b"\x00\x00" + b"msg"
    assert _sign_internal(m_prime, sk, opt_rand) == _sign_internal(m_prime, sk, opt_rand)


def test_sign_randomized_differs():
    pk, sk = _keygen_internal(_seed(b"sk-rand"), _seed(b"prf-rand"), _seed(b"pkseed-rand"))
    m_prime = b"\x00\x00" + b"msg"
    sig1 = _sign_internal(m_prime, sk, os.urandom(16))
    sig2 = _sign_internal(m_prime, sk, os.urandom(16))
    # Different opt_rand → different R → different signature (with overwhelming probability)
    assert sig1 != sig2


# ---------------------------------------------------------------------------
# Sign + Verify round-trips
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label", [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"])
def test_sign_verify_roundtrip_deterministic(label):
    pk, sk = _keygen_internal(_seed(b"sk-" + label), _seed(b"prf-" + label), _seed(b"pk-" + label))
    opt_rand = _seed(b"r-" + label)
    m_prime = b"\x00\x00" + label
    sig = _sign_internal(m_prime, sk, opt_rand)
    assert _verify_internal(m_prime, sig, pk)


def test_sign_verify_roundtrip_public_api():
    pk, sk = keygen()
    m = b"the quick brown fox"
    sig = sign(m, sk, randomize=False)
    assert verify(m, sig, pk)


def test_sign_verify_with_context():
    pk, sk = keygen()
    m = b"message"
    ctx = b"my-context"
    sig = sign(m, sk, ctx=ctx, randomize=False)
    assert verify(m, sig, pk, ctx=ctx)
    assert not verify(m, sig, pk, ctx=b"wrong-ctx")


def test_sign_verify_multiple_random():
    for _ in range(3):
        pk, sk = keygen()
        m = os.urandom(100)
        sig = sign(m, sk)
        assert verify(m, sig, pk)


# ---------------------------------------------------------------------------
# Rejection cases
# ---------------------------------------------------------------------------


def test_verify_rejects_tampered_message():
    pk, sk = _keygen_internal(_seed(b"sk-tm"), _seed(b"prf-tm"), _seed(b"pk-tm"))
    m_prime = b"\x00\x00original"
    sig = _sign_internal(m_prime, sk, _seed(b"r-tm"))
    assert _verify_internal(b"\x00\x00tampered", sig, pk) is False


def test_verify_rejects_tampered_signature():
    pk, sk = _keygen_internal(_seed(b"sk-ts"), _seed(b"prf-ts"), _seed(b"pk-ts"))
    m_prime = b"\x00\x00msg"
    sig = bytearray(_sign_internal(m_prime, sk, _seed(b"r-ts")))
    sig[100] ^= 0xFF
    assert _verify_internal(m_prime, bytes(sig), pk) is False


def test_verify_rejects_wrong_pk():
    pk1, sk1 = _keygen_internal(_seed(b"sk1"), _seed(b"prf1"), _seed(b"pkseed1"))
    pk2, _   = _keygen_internal(_seed(b"sk2"), _seed(b"prf2"), _seed(b"pkseed2"))
    m_prime  = b"\x00\x00msg"
    sig = _sign_internal(m_prime, sk1, _seed(b"r"))
    assert _verify_internal(m_prime, sig, pk1) is True
    assert _verify_internal(m_prime, sig, pk2) is False


def test_verify_rejects_wrong_size_inputs():
    pk, sk = _keygen_internal(_seed(b"sk-ws"), _seed(b"prf-ws"), _seed(b"pk-ws"))
    m_prime = b"\x00\x00msg"
    sig = _sign_internal(m_prime, sk, _seed(b"r-ws"))
    assert _verify_internal(m_prime, sig[:-1], pk) is False
    assert _verify_internal(m_prime, sig, pk[:-1]) is False


def test_verify_rejects_context_mismatch():
    pk, sk = keygen()
    m = b"msg"
    sig = sign(m, sk, ctx=b"ctx-a", randomize=False)
    assert verify(m, sig, pk, ctx=b"ctx-a") is True
    assert verify(m, sig, pk, ctx=b"ctx-b") is False
    assert verify(m, sig, pk) is False
