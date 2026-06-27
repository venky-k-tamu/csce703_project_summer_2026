"""Public API and HashSLH-DSA tests for SLH-DSA-SHAKE-128s (FIPS 205 §9–§10)."""

import hashlib
import os

import pytest

from slhdsa import hash_sign, hash_verify, keygen, sign, verify
from slhdsa.slhdsa import _keygen_internal, _PREHASH_FUNCTIONS
from slhdsa.params import PK_SIZE, SK_SIZE, SIG_SIZE


def _seed(tag: bytes, n: int = 16) -> bytes:
    return hashlib.shake_256(tag).digest(n)


def _det_keygen(label: bytes):
    return _keygen_internal(_seed(b"sk-" + label), _seed(b"prf-" + label), _seed(b"pk-" + label))


# ---------------------------------------------------------------------------
# SLH-DSA public API
# ---------------------------------------------------------------------------


def test_keygen_random_sizes_and_freshness():
    pk1, sk1 = keygen()
    pk2, sk2 = keygen()
    assert len(pk1) == PK_SIZE and len(sk1) == SK_SIZE
    assert pk1 != pk2
    assert sk1 != sk2


@pytest.mark.parametrize("ctx", [b"", b"app=mail", b"\x00\x01\x02", b"x" * 255])
def test_sign_verify_roundtrip(ctx):
    pk, sk = _det_keygen(b"ctx-roundtrip-" + ctx)
    m = b"the message"
    sig = sign(m, sk, ctx, randomize=False)
    assert len(sig) == SIG_SIZE
    assert verify(m, sig, pk, ctx) is True


def test_verify_rejects_wrong_ctx():
    pk, sk = _det_keygen(b"wrong-ctx")
    m = b"message"
    sig = sign(m, sk, b"ctx-A", randomize=False)
    assert verify(m, sig, pk, b"ctx-B") is False


def test_ctx_too_long_sign_raises_verify_returns_false():
    pk, sk = _det_keygen(b"toolong")
    m = b"m"
    with pytest.raises(ValueError):
        sign(m, sk, b"x" * 256, randomize=False)
    sig = sign(m, sk, b"", randomize=False)
    assert verify(m, sig, pk, b"x" * 256) is False


def test_deterministic_vs_hedged():
    pk, sk = _det_keygen(b"det-vs-hedged")
    m = b"msg"
    a = sign(m, sk, randomize=False)
    b = sign(m, sk, randomize=False)
    assert a == b
    c = sign(m, sk)
    d = sign(m, sk)
    assert c != d
    assert a != c
    for s in (a, b, c, d):
        assert verify(m, s, pk) is True


# ---------------------------------------------------------------------------
# HashSLH-DSA (FIPS 205 §10, Algorithms 23–24)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("hash_alg", list(_PREHASH_FUNCTIONS.keys()))
def test_hash_sign_verify_roundtrip(hash_alg):
    pk, sk = _det_keygen(b"hash-rt-" + hash_alg.encode())
    m = b"document to be pre-hashed"
    sig = hash_sign(m, sk, hash_alg=hash_alg, randomize=False)
    assert hash_verify(m, sig, pk, hash_alg=hash_alg) is True


def test_hashslhdsa_domain_separates_from_plain():
    pk, sk = _det_keygen(b"domain-sep")
    m = b"m"
    sig_plain = sign(m, sk, randomize=False)
    sig_hash  = hash_sign(m, sk, hash_alg="SHA2-256", randomize=False)
    assert sig_plain != sig_hash
    assert verify(m, sig_hash, pk) is False
    assert hash_verify(m, sig_plain, pk, hash_alg="SHA2-256") is False


def test_hash_verify_rejects_wrong_hash_alg():
    pk, sk = _det_keygen(b"wrong-hash")
    m = b"m"
    sig = hash_sign(m, sk, hash_alg="SHA2-256", randomize=False)
    assert hash_verify(m, sig, pk, hash_alg="SHA2-512") is False


def test_hash_sign_rejects_unknown_hash_alg():
    _, sk = _det_keygen(b"unknown")
    with pytest.raises(ValueError, match="unsupported"):
        hash_sign(b"m", sk, hash_alg="MD5")


def test_hash_verify_returns_false_on_unknown_hash_alg():
    pk, sk = _det_keygen(b"unknown-v")
    sig = sign(b"m", sk, randomize=False)
    assert hash_verify(b"m", sig, pk, hash_alg="MD5") is False


def test_hash_sign_ctx_too_long_raises_verify_returns_false():
    pk, sk = _det_keygen(b"hash-toolong")
    m = b"m"
    with pytest.raises(ValueError):
        hash_sign(m, sk, b"x" * 256, randomize=False)
    sig = hash_sign(m, sk, b"", randomize=False)
    assert hash_verify(m, sig, pk, b"x" * 256) is False


# ---------------------------------------------------------------------------
# Random end-to-end
# ---------------------------------------------------------------------------


def test_random_keys_and_messages():
    for _ in range(3):
        pk, sk = keygen()
        m = os.urandom(80)
        ctx = os.urandom(20)
        assert verify(m, sign(m, sk, ctx), pk, ctx) is True
