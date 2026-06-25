import hashlib
import os

import pytest

from mldsa import hash_sign, hash_verify, keygen, sign, verify
from mldsa.mldsa import _keygen_internal, _PREHASH_FUNCTIONS
from mldsa.params import DK_SIZE, EK_SIZE, SIG_SIZE


def _seed(label):
    return hashlib.shake_256(label).digest(32)


# ----- ML-DSA public API ----------------------------------------------------


def test_keygen_random_sizes_and_freshness():
    pk1, sk1 = keygen()
    pk2, sk2 = keygen()
    assert len(pk1) == EK_SIZE and len(sk1) == DK_SIZE
    assert pk1 != pk2
    assert sk1 != sk2


@pytest.mark.parametrize("ctx", [b"", b"app=mail", b"\x00\x01\x02", b"x" * 255])
def test_sign_verify_roundtrip(ctx):
    pk, sk = _keygen_internal(_seed(b"ctx-roundtrip-" + ctx))
    M = b"the message"
    sig = sign(sk, M, ctx, deterministic=True)
    assert len(sig) == SIG_SIZE
    assert verify(pk, M, sig, ctx) is True


def test_verify_rejects_wrong_ctx():
    pk, sk = _keygen_internal(_seed(b"wrong-ctx"))
    M = b"message"
    sig = sign(sk, M, b"ctx-A", deterministic=True)
    assert verify(pk, M, sig, b"ctx-B") is False


def test_ctx_too_long_sign_raises_verify_returns_false():
    pk, sk = _keygen_internal(_seed(b"toolong"))
    M = b"m"
    with pytest.raises(ValueError):
        sign(sk, M, b"x" * 256, deterministic=True)
    # Verify silently returns False for over-length ctx instead of raising.
    sig = sign(sk, M, b"", deterministic=True)
    assert verify(pk, M, sig, b"x" * 256) is False


def test_deterministic_vs_hedged():
    pk, sk = _keygen_internal(_seed(b"det-vs-hedged"))
    M = b"msg"
    a = sign(sk, M, deterministic=True)
    b = sign(sk, M, deterministic=True)
    assert a == b  # deterministic mode is reproducible
    c = sign(sk, M)  # hedged
    d = sign(sk, M)
    assert c != d  # randomized — different each call
    assert a != c  # and different from deterministic
    for s in (a, b, c, d):
        assert verify(pk, M, s) is True


# ----- HashML-DSA -----------------------------------------------------------


@pytest.mark.parametrize("hash_alg", list(_PREHASH_FUNCTIONS.keys()))
def test_hash_sign_verify_roundtrip(hash_alg):
    pk, sk = _keygen_internal(_seed(b"hash-rt-" + hash_alg.encode()))
    M = b"document to be pre-hashed"
    sig = hash_sign(sk, M, hash_alg=hash_alg, deterministic=True)
    assert hash_verify(pk, M, sig, hash_alg=hash_alg) is True


def test_hashml_dsa_domain_separates_from_plain():
    # The 0x00 vs 0x01 domain separator means plain and hash variants
    # must produce different signatures and not cross-verify.
    pk, sk = _keygen_internal(_seed(b"domain-sep"))
    M = b"m"
    sig_plain = sign(sk, M, deterministic=True)
    sig_hash = hash_sign(sk, M, hash_alg="SHA-256", deterministic=True)
    assert sig_plain != sig_hash
    assert verify(pk, M, sig_hash) is False
    assert hash_verify(pk, M, sig_plain, hash_alg="SHA-256") is False


def test_hash_verify_rejects_wrong_hash_alg():
    pk, sk = _keygen_internal(_seed(b"wrong-hash"))
    M = b"m"
    sig = hash_sign(sk, M, hash_alg="SHA-256", deterministic=True)
    assert hash_verify(pk, M, sig, hash_alg="SHA-512") is False


def test_hash_sign_rejects_unknown_hash_alg():
    _, sk = _keygen_internal(_seed(b"unknown"))
    with pytest.raises(ValueError, match="unsupported"):
        hash_sign(sk, b"m", hash_alg="MD5", deterministic=True)


def test_hash_verify_returns_false_on_unknown_hash_alg():
    pk, sk = _keygen_internal(_seed(b"unknown-v"))
    sig = sign(sk, b"m", deterministic=True)
    assert hash_verify(pk, b"m", sig, hash_alg="MD5") is False


# ----- Random end-to-end ------------------------------------------------------


def test_random_keys_and_messages():
    for _ in range(5):
        pk, sk = keygen()
        M = os.urandom(80)
        ctx = os.urandom(20)
        assert verify(pk, M, sign(sk, M, ctx), ctx) is True
