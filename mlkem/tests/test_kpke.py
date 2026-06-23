import hashlib
import os

import pytest

from mlkem.kpke import kpke_decrypt, kpke_encrypt, kpke_keygen
from mlkem.params import CT_SIZE, DK_PKE_SIZE, EK_PKE_SIZE


def _seed(label: bytes) -> bytes:
    return hashlib.sha3_256(label).digest()


def test_kpke_key_sizes_match_spec():
    d = _seed(b"kpke-keygen-1")
    ek, dk = kpke_keygen(d)
    assert len(ek) == EK_PKE_SIZE == 1184
    assert len(dk) == DK_PKE_SIZE == 1152


def test_kpke_keygen_is_deterministic():
    d = _seed(b"kpke-keygen-deterministic")
    ek1, dk1 = kpke_keygen(d)
    ek2, dk2 = kpke_keygen(d)
    assert ek1 == ek2
    assert dk1 == dk2


def test_kpke_keygen_different_seeds_different_keys():
    ek1, _ = kpke_keygen(_seed(b"a"))
    ek2, _ = kpke_keygen(_seed(b"b"))
    assert ek1 != ek2


def test_kpke_ciphertext_size():
    ek, _ = kpke_keygen(_seed(b"kpke-ct-size"))
    m = _seed(b"message-1")
    r = _seed(b"randomness-1")
    c = kpke_encrypt(ek, m, r)
    assert len(c) == CT_SIZE == 1088


def test_kpke_encrypt_is_deterministic_given_r():
    ek, _ = kpke_keygen(_seed(b"kpke-det-encrypt"))
    m = _seed(b"m")
    r = _seed(b"r")
    assert kpke_encrypt(ek, m, r) == kpke_encrypt(ek, m, r)


@pytest.mark.parametrize("label", [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"])
def test_kpke_roundtrip(label):
    d = _seed(b"kg-" + label)
    ek, dk = kpke_keygen(d)
    m = _seed(b"msg-" + label)
    r = _seed(b"rng-" + label)
    c = kpke_encrypt(ek, m, r)
    assert kpke_decrypt(dk, c) == m


def test_kpke_roundtrip_random_seeds():
    # A handful of independent random trials. ML-KEM-768 decryption failure
    # rate is ≈ 2^-138 so we will never see one here.
    for _ in range(10):
        ek, dk = kpke_keygen(os.urandom(32))
        m = os.urandom(32)
        r = os.urandom(32)
        assert kpke_decrypt(dk, kpke_encrypt(ek, m, r)) == m


def test_kpke_rejects_wrong_input_sizes():
    ek, dk = kpke_keygen(_seed(b"size-checks"))
    with pytest.raises(ValueError):
        kpke_encrypt(ek[:-1], b"\x00" * 32, b"\x00" * 32)
    with pytest.raises(ValueError):
        kpke_encrypt(ek, b"\x00" * 31, b"\x00" * 32)
    with pytest.raises(ValueError):
        kpke_encrypt(ek, b"\x00" * 32, b"\x00" * 31)
    with pytest.raises(ValueError):
        kpke_decrypt(dk[:-1], b"\x00" * CT_SIZE)
    with pytest.raises(ValueError):
        kpke_decrypt(dk, b"\x00" * (CT_SIZE - 1))
    with pytest.raises(ValueError):
        kpke_keygen(b"\x00" * 31)
