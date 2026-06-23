import hashlib
import os

import pytest

from mlkem import decaps, encaps, keygen
from mlkem.hashes import H, J
from mlkem.mlkem import (
    _decaps_internal,
    _encaps_internal,
    _keygen_internal,
)
from mlkem.params import CT_SIZE, DK_SIZE, EK_SIZE, K, SS_SIZE


def _seed(label: bytes) -> bytes:
    return hashlib.sha3_256(label).digest()


def test_keygen_sizes_match_spec():
    ek, dk = keygen()
    assert len(ek) == EK_SIZE == 1184
    assert len(dk) == DK_SIZE == 2400


def test_encaps_outputs():
    ek, _ = keygen()
    K_ss, c = encaps(ek)
    assert len(K_ss) == SS_SIZE == 32
    assert len(c) == CT_SIZE == 1088


def test_roundtrip_random():
    for _ in range(20):
        ek, dk = keygen()
        K_ss, c = encaps(ek)
        assert decaps(dk, c) == K_ss


def test_keygen_internal_is_deterministic():
    d = _seed(b"d-seed")
    z = _seed(b"z-seed")
    ek1, dk1 = _keygen_internal(d, z)
    ek2, dk2 = _keygen_internal(d, z)
    assert ek1 == ek2
    assert dk1 == dk2


def test_encaps_internal_is_deterministic():
    ek, _ = _keygen_internal(_seed(b"d"), _seed(b"z"))
    m = _seed(b"m")
    K1, c1 = _encaps_internal(ek, m)
    K2, c2 = _encaps_internal(ek, m)
    assert (K1, c1) == (K2, c2)


def test_dk_layout_contains_ek_and_hash():
    # FIPS 203 §6: dk = dk_pke ‖ ek ‖ H(ek) ‖ z.
    ek, dk = _keygen_internal(_seed(b"layout-d"), _seed(b"layout-z"))
    assert dk[384 * K : 768 * K + 32] == ek
    assert dk[768 * K + 32 : 768 * K + 64] == H(ek)
    assert dk[768 * K + 64 :] == _seed(b"layout-z")


def test_implicit_rejection_on_tampered_ciphertext():
    ek, dk = keygen()
    K_good, c = encaps(ek)
    # Flip one byte in the middle of the ciphertext.
    c_bad = bytearray(c)
    c_bad[len(c_bad) // 2] ^= 0x01
    c_bad = bytes(c_bad)

    K_rejected = decaps(dk, c_bad)
    z = dk[-32:]
    assert K_rejected == J(z + c_bad)
    assert K_rejected != K_good
    # Critically: decaps does NOT raise on a tampered (but well-formed) ciphertext.


def test_decaps_internal_returns_J_z_c_for_random_ct():
    # A purely random ciphertext is overwhelmingly unlikely to re-encrypt to
    # itself, so decaps_internal must return the implicit-rejection branch.
    ek, dk = keygen()
    bogus = os.urandom(CT_SIZE)
    out = _decaps_internal(dk, bogus)
    z = dk[-32:]
    assert out == J(z + bogus)


def test_encaps_rejects_wrong_ek_size():
    ek, _ = keygen()
    with pytest.raises(ValueError):
        encaps(ek[:-1])
    with pytest.raises(ValueError):
        encaps(ek + b"\x00")


def test_encaps_rejects_invalid_modulus_in_ek():
    # Replace the first 12-bit field with 0xFFF (=4095, ≥ q) and confirm the
    # §7.2 modulus check rejects it.
    ek, _ = keygen()
    tampered = bytearray(ek)
    # Bits 0..11 of ek correspond to bytes 0 and 1: first byte's 8 bits +
    # low 4 bits of second byte. Setting both to 0xFF gives 12-bit value 0xFFF.
    tampered[0] = 0xFF
    tampered[1] = (tampered[1] & 0xF0) | 0x0F
    with pytest.raises(ValueError, match="modulus check"):
        encaps(bytes(tampered))


def test_decaps_rejects_wrong_ct_size():
    _, dk = keygen()
    with pytest.raises(ValueError, match="ciphertext"):
        decaps(dk, b"\x00" * (CT_SIZE - 1))


def test_decaps_rejects_wrong_dk_size():
    ek, dk = keygen()
    _, c = encaps(ek)
    with pytest.raises(ValueError, match="dk"):
        decaps(dk[:-1], c)


def test_decaps_rejects_tampered_dk_hash():
    ek, dk = keygen()
    _, c = encaps(ek)
    bad = bytearray(dk)
    # Flip one byte inside the H(ek) field of dk.
    bad[768 * K + 32] ^= 0x01
    with pytest.raises(ValueError, match="hash check"):
        decaps(bytes(bad), c)


def test_kat_replay_via_internal_apis():
    # End-to-end determinism using only internal variants (the shape KAT
    # vectors in Phase 5 will use).
    d = _seed(b"kat-d")
    z = _seed(b"kat-z")
    m = _seed(b"kat-m")
    ek, dk = _keygen_internal(d, z)
    K_enc, c = _encaps_internal(ek, m)
    K_dec = _decaps_internal(dk, c)
    assert K_enc == K_dec
