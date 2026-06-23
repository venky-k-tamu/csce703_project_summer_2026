"""ML-KEM KeyGen / Encaps / Decaps per FIPS 203 §6, with §7 input checks.

Public API: keygen(), encaps(ek), decaps(dk, c).
Internal deterministic variants are exposed for testing and KAT replay.
"""

import secrets

from .hashes import G, H, J
from .kpke import _vec_byte_decode, kpke_decrypt, kpke_encrypt, kpke_keygen
from .params import CT_SIZE, DK_SIZE, EK_SIZE, K
from .serialize import byte_encode


def _keygen_internal(d: bytes, z: bytes):
    """Algorithm 16: ML-KEM.KeyGen_internal(d, z)."""
    if len(d) != 32 or len(z) != 32:
        raise ValueError("d and z must each be 32 bytes")
    ek_pke, dk_pke = kpke_keygen(d)
    ek = ek_pke
    dk = dk_pke + ek + H(ek) + z
    assert len(ek) == EK_SIZE
    assert len(dk) == DK_SIZE
    return ek, dk


def _encaps_internal(ek: bytes, m: bytes):
    """Algorithm 17: ML-KEM.Encaps_internal(ek, m)."""
    if len(m) != 32:
        raise ValueError("m must be 32 bytes")
    K_ss, r = G(m + H(ek))
    c = kpke_encrypt(ek, m, r)
    return K_ss, c


def _decaps_internal(dk: bytes, c: bytes) -> bytes:
    """Algorithm 18: ML-KEM.Decaps_internal(dk, c).

    Returns the shared secret on success; on ciphertext mismatch returns the
    implicit-rejection key J(z ‖ c) — not an exception.
    """
    dk_pke = dk[: 384 * K]
    ek = dk[384 * K : 768 * K + 32]
    h = dk[768 * K + 32 : 768 * K + 64]
    z = dk[768 * K + 64 : 768 * K + 96]

    m_prime = kpke_decrypt(dk_pke, c)
    K_prime, r_prime = G(m_prime + h)
    K_bar = J(z + c)
    c_prime = kpke_encrypt(ek, m_prime, r_prime)
    if c != c_prime:
        K_prime = K_bar
    return K_prime


def _encapsulation_key_check(ek: bytes) -> None:
    """FIPS 203 §7.2: type check + modulus check on ek."""
    if len(ek) != EK_SIZE:
        raise ValueError(f"ek must be {EK_SIZE} bytes (got {len(ek)})")
    t_hat = _vec_byte_decode(12, K, ek[: 384 * K])
    re_encoded = b"".join(byte_encode(12, p) for p in t_hat)
    if re_encoded != ek[: 384 * K]:
        raise ValueError("ek modulus check failed: encoded values ≥ q")


def _decapsulation_key_check(dk: bytes) -> None:
    """FIPS 203 §7.3: type check + hash check on dk."""
    if len(dk) != DK_SIZE:
        raise ValueError(f"dk must be {DK_SIZE} bytes (got {len(dk)})")
    ek = dk[384 * K : 768 * K + 32]
    h_stored = dk[768 * K + 32 : 768 * K + 64]
    if H(ek) != h_stored:
        raise ValueError("dk hash check failed: H(ek) mismatch")


def _ciphertext_type_check(c: bytes) -> None:
    """FIPS 203 §7.3: ciphertext type check."""
    if len(c) != CT_SIZE:
        raise ValueError(f"ciphertext must be {CT_SIZE} bytes (got {len(c)})")


def keygen():
    """Algorithm 19: ML-KEM.KeyGen."""
    d = secrets.token_bytes(32)
    z = secrets.token_bytes(32)
    return _keygen_internal(d, z)


def encaps(ek: bytes):
    """Algorithm 20: ML-KEM.Encaps."""
    _encapsulation_key_check(ek)
    m = secrets.token_bytes(32)
    return _encaps_internal(ek, m)


def decaps(dk: bytes, c: bytes) -> bytes:
    """Algorithm 21: ML-KEM.Decaps."""
    _ciphertext_type_check(c)
    _decapsulation_key_check(dk)
    return _decaps_internal(dk, c)
