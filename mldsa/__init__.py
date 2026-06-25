"""ML-DSA-65 reference implementation (FIPS 204)."""

from .mldsa import hash_sign, hash_verify, keygen, sign, verify

__all__ = ["keygen", "sign", "verify", "hash_sign", "hash_verify"]
