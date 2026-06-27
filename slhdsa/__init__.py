"""SLH-DSA-SHAKE-128s reference implementation (FIPS 205)."""

from .slhdsa import keygen, sign, verify

__all__ = ["keygen", "sign", "verify"]
