"""SLH-DSA-SHAKE-128s hash functions per FIPS 205 §10.2.

All hash functions are instantiated with SHAKE128:

  F(PK.seed, ADRS, M₁)          = SHAKE128(PK.seed ‖ ADRS ‖ M₁,         8n)
  H(PK.seed, ADRS, M)           = SHAKE128(PK.seed ‖ ADRS ‖ M,           8n)
  T_l(PK.seed, ADRS, M)         = SHAKE128(PK.seed ‖ ADRS ‖ M,           8n)
  PRF(PK.seed, SK.seed, ADRS)   = SHAKE128(PK.seed ‖ ADRS ‖ SK.seed,     8n)
  PRF_msg(SK.prf, opt_rand, M)  = SHAKE128(SK.prf  ‖ opt_rand ‖ M,       8n)
  H_msg(R, PK.seed, PK.root, M) = SHAKE128(R       ‖ PK.seed ‖ PK.root ‖ M, 8m)

For n = 16: output is 16 bytes.  For m = 30: H_msg output is 30 bytes.
ADRS is always 32 bytes.
"""

import hashlib

from .params import M_BYTES, N


def _shake128(data: bytes, out_len: int) -> bytes:
    return hashlib.shake_128(data).digest(out_len)


def F(pk_seed: bytes, adrs: bytearray, m1: bytes) -> bytes:
    """1-input T-hash (Algorithm — §10.2). Inputs: PK.seed (n), ADRS (32), M (n)."""
    return _shake128(bytes(pk_seed) + bytes(adrs) + bytes(m1), N)


def H(pk_seed: bytes, adrs: bytearray, m: bytes) -> bytes:
    """2-input T-hash (§10.2). Inputs: PK.seed (n), ADRS (32), M (2n)."""
    return _shake128(bytes(pk_seed) + bytes(adrs) + bytes(m), N)


def T_l(pk_seed: bytes, adrs: bytearray, m: bytes) -> bytes:
    """l-input T-hash (§10.2). Inputs: PK.seed (n), ADRS (32), M (l·n)."""
    return _shake128(bytes(pk_seed) + bytes(adrs) + bytes(m), N)


def PRF(pk_seed: bytes, sk_seed: bytes, adrs: bytearray) -> bytes:
    """Pseudorandom function (§10.2). Inputs: PK.seed (n), ADRS (32), SK.seed (n)."""
    return _shake128(bytes(pk_seed) + bytes(adrs) + bytes(sk_seed), N)


def PRF_msg(sk_prf: bytes, opt_rand: bytes, m: bytes) -> bytes:
    """Message randomizer (§10.2). Inputs: SK.prf (n), opt_rand (n), M (*)."""
    return _shake128(bytes(sk_prf) + bytes(opt_rand) + bytes(m), N)


def H_msg(r: bytes, pk_seed: bytes, pk_root: bytes, m: bytes) -> bytes:
    """Message hash (§10.2). Output: M_BYTES bytes."""
    return _shake128(bytes(r) + bytes(pk_seed) + bytes(pk_root) + bytes(m), M_BYTES)
