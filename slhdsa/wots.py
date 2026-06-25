"""WOTS+ per FIPS 205 §6 (Algorithms 5–8).

WOTS+ uses LEN = len1 + len2 = 35 chains for SLH-DSA-SHAKE-128s.
Each chain produces an n-byte value.  A WOTS+ public key is the Tlen
compression of all LEN chain heads.
"""

from .address import (
    WOTS_HASH,
    WOTS_PK,
    WOTS_PRF,
    copy_adrs,
    get_key_pair_address,
    set_chain_address,
    set_hash_address,
    set_key_pair_address,
    set_type_and_clear,
)
from .hashes import F, PRF, T_l
from .params import LEN, LEN1, LEN2, LG_W, N, W


def _base_2b(x: bytes, b: int, out_len: int) -> list:
    """Algorithm 4. Convert byte string to base-2^b digits (MSB first)."""
    acc = 0
    bits = 0
    idx = 0
    out = []
    for _ in range(out_len):
        while bits < b:
            acc = (acc << 8) | x[idx]
            idx += 1
            bits += 8
        bits -= b
        out.append((acc >> bits) & ((1 << b) - 1))
    return out


def _chain(x: bytes, i: int, s: int, pk_seed: bytes, adrs: bytearray) -> bytes:
    """Algorithm 5. Compute s steps of the hash chain starting at index i.

    x    : n-byte input
    i    : start index
    s    : number of steps (0 means identity)
    """
    if s == 0:
        return x
    tmp = _chain(x, i, s - 1, pk_seed, adrs)
    set_hash_address(adrs, i + s - 1)
    return F(pk_seed, adrs, tmp)


def wots_pkgen(sk_seed: bytes, pk_seed: bytes, adrs: bytearray) -> bytes:
    """Algorithm 6. Generate a WOTS+ public key (n bytes).

    adrs must have its layer, tree, and key_pair fields set before calling.
    """
    sk_adrs = copy_adrs(adrs)
    set_type_and_clear(sk_adrs, WOTS_PRF)
    set_key_pair_address(sk_adrs, get_key_pair_address(adrs))

    tmp = b""
    for i in range(LEN):
        set_chain_address(sk_adrs, i)
        sk_i = PRF(pk_seed, sk_seed, sk_adrs)

        wots_adrs = copy_adrs(adrs)
        set_type_and_clear(wots_adrs, WOTS_HASH)
        set_key_pair_address(wots_adrs, get_key_pair_address(adrs))
        set_chain_address(wots_adrs, i)
        tmp += _chain(sk_i, 0, W - 1, pk_seed, wots_adrs)

    wots_pk_adrs = copy_adrs(adrs)
    set_type_and_clear(wots_pk_adrs, WOTS_PK)
    set_key_pair_address(wots_pk_adrs, get_key_pair_address(adrs))
    return T_l(pk_seed, wots_pk_adrs, tmp)


def _msg_to_base_w_with_checksum(m: bytes) -> list:
    """Derive the LEN base-w message digits plus checksum digits (Algorithms 7/8)."""
    msg_digits = _base_2b(m, LG_W, LEN1)

    csum = sum(W - 1 - d for d in msg_digits)
    shift = (8 - (LEN2 * LG_W) % 8) % 8
    csum <<= shift
    csum_bytes = csum.to_bytes((LEN2 * LG_W + 7) // 8, "big")
    csum_digits = _base_2b(csum_bytes, LG_W, LEN2)

    return msg_digits + csum_digits


def wots_sign(m: bytes, sk_seed: bytes, pk_seed: bytes, adrs: bytearray) -> bytes:
    """Algorithm 7. Sign an n-byte message. Returns LEN·n bytes."""
    digits = _msg_to_base_w_with_checksum(m)

    sk_adrs = copy_adrs(adrs)
    set_type_and_clear(sk_adrs, WOTS_PRF)
    set_key_pair_address(sk_adrs, get_key_pair_address(adrs))

    sig = b""
    for i in range(LEN):
        set_chain_address(sk_adrs, i)
        sk_i = PRF(pk_seed, sk_seed, sk_adrs)

        wots_adrs = copy_adrs(adrs)
        set_type_and_clear(wots_adrs, WOTS_HASH)
        set_key_pair_address(wots_adrs, get_key_pair_address(adrs))
        set_chain_address(wots_adrs, i)
        sig += _chain(sk_i, 0, digits[i], pk_seed, wots_adrs)

    return sig


def wots_pk_from_sig(sig: bytes, m: bytes, pk_seed: bytes, adrs: bytearray) -> bytes:
    """Algorithm 8. Recover WOTS+ public key from signature. Returns n bytes."""
    if len(sig) != LEN * N:
        raise ValueError(f"wots signature must be {LEN * N} bytes")

    digits = _msg_to_base_w_with_checksum(m)

    tmp = b""
    for i in range(LEN):
        sig_i = sig[i * N : (i + 1) * N]

        wots_adrs = copy_adrs(adrs)
        set_type_and_clear(wots_adrs, WOTS_HASH)
        set_key_pair_address(wots_adrs, get_key_pair_address(adrs))
        set_chain_address(wots_adrs, i)
        tmp += _chain(sig_i, digits[i], W - 1 - digits[i], pk_seed, wots_adrs)

    wots_pk_adrs = copy_adrs(adrs)
    set_type_and_clear(wots_pk_adrs, WOTS_PK)
    set_key_pair_address(wots_pk_adrs, get_key_pair_address(adrs))
    return T_l(pk_seed, wots_pk_adrs, tmp)
