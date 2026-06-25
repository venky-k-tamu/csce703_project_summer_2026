"""SLH-DSA-SHAKE-128s KeyGen / Sign / Verify per FIPS 205 §9 (Algorithms 19–22).

Public API:
  keygen()                         → (pk, sk)
  sign(m, sk, ctx=b"", randomize=True)  → sig
  verify(m, sig, pk, ctx=b"")     → bool

Internal (deterministic) API used for KAT testing:
  _keygen_internal(sk_seed, sk_prf, pk_seed) → (pk, sk)
  _sign_internal(m_prime, sk, opt_rand)      → sig
  _verify_internal(m_prime, sig, pk)         → bool
"""

import os

from .address import (
    FORS_TREE,
    new_adrs,
    set_key_pair_address,
    set_layer_address,
    set_tree_address,
    set_type_and_clear,
)
from .fors import fors_pk_from_sig, fors_sign
from .hashes import H_msg, PRF_msg
from .ht import ht_pkgen, ht_sign, ht_verify
from .params import (
    A,
    IDX_LEAF_MASK,
    IDX_TREE_MASK,
    K,
    LEAF_END,
    M_BYTES,
    MD_END,
    N,
    PK_SIZE,
    SK_SIZE,
    SIG_SIZE,
    TREE_END,
)


# ---------------------------------------------------------------------------
# Internal algorithms
# ---------------------------------------------------------------------------


def _keygen_internal(sk_seed: bytes, sk_prf: bytes, pk_seed: bytes):
    """Algorithm 19 (internal). Returns (pk, sk) both as bytes."""
    if len(sk_seed) != N or len(sk_prf) != N or len(pk_seed) != N:
        raise ValueError("sk_seed, sk_prf, pk_seed must each be n bytes")

    pk_root = ht_pkgen(sk_seed, pk_seed)

    sk = sk_seed + sk_prf + pk_seed + pk_root   # 4n bytes
    pk = pk_seed + pk_root                        # 2n bytes
    return pk, sk


def _sign_internal(m_prime: bytes, sk: bytes, opt_rand: bytes) -> bytes:
    """Algorithm 21 (internal). Sign the pre-processed message M'.

    opt_rand : n random bytes (randomized signing) or PK.seed (deterministic).
    """
    if len(sk) != SK_SIZE:
        raise ValueError(f"sk must be {SK_SIZE} bytes")
    if len(opt_rand) != N:
        raise ValueError("opt_rand must be n bytes")

    sk_seed = sk[:N]
    sk_prf  = sk[N:2*N]
    pk_seed = sk[2*N:3*N]
    pk_root = sk[3*N:4*N]

    # Randomize (or not) the message
    R = PRF_msg(sk_prf, opt_rand, m_prime)

    # Compute message digest (m bytes)
    digest = H_msg(R, pk_seed, pk_root, m_prime)

    # Split digest into FORS md, idx_tree, idx_leaf
    md      = digest[:MD_END]
    idx_tree = int.from_bytes(digest[MD_END:TREE_END], "big") & IDX_TREE_MASK
    idx_leaf = int.from_bytes(digest[TREE_END:LEAF_END], "big") & IDX_LEAF_MASK

    # FORS signature
    fors_adrs = new_adrs()
    set_type_and_clear(fors_adrs, FORS_TREE)
    set_layer_address(fors_adrs, 0)
    set_tree_address(fors_adrs, idx_tree)
    set_key_pair_address(fors_adrs, idx_leaf)

    sig_fors = fors_sign(md, sk_seed, pk_seed, fors_adrs)
    pk_fors  = fors_pk_from_sig(sig_fors, md, pk_seed, fors_adrs)

    # HT signature
    sig_ht = ht_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf)

    sig = R + sig_fors + sig_ht
    assert len(sig) == SIG_SIZE, f"sig size {len(sig)} ≠ {SIG_SIZE}"
    return sig


def _verify_internal(m_prime: bytes, sig: bytes, pk: bytes) -> bool:
    """Algorithm 22 (internal). Verify a signature on M'."""
    if len(sig) != SIG_SIZE:
        return False
    if len(pk) != PK_SIZE:
        return False

    pk_seed = pk[:N]
    pk_root = pk[N:2*N]

    R       = sig[:N]
    sig_fors = sig[N : N + K * (A + 1) * N]
    sig_ht  = sig[N + K * (A + 1) * N :]

    digest  = H_msg(R, pk_seed, pk_root, m_prime)
    md      = digest[:MD_END]
    idx_tree = int.from_bytes(digest[MD_END:TREE_END], "big") & IDX_TREE_MASK
    idx_leaf = int.from_bytes(digest[TREE_END:LEAF_END], "big") & IDX_LEAF_MASK

    fors_adrs = new_adrs()
    set_type_and_clear(fors_adrs, FORS_TREE)
    set_layer_address(fors_adrs, 0)
    set_tree_address(fors_adrs, idx_tree)
    set_key_pair_address(fors_adrs, idx_leaf)

    pk_fors = fors_pk_from_sig(sig_fors, md, pk_seed, fors_adrs)

    return ht_verify(pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def keygen():
    """Algorithm 20. Generate a fresh key pair using OS randomness."""
    sk_seed = os.urandom(N)
    sk_prf  = os.urandom(N)
    pk_seed = os.urandom(N)
    return _keygen_internal(sk_seed, sk_prf, pk_seed)


def sign(m: bytes, sk: bytes, ctx: bytes = b"", randomize: bool = True) -> bytes:
    """Algorithm 21. Sign message m with context ctx.

    randomize=True  : hedged signing (FIPS 205 §9.2, preferred)
    randomize=False : deterministic signing (opt_rand = PK.seed)
    """
    if len(ctx) > 255:
        raise ValueError("context must be at most 255 bytes")
    m_prime = b"\x00" + len(ctx).to_bytes(1, "big") + ctx + m

    pk_seed = sk[2*N:3*N]
    opt_rand = os.urandom(N) if randomize else pk_seed
    return _sign_internal(m_prime, sk, opt_rand)


def verify(m: bytes, sig: bytes, pk: bytes, ctx: bytes = b"") -> bool:
    """Algorithm 22. Verify signature sig on message m under public key pk."""
    if len(ctx) > 255:
        return False
    m_prime = b"\x00" + len(ctx).to_bytes(1, "big") + ctx + m
    return _verify_internal(m_prime, sig, pk)
