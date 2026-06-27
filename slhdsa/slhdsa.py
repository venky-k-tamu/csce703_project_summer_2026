"""SLH-DSA-SHAKE-128s KeyGen / Sign / Verify per FIPS 205 §9–§10.

Public API:
  keygen()                                                       → (pk, sk)
  sign(m, sk, ctx=b"", randomize=True)                          → sig
  verify(m, sig, pk, ctx=b"")                                   → bool
  hash_sign(m, sk, ctx=b"", *, hash_alg="SHA2-512", randomize=True) → sig
  hash_verify(m, sig, pk, ctx=b"", *, hash_alg="SHA2-512")     → bool

Internal (deterministic) API used for KAT testing:
  _keygen_internal(sk_seed, sk_prf, pk_seed) → (pk, sk)
  _sign_internal(m_prime, sk, opt_rand)      → sig
  _verify_internal(m_prime, sig, pk)         → bool
"""

import hashlib
import secrets

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
# Public API (FIPS 205 §9, Algorithms 19–22)
# ---------------------------------------------------------------------------


# DER-encoded OIDs for permitted pre-hash functions (FIPS 205 §10.1).
# Names match ACVP-style identifiers used in NIST test vectors.
_PREHASH_FUNCTIONS = {
    "SHA2-224":     (bytes.fromhex("0609608648016503040204"), lambda m: hashlib.new("sha224", m).digest()),
    "SHA2-256":     (bytes.fromhex("0609608648016503040201"), lambda m: hashlib.sha256(m).digest()),
    "SHA2-384":     (bytes.fromhex("0609608648016503040202"), lambda m: hashlib.sha384(m).digest()),
    "SHA2-512":     (bytes.fromhex("0609608648016503040203"), lambda m: hashlib.sha512(m).digest()),
    "SHA2-512/224": (bytes.fromhex("0609608648016503040205"), lambda m: hashlib.new("sha512_224", m).digest()),
    "SHA2-512/256": (bytes.fromhex("0609608648016503040206"), lambda m: hashlib.new("sha512_256", m).digest()),
    "SHA3-224":     (bytes.fromhex("0609608648016503040207"), lambda m: hashlib.sha3_224(m).digest()),
    "SHA3-256":     (bytes.fromhex("0609608648016503040208"), lambda m: hashlib.sha3_256(m).digest()),
    "SHA3-384":     (bytes.fromhex("0609608648016503040209"), lambda m: hashlib.sha3_384(m).digest()),
    "SHA3-512":     (bytes.fromhex("060960864801650304020A"), lambda m: hashlib.sha3_512(m).digest()),
    "SHAKE-128":    (bytes.fromhex("060960864801650304020B"), lambda m: hashlib.shake_128(m).digest(32)),
    "SHAKE-256":    (bytes.fromhex("060960864801650304020C"), lambda m: hashlib.shake_256(m).digest(64)),
}


def _format_M_prime(m: bytes, ctx: bytes, prehash_oid: bytes | None = None) -> bytes:
    """Build M' for SLH-DSA (prehash_oid=None) or HashSLH-DSA (FIPS 205 §9.1/§10)."""
    if len(ctx) > 255:
        raise ValueError("ctx must be at most 255 bytes")
    domain = 1 if prehash_oid is not None else 0
    head = bytes([domain, len(ctx)]) + ctx
    if prehash_oid is None:
        return head + m
    return head + prehash_oid + m


def _resolve_prehash(name: str):
    try:
        return _PREHASH_FUNCTIONS[name]
    except KeyError:
        raise ValueError(f"unsupported pre-hash function {name!r}") from None


def keygen():
    """Algorithm 20. Generate a fresh key pair using OS randomness."""
    sk_seed = secrets.token_bytes(N)
    sk_prf  = secrets.token_bytes(N)
    pk_seed = secrets.token_bytes(N)
    return _keygen_internal(sk_seed, sk_prf, pk_seed)


def sign(m: bytes, sk: bytes, ctx: bytes = b"", randomize: bool = True) -> bytes:
    """Algorithm 21. Sign message m with context ctx.

    randomize=True  : hedged signing (FIPS 205 §9.2, preferred)
    randomize=False : deterministic signing (opt_rand = PK.seed)
    """
    m_prime = _format_M_prime(m, ctx)
    pk_seed = sk[2*N:3*N]
    opt_rand = secrets.token_bytes(N) if randomize else pk_seed
    return _sign_internal(m_prime, sk, opt_rand)


def verify(m: bytes, sig: bytes, pk: bytes, ctx: bytes = b"") -> bool:
    """Algorithm 22. Verify signature sig on message m under public key pk."""
    if len(ctx) > 255:
        return False
    m_prime = _format_M_prime(m, ctx)
    return _verify_internal(m_prime, sig, pk)


# ---------------------------------------------------------------------------
# HashSLH-DSA public API (FIPS 205 §10, Algorithms 23–24)
# ---------------------------------------------------------------------------


def hash_sign(
    m: bytes,
    sk: bytes,
    ctx: bytes = b"",
    *,
    hash_alg: str = "SHA2-512",
    randomize: bool = True,
) -> bytes:
    """Algorithm 23. HashSLH-DSA.Sign."""
    oid, prehash = _resolve_prehash(hash_alg)
    m_prime = _format_M_prime(prehash(m), ctx, prehash_oid=oid)
    pk_seed = sk[2*N:3*N]
    opt_rand = secrets.token_bytes(N) if randomize else pk_seed
    return _sign_internal(m_prime, sk, opt_rand)


def hash_verify(
    m: bytes,
    sig: bytes,
    pk: bytes,
    ctx: bytes = b"",
    *,
    hash_alg: str = "SHA2-512",
) -> bool:
    """Algorithm 24. HashSLH-DSA.Verify."""
    if len(ctx) > 255:
        return False
    try:
        oid, prehash = _resolve_prehash(hash_alg)
    except ValueError:
        return False
    m_prime = _format_M_prime(prehash(m), ctx, prehash_oid=oid)
    return _verify_internal(m_prime, sig, pk)
