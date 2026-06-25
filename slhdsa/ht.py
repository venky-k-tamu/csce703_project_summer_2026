"""Hypertree (HT) operations per FIPS 205 §8 (Algorithms 13–15).

The hypertree stacks D XMSS trees.  Layer 0 is at the bottom (signs
the FORS public key).  Layer D-1 is the top (its root is PK.root).

ht_pkgen    – Algorithm 13: compute PK.root
ht_sign     – Algorithm 14: produce an HT signature
ht_verify   – Algorithm 15: verify an HT signature
"""

from .address import (
    new_adrs,
    set_layer_address,
    set_tree_address,
)
from .params import D, HP, LEN, N
from .xmss import xmss_pk_from_sig, xmss_pkgen, xmss_sign

# Size of one XMSS signature (WOTS sig + auth path)
_XMSS_SIG_BYTES = (LEN + HP) * N


def ht_pkgen(sk_seed: bytes, pk_seed: bytes) -> bytes:
    """Algorithm 13. Compute the HT public key (= top-layer XMSS root)."""
    adrs = new_adrs()
    set_layer_address(adrs, D - 1)
    set_tree_address(adrs, 0)
    return xmss_pkgen(sk_seed, pk_seed, adrs)


def ht_sign(m: bytes, sk_seed: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int) -> bytes:
    """Algorithm 14. Sign an n-byte message with the hypertree.

    idx_tree : (h - h') bit tree index at the bottom layer
    idx_leaf : h'-bit leaf index within the bottom-layer tree
    Returns  : D * (LEN + HP) * n bytes
    """
    adrs = new_adrs()
    set_layer_address(adrs, 0)
    set_tree_address(adrs, idx_tree)

    sig_tmp = xmss_sign(m, sk_seed, idx_leaf, pk_seed, adrs)
    sig_ht = sig_tmp
    root = xmss_pk_from_sig(idx_leaf, sig_tmp, m, pk_seed, adrs)

    for j in range(1, D):
        idx_leaf = idx_tree & ((1 << HP) - 1)   # low HP bits
        idx_tree >>= HP

        set_layer_address(adrs, j)
        set_tree_address(adrs, idx_tree)

        sig_tmp = xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs)
        sig_ht += sig_tmp
        if j < D - 1:
            root = xmss_pk_from_sig(idx_leaf, sig_tmp, root, pk_seed, adrs)

    return sig_ht


def ht_verify(m: bytes, sig_ht: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int, pk_root: bytes) -> bool:
    """Algorithm 15. Verify an HT signature. Returns True iff valid."""
    if len(sig_ht) != D * _XMSS_SIG_BYTES:
        return False

    adrs = new_adrs()
    set_layer_address(adrs, 0)
    set_tree_address(adrs, idx_tree)

    sig_tmp = sig_ht[:_XMSS_SIG_BYTES]
    node = xmss_pk_from_sig(idx_leaf, sig_tmp, m, pk_seed, adrs)

    for j in range(1, D):
        idx_leaf = idx_tree & ((1 << HP) - 1)
        idx_tree >>= HP

        set_layer_address(adrs, j)
        set_tree_address(adrs, idx_tree)

        sig_tmp = sig_ht[j * _XMSS_SIG_BYTES : (j + 1) * _XMSS_SIG_BYTES]
        node = xmss_pk_from_sig(idx_leaf, sig_tmp, node, pk_seed, adrs)

    return node == pk_root
