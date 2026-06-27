"""XMSS tree operations per FIPS 205 §7 (Algorithms 9–12).

xmss_node    – Algorithm 9:  compute a single tree node
xmss_pkgen   – Algorithm 12: compute root = xmss_node(0, h')
xmss_sign    – Algorithm 10: sign + build authentication path
xmss_pk_from_sig – Algorithm 11: recover root from signature
"""

from .address import (
    TREE,
    WOTS_HASH,
    copy_adrs,
    get_tree_index,
    set_key_pair_address,
    set_tree_height,
    set_tree_index,
    set_type_and_clear,
)
from .hashes import H
from .params import HP, LEN, N
from .wots import wots_pk_from_sig, wots_pkgen, wots_sign


def xmss_node(sk_seed: bytes, i: int, z: int, pk_seed: bytes, adrs: bytearray) -> bytes:
    """Algorithm 9. Compute XMSS tree node at height z with index i.

    i : leaf index (z = 0) or level-z node index (z > 0)
    z : height within the XMSS tree (0 = leaf, HP = root)
    """
    if z == 0:
        adrs_copy = copy_adrs(adrs)
        set_type_and_clear(adrs_copy, WOTS_HASH)
        set_key_pair_address(adrs_copy, i)
        return wots_pkgen(sk_seed, pk_seed, adrs_copy)

    lnode = xmss_node(sk_seed, 2 * i,     z - 1, pk_seed, adrs)
    rnode = xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)

    adrs_copy = copy_adrs(adrs)
    set_type_and_clear(adrs_copy, TREE)
    set_tree_height(adrs_copy, z)
    set_tree_index(adrs_copy, i)
    return H(pk_seed, adrs_copy, lnode + rnode)


def xmss_pkgen(sk_seed: bytes, pk_seed: bytes, adrs: bytearray) -> bytes:
    """Algorithm 12. Compute XMSS public key (= root node)."""
    return xmss_node(sk_seed, 0, HP, pk_seed, adrs)


def xmss_sign(m: bytes, sk_seed: bytes, idx: int, pk_seed: bytes, adrs: bytearray) -> bytes:
    """Algorithm 10. Sign m and produce XMSS signature (AUTH + wots_sig).

    Returns (len + HP) * n bytes:
      WOTS+ signature: LEN * n bytes
      Authentication path: HP * n bytes
    """
    auth = b""
    for j in range(HP):
        k = (idx >> j) ^ 1  # sibling node index at height j
        auth += xmss_node(sk_seed, k, j, pk_seed, adrs)

    wots_adrs = copy_adrs(adrs)
    set_type_and_clear(wots_adrs, WOTS_HASH)
    set_key_pair_address(wots_adrs, idx)
    sig_wots = wots_sign(m, sk_seed, pk_seed, wots_adrs)

    return sig_wots + auth


def xmss_pk_from_sig(idx: int, xmss_sig: bytes, m: bytes, pk_seed: bytes, adrs: bytearray) -> bytes:
    """Algorithm 11. Recover XMSS root from signature.

    xmss_sig : (LEN + HP) * n bytes
    Returns   : n-byte root
    """
    wots_sig = xmss_sig[: LEN * N]
    auth = [xmss_sig[(LEN + j) * N : (LEN + j + 1) * N] for j in range(HP)]

    wots_adrs = copy_adrs(adrs)
    set_type_and_clear(wots_adrs, WOTS_HASH)
    set_key_pair_address(wots_adrs, idx)
    node = wots_pk_from_sig(wots_sig, m, pk_seed, wots_adrs)

    tree_adrs = copy_adrs(adrs)
    set_type_and_clear(tree_adrs, TREE)
    set_tree_index(tree_adrs, idx)

    for k in range(HP):
        set_tree_height(tree_adrs, k + 1)
        if (idx >> k) & 1 == 0:
            # current node is left child; sibling is right
            set_tree_index(tree_adrs, get_tree_index(tree_adrs) >> 1)
            node = H(pk_seed, tree_adrs, node + auth[k])
        else:
            # current node is right child; sibling is left
            set_tree_index(tree_adrs, (get_tree_index(tree_adrs) - 1) >> 1)
            node = H(pk_seed, tree_adrs, auth[k] + node)

    return node
