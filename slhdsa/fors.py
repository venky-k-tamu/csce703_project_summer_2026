"""FORS (Forest Of Random Subsets) per FIPS 205 §9 (Algorithms 15–18).

FORS uses K independent binary trees of height A.
Each tree has 2^A leaves.  The FORS public key is the T_k compression of
the K tree roots.

fors_skgen       – Algorithm 15: derive a secret leaf value
fors_node        – Algorithm 16: compute a FORS tree node
fors_sign        – Algorithm 17: produce a FORS signature
fors_pk_from_sig – Algorithm 18: recover FORS public key from signature
"""

from .address import (
    FORS_PRF,
    FORS_ROOTS,
    FORS_TREE,
    copy_adrs,
    get_key_pair_address,
    get_tree_index,
    set_key_pair_address,
    set_tree_height,
    set_tree_index,
    set_type_and_clear,
)
from .hashes import F, H, PRF, T_l
from .params import A, K, N


def _base_2a(md: bytes) -> list:
    """Extract K indices of A bits each from the FORS message digest (MSB first)."""
    out = []
    acc = 0
    bits = 0
    byte_idx = 0
    for _ in range(K):
        while bits < A:
            acc = (acc << 8) | md[byte_idx]
            byte_idx += 1
            bits += 8
        bits -= A
        out.append((acc >> bits) & ((1 << A) - 1))
    return out


def fors_skgen(sk_seed: bytes, pk_seed: bytes, adrs: bytearray, idx: int) -> bytes:
    """Algorithm 15. Derive the secret value for FORS leaf idx."""
    sk_adrs = copy_adrs(adrs)
    set_type_and_clear(sk_adrs, FORS_PRF)
    set_key_pair_address(sk_adrs, get_key_pair_address(adrs))
    set_tree_height(sk_adrs, 0)
    set_tree_index(sk_adrs, idx)
    return PRF(pk_seed, sk_seed, sk_adrs)


def fors_node(sk_seed: bytes, i: int, z: int, pk_seed: bytes, adrs: bytearray) -> bytes:
    """Algorithm 16. Compute FORS tree node at height z with (global) index i.

    i : global leaf index (z = 0) or global level-z node index (z > 0).
        Global means across all K trees: leaf i belongs to tree i // 2^A.
    z : height within the FORS tree (0 = leaf, A = root).
    """
    if z == 0:
        sk = fors_skgen(sk_seed, pk_seed, adrs, i)
        leaf_adrs = copy_adrs(adrs)
        set_type_and_clear(leaf_adrs, FORS_TREE)
        set_key_pair_address(leaf_adrs, get_key_pair_address(adrs))
        set_tree_height(leaf_adrs, 0)
        set_tree_index(leaf_adrs, i)
        return F(pk_seed, leaf_adrs, sk)

    lnode = fors_node(sk_seed, 2 * i,     z - 1, pk_seed, adrs)
    rnode = fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)

    node_adrs = copy_adrs(adrs)
    set_type_and_clear(node_adrs, FORS_TREE)
    set_key_pair_address(node_adrs, get_key_pair_address(adrs))
    set_tree_height(node_adrs, z)
    set_tree_index(node_adrs, i)
    return H(pk_seed, node_adrs, lnode + rnode)


def fors_sign(md: bytes, sk_seed: bytes, pk_seed: bytes, adrs: bytearray) -> bytes:
    """Algorithm 17. Produce FORS signature for message digest md.

    md must be at least ceil(K*A/8) bytes; only the first K*A bits are used.
    Returns K*(A+1)*N bytes: for each tree, SK + auth path.
    """
    indices = _base_2a(md)
    sig = b""
    for i in range(K):
        # Secret leaf value
        sig += fors_skgen(sk_seed, pk_seed, adrs, i * (1 << A) + indices[i])
        # Authentication path: A sibling nodes from leaf to (just below) root
        for j in range(A):
            s = (indices[i] >> j) ^ 1          # sibling node index at height j within tree i
            global_node = i * (1 << (A - j)) + s  # global level-j node index
            sig += fors_node(sk_seed, global_node, j, pk_seed, adrs)

    return sig


def fors_pk_from_sig(sig: bytes, md: bytes, pk_seed: bytes, adrs: bytearray) -> bytes:
    """Algorithm 18. Recover FORS public key from signature.

    Returns n bytes (the compressed root of all K trees).
    """
    if len(sig) != K * (A + 1) * N:
        raise ValueError(f"FORS signature must be {K * (A + 1) * N} bytes")

    indices = _base_2a(md)
    roots = b""

    offset = 0
    for i in range(K):
        sk = sig[offset : offset + N]; offset += N
        auth = [sig[offset + j * N : offset + (j + 1) * N] for j in range(A)]
        offset += A * N

        # Compute the leaf and walk up to the root
        leaf_adrs = copy_adrs(adrs)
        set_type_and_clear(leaf_adrs, FORS_TREE)
        set_key_pair_address(leaf_adrs, get_key_pair_address(adrs))
        set_tree_height(leaf_adrs, 0)
        set_tree_index(leaf_adrs, i * (1 << A) + indices[i])
        node = F(pk_seed, leaf_adrs, sk)

        tree_adrs = copy_adrs(adrs)
        set_type_and_clear(tree_adrs, FORS_TREE)
        set_key_pair_address(tree_adrs, get_key_pair_address(adrs))
        set_tree_index(tree_adrs, i * (1 << A) + indices[i])

        for k in range(A):
            set_tree_height(tree_adrs, k + 1)
            if (indices[i] >> k) & 1 == 0:
                # Current node is left child
                set_tree_index(tree_adrs, get_tree_index(tree_adrs) >> 1)
                node = H(pk_seed, tree_adrs, node + auth[k])
            else:
                # Current node is right child
                set_tree_index(tree_adrs, (get_tree_index(tree_adrs) - 1) >> 1)
                node = H(pk_seed, tree_adrs, auth[k] + node)

        roots += node

    fors_pk_adrs = copy_adrs(adrs)
    set_type_and_clear(fors_pk_adrs, FORS_ROOTS)
    set_key_pair_address(fors_pk_adrs, get_key_pair_address(adrs))
    return T_l(pk_seed, fors_pk_adrs, roots)
