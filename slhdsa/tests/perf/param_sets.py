"""FIPS 205 Table 1 parameter values for the six SHAKE-based SLH-DSA sets.

Only SLH-DSA-SHAKE-128s (slhdsa/params.py) ships as a real, NIST-ACVP-KAT
-verified implementation in this repo -- see CLAUDE.md. The other five
SHAKE sets defined here (category 1/2/3 x small/fast) exist purely for
benchmarking: derive_constants() reproduces slhdsa/params.py's derivation
formulas so the *same* unmodified algorithm code can be run against each
set's (n, h, d, a, k) via monkeypatch + reload -- see param_loader.py.

lg_w = 4 (w = 16) is fixed across every FIPS 205 parameter set (SHA2 and
SHAKE alike), so it is not varied here.
"""

# name -> (n, h, d, a, k), FIPS 205 Table 1 (category 1/2/3 x small/fast).
# "s" (small) sets favor small signatures at the cost of slow signing;
# "f" (fast) sets favor fast signing at the cost of larger signatures.
RAW_PARAMS = {
    "SHAKE-128s": dict(n=16, h=63, d=7, a=12, k=14),
    "SHAKE-128f": dict(n=16, h=66, d=22, a=6, k=33),
    "SHAKE-192s": dict(n=24, h=63, d=7, a=14, k=17),
    "SHAKE-192f": dict(n=24, h=66, d=22, a=8, k=33),
    "SHAKE-256s": dict(n=32, h=64, d=8, a=14, k=22),
    "SHAKE-256f": dict(n=32, h=68, d=17, a=9, k=35),
}

LG_W = 4
W = 1 << LG_W


def derive_constants(n, h, d, a, k):
    """Reproduce slhdsa/params.py's derivations for an arbitrary (n, h, d, a, k).

    Returns every module-level name slhdsa/params.py defines, so the dict
    can be applied wholesale via setattr onto the slhdsa.params module.
    """
    hp = h // d
    len1 = 8 * n // LG_W
    len2 = (len1 * (W - 1)).bit_length() // LG_W + 1
    length = len1 + len2

    ka_bytes = (k * a + 7) // 8
    idx_tree_bytes = (h - hp + 7) // 8
    idx_leaf_bytes = (hp + 7) // 8

    md_end = ka_bytes
    tree_end = ka_bytes + idx_tree_bytes
    leaf_end = tree_end + idx_leaf_bytes  # == m (FIPS 205 Table 1 "m" column)

    return {
        "N": n,
        "H": h,
        "D": d,
        "HP": hp,
        "A": a,
        "K": k,
        "LG_W": LG_W,
        "W": W,
        "LEN1": len1,
        "LEN2": len2,
        "LEN": length,
        "M_BYTES": leaf_end,
        "PK_SIZE": 2 * n,
        "SK_SIZE": 4 * n,
        "SIG_SIZE": n + k * (a + 1) * n + (h + d * length) * n,
        "_KA_BYTES": ka_bytes,
        "_IDX_TREE_BYTES": idx_tree_bytes,
        "_IDX_LEAF_BYTES": idx_leaf_bytes,
        "MD_END": md_end,
        "TREE_END": tree_end,
        "LEAF_END": leaf_end,
        "IDX_TREE_MASK": (1 << (h - hp)) - 1,
        "IDX_LEAF_MASK": (1 << hp) - 1,
    }
