"""Smoke-tests that SLH-DSA-SHAKE-128s parameters match FIPS 205 Table 1."""

from slhdsa.params import (
    A,
    D,
    H,
    HP,
    K,
    LEAF_END,
    LEN,
    LEN1,
    LEN2,
    LG_W,
    M_BYTES,
    MD_END,
    N,
    PK_SIZE,
    SK_SIZE,
    SIG_SIZE,
    TREE_END,
    W,
)


def test_primary_params():
    assert N == 16
    assert H == 63
    assert D == 7
    assert HP == 9
    assert A == 12
    assert K == 14
    assert LG_W == 4
    assert W == 16
    assert M_BYTES == 30


def test_wots_len():
    assert LEN1 == 32
    assert LEN2 == 3
    assert LEN == 35


def test_key_sizes():
    assert PK_SIZE == 32
    assert SK_SIZE == 64


def test_sig_size():
    # R + FORS sig + HT sig = 16 + 2912 + 4928 = 7856
    assert SIG_SIZE == 7856


def test_digest_split_offsets():
    # md occupies bytes [0, MD_END)
    # idx_tree bytes [MD_END, TREE_END)
    # idx_leaf bytes [TREE_END, LEAF_END)
    assert MD_END == 21
    assert TREE_END == 28
    assert LEAF_END == 30
    assert LEAF_END == M_BYTES
