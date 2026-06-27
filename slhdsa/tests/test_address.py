"""Tests for ADRS structure (slhdsa/address.py)."""

from slhdsa.address import (
    FORS_PRF,
    FORS_ROOTS,
    FORS_TREE,
    TREE,
    WOTS_HASH,
    WOTS_PK,
    WOTS_PRF,
    copy_adrs,
    get_key_pair_address,
    get_layer_address,
    get_tree_address,
    get_tree_height,
    get_tree_index,
    get_type,
    new_adrs,
    set_chain_address,
    set_hash_address,
    set_key_pair_address,
    set_layer_address,
    set_tree_address,
    set_tree_height,
    set_tree_index,
    set_type_and_clear,
)


def test_new_adrs_zeros():
    adrs = new_adrs()
    assert len(adrs) == 32
    assert adrs == bytearray(32)


def test_layer_roundtrip():
    adrs = new_adrs()
    set_layer_address(adrs, 6)
    assert get_layer_address(adrs) == 6


def test_tree_address_roundtrip():
    adrs = new_adrs()
    tree_val = (1 << 54) - 1  # max 54-bit value
    set_tree_address(adrs, tree_val)
    assert get_tree_address(adrs) == tree_val


def test_tree_address_padding():
    adrs = new_adrs()
    set_tree_address(adrs, 42)
    # Bytes [4:8] must be zero (padding)
    assert adrs[4:8] == b"\x00\x00\x00\x00"


def test_set_type_clears_type_specific():
    adrs = new_adrs()
    set_key_pair_address(adrs, 0xFF)
    set_type_and_clear(adrs, WOTS_HASH)
    assert get_type(adrs) == WOTS_HASH
    assert adrs[20:32] == b"\x00" * 12


def test_type_constants():
    assert WOTS_HASH == 0
    assert WOTS_PK == 1
    assert TREE == 2
    assert FORS_TREE == 3
    assert FORS_ROOTS == 4
    assert WOTS_PRF == 5
    assert FORS_PRF == 6


def test_key_pair_roundtrip():
    adrs = new_adrs()
    set_key_pair_address(adrs, 511)
    assert get_key_pair_address(adrs) == 511


def test_tree_height_and_index_roundtrip():
    adrs = new_adrs()
    set_tree_height(adrs, 9)
    set_tree_index(adrs, 123456)
    assert get_tree_height(adrs) == 9
    assert get_tree_index(adrs) == 123456


def test_copy_is_independent():
    adrs = new_adrs()
    set_layer_address(adrs, 3)
    copy = copy_adrs(adrs)
    set_layer_address(adrs, 0)
    assert get_layer_address(copy) == 3


def test_adrs_length_unchanged_after_all_sets():
    adrs = new_adrs()
    set_layer_address(adrs, 1)
    set_tree_address(adrs, 100)
    set_type_and_clear(adrs, FORS_TREE)
    set_key_pair_address(adrs, 5)
    set_tree_height(adrs, 3)
    set_tree_index(adrs, 7)
    assert len(adrs) == 32
