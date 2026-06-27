"""Tests for XMSS tree operations (slhdsa/xmss.py)."""

import hashlib

import pytest

from slhdsa.address import new_adrs, set_layer_address, set_tree_address
from slhdsa.params import HP, LEN, N
from slhdsa.xmss import xmss_node, xmss_pk_from_sig, xmss_pkgen, xmss_sign


def _seed(tag: bytes) -> bytes:
    return hashlib.shake_256(tag).digest(N)


def _make_adrs(layer: int = 0, tree: int = 0) -> bytearray:
    adrs = new_adrs()
    set_layer_address(adrs, layer)
    set_tree_address(adrs, tree)
    return adrs


def test_xmss_node_leaf_length():
    adrs = _make_adrs()
    node = xmss_node(_seed(b"sk"), 0, 0, _seed(b"pk"), adrs)
    assert len(node) == N


def test_xmss_node_root_length():
    adrs = _make_adrs()
    root = xmss_node(_seed(b"sk"), 0, HP, _seed(b"pk"), adrs)
    assert len(root) == N


def test_xmss_pkgen_matches_node():
    sk_seed = _seed(b"sk-pg")
    pk_seed = _seed(b"pk-pg")
    adrs1 = _make_adrs()
    adrs2 = _make_adrs()
    assert xmss_pkgen(sk_seed, pk_seed, adrs1) == xmss_node(sk_seed, 0, HP, pk_seed, adrs2)


def test_xmss_sign_size():
    adrs = _make_adrs()
    sig = xmss_sign(_seed(b"m"), _seed(b"sk"), 0, _seed(b"pk"), adrs)
    assert len(sig) == (LEN + HP) * N


def test_xmss_sign_verify_leaf_0():
    sk_seed = _seed(b"sk-v0")
    pk_seed = _seed(b"pk-v0")
    m = _seed(b"m-v0")
    adrs1 = _make_adrs()
    adrs2 = _make_adrs()
    root = xmss_pkgen(sk_seed, pk_seed, adrs1)
    sig = xmss_sign(m, sk_seed, 0, pk_seed, adrs2)
    recovered = xmss_pk_from_sig(0, sig, m, pk_seed, _make_adrs())
    assert recovered == root


@pytest.mark.parametrize("idx", [0, 1, 2, 5, (1 << HP) - 1])
def test_xmss_sign_verify_various_leaf_indices(idx):
    sk_seed = _seed(b"sk-vi")
    pk_seed = _seed(b"pk-vi")
    m = _seed(b"m-vi")
    root = xmss_pkgen(sk_seed, pk_seed, _make_adrs())
    sig = xmss_sign(m, sk_seed, idx, pk_seed, _make_adrs())
    recovered = xmss_pk_from_sig(idx, sig, m, pk_seed, _make_adrs())
    assert recovered == root


def test_xmss_wrong_leaf_fails():
    sk_seed = _seed(b"sk-wl")
    pk_seed = _seed(b"pk-wl")
    m = _seed(b"m-wl")
    root = xmss_pkgen(sk_seed, pk_seed, _make_adrs())
    sig = xmss_sign(m, sk_seed, 0, pk_seed, _make_adrs())
    bad = xmss_pk_from_sig(1, sig, m, pk_seed, _make_adrs())
    assert bad != root


def test_xmss_wrong_message_fails():
    sk_seed = _seed(b"sk-wm")
    pk_seed = _seed(b"pk-wm")
    m = _seed(b"m-wm")
    root = xmss_pkgen(sk_seed, pk_seed, _make_adrs())
    sig = xmss_sign(m, sk_seed, 0, pk_seed, _make_adrs())
    bad = xmss_pk_from_sig(0, sig, _seed(b"wrong"), pk_seed, _make_adrs())
    assert bad != root
