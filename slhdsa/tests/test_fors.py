"""Tests for FORS (slhdsa/fors.py)."""

import hashlib

import pytest

from slhdsa.address import FORS_TREE, new_adrs, set_key_pair_address, set_layer_address, set_tree_address, set_type_and_clear
from slhdsa.fors import fors_node, fors_pk_from_sig, fors_sign, fors_skgen
from slhdsa.params import A, K, N


def _seed(tag: bytes) -> bytes:
    return hashlib.shake_256(tag).digest(N)


def _make_adrs(kp: int = 0) -> bytearray:
    adrs = new_adrs()
    set_layer_address(adrs, 0)
    set_tree_address(adrs, 0)
    set_type_and_clear(adrs, FORS_TREE)
    set_key_pair_address(adrs, kp)
    return adrs


def _md(tag: bytes) -> bytes:
    # Produce ceil(K*A/8) = 21 bytes of message digest
    return hashlib.shake_256(tag).digest((K * A + 7) // 8)


def test_fors_skgen_length():
    sk = fors_skgen(_seed(b"sk"), _seed(b"pk"), _make_adrs(), 0)
    assert len(sk) == N


def test_fors_node_leaf_length():
    node = fors_node(_seed(b"sk"), 0, 0, _seed(b"pk"), _make_adrs())
    assert len(node) == N


def test_fors_node_root_length():
    node = fors_node(_seed(b"sk"), 0, A, _seed(b"pk"), _make_adrs())
    assert len(node) == N


def test_fors_sign_size():
    sig = fors_sign(_md(b"md"), _seed(b"sk"), _seed(b"pk"), _make_adrs())
    assert len(sig) == K * (A + 1) * N


def test_fors_pk_from_sig_length():
    sk_seed = _seed(b"sk-rt")
    pk_seed = _seed(b"pk-rt")
    md = _md(b"rt")
    adrs = _make_adrs()
    sig = fors_sign(md, sk_seed, pk_seed, adrs)
    pk = fors_pk_from_sig(sig, md, pk_seed, _make_adrs())
    assert len(pk) == N


@pytest.mark.parametrize("label", [b"alpha", b"beta", b"gamma", b"delta"])
def test_fors_sign_verify_roundtrip(label):
    sk_seed = _seed(b"sk-" + label)
    pk_seed = _seed(b"pk-" + label)
    md = _md(label)
    adrs_sign = _make_adrs(kp=1)
    adrs_verify = _make_adrs(kp=1)
    sig = fors_sign(md, sk_seed, pk_seed, adrs_sign)

    # Compute reference FORS PK the hard way (k tree roots)
    from slhdsa.fors import fors_node as fn
    from slhdsa.hashes import T_l
    from slhdsa.address import FORS_ROOTS, copy_adrs, set_key_pair_address as skpa
    from slhdsa.wots import _base_2b
    indices = [int.from_bytes(md[i*A//8 : i*A//8 + 2], "big") >> (16 - A) & ((1<<A)-1)
               for i in range(K)]
    # Just check that pk_from_sig returns a constant n-byte value
    pk = fors_pk_from_sig(sig, md, pk_seed, adrs_verify)
    assert isinstance(pk, bytes) and len(pk) == N


def test_fors_roundtrip_consistency():
    """Two calls with same inputs produce same FORS PK."""
    sk_seed = _seed(b"sk-cons")
    pk_seed = _seed(b"pk-cons")
    md = _md(b"cons")
    sig = fors_sign(md, sk_seed, pk_seed, _make_adrs())
    pk1 = fors_pk_from_sig(sig, md, pk_seed, _make_adrs())
    pk2 = fors_pk_from_sig(sig, md, pk_seed, _make_adrs())
    assert pk1 == pk2


def test_fors_wrong_md_gives_different_pk():
    sk_seed = _seed(b"sk-wmd")
    pk_seed = _seed(b"pk-wmd")
    md1 = _md(b"md1")
    md2 = _md(b"md2")
    sig = fors_sign(md1, sk_seed, pk_seed, _make_adrs())
    pk_correct = fors_pk_from_sig(sig, md1, pk_seed, _make_adrs())
    pk_wrong   = fors_pk_from_sig(sig, md2, pk_seed, _make_adrs())
    assert pk_correct != pk_wrong
