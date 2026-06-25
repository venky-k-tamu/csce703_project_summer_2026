"""Tests for WOTS+ (slhdsa/wots.py)."""

import hashlib

import pytest

from slhdsa.address import WOTS_HASH, new_adrs, set_key_pair_address, set_layer_address, set_type_and_clear
from slhdsa.params import LEN, N
from slhdsa.wots import wots_pk_from_sig, wots_pkgen, wots_sign


def _seed(tag: bytes) -> bytes:
    return hashlib.shake_256(tag).digest(N)


def _make_adrs(kp: int = 0, layer: int = 0) -> bytearray:
    adrs = new_adrs()
    set_layer_address(adrs, layer)
    set_type_and_clear(adrs, WOTS_HASH)
    set_key_pair_address(adrs, kp)
    return adrs


def test_wots_sign_size():
    adrs = _make_adrs()
    sig = wots_sign(_seed(b"m"), _seed(b"sk"), _seed(b"pk"), adrs)
    assert len(sig) == LEN * N


def test_wots_pkgen_size():
    adrs = _make_adrs()
    pk = wots_pkgen(_seed(b"sk"), _seed(b"pk"), adrs)
    assert len(pk) == N


def test_wots_pk_from_sig_size():
    adrs = _make_adrs()
    sk_seed = _seed(b"sk")
    pk_seed = _seed(b"pk")
    m = _seed(b"msg")
    sig = wots_sign(m, sk_seed, pk_seed, adrs)
    recovered = wots_pk_from_sig(sig, m, pk_seed, adrs)
    assert len(recovered) == N


def test_wots_sign_verify_roundtrip():
    sk_seed = _seed(b"sk-rt")
    pk_seed = _seed(b"pk-rt")
    m = _seed(b"msg-rt")
    adrs = _make_adrs(kp=0)
    pk_direct = wots_pkgen(sk_seed, pk_seed, adrs)
    sig = wots_sign(m, sk_seed, pk_seed, adrs)
    pk_recovered = wots_pk_from_sig(sig, m, pk_seed, adrs)
    assert pk_recovered == pk_direct


@pytest.mark.parametrize("label", [b"a", b"b", b"c", b"d", b"e"])
def test_wots_roundtrip_multiple_messages(label):
    sk_seed = _seed(b"sk-" + label)
    pk_seed = _seed(b"pk-" + label)
    m = _seed(b"m-" + label)
    adrs = _make_adrs(kp=1)
    pk = wots_pkgen(sk_seed, pk_seed, adrs)
    sig = wots_sign(m, sk_seed, pk_seed, adrs)
    assert wots_pk_from_sig(sig, m, pk_seed, adrs) == pk


def test_wots_sig_covers_message():
    sk_seed = _seed(b"sk2")
    pk_seed = _seed(b"pk2")
    m1 = _seed(b"msg1")
    m2 = _seed(b"msg2")
    adrs = _make_adrs(kp=0)
    pk = wots_pkgen(sk_seed, pk_seed, adrs)
    sig = wots_sign(m1, sk_seed, pk_seed, adrs)
    # Signature on m1 should NOT verify for m2
    recovered = wots_pk_from_sig(sig, m2, pk_seed, adrs)
    assert recovered != pk


def test_wots_deterministic():
    sk_seed = _seed(b"det-sk")
    pk_seed = _seed(b"det-pk")
    m = _seed(b"det-m")
    adrs = _make_adrs(kp=3)
    assert wots_sign(m, sk_seed, pk_seed, adrs) == wots_sign(m, sk_seed, pk_seed, adrs)
    assert wots_pkgen(sk_seed, pk_seed, adrs) == wots_pkgen(sk_seed, pk_seed, adrs)
