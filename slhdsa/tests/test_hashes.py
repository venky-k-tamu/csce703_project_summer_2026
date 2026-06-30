"""Tests for SLH-DSA hash function wrappers (slhdsa/hashes.py)."""

import hashlib

from slhdsa.hashes import F, H, H_msg, PRF, PRF_msg, T_l
from slhdsa.params import M_BYTES, N


def _shake256(data: bytes, out: int) -> bytes:
    return hashlib.shake_256(data).digest(out)


def _make_seed(tag: bytes) -> bytes:
    return hashlib.shake_256(tag).digest(N)


def test_F_matches_shake256():
    pk_seed = _make_seed(b"pk")
    adrs = bytearray(32)
    m1 = _make_seed(b"m1")
    expected = _shake256(bytes(pk_seed) + bytes(adrs) + bytes(m1), N)
    assert F(pk_seed, adrs, m1) == expected


def test_H_matches_shake256():
    pk_seed = _make_seed(b"pk")
    adrs = bytearray(32)
    m = _make_seed(b"left") + _make_seed(b"right")
    expected = _shake256(bytes(pk_seed) + bytes(adrs) + bytes(m), N)
    assert H(pk_seed, adrs, m) == expected


def test_T_l_matches_shake256():
    pk_seed = _make_seed(b"pk")
    adrs = bytearray(32)
    m = b"\xab" * (35 * N)   # 35-poly WOTS+ compression
    expected = _shake256(bytes(pk_seed) + bytes(adrs) + bytes(m), N)
    assert T_l(pk_seed, adrs, m) == expected


def test_PRF_matches_shake256():
    pk_seed = _make_seed(b"pk")
    sk_seed = _make_seed(b"sk")
    adrs = bytearray(32)
    expected = _shake256(bytes(pk_seed) + bytes(adrs) + bytes(sk_seed), N)
    assert PRF(pk_seed, sk_seed, adrs) == expected


def test_PRF_msg_matches_shake256():
    sk_prf = _make_seed(b"prf")
    opt_rand = _make_seed(b"rand")
    m = b"hello world"
    expected = _shake256(bytes(sk_prf) + bytes(opt_rand) + m, N)
    assert PRF_msg(sk_prf, opt_rand, m) == expected


def test_H_msg_output_length():
    r = _make_seed(b"r")
    pk_seed = _make_seed(b"pk")
    pk_root = _make_seed(b"root")
    m = b"message"
    out = H_msg(r, pk_seed, pk_root, m)
    assert len(out) == M_BYTES


def test_H_msg_matches_shake256():
    r = _make_seed(b"r2")
    pk_seed = _make_seed(b"pk2")
    pk_root = _make_seed(b"root2")
    m = b"test"
    expected = _shake256(bytes(r) + bytes(pk_seed) + bytes(pk_root) + m, M_BYTES)
    assert H_msg(r, pk_seed, pk_root, m) == expected


def test_hash_output_length():
    pk_seed = _make_seed(b"pk")
    adrs = bytearray(32)
    m = _make_seed(b"x")
    assert len(F(pk_seed, adrs, m)) == N
    assert len(H(pk_seed, adrs, m + m)) == N
    assert len(PRF(pk_seed, m, adrs)) == N
    assert len(PRF_msg(m, m, b"")) == N


def test_distinct_adrs_gives_distinct_output():
    pk_seed = _make_seed(b"pk")
    m = _make_seed(b"m")
    adrs1 = bytearray(32)
    adrs2 = bytearray(32)
    adrs2[0] = 1
    assert F(pk_seed, adrs1, m) != F(pk_seed, adrs2, m)
