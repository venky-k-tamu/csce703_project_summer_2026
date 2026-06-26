"""NIST ACVP KAT verification for ML-DSA-65.

Vectors filtered from upstream ACVP-Server JSON files. See
mldsa/tests/vectors/README.md for provenance.
"""

import json
from pathlib import Path

import pytest

from mldsa.mldsa import (
    _PREHASH_FUNCTIONS,
    _format_M_prime,
    _keygen_internal,
    _sign_internal,
    _verify_internal,
)

VECTORS_DIR = Path(__file__).parent / "vectors"


def _load(name):
    with open(VECTORS_DIR / name) as f:
        return json.load(f)


def _hex(s):
    return bytes.fromhex(s)


def _pair(prompt_file, expected_file):
    prompts = _load(prompt_file)
    expected = _load(expected_file)
    exp_by_tg = {g["tgId"]: g for g in expected["testGroups"]}
    out = []
    for pg in prompts["testGroups"]:
        eg = exp_by_tg[pg["tgId"]]
        exp_by_tc = {t["tcId"]: t for t in eg["tests"]}
        for pt in pg["tests"]:
            out.append((pg, pt, exp_by_tc[pt["tcId"]]))
    return out


def _kat_id(triple):
    group, prompt, _ = triple
    bits = [f"tg{group['tgId']}", f"tc{prompt['tcId']}"]
    if "preHash" in group:
        bits.append(group["preHash"])
    if group.get("deterministic"):
        bits.append("det")
    elif "deterministic" in group:
        bits.append("hedged")
    return "-".join(bits)


KEYGEN_CASES = _pair("keyGen-prompt.json", "keyGen-expected.json")
SIG_GEN_CASES = _pair("sigGen-prompt.json", "sigGen-expected.json")
SIG_VER_CASES = _pair("sigVer-prompt.json", "sigVer-expected.json")


def _prehash_oid_for(group, prompt):
    """Return OID bytes for HashML-DSA groups, None for pure ML-DSA."""
    if group.get("preHash") == "preHash":
        oid, _hash = _PREHASH_FUNCTIONS[prompt["hashAlg"]]
        return oid
    return None


def _hash_message(group, prompt, message):
    if group.get("preHash") == "preHash":
        _oid, hash_fn = _PREHASH_FUNCTIONS[prompt["hashAlg"]]
        return hash_fn(message)
    return message


# ----- counts sanity check ---------------------------------------------------


def test_vector_counts():
    assert len(KEYGEN_CASES) == 25
    assert len(SIG_GEN_CASES) == 60
    assert len(SIG_VER_CASES) == 30


# ----- keyGen ----------------------------------------------------------------


@pytest.mark.parametrize("case", KEYGEN_CASES, ids=_kat_id)
def test_kat_keygen(case):
    _, prompt, expected = case
    pk, sk = _keygen_internal(_hex(prompt["seed"]))
    assert pk.hex().upper() == expected["pk"].upper()
    assert sk.hex().upper() == expected["sk"].upper()


# ----- sigGen ----------------------------------------------------------------


@pytest.mark.parametrize("case", SIG_GEN_CASES, ids=_kat_id)
def test_kat_sig_gen(case):
    group, prompt, expected = case
    sk = _hex(prompt["sk"])
    ctx = _hex(prompt.get("context", ""))
    M = _hex(prompt["message"])
    M_eff = _hash_message(group, prompt, M)
    M_prime = _format_M_prime(M_eff, ctx, prehash_oid=_prehash_oid_for(group, prompt))
    rnd = _hex(prompt["rnd"]) if "rnd" in prompt else b"\x00" * 32
    sig = _sign_internal(sk, M_prime, rnd)
    assert sig.hex().upper() == expected["signature"].upper()


# ----- sigVer ----------------------------------------------------------------


@pytest.mark.parametrize("case", SIG_VER_CASES, ids=_kat_id)
def test_kat_sig_ver(case):
    group, prompt, expected = case
    pk = _hex(prompt["pk"])
    ctx = _hex(prompt.get("context", ""))
    M = _hex(prompt["message"])
    sig = _hex(prompt["signature"])
    M_eff = _hash_message(group, prompt, M)
    M_prime = _format_M_prime(M_eff, ctx, prehash_oid=_prehash_oid_for(group, prompt))
    assert _verify_internal(pk, M_prime, sig) == expected["testPassed"]
