"""NIST ACVP KAT verification for SLH-DSA-SHAKE-128s.

Vectors filtered from upstream ACVP-Server JSON files. See
slhdsa/tests/vectors/README.md for provenance.
"""

import json
from pathlib import Path

import pytest

from slhdsa.params import N
from slhdsa.slhdsa import (
    _format_M_prime,
    _keygen_internal,
    _PREHASH_FUNCTIONS,
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
    if "hashAlg" in prompt:
        bits.append(prompt["hashAlg"])
    bits.append("hedged" if "additionalRandomness" in prompt else "det")
    return "-".join(bits)


KEYGEN_CASES = _pair("keyGen-prompt.json", "keyGen-expected.json")
SIG_GEN_CASES = _pair("sigGen-prompt.json", "sigGen-expected.json")
SIG_VER_CASES = _pair("sigVer-prompt.json", "sigVer-expected.json")


def _prehash_oid_for(prompt):
    """Return OID bytes for HashSLH-DSA cases, None for pure SLH-DSA."""
    if "hashAlg" in prompt:
        oid, _hash = _PREHASH_FUNCTIONS[prompt["hashAlg"]]
        return oid
    return None


def _hash_message(prompt, message):
    if "hashAlg" in prompt:
        _oid, hash_fn = _PREHASH_FUNCTIONS[prompt["hashAlg"]]
        return hash_fn(message)
    return message


# ----- counts sanity check ---------------------------------------------------


def test_vector_counts():
    assert len(KEYGEN_CASES) == 10
    assert len(SIG_GEN_CASES) == 38
    assert len(SIG_VER_CASES) == 28


# ----- keyGen ----------------------------------------------------------------


@pytest.mark.parametrize("case", KEYGEN_CASES, ids=_kat_id)
def test_kat_keygen(case):
    _, prompt, expected = case
    pk, sk = _keygen_internal(_hex(prompt["skSeed"]), _hex(prompt["skPrf"]), _hex(prompt["pkSeed"]))
    assert pk.hex().upper() == expected["pk"].upper()
    assert sk.hex().upper() == expected["sk"].upper()


# ----- sigGen ----------------------------------------------------------------


@pytest.mark.parametrize("case", SIG_GEN_CASES, ids=_kat_id)
def test_kat_sig_gen(case):
    _, prompt, expected = case
    sk = _hex(prompt["sk"])
    ctx = _hex(prompt.get("context", ""))
    m = _hex(prompt["message"])
    m_eff = _hash_message(prompt, m)
    m_prime = _format_M_prime(m_eff, ctx, prehash_oid=_prehash_oid_for(prompt))
    if "additionalRandomness" in prompt:
        opt_rand = _hex(prompt["additionalRandomness"])
    else:
        opt_rand = sk[2 * N : 3 * N]  # deterministic: opt_rand = PK.seed
    sig = _sign_internal(m_prime, sk, opt_rand)
    assert sig.hex().upper() == expected["signature"].upper()


# ----- sigVer ----------------------------------------------------------------


@pytest.mark.parametrize("case", SIG_VER_CASES, ids=_kat_id)
def test_kat_sig_ver(case):
    _, prompt, expected = case
    pk = _hex(prompt["pk"])
    ctx = _hex(prompt.get("context", ""))
    m = _hex(prompt["message"])
    sig = _hex(prompt["signature"])
    m_eff = _hash_message(prompt, m)
    m_prime = _format_M_prime(m_eff, ctx, prehash_oid=_prehash_oid_for(prompt))
    assert _verify_internal(m_prime, sig, pk) == expected["testPassed"]
