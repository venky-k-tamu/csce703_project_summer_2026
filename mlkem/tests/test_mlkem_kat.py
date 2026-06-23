"""NIST ACVP KAT verification for ML-KEM-768.

Vectors filtered from upstream ACVP-Server JSON files. See
mlkem/tests/vectors/README.md for provenance.
"""

import json
from pathlib import Path

import pytest

from mlkem.mlkem import (
    _decaps_internal,
    _decapsulation_key_check,
    _encaps_internal,
    _encapsulation_key_check,
    _keygen_internal,
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
    func = group.get("function") or group.get("testType")
    return f"tg{group['tgId']}-{func}-tc{prompt['tcId']}"


KEYGEN_CASES = _pair("keyGen-prompt.json", "keyGen-expected.json")
ENCAPDECAP_CASES = _pair("encapDecap-prompt.json", "encapDecap-expected.json")


def _by_function(cases, name):
    return [c for c in cases if c[0].get("function") == name]


ENCAPS_CASES = _by_function(ENCAPDECAP_CASES, "encapsulation")
DECAPS_CASES = _by_function(ENCAPDECAP_CASES, "decapsulation")
ENC_KEY_CHECK_CASES = _by_function(ENCAPDECAP_CASES, "encapsulationKeyCheck")
DEC_KEY_CHECK_CASES = _by_function(ENCAPDECAP_CASES, "decapsulationKeyCheck")


def test_vector_counts():
    # Sanity that the filtered vector set is what we expect (see vectors/README.md).
    assert len(KEYGEN_CASES) == 25
    assert len(ENCAPS_CASES) == 25
    assert len(DECAPS_CASES) == 10
    assert len(ENC_KEY_CHECK_CASES) == 10
    assert len(DEC_KEY_CHECK_CASES) == 10


@pytest.mark.parametrize("case", KEYGEN_CASES, ids=_kat_id)
def test_kat_keygen(case):
    _, prompt, expected = case
    ek, dk = _keygen_internal(_hex(prompt["d"]), _hex(prompt["z"]))
    assert ek.hex().upper() == expected["ek"].upper()
    assert dk.hex().upper() == expected["dk"].upper()


@pytest.mark.parametrize("case", ENCAPS_CASES, ids=_kat_id)
def test_kat_encaps(case):
    _, prompt, expected = case
    K, c = _encaps_internal(_hex(prompt["ek"]), _hex(prompt["m"]))
    assert K.hex().upper() == expected["k"].upper()
    assert c.hex().upper() == expected["c"].upper()


@pytest.mark.parametrize("case", DECAPS_CASES, ids=_kat_id)
def test_kat_decaps(case):
    _, prompt, expected = case
    K = _decaps_internal(_hex(prompt["dk"]), _hex(prompt["c"]))
    assert K.hex().upper() == expected["k"].upper()


@pytest.mark.parametrize("case", ENC_KEY_CHECK_CASES, ids=_kat_id)
def test_kat_encapsulation_key_check(case):
    _, prompt, expected = case
    try:
        _encapsulation_key_check(_hex(prompt["ek"]))
        passed = True
    except ValueError:
        passed = False
    assert passed == expected["testPassed"]


@pytest.mark.parametrize("case", DEC_KEY_CHECK_CASES, ids=_kat_id)
def test_kat_decapsulation_key_check(case):
    _, prompt, expected = case
    try:
        _decapsulation_key_check(_hex(prompt["dk"]))
        passed = True
    except ValueError:
        passed = False
    assert passed == expected["testPassed"]
