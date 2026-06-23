# NIST ACVP test vectors for ML-KEM-768

These JSON files are derived from the NIST CAVP ACVP-Server repository:

- Source: <https://github.com/usnistgov/ACVP-Server>
  - `gen-val/json-files/ML-KEM-keyGen-FIPS203/` → `keyGen-prompt.json` + `keyGen-expected.json`
  - `gen-val/json-files/ML-KEM-encapDecap-FIPS203/` → `encapDecap-prompt.json` + `encapDecap-expected.json`

The upstream files contain test groups for all three ML-KEM parameter sets
(512, 768, 1024). The copies here have been **filtered** to only the
ML-KEM-768 groups:

- `keyGen-*.json`: tgId 2 (25 AFT cases).
- `encapDecap-*.json`: tgId 2 (encapsulation, 25 cases), tgId 5
  (decapsulation, 10 cases), tgId 9 (decapsulationKeyCheck, 10 cases),
  tgId 10 (encapsulationKeyCheck, 10 cases).

Total: 80 ML-KEM-768 KAT cases. All other content (`vsId`, `algorithm`,
`mode`, `revision`, `isSample`) is preserved verbatim from the upstream
prompts/expectedResults.

Refresh procedure (if NIST publishes new vectors): re-fetch the four
files from the upstream URLs above, filter via the snippet in the Phase 5
commit message, and re-run `pytest mlkem/tests/test_mlkem_kat.py`.
