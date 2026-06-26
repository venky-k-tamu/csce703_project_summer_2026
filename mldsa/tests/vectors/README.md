# NIST ACVP test vectors for ML-DSA-65

Filtered from <https://github.com/usnistgov/ACVP-Server>
(`gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/`).

The upstream files cover all three ML-DSA parameter sets (44, 65, 87)
and three signature interfaces (pure ML-DSA, HashML-DSA, externalMu).
The copies here are filtered to **ML-DSA-65 only**, and within ML-DSA-65
to the **external-signature-interface** groups (i.e. NOT the externalMu
interface, which is a separate signing API for callers that
pre-compute μ):

| File pair | Source tgIds | What it tests |
|---|---|---|
| `keyGen-{prompt,expected}.json` | 2 | KeyGen AFT (25 cases) |
| `sigGen-{prompt,expected}.json` | 3, 4, 15, 16 | Pure ML-DSA + HashML-DSA, deterministic and hedged (60 cases) |
| `sigVer-{prompt,expected}.json` | 3, 4 | Pure ML-DSA + HashML-DSA verification (30 cases) |

Total: **115 ML-DSA-65 KAT cases**.

externalMu groups (`signatureInterface == "internal"`) are deliberately
skipped — they exercise the "caller supplies μ" API which is a separate
public function that hasn't been implemented yet.

Refresh procedure: re-fetch the six upstream files, run the
filter snippet from the Phase 5 commit message against `/tmp/mldsa-kat/`,
and re-run `pytest mldsa/tests/test_mldsa_kat.py`.
