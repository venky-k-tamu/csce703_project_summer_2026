# NIST ACVP test vectors for SLH-DSA-SHAKE-128s

Filtered from <https://github.com/usnistgov/ACVP-Server>
(`gen-val/json-files/SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205/`).

The upstream files cover all twelve SLH-DSA parameter sets (SHA2/SHAKE
× 128/192/256 × s/f) and two signature interfaces (external and
internal). The copies here are filtered to **SLH-DSA-SHAKE-128s only**,
and within that to the **external signature interface** (i.e. NOT the
internal interface, which is a separate API where the caller passes
the pre-formatted message directly to the internal sign/verify
routines — analogous to ML-DSA's externalMu interface, and likewise
not yet implemented here):

| File pair | Source tgIds | What it tests |
|---|---|---|
| `keyGen-{prompt,expected}.json` | 2 | KeyGen AFT (10 cases) |
| `sigGen-{prompt,expected}.json` | 25, 26, 61, 62 | Pure SLH-DSA + HashSLH-DSA, deterministic and hedged (38 cases) |
| `sigVer-{prompt,expected}.json` | 25, 26 | Pure SLH-DSA + HashSLH-DSA verification (28 cases) |

Total: **76 SLH-DSA-SHAKE-128s KAT cases**.

Field mapping:
- keyGen: `skSeed`/`skPrf`/`pkSeed` → `_keygen_internal(sk_seed, sk_prf, pk_seed)`.
- sigGen/sigVer: `message` is the raw, pre-hash message; for HashSLH-DSA
  groups (`hashAlg` present) it is hashed locally via `_PREHASH_FUNCTIONS`
  before building M' with `_format_M_prime`. Deterministic groups omit
  `additionalRandomness` — `opt_rand` is then `PK.seed` (`sk[2N:3N]`),
  matching this implementation's `sign(..., randomize=False)`. Hedged
  groups supply `additionalRandomness` directly as `opt_rand`.

Internal-interface groups (tgId 34/70 for sigGen, tgId 34 for sigVer)
are deliberately skipped, same rationale as ML-DSA's externalMu skip.

Refresh procedure: re-fetch the six upstream files from
`SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205/{prompt,expectedResults}.json`,
filter to `parameterSet == "SLH-DSA-SHAKE-128s"` and
`signatureInterface != "internal"`, and re-run
`pytest slhdsa/tests/test_slhdsa_kat.py`.
