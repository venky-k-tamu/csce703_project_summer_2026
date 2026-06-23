# ML-KEM / ML-DSA Implementation Plan

CSCE 701, Summer 2026 — Venky Kottapalli.

## Goal

Implement and verify **ML-KEM-768** (FIPS 203) from scratch in Python, then later
extend the same repository with **ML-DSA** (FIPS 204).

"Verify" here means:
1. **NIST ACVP Known-Answer-Test vectors** — the official functional-correctness
   bar. Passing the full ACVP vector set is the headline result.
2. **Property tests** — `Decaps(Encaps(ek)) == K` round-trip, implicit-rejection
   behavior on tampered ciphertexts, determinism from fixed seeds.

Not in scope:
- Constant-time / side-channel hardening.
- Performance optimization beyond what falls out of the natural algorithm
  expression (no packed-integer NTT, no Montgomery reduction, no Cython).
- Multiple parameter sets (only ML-KEM-768).
- Implementing Keccak from scratch — uses `hashlib`'s SHA3/SHAKE.

## Key decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Maps line-by-line onto FIPS 203 pseudocode; easy to read and audit. |
| Parameter set | ML-KEM-768 only | NIST's recommended default; n=256, q=3329, k=3, η₁=η₂=2, d_u=10, d_v=4. |
| Hash primitive | `hashlib` SHA3 / SHAKE | Lets us focus on lattice/NTT/K-PKE/ML-KEM logic, which is the interesting part. |
| Verification | NIST ACVP KATs + property tests | KATs are the standard correctness bar; property tests catch regressions cheaply. |
| Tests location | In-package (`mlkem/tests/`) | Keeps each algorithm's package self-contained; mirrors will work for `mldsa/`. |
| Shared code with ML-DSA | None up front | Different moduli (3329 vs 8380417) and different zetas mean NTT can't be naïvely shared. Factor only if duplication is verbatim. |

## Repository layout

```
mlkem/
  __init__.py
  params.py          # ML-KEM-768 constants
  bytes_bits.py      # Algorithms 3, 4
  serialize.py       # ByteEncode/Decode (Alg 5/6), Compress/Decompress
  ntt.py             # zetas, NTT, NTT^-1, BaseCaseMultiply, MultiplyNTTs
  sampling.py        # SampleNTT (SHAKE-128 rejection), SamplePolyCBD
  hashes.py          # PRF, H, J, G wrappers over hashlib
  kpke.py            # K-PKE.KeyGen / Encrypt / Decrypt (Alg 13-15)
  mlkem.py           # ML-KEM KeyGen / Encaps / Decaps (Alg 16-21) + §7 input checks
  tests/
    __init__.py
    test_bytes_bits.py
    test_serialize.py
    test_ntt.py
    test_sampling.py
    test_kpke.py
    test_mlkem_properties.py
    test_mlkem_kat.py
    vectors/                 # NIST ACVP JSON vectors
mldsa/                       # added later (FIPS 204)
docs/
  PLAN.md
  PROMPTS.md
pyproject.toml
.gitignore
README.md
```

`pyproject.toml` configures pytest discovery (`testpaths = ["mlkem/tests"]`) so
`pytest` from the repo root runs everything.

## Phased delivery

Each phase ends with a passing test suite and a commit.

### Phase 1 — Foundation ✅ (commit `e8cc502`)

- `mlkem/params.py` — ML-KEM-768 constants and derived sizes.
- `mlkem/bytes_bits.py` — `bits_to_bytes`, `bytes_to_bits` (Alg 3, 4).
- `mlkem/serialize.py` — `byte_encode(d, f)`, `byte_decode(d, b)`,
  `compress(d, x)`, `decompress(d, y)` (FIPS 203 §4.2.1).
- Tests: bit/byte round-trip, ByteEncode/Decode round-trip for d ∈ {1, 4, 10, 12},
  `Compress(Decompress(y)) == y` for all y in [0, 2ᵈ), lossy bound check,
  modular-reduction edge cases. **19/19 pass.**

### Phase 2 — NTT and sampling ✅ (commit `f978c1c`)

- `mlkem/hashes.py` — `H`, `J`, `G`, `prf` wrappers around SHA3/SHAKE, plus
  an incremental SHAKE-128 `XOF` stream that re-digests a growing prefix
  (hashlib has no streaming squeeze).
- `mlkem/ntt.py` — precomputed `ZETAS` / `GAMMAS` tables for ζ = 17 mod q
  in bit-reversed-7 order, `ntt(f)`, `intt(f)`, `base_case_multiply`,
  `multiply_ntts` (Alg 9–12).
- `mlkem/sampling.py` — `sample_ntt(seed)` (SHAKE-128 rejection sampler
  producing an NTT-domain polynomial) and `sample_poly_cbd(eta, B)`
  (centered binomial distribution).
- Tests: hashes match `hashlib` byte-for-byte; XOF prefix consistency
  across grow rounds; `ZETAS` leading values match FIPS 203 Appendix A
  and γᵢ = 17·ζᵢ² identity; NTT round-trip on random polynomials; NTT
  homomorphism vs naïve multiplication in ℤ_q[X]/(X²⁵⁶+1); CBD range
  checks and distribution sanity (mean ≈ 0, var ≈ η/2 over ~10k samples).
  **27 new tests.**

### Phase 3 — K-PKE ✅ (commit `3fc1801`)

- `mlkem/kpke.py` — `kpke_keygen(d)`, `kpke_encrypt(ek_pke, m, r)`,
  `kpke_decrypt(dk_pke, c)` mapping to FIPS 203 Algorithms 13–15.
- Tests: ek/dk/ct sizes match spec (1184 / 1152 / 1088 for ML-KEM-768);
  determinism from fixed seeds; 5 labeled-seed + 10 random-seed
  encrypt/decrypt round-trips (no decryption failures expected —
  ML-KEM-768's failure probability is ~2⁻¹³⁸); input-size validation.
  **12 new tests.**

### Phase 4 — ML-KEM with input checks ✅ (commit `88ca535`)

- `mlkem/mlkem.py` — public API: `keygen()`, `encaps(ek)`, `decaps(dk, c)`
  (re-exported from `mlkem` package root). Internal deterministic
  variants `_keygen_internal(d, z)`, `_encaps_internal(ek, m)`,
  `_decaps_internal(dk, c)` (Algorithms 16–18).
- Input checks: §7.2 encapsulation-key check (type + modulus via
  decode/re-encode round-trip), §7.3 decapsulation-key check (type +
  H(ek) hash check), and ciphertext type check.
- `decaps` implements **implicit rejection**: on c ≠ c' it returns
  J(z‖c), not an exception.
- Tests: ek/dk/ct sizes; 20-cycle random round-trip via the public API;
  dk layout (`dk_pke ‖ ek ‖ H(ek) ‖ z`); implicit rejection on tampered
  and random ciphertexts; each §7 check fires on intentionally corrupted
  input. **14 new tests.**

### Phase 5 — NIST ACVP KAT verification ✅ (commit `8f115ea`)

- Vendored NIST ACVP test vectors for ML-KEM-768, filtered from
  `usnistgov/ACVP-Server` (gen-val/json-files), saved to
  `mlkem/tests/vectors/{keyGen,encapDecap}-{prompt,expected}.json` with
  provenance documented in `mlkem/tests/vectors/README.md`.
- `mlkem/tests/test_mlkem_kat.py` — parses prompt/expected pairs, joins
  by (tgId, tcId), dispatches each function (keyGen / encapsulation /
  decapsulation / encapsulationKeyCheck / decapsulationKeyCheck) to the
  matching internal algorithm.
- **All 80 ML-KEM-768 KAT cases pass**: 25 keyGen + 25 encapsulation +
  10 decapsulation + 10 encapKeyCheck + 10 decapKeyCheck. This is the
  headline verification result.

## Final status

**153/153 tests pass.** The ML-KEM-768 implementation matches NIST's
official FIPS 203 vectors byte-for-byte. Next move is ML-DSA (FIPS 204),
or hand-off / writeup — see the addendum below.

## ML-DSA addendum (post-Phase 5)

When ML-DSA work begins, mirror the layout under `mldsa/` with its own
`mldsa/tests/` directory. Add `"mldsa/tests"` to `testpaths` in
`pyproject.toml`. At that point evaluate whether `bytes_bits.py` is
literally identical (likely yes) and whether anything else is worth lifting
into a shared `common/` package — but only on demonstrated duplication, not
speculation. Different ring (q = 8380417) means `ntt.py` and `sampling.py`
will be separate.
