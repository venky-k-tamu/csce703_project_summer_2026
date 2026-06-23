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

Each phase ends with a passing test suite and a commit. Tasks are tracked in
`TaskList` (`#1`–`#5`).

### Phase 1 — Foundation ✅ (commit `e8cc502`)

- `mlkem/params.py` — ML-KEM-768 constants and derived sizes.
- `mlkem/bytes_bits.py` — `bits_to_bytes`, `bytes_to_bits` (Alg 3, 4).
- `mlkem/serialize.py` — `byte_encode(d, f)`, `byte_decode(d, b)`,
  `compress(d, x)`, `decompress(d, y)` (FIPS 203 §4.2.1).
- Tests: bit/byte round-trip, ByteEncode/Decode round-trip for d ∈ {1, 4, 10, 12},
  `Compress(Decompress(y)) == y` for all y in [0, 2ᵈ), lossy bound check,
  modular-reduction edge cases. **19/19 pass.**

### Phase 2 — NTT and sampling

- `mlkem/hashes.py` — `prf_eta(eta, s, b)`, `H`, `J`, `G` wrappers around SHA3/SHAKE.
- `mlkem/ntt.py` — precomputed zetas table (powers of ζ = 17 mod 3329 in
  bit-reversed order), `ntt(f)`, `intt(f)`, `base_case_multiply`, `multiply_ntts`.
- `mlkem/sampling.py` — `sample_ntt(B)` (SHAKE-128 rejection sampler producing
  an NTT-domain polynomial) and `sample_poly_cbd(eta, B)` (centered binomial
  distribution sampler).
- Tests: NTT round-trip (`intt(ntt(f)) == f`), NTT homomorphism
  (`multiply_ntts(ntt(a), ntt(b)) == ntt(a*b mod X^256+1)`), centered-binomial
  distribution sanity, fixed-seed `sample_ntt` output.

### Phase 3 — K-PKE

- `mlkem/kpke.py` — `kpke_keygen(d)`, `kpke_encrypt(ek_pke, m, r)`,
  `kpke_decrypt(dk_pke, c)` mapping to FIPS 203 Algorithms 13–15.
- Tests: deterministic-seed round-trip
  (`kpke_decrypt(dk, kpke_encrypt(ek, m, r)) == m` w.h.p.), key/ct sizes match
  spec constants.

### Phase 4 — ML-KEM with input checks

- `mlkem/mlkem.py` — public API: `keygen()`, `encaps(ek)`, `decaps(dk, c)`.
  Internal deterministic variants `_keygen_internal(d, z)`,
  `_encaps_internal(ek, m)`, `_decaps_internal(dk, c)` (Algorithms 16–18).
  Includes FIPS 203 §7.2 (modulus check on `ek`) and §7.3 (ciphertext type
  check) input validation.
- Tests: 100× random round-trip; tampered-ciphertext returns the implicit
  rejection key (not an exception); `encaps(ek)` is deterministic given a fixed
  seed via the internal variant.

### Phase 5 — NIST ACVP KAT verification

- Vendor NIST ACVP test vectors for ML-KEM-768
  (`mlkem/tests/vectors/keygen.json`, `encapDecap.json`).
- `mlkem/tests/test_mlkem_kat.py` — parse and run each vector against the
  implementation. This is the headline "verified" result.

## ML-DSA addendum (post-Phase 5)

When ML-DSA work begins, mirror the layout under `mldsa/` with its own
`mldsa/tests/` directory. Add `"mldsa/tests"` to `testpaths` in
`pyproject.toml`. At that point evaluate whether `bytes_bits.py` is
literally identical (likely yes) and whether anything else is worth lifting
into a shared `common/` package — but only on demonstrated duplication, not
speculation. Different ring (q = 8380417) means `ntt.py` and `sampling.py`
will be separate.
