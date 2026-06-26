# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project context

CSCE 701 course project (Summer 2026): a from-scratch Python reference
implementation of **ML-KEM-768** (FIPS 203) *and* **ML-DSA-65** (FIPS 204),
sharing a small `common/` package for the bit/byte primitives. The
implementation prioritizes **spec fidelity** over performance: code is
meant to be auditable against the FIPS pseudocode line-by-line.

**Status**: both algorithms are complete and verified.

- **ML-KEM-768**: 80 NIST ACVP KAT cases (keyGen, encapsulation,
  decapsulation, encapsulationKeyCheck, decapsulationKeyCheck) + 73
  in-house tests = 153/153 pass.
- **ML-DSA-65**: 115 NIST ACVP KAT cases (keyGen + pure-ML-DSA and
  HashML-DSA sigGen/sigVer, deterministic + hedged) + 119 in-house tests
  = 234/234 pass.
- **Grand total: 387/387 tests, 195 of them NIST ACVP KATs.**

KAT vectors live in `mlkem/tests/vectors/` and `mldsa/tests/vectors/`.

`docs/PLAN.md` is the authoritative plan (phases, decisions, layout).
`docs/PROMPTS.md` is the chronological record of design choices.

## Commands

Dev dependencies (pytest + hypothesis) are not yet a managed install — install once with:

```
python3 -m pip install --user pytest hypothesis
```

Test commands (run from repo root; `pyproject.toml` sets `testpaths`):

```
python3 -m pytest                                                  # full suite (mlkem + mldsa)
python3 -m pytest mlkem/tests/                                     # ML-KEM only
python3 -m pytest mldsa/tests/                                     # ML-DSA only
python3 -m pytest mldsa/tests/test_mldsa_kat.py -v                 # one file
python3 -m pytest mldsa/tests/test_mldsa_kat.py::test_kat_keygen -v  # one test
python3 -m pytest -k "kat and keygen"                              # by keyword
```

There is no build, lint, or formatter configured. Python 3.10+ required
(uses PEP 604 typing and `pow(x, -1, m)` modular inverse).

## Architecture

The repo has three top-level Python packages: `common/` (truly shared
primitives), `mlkem/` (FIPS 203 ML-KEM-768), and `mldsa/` (FIPS 204
ML-DSA-65). Each algorithm package's modules form a clean dependency
stack — every layer only uses things below it.

### ML-KEM dependency stack (FIPS 203)

```
mlkem.py            KeyGen/Encaps/Decaps + §7 input checks — FIPS 203 §6, §7
kpke.py             K-PKE KeyGen/Encrypt/Decrypt — FIPS 203 §5
sampling.py         SampleNTT (Alg 7), SamplePolyCBD (Alg 8)
ntt.py              ZETAS/GAMMAS, NTT, NTT⁻¹, MultiplyNTTs (Alg 9–12)
hashes.py           H, J, G, PRF_η, streaming SHAKE-128 XOF
serialize.py        ByteEncode/Decode (Alg 5/6), Compress/Decompress
bytes_bits.py       Re-exports common.bytes_bits
params.py           ML-KEM-768 constants (N=256, Q=3329, K=3, η₁=η₂=2, d_u=10, d_v=4)
```

### ML-DSA dependency stack (FIPS 204)

```
mldsa.py            KeyGen/Sign/Verify, HashML-DSA, public API — FIPS 204 §5, §6
sampling.py         RejNTTPoly, RejBoundedPoly, ExpandA/S/Mask, SampleInBall (Alg 14, 15, 29–34)
encoding.py         SimpleBitPack/BitPack/HintBitPack + pk/sk/sig/w1 encoders (Alg 16–28)
rounding.py         Power2Round, Decompose, HighBits/LowBits, MakeHint/UseHint (Alg 35–40)
ntt.py              ZETAS, NTT, NTT⁻¹, multiply_ntts (Alg 41, 42, pointwise)
hashes.py           H = SHAKE-256, G = SHAKE-128, streaming XOF128/XOF256
conversions.py      IntegerToBits, BitsToInteger, IntegerToBytes (Alg 9–11)
params.py           ML-DSA-65 constants (N=256, Q=8380417, K=6, L=5, η=4, τ=49, γ₁=2¹⁹, γ₂=(q-1)/32, ω=55)
```

### Shared

```
common/bytes_bits.py    BitsToBytes / BytesToBits — identical in FIPS 203 §4.2.1 and FIPS 204 §4.2
```

Each Python module maps to a specific FIPS section — when editing, keep
the algorithm-to-function mapping intact and reference algorithm numbers
in docstrings.

### ML-KEM ring and NTT

Working ring is **R_q = ℤ_q[X]/(X²⁵⁶ + 1)** with q = 3329. ζ = 17 is a
primitive 256-th root of unity mod q (NOT a 512-th root), so the NTT
factors X²⁵⁶ + 1 into **128 quadratic factors**, not 256 linear ones.
Therefore:

- `ntt(f)` returns a length-256 list, but it is laid out as 128 pairs
  (â_{2i}, â_{2i+1}), each representing f mod (X² − γᵢ).
- Pointwise multiplication uses `multiply_ntts` / `base_case_multiply`,
  **not** an element-by-element product.
- `ZETAS[k] = ζ^{BitRev_7(k)} mod q`; `GAMMAS[i] = ζ^{2·BitRev_7(i)+1} mod q`.

### ML-DSA ring and NTT

Working ring is **R_q = ℤ_q[X]/(X²⁵⁶ + 1)** with q = 8380417 = 2²³ − 2¹³ + 1.
ζ = 1753 is a primitive **512-th** root of unity mod q (verified by the
ζ²⁵⁶ ≡ −1 mod q test), so X²⁵⁶ + 1 factors into 256 *linear* factors.
The NTT is **fully diagonal** — `multiply_ntts` is element-wise, with no
base-case multiplication needed. `ZETAS[k] = ζ^{BitRev_8(k)} mod q`,
indexed 0..255, and 256⁻¹ mod q = 8347681.

### Matrix indexing

- **ML-KEM**: `Â[i][j] = SampleNTT(ρ ‖ j ‖ i)` — byte order **(j, i)** per
  FIPS 203 Algorithm 13 line 5. Encrypt multiplies by `Âᵀ`, KeyGen by Â.
- **ML-DSA**: `Â[r][s] = SampleNTT(ρ ‖ s ‖ r)` — same **(col, row)** byte
  order pattern, per FIPS 204 Algorithm 32. Matrix is K × L (rows × cols).

If KATs fail after a change, the (col, row) vs (row, col) byte order is
the first thing to recheck in both packages.

### Centered ℓ∞ norm pitfall (ML-DSA)

`_inf_norm_poly` in `mldsa/mldsa.py` must canonicalize inputs from
*either* signed (`low_bits` returns r₀ ∈ (−γ₂, γ₂]) *or* mod-q ([0, q))
form before taking absolute value. The naïve `max(min(c, q−c))` formula
silently drops the negative side of signed inputs and broke ~2.5% of
random round-trips before the fix. KATs eventually caught it; property
tests with `os.urandom` did before then. When adding new norm-check call
sites, do not "simplify" this back to the naïve form.

### Hashes vs XOF

Both packages expose fixed-output hash wrappers and an incremental
streaming XOF for the rejection samplers. `hashlib`'s SHAKE has no
incremental squeeze API, so the streaming XOFs re-digest a growing
prefix on demand. This is correct but quadratic in worst-case reads —
don't "optimize" it unless you have a measured reason.

## Conventions

- **Tests live in-package** under `mlkem/tests/` and `mldsa/tests/`,
  not a top-level `tests/` directory.
- **`common/` only contains demonstrated duplication.** Today it's just
  `bytes_bits.py` because FIPS 203 §4.2.1 and FIPS 204 §4.2 specify
  identical algorithms. Different moduli (3329 vs 8380417) and different
  zetas mean NTT / sampling / encoding stay per-package. Resist the urge
  to lift speculatively shared utilities.
- **No constant-time / no perf optimizations.** Explicit non-goal per
  `docs/PLAN.md`. Don't introduce Montgomery reduction, packed integers,
  or branch-free tricks.
- **Commit per phase.** Each phase ends with a passing test suite and a
  single commit (`ML-KEM Phase N: …` or `ML-DSA Phase N: …`).
  Plan/decision changes go in their own `docs:` commit.
- **Never push without explicit user request.** Local commits are fine
  to make freely; pushes are not.
