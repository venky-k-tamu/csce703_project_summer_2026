# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project context

CSCE 701 course project (Summer 2026): a from-scratch Python reference
implementation of **ML-KEM-768** (FIPS 203). A sibling **ML-DSA** (FIPS 204)
package will be added later under `mldsa/`. The implementation prioritizes
**spec fidelity** over performance: code is meant to be auditable against
the FIPS 203 pseudocode line-by-line.

`docs/PLAN.md` is the authoritative plan (phases, decisions, layout).
`docs/PROMPTS.md` is the chronological record of design choices.

## Commands

Dev dependencies (pytest + hypothesis) are not yet a managed install — install once with:

```
python3 -m pip install --user pytest hypothesis
```

Test commands (run from repo root; `pyproject.toml` sets `testpaths`):

```
python3 -m pytest mlkem/tests/                                 # full suite
python3 -m pytest mlkem/tests/test_ntt.py -v                   # one file
python3 -m pytest mlkem/tests/test_kpke.py::test_kpke_roundtrip -v   # one test
python3 -m pytest -k "homomorphism or roundtrip"               # by keyword
```

There is no build, lint, or formatter configured. Python 3.10+ required
(uses PEP 604 typing and `pow(x, -1, m)` modular inverse).

## Architecture

Module dependency stack (each layer uses everything below it):

```
mlkem.py            ML-KEM KeyGen/Encaps/Decaps + §7 input checks   (Phase 4, pending)
kpke.py             K-PKE KeyGen/Encrypt/Decrypt — FIPS 203 §5
sampling.py         SampleNTT (Alg 7), SamplePolyCBD (Alg 8)
ntt.py              ZETAS/GAMMAS, NTT, NTT⁻¹, MultiplyNTTs (Alg 9–12)
hashes.py           H, J, G, PRF_η, streaming SHAKE-128 XOF
serialize.py        ByteEncode/Decode (Alg 5/6), Compress/Decompress
bytes_bits.py       BitsToBytes / BytesToBits (Alg 3/4)
params.py           ML-KEM-768 constants (N=256, Q=3329, K=3, η₁=η₂=2, d_u=10, d_v=4)
```

Each Python module maps to a specific FIPS 203 section — when editing,
keep the algorithm-to-function mapping intact and reference algorithm
numbers in docstrings.

### Ring and NTT

Working ring is **R_q = ℤ_q[X]/(X²⁵⁶ + 1)** with q = 3329. ζ = 17 is a
primitive 256-th root of unity mod q (NOT a 512-th root), so the NTT
factors X²⁵⁶ + 1 into **128 quadratic factors**, not 256 linear ones.
Therefore:

- `ntt(f)` returns a length-256 list, but it is laid out as 128 pairs
  (â_{2i}, â_{2i+1}), each representing f mod (X² − γᵢ).
- Pointwise multiplication uses `multiply_ntts` / `base_case_multiply`,
  **not** an element-by-element product.
- `ZETAS[k] = ζ^{BitRev_7(k)} mod q`; `GAMMAS[i] = ζ^{2·BitRev_7(i)+1} mod q`.

### Matrix indexing in K-PKE

`_sample_matrix(rho)` produces Â with `Â[i][j] = SampleNTT(ρ ‖ j ‖ i)`
— byte order is **(j, i)** per FIPS 203 Algorithm 13 line 5. Encrypt then
multiplies by `Â^T` (transposed in code), while KeyGen multiplies by `Â`.
If KAT vectors fail in Phase 5, the (j, i) vs (i, j) byte order is the
first thing to recheck.

### Hashes vs XOF

`hashes.py` exposes both fixed-output wrappers (`H`, `J`, `G`, `prf`) and
a streaming `XOF` class for SHAKE-128 used in rejection sampling.
hashlib's SHAKE has no incremental squeeze API, so `XOF` re-digests a
growing buffer; this is correct but quadratic in worst-case reads. Don't
"optimize" it unless you have a measured reason — correctness comes
first.

## Conventions

- **Tests live in-package** under `mlkem/tests/`, not a top-level
  `tests/` directory. ML-DSA will mirror this as `mldsa/tests/`.
- **No `common/` shared package up front.** ML-KEM and ML-DSA use
  different moduli (3329 vs 8380417) and different zetas; ring code
  cannot be naïvely shared. Factor only on demonstrated duplication when
  ML-DSA work starts.
- **No constant-time / no perf optimizations.** Explicit non-goal per
  `docs/PLAN.md`. Don't introduce Montgomery reduction, packed integers,
  or branch-free tricks.
- **Commit per phase.** Each phase ends with a passing test suite and a
  single commit (`ML-KEM Phase N: …`). Plan/decision changes go in their
  own `docs:` commit.
- **Never push without explicit user request.** Local commits are fine
  to make freely; pushes are not.
