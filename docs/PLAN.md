# ML-KEM / ML-DSA Implementation Plan

CSCE 701, Summer 2026 — Venky Kottapalli.

## Goal

Implement and verify **ML-KEM-768** (FIPS 203) *and* **ML-DSA-65** (FIPS 204)
from scratch in Python, with a small `common/` package for code that is
genuinely identical between the two FIPS specs.

"Verify" here means:
1. **NIST ACVP Known-Answer-Test vectors** — the official functional-correctness
   bar. Passing the full ACVP vector set is the headline result for each.
2. **Property tests** — Decaps(Encaps(ek)) == K and Sign / Verify round-trips,
   implicit-rejection / signature-rejection behavior on tampering, determinism
   from fixed seeds.

Not in scope:
- Constant-time / side-channel hardening.
- Performance optimization beyond what falls out of the natural algorithm
  expression (no packed-integer NTT, no Montgomery reduction, no Cython).
- Multiple parameter sets — only ML-KEM-768 and ML-DSA-65.
- Implementing Keccak from scratch — uses `hashlib`'s SHA3/SHAKE.
- The ML-DSA **externalMu** signing interface (caller pre-computes μ).

## Key decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Maps line-by-line onto FIPS pseudocode; easy to read and audit. |
| ML-KEM parameter set | ML-KEM-768 | NIST's recommended default; n=256, q=3329, k=3, η₁=η₂=2, d_u=10, d_v=4. |
| ML-DSA parameter set | ML-DSA-65 | NIST Cat 3 default; n=256, q=8380417, k=6, l=5, η=4, τ=49, γ₁=2¹⁹, γ₂=(q-1)/32, ω=55. |
| Hash primitive | `hashlib` SHA3 / SHAKE | Lets us focus on lattice/NTT/PKE/signing logic. |
| Verification | NIST ACVP KATs + property tests | KATs are the standard correctness bar; property tests catch regressions cheaply. |
| Tests location | In-package (`mlkem/tests/`, `mldsa/tests/`) | Each algorithm's package self-contained. |
| Shared code | Only `common/bytes_bits.py` | Factored once ML-DSA showed identical FIPS 203 §4.2.1 / FIPS 204 §4.2 algorithms — demonstrated duplication, not speculation. |
| HashML-DSA | Included | Adds 12 pre-hash function variants; thin wrapper around ML-DSA-internal. |

## Repository layout

```
common/
  __init__.py
  bytes_bits.py       # FIPS 203 §4.2.1 ≡ FIPS 204 §4.2 (Alg 3/4 ≡ Alg 12/13)
mlkem/
  __init__.py         # re-exports keygen/encaps/decaps
  params.py
  bytes_bits.py       # re-export from common
  serialize.py        # ByteEncode/Decode (Alg 5/6), Compress/Decompress
  ntt.py              # ZETAS/GAMMAS for ζ=17, NTT/NTT⁻¹, MultiplyNTTs
  sampling.py         # SampleNTT (SHAKE-128 rejection), SamplePolyCBD
  hashes.py           # H, J, G, PRF, streaming SHAKE-128 XOF
  kpke.py             # K-PKE (Alg 13-15)
  mlkem.py            # ML-KEM (Alg 16-21) + §7 input checks
  tests/
    test_bytes_bits.py, test_serialize.py, test_ntt.py,
    test_sampling.py, test_hashes.py, test_kpke.py,
    test_mlkem_properties.py, test_mlkem_kat.py
    vectors/          # NIST ACVP JSON vectors
mldsa/
  __init__.py         # re-exports keygen/sign/verify, hash_sign/hash_verify
  params.py
  conversions.py      # IntegerToBits/BitsToInteger/IntegerToBytes (Alg 9-11)
  rounding.py         # Power2Round/Decompose/HighBits/LowBits/MakeHint/UseHint (Alg 35-40)
  encoding.py         # SimpleBitPack/BitPack/HintBitPack + pk/sk/sig/w1 encoders (Alg 16-28)
  ntt.py              # ZETAS for ζ=1753 (256 linear factors), NTT/NTT⁻¹
  sampling.py         # CoeffFromThreeBytes/HalfByte, RejNTTPoly, RejBoundedPoly,
                      # ExpandA/S/Mask, SampleInBall (Alg 14, 15, 29-34)
  hashes.py           # H=SHAKE-256, G=SHAKE-128, XOF128/XOF256
  mldsa.py            # KeyGen/Sign/Verify internal + public; HashML-DSA (Alg 1-8)
  tests/
    test_conversions.py, test_rounding.py, test_encoding.py,
    test_ntt.py, test_sampling.py, test_hashes.py,
    test_mldsa_properties.py, test_mldsa_api.py, test_mldsa_kat.py
    vectors/          # NIST ACVP JSON vectors
docs/
  PLAN.md
  PROMPTS.md
pyproject.toml
.gitignore
README.md             # symlink → CLAUDE.md
CLAUDE.md
```

`pyproject.toml` configures pytest discovery
(`testpaths = ["mlkem/tests", "mldsa/tests"]`) so `pytest` from the repo
root runs everything.

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

## ML-KEM-768 final status

**153/153 tests pass.** The ML-KEM-768 implementation matches NIST's
official FIPS 203 vectors byte-for-byte.

## Refactor — `common/bytes_bits.py` ✅ (commit `297e84e`)

Pre-Phase-1 work for ML-DSA. FIPS 203 §4.2.1 BitsToBytes/BytesToBits
(Alg 3/4) and FIPS 204 §4.2 BitsToBytes/BytesToBits (Alg 12/13) are
byte-identical, so this is the first demonstrated duplication justifying
factoring per the convention. `mlkem/bytes_bits.py` becomes a re-export.
ML-KEM suite still 153/153 after.

## ML-DSA phased delivery

### Phase 1 — Foundation ✅ (commit `2a0e513`)

- `mldsa/params.py` — ML-DSA-65 constants and derived encoded sizes
  (ek=1952, dk=4032, sig=3309 match FIPS 204 Table 1).
- `mldsa/conversions.py` — IntegerToBits / BitsToInteger / IntegerToBytes
  (Alg 9–11), LSB-first.
- `mldsa/rounding.py` — Power2Round, Decompose (with the q−1 wraparound
  case), HighBits, LowBits, MakeHint, UseHint (Alg 35–40).
  UseHint(MakeHint(z, r), r) == HighBits(r+z) for |z| ≤ γ₂ — the
  load-bearing correctness property of the signature scheme.
- `mldsa/encoding.py` — SimpleBitPack / BitPack and inverses;
  HintBitPack with weight check and HintBitUnpack with full validation
  (length, monotonic per-row counts, strictly increasing positions, zero
  trailing slots); pkEncode/Decode, skEncode/Decode, sigEncode/Decode,
  w1Encode (Alg 16–28).
- Tests: integer/bit round-trip and LSB ordering; power2round/decompose
  identities (including the wraparound boundary); MakeHint/UseHint
  correctness over 600 random (r, z) pairs; bit-pack range rejection;
  hint unpack rejects every well-known malformed encoding; pk/sk/sig
  round-trips confirming the spec sizes. **47 new tests.**

### Phase 2 — NTT and sampling ✅ (commit `d1a0db6`)

- `mldsa/hashes.py` — H = SHAKE-256, G = SHAKE-128 wrappers, plus
  incremental XOF128 / XOF256 streams using the same re-digest pattern
  as ML-KEM.
- `mldsa/ntt.py` — `ZETAS` for ζ = 1753 in BitRev_8 order (256 entries).
  Because ζ is a primitive **512-th** root of unity mod q, X²⁵⁶ + 1
  factors into 256 *linear* factors, so `multiply_ntts` is pointwise
  (no base-case multiplication).
- `mldsa/sampling.py` — CoeffFromThreeBytes / CoeffFromHalfByte
  (Alg 14/15), RejNTTPoly (SHAKE-128 rejection), RejBoundedPoly
  (SHAKE-256 η-bounded), ExpandA / ExpandS / ExpandMask, SampleInBall
  (Fisher-Yates-style sparse ±1 polynomial via SHAKE-256).
- Tests: ζ²⁵⁶ ≡ −1 (so ζ is a primitive 512-th root); ZETAS[1]² ≡ −1;
  NTT round-trip and homomorphism vs naïve poly multiplication;
  rej_bounded_poly outputs signed coeffs strictly in [−η, η];
  SampleInBall produces exactly τ = 49 nonzero ±1 entries;
  ExpandA/S/Mask have correct dimensions and are deterministic.
  **31 new tests.**

### Phase 3 — Internal KeyGen, Sign, Verify ✅ (commit `7b244e0`)

- `mldsa/mldsa.py` — `_keygen_internal(ξ)` (Alg 6),
  `_sign_internal(sk, M′, rnd)` (Alg 7) with the full rejection-sampling
  loop and all four norm checks (‖z‖∞ < γ₁−β, ‖r₀‖∞ < γ₂−β,
  ‖c·t₀‖∞ < γ₂, weight(h) ≤ ω), `_verify_internal(pk, M′, σ)` (Alg 8).
  Plus vector helpers (matvec/scalvec product in NTT domain,
  vectorized HighBits/LowBits/MakeHint/UseHint, centered ℓ∞ norm).
- One drive-by fix in `encoding.bit_pack`: now canonicalizes inputs via
  `_to_signed`, removing the mismatch with the sampler/NTT pipeline
  (mod-q outputs vs. spec's centered-form inputs).
- Tests: 5 fixed-seed + 5 random-seed Sign/Verify round-trips;
  tampered message / tampered byte / wrong pk / undersized pk and sig
  all reject. **15 new tests.**

### Phase 4 — Public API, HashML-DSA, and the norm bugfix ✅ (commit `57b5e41`)

- Public API (Alg 1–3): `keygen()`, `sign(sk, M, ctx, deterministic=False)`,
  `verify(pk, M, sig, ctx)` building M′ = 0x00 ‖ len(ctx) ‖ ctx ‖ M.
  HashML-DSA (Alg 4–5): `hash_sign` / `hash_verify` building
  M′ = 0x01 ‖ len(ctx) ‖ ctx ‖ OID ‖ PH(M), with 12 pre-hash functions
  (SHA2-224/256/384/512, SHA2-512/224, SHA2-512/256, SHA3-224/256/384/512,
  SHAKE-128/256) registered with their DER OIDs.
- **Bugfix in `_inf_norm_poly`**: the previous `max(min(c, q−c))`
  formula silently dropped the negative side of *signed* inputs from
  `low_bits` — sign's ‖r₀‖∞ < γ₂ − β rejection only constrained the
  positive coefficients, occasionally accepting cases that violated
  HighBits(w − c·s₂) = HighBits(w) and broke verify on ~2.5% of random
  round-trips. Now canonicalizes either form into (−q/2, q/2] before
  taking |·|. 0/500 random round-trips fail after the fix.
- Tests: randomized keygen freshness; round-trip for ctx ∈ {empty,
  ASCII, binary, 255-byte max}; ctx-mismatch rejection; ctx > 255
  raises in sign / returns False in verify; deterministic vs hedged
  determinism comparison; HashML-DSA round-trip for all 12 pre-hash
  functions; plain↔HashML domain separation; wrong/unknown hash
  algorithm handling. **21 new tests.**

### Phase 5 — NIST ACVP KAT verification ✅ (commit `3e0597c`)

- Vendored ML-DSA-65 ACVP vectors filtered from `usnistgov/ACVP-Server`
  `gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/`, scoped to
  the external signature interface only (`externalMu` interface
  deliberately deferred — separate signing API, no current need).
- Kept groups: keyGen tg2 (25 cases); sigGen tg3+tg4+tg15+tg16
  covering pure + HashML-DSA × deterministic + hedged (60 cases);
  sigVer tg3+tg4 (30 cases). **115 KAT cases total.**
- `mldsa/tests/test_mldsa_kat.py` parametrizes each case, builds M′ via
  `_format_M_prime`, and dispatches to the internal functions. For
  hedged groups rnd comes from the prompt; for deterministic groups
  rnd is all-zeros.
- **All 115 ML-DSA-65 KAT cases pass on first run.** Headline result.

## Project final status

**387/387 tests pass.** Of those, **195 are byte-for-byte NIST ACVP KAT
cases** — 80 ML-KEM-768 + 115 ML-DSA-65. Both algorithms verified
against the official FIPS 203 / FIPS 204 vectors.

Potential follow-ups (none currently planned):
- ML-DSA externalMu signing interface.
- Additional parameter sets (ML-KEM-512/1024, ML-DSA-44/87) — would need
  parameter-set-aware versions of the encoders/samplers but most code is
  parameter-driven already.
- A CLI or higher-level KEM-DEM wrapper.
