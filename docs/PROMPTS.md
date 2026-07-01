# Session Prompts

Transcript of the user-driven prompts and decisions that shaped the plan in
`PLAN.md`. Kept here so the design intent is recoverable later without
re-reading chat history.

## 1. Opening prompt

> I want to implement and verify ML-KEM, help me plan and implement

Response framed two questions: what does *verify* mean (formal proof vs. KAT
testing vs. constant-time), and what language to use. Recommended a Python
reference implementation of ML-KEM-768 verified against NIST KATs.

## 2. Scope-locking answers

Asked four multiple-choice scoping questions. User answered:

| Question | Choice |
|---|---|
| Verification meaning | **NIST KAT vectors** + **Property-based / fuzz testing** |
| Implementation language | **Python** |
| Parameter sets | **ML-KEM-768 only** |
| SHA3/SHAKE source | **Library (`hashlib`)** |

All four matched the recommended defaults.

## 3. Layout adjustment + ML-DSA scope expansion

> organize tests under mlkem directory. I also want to implement ml-dsa in this directory later

Two changes to the original sketch:
1. Move tests into `mlkem/tests/` (in-package) rather than a top-level
   `tests/` dir.
2. Plan for a sibling `mldsa/` package later. No shared `common/` package
   up front — different moduli mean ring-arithmetic code can't be shared
   verbatim. Re-evaluate after ML-DSA work begins.

`pyproject.toml` updated so `testpaths = ["mlkem/tests"]`.

## 4. Phase 1 implementation

After plan approval, implemented Phase 1 (params, bits/bytes, serialize,
compress) with 19 passing tests. One initial test failure
(`test_byte_encode_d_lt_12_modular_reduction`) caused by a faulty test
assumption — fixed by computing the mod-2ᵈ expected values correctly.

## 5. Commit

> commit phase 1 to git

Committed as `e8cc502` after adding a `.gitignore` to keep `__pycache__/`
out of the tree. 9 files / 206 insertions. Not pushed.

## 6. Documentation

> Document our prompts and detailed plan into mark down files

This file plus `PLAN.md`.

## 7. Separate docs commit + first push

> separate commit and push into git

Created a dedicated `docs: add PLAN.md and PROMPTS.md` commit
(`8e94eaa`) and pushed `main` to `origin` for the first time.
Established the pattern: code/docs are separate commits.

## 8. Phase 2 — NTT, sampling, hash/XOF (commit `f978c1c`)

> start phase 2 → commit phase 2 and push

Implemented `hashes.py` (with a re-digesting SHAKE-128 `XOF` stream
because hashlib has no streaming squeeze), `ntt.py` (Algorithms 9–12
with precomputed `ZETAS` / `GAMMAS`), `sampling.py` (Algorithms 7–8).
One initial test bug: the spec-table check named `ZETAS[127] == 1175`
from (incorrect) recall — replaced with checks against confirmed Table 4
values for indices 0–7. 46/46 tests passed after that fix.

## 9. Phase 3 — K-PKE (commit `3fc1801`)

> start phase 3 → commit phase 3 and push

Implemented K-PKE (Algorithms 13–15) plus NTT-domain matrix/vector
arithmetic helpers. Got the (j, i) byte order for `Â[i][j] =
SampleNTT(ρ ‖ j ‖ i)` right on first try by reading the spec literally.
58/58 tests after Phase 3.

## 10. CLAUDE.md initialization

> before phase 4 initialize a claude.md file

Used the built-in `/init` skill. Captured the FIPS 203 module
dependency stack, the spec-fidelity stance, three non-obvious
details (ζ=17 is a 256-th root → 128 quadratic factors; the (j,i)
matrix byte order; hashlib SHAKE has no streaming squeeze), and the
project conventions (in-package tests, no `common/` package yet, no
constant-time / perf work, commit per phase, no push without explicit
ask).

Then:

> commit now
> git commit and push
> push

First "commit now" committed `CLAUDE.md` only (`f65b5af`). "git commit
and push" published it. The follow-up "push" surfaced an unstaged
`typechange` from the user: `README.md` had been replaced with a
symlink to `CLAUDE.md`. Inspected before acting; confirmed
intentional; committed as `492e551` with a note that GitHub does not
follow symlinks when rendering the repo front page.

## 11. Phase 4 — ML-KEM proper + §7 checks (commit `88ca535`)

> start phase 4 → commit phase 4 and push

Implemented `mlkem/mlkem.py` (Algorithms 16–21 + §7.2/§7.3 input
checks). The interesting design call: §7.2's "modulus check" is
performed by re-running `ByteEncode_12 ∘ ByteDecode_12` over the
encoded `t̂` and checking byte-equality with the input — a clean way
to detect 12-bit fields ≥ q. Implicit rejection returns `J(z ‖ c)`
exactly; tested both with a tampered ciphertext and a fully random
one. 72/72 after Phase 4.

## 12. Phase 5 — NIST ACVP KAT verification (commit `8f115ea`)

> start phase 5 → commit phase 5 and push

Fetched the four ACVP JSON files (keyGen + encapDecap, prompt +
expectedResults) from `usnistgov/ACVP-Server`, filtered to ML-KEM-768
only (tgId 2 from keyGen; tgIds 2/5/9/10 from encapDecap), and saved
to `mlkem/tests/vectors/` with a provenance README. The parametrized
test runner dispatches each `function` to the matching internal API.
**All 80 ML-KEM-768 KAT cases pass on first run.** Full suite 153/153.

## 13. Doc refresh

> update all docs

This entry — plus the ✅ marks and commit hashes added in `PLAN.md`,
and the "Status" + Phase 5 outcomes propagated into `CLAUDE.md`.

## 14. Start ML-DSA — scope-locking + shared common/ (commit `297e84e`)

> start ml-dsa

Three scoping questions, all matched the recommendation: ML-DSA-65 only,
factor `bytes_bits.py` into a shared `common/` package now (genuine
demonstrated duplication between FIPS 203 §4.2.1 and FIPS 204 §4.2),
include HashML-DSA. Refactor commit lands first so the Phase 1 commit
contains only ML-DSA logic.

## 15. ML-DSA Phase 1 — params, conversions, rounding, encoding (commit `2a0e513`)

> start phase 1 → commit phase 1 and push

Encoding is the bulk of the work — bit packers, hint vector packer with
full validation, and the four high-level encoders (pk / sk / sig / w1).
Hint unpack's validation predicates (length, monotonic per-row counts,
strictly increasing positions, zero trailing slots) were tested with
intentionally tampered inputs. 47 new tests passing on first run.

## 16. ML-DSA Phase 2 — NTT (ζ=1753) and sampling (commit `d1a0db6`)

> start phase 2 → commit phase 2 and push

ML-DSA's NTT diverges from ML-KEM's: ζ = 1753 is a primitive **512-th**
root of unity, so X²⁵⁶ + 1 factors into 256 linear factors and
`multiply_ntts` is pointwise. The reused-from-ML-KEM design pattern is
the streaming XOF — same re-digest-a-growing-buffer trick because
hashlib's SHAKE has no incremental squeeze API. 31 new tests.

## 17. ML-DSA Phase 3 — internal KeyGen / Sign / Verify (commit `7b244e0`)

> start phase 3 → yes

Sign's rejection-sampling retry loop is implemented straight from the
spec — all four norm conditions, plus a 1000·L iteration safety guard
against runaway loops. One drive-by encoding fix landed: `bit_pack` now
accepts either signed or mod-q inputs (canonicalizes via `_to_signed`),
removing impedance mismatch with the rest of the pipeline. 15 new tests
covering round-trip plus four kinds of negative cases (tampered message,
tampered byte, wrong pk, undersized inputs).

## 18. ML-DSA Phase 4 — public API + HashML-DSA + the norm bugfix (commit `57b5e41`)

> start phase 4 → yes go ahead

Built the FIPS 204 §5 public-API shape on top of internal: `keygen()`,
`sign(sk, M, ctx, deterministic)`, `verify(pk, M, sig, ctx)`, plus
HashML-DSA variants with 8 pre-hash functions initially.

Then a **real bug**: `test_random_keys_and_messages` failed sporadically.
A 200-trial stress test showed ~2.5% verify failures. Root cause traced
to `_inf_norm_poly` using `max(min(c, q−c))` — works for mod-q inputs in
[0, q) but silently drops the negative half of *signed* inputs coming
from `low_bits` (which returns r₀ ∈ (−γ₂, γ₂]). Sign's `‖r₀‖∞ < γ₂ − β`
check therefore only constrained the positive coefficients, occasionally
accepting cases that violated `HighBits(w − c·s₂) = HighBits(w)`. Fix:
canonicalize either form into the centered representative before taking
|·|. 0/500 failures after fix.

Important lesson: deterministic unit tests can't catch this — it
requires randomized inputs to surface the asymmetry. Property tests with
`os.urandom` caught it; subsequent KATs would have caught it more
loudly, but slower.

## 19. ML-DSA Phase 5 — NIST ACVP KATs all pass (commit `3e0597c`)

> start phase 5 → yes

Fetched the six ACVP files (keyGen + sigGen + sigVer × prompt +
expectedResults), filtered to ML-DSA-65 + the external signature
interface. Scope: 25 keyGen + 60 sigGen (pure + HashML-DSA × det +
hedged) + 30 sigVer = 115 cases. Skipped `externalMu` (caller pre-
computes μ) — separate signing API, no current need.

The pre-hash table needed expanding from 8 to 12 entries to cover
SHA2-224 / SHA2-512/224 / SHA2-512/256 / SHA3-224, and renaming from
`SHA-256` style to ACVP's `SHA2-256` style. All 115 KAT cases pass on
first run. Full suite at 387/387.

## 20. ML-DSA doc refresh

> update docs

This entry, plus ML-DSA architecture / phase / addendum sections added
to `PLAN.md` and `CLAUDE.md`.

## 21. SLH-DSA arrives via branch + PR #1 (merge `2635923`)

SLH-DSA-SHAKE-128s was contributed by Philip Marshall (paired with
Claude) on the `phil_dev.slhdsa_impl` branch rather than in this
session's linear flow, then merged into `main` through PR #1. The
initial commit (`8aaa886`) landed the whole hash-based stack at once:
`params` / `hashes` / `address`, the `wots → xmss → ht` Merkle stack,
`fors`, and `slhdsa.py` with internal + hedged public KeyGen/Sign/Verify,
plus per-module and property tests. No `common/` code was shared — being
hash-based, SLH-DSA has no ring/NTT surface in common with the lattice
schemes; only the `hashlib` SHAKE dependency overlaps.

## 22. SLH-DSA Phase 2 — HashSLH-DSA public API (commit `b07e2b9`)

Mirrored the HashML-DSA work: `hash_sign` (Alg 23) / `hash_verify`
(Alg 24), a 12-entry `_PREHASH_FUNCTIONS` OID table with ACVP-style
names, and `_format_M_prime` with the 0x00/0x01 domain separator so
plain and pre-hash signatures can't cross-verify. Argument order and
three-seed keygen differ from ML-DSA, so it's a parallel implementation
rather than shared code. Switched to `secrets.token_bytes` for
consistency. `test_slhdsa_api.py` added 46 cases; suite at 104/104.

## 23. SLH-DSA Phase 3 — ACVP KATs expose a SHAKE128/256 bug (commit `1b662d7`)

Vendored 76 SLH-DSA-SHAKE-128s ACVP cases (10 keyGen + 38 sigGen +
28 sigVer), external interface only. The first run failed **every**
keyGen vector: `hashes.py` had wired F/H/T_l/PRF/PRF_msg/H_msg to
**SHAKE128**, but FIPS 205 §10.2 fixes **SHAKE256** for every SHAKE
parameter set — the "128" in the name is the classical security level,
not the XOF width. The internal round-trip tests couldn't catch it
because sign and verify shared the same wrong hash; it took an external
oracle to surface. Exactly the ML-DSA norm-bug lesson restated:
self-consistent code passes its own tests while still being wrong. Fixed
the six hash instantiations and the hardcoded `test_hashes.py`
expectations. **181/181 pass** — 271 NIST ACVP KATs across all three
algorithms.

## 24. Doc refresh after SLH-DSA

> Update docs

This entry, plus the SLH-DSA sections (goal, key decisions, repository
layout, phased delivery, final status) added to `PLAN.md`, and the
SLH-DSA architecture / gotchas / status added to `CLAUDE.md`.
