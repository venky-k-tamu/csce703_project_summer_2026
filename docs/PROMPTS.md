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
