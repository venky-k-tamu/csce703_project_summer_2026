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
