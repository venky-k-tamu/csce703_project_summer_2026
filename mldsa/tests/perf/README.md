# ML-DSA performance benchmarks

Standalone timing suite, deliberately **not** named `test_*.py` so plain
`pytest` never collects it (mirrors `slhdsa/tests/perf/`).

There are two benchmarks here:

1. **`bench_mldsa.py`** — API-usage variants of the one real,
   NIST-ACVP-KAT-verified implementation this repo ships: ML-DSA-65.
2. **`bench_param_sets.py`** — the FIPS 204 parameter-set axis itself
   (categories 2/3/5 = ML-DSA-44/65/87), by running the *same*
   unmodified algorithm code under monkeypatched parameters via
   `param_loader.py`.

## `bench_mldsa.py` — operational configurations of ML-DSA-65

- `keygen` — fresh key pair generation
- `sign` x {deterministic, hedged} x {small (32 B), large (16 KiB) message}
- `verify` x {small, large message}
- `hash_sign` / `hash_verify` (HashML-DSA) x {SHA2-256, SHA2-512, SHAKE-256}

Unlike SLH-DSA, ML-DSA's keygen/sign/verify are all the same order of
magnitude (tens of milliseconds — this is a lattice scheme with a
rejection-sampling loop in Sign, not a hash-tree scheme with exponential
tree-rebuild costs), so this suite uses one uniform trial count rather
than an expensive-vs-cheap split. Expect `sign`'s stdev to be
noticeably higher than the other ops': the number of rejection-sampling
iterations per call varies run to run.

```
python3 -m mldsa.tests.perf.bench_mldsa                     # defaults: 3 repeats x 50 trials
python3 -m mldsa.tests.perf.bench_mldsa --repeats 5 --trials 100
python3 -m mldsa.tests.perf.bench_mldsa --quiet             # suppress per-trial lines
```

Writes raw timings + summaries to `results/perf_<UTC timestamp>.json`.

## `bench_param_sets.py` — category 2/3/5

FIPS 204 defines three ML-DSA parameter sets; only ML-DSA-65 is
implemented here (see CLAUDE.md). `param_sets.py` reproduces
`mldsa/params.py`'s derivation formulas for ML-DSA-44/87's
(k, l, eta, tau, lambda, gamma1, gamma2, omega); `param_loader.py`
monkeypatches `mldsa.params` and reloads the dependency stack
(ntt -> rounding -> sampling -> encoding -> mldsa) so the exact same
algorithm code runs against each set. Correctness for the non-65 sets
is checked only by a sign/verify self-test per subprocess, not NIST
ACVP vectors.

Only `keygen` / `sign` (deterministic, small message) / `verify` are
benchmarked here, for the same reason as SLH-DSA's sweep: `bench_mldsa.py`
already showed det-vs-hedged/message-size/pre-hash don't matter, so
re-running all 13 configs across 3 parameter sets would be redundant.

Each parameter set runs in its own subprocess (`_param_worker.py`).

```
python3 -m mldsa.tests.perf.bench_param_sets                       # all 3 sets, defaults
python3 -m mldsa.tests.perf.bench_param_sets --param-sets ML-DSA-44 ML-DSA-87
python3 -m mldsa.tests.perf.bench_param_sets --repeats 5 --trials 100
```

Cost does not scale monotonically with category the way key/signature
size does — `sign` cost is driven by the rejection-sampling loop's
expected iteration count (a function of tau, eta, gamma1, gamma2
together), not just k/l — so don't assume ML-DSA-87 is uniformly
slower than ML-DSA-44 without checking.

Writes raw timings + summaries + a cross-parameter-set table to
`results/perf_param_sets_<UTC timestamp>.json`.
