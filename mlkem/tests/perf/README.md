# ML-KEM performance benchmarks

Standalone timing suite, deliberately **not** named `test_*.py` so plain
`pytest` never collects it (mirrors `slhdsa/tests/perf/`, though ML-KEM
is fast enough — single-digit/low-double-digit milliseconds per op —
that there's no real risk of blowing out a test-run timeout).

There are two benchmarks here:

1. **`bench_mlkem.py`** — keygen/encaps/decaps for the one real,
   NIST-ACVP-KAT-verified implementation this repo ships: ML-KEM-768.
2. **`bench_param_sets.py`** — the FIPS 203 parameter-set axis itself
   (categories 1/3/5 = ML-KEM-512/768/1024), by running the *same*
   unmodified algorithm code under monkeypatched parameters via
   `param_loader.py`.

## `bench_mlkem.py` — ML-KEM-768 operations

Unlike SLH-DSA/ML-DSA, ML-KEM's public API has no deterministic/hedged
switch, no caller-supplied message (encaps samples its own 32-byte m
internally), and no pre-hash option — there isn't much of an
"operational configuration" axis within one parameter set. The one real
behavioral fork is `decaps`' implicit-rejection path (FIPS 203
Algorithm 21): on a mismatched ciphertext, `decaps` returns a
pseudorandom key derived from z instead of raising, so this suite times
`decaps` on both a valid and a bit-flipped ciphertext to see whether
that fork is visible in wall-clock cost.

- `keygen` — fresh key pair generation
- `encaps` — encapsulation
- `decaps` x {valid ciphertext, corrupted ciphertext}

```
python3 -m mlkem.tests.perf.bench_mlkem                     # defaults: 3 repeats x 100 trials
python3 -m mlkem.tests.perf.bench_mlkem --repeats 5 --trials 200
python3 -m mlkem.tests.perf.bench_mlkem --quiet             # suppress per-trial lines
```

Writes raw timings + summaries to `results/perf_<UTC timestamp>.json`.

## `bench_param_sets.py` — category 1/3/5

FIPS 203 defines three ML-KEM parameter sets; only ML-KEM-768 is
implemented here (see CLAUDE.md). `param_sets.py` reproduces
`mlkem/params.py`'s derivation formulas for ML-KEM-512/1024's
(k, eta1, eta2, du, dv); `param_loader.py` monkeypatches `mlkem.params`
and reloads the dependency stack (ntt -> sampling -> serialize -> kpke
-> mlkem) so the exact same algorithm code runs against each set.
Correctness for the non-768 sets is checked only by an encaps/decaps
self-test per subprocess, not NIST ACVP vectors.

Each parameter set runs in its own subprocess (`_param_worker.py`).

```
python3 -m mlkem.tests.perf.bench_param_sets                       # all 3 sets, defaults
python3 -m mlkem.tests.perf.bench_param_sets --param-sets ML-KEM-512 ML-KEM-1024
python3 -m mlkem.tests.perf.bench_param_sets --repeats 5 --trials 200
```

Cost scales smoothly with module rank `k` (2/3/4) — no exponential
blowup like SLH-DSA's tree constructions, since ML-KEM is lattice/NTT
based with no recursive tree recomputation. Expect ML-KEM-1024's
`decaps` to run ~2x ML-KEM-512's.

Writes raw timings + summaries + a cross-parameter-set table to
`results/perf_param_sets_<UTC timestamp>.json`.
