# SLH-DSA performance benchmarks

Standalone timing suite, deliberately **not** named `test_*.py` so plain
`pytest` never collects it — SLH-DSA signing takes seconds (or tens of
seconds, for larger parameter sets) per call, so this needs to be run
explicitly, not on every test run.

There are two benchmarks here:

1. **`bench_slhdsa.py`** — API-usage variants of the one real, NIST-ACVP
   -KAT-verified implementation this repo ships: SLH-DSA-SHAKE-128s.
2. **`bench_param_sets.py`** — the FIPS 205 parameter-set axis itself
   (category 1/2/3 x small/fast), by running the *same* unmodified
   algorithm code under monkeypatched parameters via `param_loader.py`.

## `bench_slhdsa.py` — operational configurations of SLH-DSA-SHAKE-128s

Since only SHAKE-128s is a real implementation, "configuration" here
means the operational variants exposed by the public API, not different
NIST parameter sets:

- `keygen` — fresh key pair generation
- `sign` × {deterministic, hedged} × {small (32 B), large (16 KiB) message}
- `verify` × {small, large message}
- `hash_sign` / `hash_verify` (HashSLH-DSA) × {SHA2-256, SHA2-512, SHAKE-256}

Key generation / signature production used as fixtures (e.g. the
signature `verify` checks) is excluded from the timed region.

```
python3 -m slhdsa.tests.perf.bench_slhdsa                     # defaults: 3 repeats
python3 -m slhdsa.tests.perf.bench_slhdsa --repeats 5
python3 -m slhdsa.tests.perf.bench_slhdsa --expensive-trials 10 --cheap-trials 50
python3 -m slhdsa.tests.perf.bench_slhdsa --quiet             # suppress per-trial lines
```

Each invocation runs the full configuration matrix `--repeats` times,
prints per-repeat and overall (mean/median/stdev/min/max) summaries, and
writes raw timings + summaries to `results/perf_<UTC timestamp>.json`.

Wall-clock cost is dominated by `sign`/`hash_sign` (~5s each on typical
hardware); the default 3 repeats x 5 expensive trials x 8 sign-like
configs takes roughly 8-10 minutes.

## `bench_param_sets.py` — category 1/2/3 x small/fast

FIPS 205 defines 6 SHAKE parameter sets (SHAKE-{128,192,256}{s,f}) that
this repo does not implement — only SHAKE-128s does, deliberately (see
CLAUDE.md). `param_sets.py` reproduces `slhdsa/params.py`'s derivation
formulas for the other 5 sets' (n, h, d, a, k); `param_loader.py`
monkeypatches `slhdsa.params`'s constants and reloads the dependency
stack (hashes -> wots -> xmss -> fors -> ht -> slhdsa) so the exact same
algorithm code runs against each set. This means correctness for the 5
non-128s sets is checked only by a sign/verify self-test done once per
subprocess before timing starts — **not** by NIST ACVP vectors, since
none exist for them in this repo.

Each parameter set runs in its own subprocess (`_param_worker.py`), so
the monkeypatch+reload never has to be interleaved between configs.

```
python3 -m slhdsa.tests.perf.bench_param_sets                              # all 6 sets, defaults
python3 -m slhdsa.tests.perf.bench_param_sets --param-sets SHAKE-128s SHAKE-256f
python3 -m slhdsa.tests.perf.bench_param_sets --repeats 5 --expensive-trials 5
```

Only `keygen` / `sign` (deterministic, small message) / `verify` are
benchmarked here — `bench_slhdsa.py` already established that det-vs
-hedged, message size, and pre-hash algorithm don't move the needle for
SLH-DSA-SHAKE-128s, and re-running all 13 of its configs across 6
parameter sets whose signing costs differ by 1-2 orders of magnitude
would make the sweep impractically slow.

**Cost varies enormously across sets** — "s" (small) sets have the
smallest signatures but the slowest signing (their per-layer / FORS
trees are naively rebuilt from scratch for every authentication-path
node, so cost scales with `2^h'` and `2^a`); "f" (fast) sets sign much
faster at the cost of much larger signatures, but their `verify` is
slower (verify cost scales with `d`, the number of hypertree layers,
which is much larger for "f" sets). Category (128/192/256) tracks
classical security level, not raw speed — e.g. 256s can sign *faster*
than 192s despite the higher security level, because `k` and `a` (FORS
tree count/height) don't scale monotonically with category. Expect
`SHAKE-192s`/`SHAKE-256s` signing to take 10-20s+ per call.

Writes raw timings + summaries + a cross-parameter-set table to
`results/perf_param_sets_<UTC timestamp>.json`.
