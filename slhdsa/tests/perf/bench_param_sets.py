"""Benchmark keygen/sign/verify across all six FIPS 205 SHAKE parameter sets
(category 1/2/3 x small/fast), each run in its own subprocess.

    python3 -m slhdsa.tests.perf.bench_param_sets [options]

Only SLH-DSA-SHAKE-128s (slhdsa/params.py) is the real, NIST-ACVP-KAT
-verified implementation shipped in this repo -- see CLAUDE.md. The
other five sets run the exact same algorithm code under monkeypatched
(n, h, d, a, k) (see param_loader.py) purely to measure how cost scales
across the category/speed-profile axis; treat their timings as
structural/self-tested-only (each subprocess does a sign/verify round
trip before timing), not as NIST-validated implementations.

Each parameter set gets its own subprocess so param_loader.load()'s
monkeypatch + reload never has to be interleaved between configurations.

"s" (small) sets have the smallest signatures but the slowest signing
(taller per-layer/FORS trees); "f" (fast) sets sign much faster at the
cost of much larger signatures. Category (128/192/256) tracks classical
security level, not raw speed -- e.g. 256s can sign *faster* than 192s
despite the higher security level, because of how h'/d/a/k trade off.
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import param_sets

RESULTS_DIR = Path(__file__).parent / "results"


def run_param_set(name, repeats, expensive_trials, cheap_trials):
    cmd = [
        sys.executable,
        "-m",
        "slhdsa.tests.perf._param_worker",
        name,
        "--repeats",
        str(repeats),
        "--expensive-trials",
        str(expensive_trials),
        "--cheap-trials",
        str(cheap_trials),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"worker for {name!r} failed:\n{proc.stderr}")
    return json.loads(proc.stdout)


def print_report(results):
    header = (
        f"{'param set':<14}{'n':>4}{'h':>4}{'d':>4}{'hp':>4}{'a':>4}{'k':>4}"
        f"{'sig(B)':>8}{'keygen(s)':>11}{'sign(s)':>10}{'verify(s)':>11}"
    )
    print(header)
    print("-" * len(header))
    for name, result in results.items():
        c = result["constants"]
        s = result["overall_summary"]
        print(
            f"{name:<14}{c['N']:>4}{c['H']:>4}{c['D']:>4}{c['HP']:>4}{c['A']:>4}{c['K']:>4}"
            f"{c['SIG_SIZE']:>8}{s['keygen']['mean']:>11.4f}{s['sign']['mean']:>10.4f}{s['verify']['mean']:>11.4f}"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--param-sets", nargs="+", default=list(param_sets.RAW_PARAMS), choices=list(param_sets.RAW_PARAMS)
    )
    parser.add_argument("--repeats", type=int, default=3, help="full-suite repeats per parameter set (default: 3)")
    parser.add_argument(
        "--expensive-trials", type=int, default=3, help="trials/config for keygen/sign (default: 3)"
    )
    parser.add_argument("--cheap-trials", type=int, default=10, help="trials/config for verify (default: 10)")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(exist_ok=True)
    results = {}
    for name in args.param_sets:
        print(f"\n=== {name} ===")
        result = run_param_set(name, args.repeats, args.expensive_trials, args.cheap_trials)
        results[name] = result
        for config_name, s in result["overall_summary"].items():
            print(f"  {config_name:<8} n={s['n']:<4} mean={s['mean']:.4f}s  median={s['median']:.4f}s  stdev={s['stdev']:.4f}s")

    print("\n=== Summary across all parameter sets ===")
    print_report(results)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = RESULTS_DIR / f"perf_param_sets_{timestamp}.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {out_path}")
    return out_path


if __name__ == "__main__":
    main()
