"""Benchmark keygen/sign/verify across all three FIPS 204 ML-DSA
parameter sets (categories 2/3/5), each run in its own subprocess.

    python3 -m mldsa.tests.perf.bench_param_sets [options]

Only ML-DSA-65 (mldsa/params.py) is the real, NIST-ACVP-KAT-verified
implementation shipped in this repo -- see CLAUDE.md. ML-DSA-44 and
ML-DSA-87 run the exact same algorithm code under monkeypatched
parameters (see param_loader.py) purely to measure how cost scales
across categories; each subprocess self-tests a sign/verify round trip
before timing.
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import param_sets

RESULTS_DIR = Path(__file__).parent / "results"


def run_param_set(name, repeats, trials):
    cmd = [
        sys.executable,
        "-m",
        "mldsa.tests.perf._param_worker",
        name,
        "--repeats",
        str(repeats),
        "--trials",
        str(trials),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"worker for {name!r} failed:\n{proc.stderr}")
    return json.loads(proc.stdout)


def print_report(results):
    header = (
        f"{'param set':<12}{'k':>4}{'l':>4}{'eta':>5}{'tau':>5}"
        f"{'sig(B)':>8}{'keygen(ms)':>12}{'sign(ms)':>11}{'verify(ms)':>12}"
    )
    print(header)
    print("-" * len(header))
    for name, result in results.items():
        c = result["constants"]
        s = result["overall_summary"]
        print(
            f"{name:<12}{c['K']:>4}{c['L']:>4}{c['ETA']:>5}{c['TAU']:>5}"
            f"{c['SIG_SIZE']:>8}{s['keygen']['mean']*1000:>12.4f}"
            f"{s['sign']['mean']*1000:>11.4f}{s['verify']['mean']*1000:>12.4f}"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--param-sets", nargs="+", default=list(param_sets.RAW_PARAMS), choices=list(param_sets.RAW_PARAMS)
    )
    parser.add_argument("--repeats", type=int, default=3, help="full-suite repeats per parameter set (default: 3)")
    parser.add_argument("--trials", type=int, default=50, help="trials per config (default: 50)")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(exist_ok=True)
    results = {}
    for name in args.param_sets:
        print(f"\n=== {name} ===")
        result = run_param_set(name, args.repeats, args.trials)
        results[name] = result
        for config_name, s in result["overall_summary"].items():
            print(f"  {config_name:<8} n={s['n']:<5} mean={s['mean']*1000:.4f} ms  median={s['median']*1000:.4f} ms  stdev={s['stdev']*1000:.4f} ms")

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
