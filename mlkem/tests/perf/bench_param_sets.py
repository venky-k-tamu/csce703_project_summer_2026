"""Benchmark keygen/encaps/decaps across all three FIPS 203 ML-KEM
parameter sets (categories 1/3/5), each run in its own subprocess.

    python3 -m mlkem.tests.perf.bench_param_sets [options]

Only ML-KEM-768 (mlkem/params.py) is the real, NIST-ACVP-KAT-verified
implementation shipped in this repo -- see CLAUDE.md. ML-KEM-512 and
ML-KEM-1024 run the exact same algorithm code under monkeypatched
(k, eta1, eta2, du, dv) (see param_loader.py) purely to measure how
cost scales with module rank k; each subprocess self-tests an
encaps/decaps round trip before timing.
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
        "mlkem.tests.perf._param_worker",
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
        f"{'param set':<14}{'k':>4}{'eta1':>6}{'eta2':>6}{'du':>4}{'dv':>4}"
        f"{'ek(B)':>8}{'ct(B)':>8}{'keygen(ms)':>12}{'encaps(ms)':>12}{'decaps(ms)':>12}"
    )
    print(header)
    print("-" * len(header))
    for name, result in results.items():
        c = result["constants"]
        s = result["overall_summary"]
        decaps_ms = s["decaps/valid"]["mean"] * 1000
        print(
            f"{name:<14}{c['K']:>4}{c['ETA_1']:>6}{c['ETA_2']:>6}{c['DU']:>4}{c['DV']:>4}"
            f"{c['EK_SIZE']:>8}{c['CT_SIZE']:>8}"
            f"{s['keygen']['mean']*1000:>12.4f}{s['encaps']['mean']*1000:>12.4f}{decaps_ms:>12.4f}"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--param-sets", nargs="+", default=list(param_sets.RAW_PARAMS), choices=list(param_sets.RAW_PARAMS)
    )
    parser.add_argument("--repeats", type=int, default=3, help="full-suite repeats per parameter set (default: 3)")
    parser.add_argument("--trials", type=int, default=100, help="trials per config (default: 100)")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(exist_ok=True)
    results = {}
    for name in args.param_sets:
        print(f"\n=== {name} ===")
        result = run_param_set(name, args.repeats, args.trials)
        results[name] = result
        for config_name, s in result["overall_summary"].items():
            print(f"  {config_name:<18} n={s['n']:<5} mean={s['mean']*1000:.4f} ms  median={s['median']*1000:.4f} ms  stdev={s['stdev']*1000:.4f} ms")

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
