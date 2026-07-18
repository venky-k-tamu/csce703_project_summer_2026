"""Performance benchmark suite for ML-KEM-768 (FIPS 203).

Not part of the default `pytest` run (not named `test_*.py`) -- run
explicitly:

    python3 -m mlkem.tests.perf.bench_mlkem [options]

Unlike SLH-DSA, ML-KEM's public API has no deterministic/hedged switch,
no variable message (encaps always samples its own 32-byte m), and no
pre-hash option, so there isn't much of an "operational configuration"
axis within a single parameter set. The one real behavioral fork is
decaps' implicit-rejection path (FIPS 203 Algorithm 21): on a mismatched
ciphertext, decaps returns a pseudorandom key derived from z instead of
raising, so this suite times decaps on both a valid and a corrupted
ciphertext to see whether that fork is visible in wall-clock cost.
"""

import argparse
import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from mlkem import decaps, encaps, keygen

DEFAULT_API = {
    "keygen": keygen,
    "encaps": encaps,
    "decaps": decaps,
}

RESULTS_DIR = Path(__file__).parent / "results"

CONFIGS = [
    {"name": "keygen", "op": "keygen"},
    {"name": "encaps", "op": "encaps"},
    {"name": "decaps/valid", "op": "decaps", "corrupt": False},
    {"name": "decaps/invalid_ct", "op": "decaps", "corrupt": True},
]


def _prepare(config, api):
    ek, dk = api["keygen"]()
    fixture = {"ek": ek, "dk": dk}
    if config["op"] == "decaps":
        ss, ct = api["encaps"](ek)
        if config["corrupt"]:
            ct = bytes([ct[0] ^ 0x01]) + ct[1:]
        fixture["ct"] = ct
    return fixture


def _run_once(config, fixture, api):
    op = config["op"]
    if op == "keygen":
        t0 = time.perf_counter()
        api["keygen"]()
        return time.perf_counter() - t0
    if op == "encaps":
        t0 = time.perf_counter()
        api["encaps"](fixture["ek"])
        return time.perf_counter() - t0
    if op == "decaps":
        t0 = time.perf_counter()
        api["decaps"](fixture["dk"], fixture["ct"])
        return time.perf_counter() - t0
    raise ValueError(f"unknown op {op!r}")


def run_suite(trials, progress=True, api=None, configs=None):
    api = api or DEFAULT_API
    configs = configs if configs is not None else CONFIGS
    records = []
    for config in configs:
        fixture = _prepare(config, api)
        for i in range(trials):
            dt = _run_once(config, fixture, api)
            records.append({"config": config["name"], "op": config["op"], "trial": i, "seconds": dt})
            if progress:
                print(f"  {config['name']:<20} trial {i + 1}/{trials}: {dt * 1000:.3f} ms")
    return records


def summarize(records):
    by_config = {}
    for r in records:
        by_config.setdefault(r["config"], []).append(r["seconds"])
    summary = {}
    for name, durations in by_config.items():
        summary[name] = {
            "n": len(durations),
            "mean": statistics.mean(durations),
            "median": statistics.median(durations),
            "stdev": statistics.stdev(durations) if len(durations) > 1 else 0.0,
            "min": min(durations),
            "max": max(durations),
        }
    return summary


def print_summary(summary):
    header = f"{'config':<20}{'n':>6}{'mean(ms)':>11}{'median(ms)':>12}{'stdev(ms)':>11}{'min(ms)':>10}{'max(ms)':>10}"
    print(header)
    print("-" * len(header))
    for config in CONFIGS:
        name = config["name"]
        if name not in summary:
            continue
        s = summary[name]
        print(
            f"{name:<20}{s['n']:>6}{s['mean']*1000:>11.4f}{s['median']*1000:>12.4f}"
            f"{s['stdev']*1000:>11.4f}{s['min']*1000:>10.4f}{s['max']*1000:>10.4f}"
        )


def print_per_repeat_means(all_repeats):
    print(f"{'config':<20}" + "".join(f"{'repeat ' + str(i + 1):>14}" for i in range(len(all_repeats))))
    for config in CONFIGS:
        name = config["name"]
        row = f"{name:<20}"
        for repeat_records in all_repeats:
            durations = [r["seconds"] for r in repeat_records if r["config"] == name]
            row += f"{statistics.mean(durations)*1000:>14.4f}" if durations else f"{'-':>14}"
        print(row)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeats", type=int, default=3, help="number of full-suite repeats (default: 3)")
    parser.add_argument("--trials", type=int, default=100, help="trials per config (default: 100)")
    parser.add_argument("--quiet", action="store_true", help="suppress per-trial progress lines")
    args = parser.parse_args(argv)

    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    all_repeats = []
    for repeat in range(args.repeats):
        print(f"\n=== Repeat {repeat + 1}/{args.repeats} ===")
        records = run_suite(args.trials, progress=not args.quiet)
        for r in records:
            r["repeat"] = repeat
        all_repeats.append(records)
        print(f"\n--- Repeat {repeat + 1} summary ---")
        print_summary(summarize(records))

    flat = [r for repeat_records in all_repeats for r in repeat_records]
    overall_summary = summarize(flat)

    print("\n=== Overall summary (all repeats combined) ===")
    print_summary(overall_summary)

    print("\n=== Per-repeat mean (ms), run-to-run variability ===")
    print_per_repeat_means(all_repeats)

    output = {
        "timestamp": timestamp,
        "params": {"repeats": args.repeats, "trials": args.trials},
        "raw": flat,
        "overall_summary": overall_summary,
        "per_repeat_summary": [summarize(r) for r in all_repeats],
    }
    out_path = RESULTS_DIR / f"perf_{timestamp}.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to {out_path}")
    return out_path


if __name__ == "__main__":
    main()
