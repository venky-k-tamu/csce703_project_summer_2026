"""Performance benchmark suite for SLH-DSA-SHAKE-128s (FIPS 205).

Deliberately not named `test_*.py` -- signing takes seconds per call, so
this is a standalone script, not part of the default `pytest` run:

    python3 -m slhdsa.tests.perf.bench_slhdsa [options]

See slhdsa/tests/perf/README.md for the configuration matrix and cost
estimate. Only SLH-DSA-SHAKE-128s is implemented in this repo, so
"configuration" here means the operational variants of the public API
(deterministic vs. hedged signing, message size, HashSLH-DSA pre-hash
algorithm), not distinct FIPS 205 parameter sets.
"""

import argparse
import json
import os
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from slhdsa import hash_sign, hash_verify, keygen, sign, verify

# Default API: the real, NIST-KAT-verified SLH-DSA-SHAKE-128s implementation.
# bench_param_sets.py injects a different `api` dict (same code, monkeypatched
# parameters) to benchmark the other FIPS 205 SHAKE parameter sets.
DEFAULT_API = {
    "keygen": keygen,
    "sign": sign,
    "verify": verify,
    "hash_sign": hash_sign,
    "hash_verify": hash_verify,
}

RESULTS_DIR = Path(__file__).parent / "results"

MSG_SIZES = {"small": 32, "large": 16384}

# keygen/sign/hash_sign dominate wall-clock time (full hypertree + FORS
# computation); verify/hash_verify are ~1000x cheaper (root recomputation
# only), so they get more trials by default for tighter statistics.
EXPENSIVE_OPS = {"keygen", "sign", "hash_sign"}

CONFIGS = [
    {"name": "keygen", "op": "keygen"},
    {"name": "sign/det/small", "op": "sign", "randomize": False, "msg_size": "small"},
    {"name": "sign/det/large", "op": "sign", "randomize": False, "msg_size": "large"},
    {"name": "sign/hedged/small", "op": "sign", "randomize": True, "msg_size": "small"},
    {"name": "sign/hedged/large", "op": "sign", "randomize": True, "msg_size": "large"},
    {"name": "verify/small", "op": "verify", "msg_size": "small"},
    {"name": "verify/large", "op": "verify", "msg_size": "large"},
    {"name": "hash_sign/SHA2-256", "op": "hash_sign", "hash_alg": "SHA2-256", "msg_size": "small"},
    {"name": "hash_sign/SHA2-512", "op": "hash_sign", "hash_alg": "SHA2-512", "msg_size": "small"},
    {"name": "hash_sign/SHAKE-256", "op": "hash_sign", "hash_alg": "SHAKE-256", "msg_size": "small"},
    {"name": "hash_verify/SHA2-256", "op": "hash_verify", "hash_alg": "SHA2-256", "msg_size": "small"},
    {"name": "hash_verify/SHA2-512", "op": "hash_verify", "hash_alg": "SHA2-512", "msg_size": "small"},
    {"name": "hash_verify/SHAKE-256", "op": "hash_verify", "hash_alg": "SHAKE-256", "msg_size": "small"},
]


def _message(size_label):
    return os.urandom(MSG_SIZES[size_label])


def _prepare(config, api):
    """Build fixtures (keys, message, and a signature if needed) outside the timed region."""
    pk, sk = api["keygen"]()
    msg = _message(config.get("msg_size", "small"))
    fixture = {"pk": pk, "sk": sk, "msg": msg}
    op = config["op"]
    if op == "verify":
        fixture["sig"] = api["sign"](msg, sk, randomize=False)
    elif op == "hash_verify":
        fixture["sig"] = api["hash_sign"](msg, sk, hash_alg=config["hash_alg"], randomize=False)
    return fixture


def _run_once(config, fixture, api):
    op = config["op"]
    if op == "keygen":
        t0 = time.perf_counter()
        api["keygen"]()
        return time.perf_counter() - t0
    if op == "sign":
        t0 = time.perf_counter()
        api["sign"](fixture["msg"], fixture["sk"], randomize=config["randomize"])
        return time.perf_counter() - t0
    if op == "verify":
        t0 = time.perf_counter()
        ok = api["verify"](fixture["msg"], fixture["sig"], fixture["pk"])
        dt = time.perf_counter() - t0
        assert ok
        return dt
    if op == "hash_sign":
        t0 = time.perf_counter()
        api["hash_sign"](fixture["msg"], fixture["sk"], hash_alg=config["hash_alg"], randomize=False)
        return time.perf_counter() - t0
    if op == "hash_verify":
        t0 = time.perf_counter()
        ok = api["hash_verify"](fixture["msg"], fixture["sig"], fixture["pk"], hash_alg=config["hash_alg"])
        dt = time.perf_counter() - t0
        assert ok
        return dt
    raise ValueError(f"unknown op {op!r}")


def _trials_for(config, expensive_trials, cheap_trials):
    return expensive_trials if config["op"] in EXPENSIVE_OPS else cheap_trials


def run_suite(expensive_trials, cheap_trials, progress=True, api=None, configs=None):
    """Run every configuration once and return the raw per-trial records.

    `api` lets callers inject a differently-parameterized SLH-DSA implementation
    (see param_loader.py); defaults to the real SLH-DSA-SHAKE-128s package.
    `configs` lets callers run a subset of CONFIGS (see bench_param_sets.py,
    which only needs keygen/sign/verify to compare parameter sets).
    """
    api = api or DEFAULT_API
    configs = configs if configs is not None else CONFIGS
    records = []
    for config in configs:
        fixture = _prepare(config, api)
        trials = _trials_for(config, expensive_trials, cheap_trials)
        for i in range(trials):
            dt = _run_once(config, fixture, api)
            records.append({"config": config["name"], "op": config["op"], "trial": i, "seconds": dt})
            if progress:
                print(f"  {config['name']:<24} trial {i + 1}/{trials}: {dt:.4f}s")
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
    header = f"{'config':<24}{'n':>5}{'mean(s)':>10}{'median(s)':>11}{'stdev(s)':>10}{'min(s)':>9}{'max(s)':>9}"
    print(header)
    print("-" * len(header))
    for config in CONFIGS:
        name = config["name"]
        if name not in summary:
            continue
        s = summary[name]
        print(
            f"{name:<24}{s['n']:>5}{s['mean']:>10.4f}{s['median']:>11.4f}"
            f"{s['stdev']:>10.4f}{s['min']:>9.4f}{s['max']:>9.4f}"
        )


def print_per_repeat_means(all_repeats):
    print(f"{'config':<24}" + "".join(f"{'repeat ' + str(i + 1):>12}" for i in range(len(all_repeats))))
    for config in CONFIGS:
        name = config["name"]
        row = f"{name:<24}"
        for repeat_records in all_repeats:
            durations = [r["seconds"] for r in repeat_records if r["config"] == name]
            row += f"{statistics.mean(durations):>12.4f}" if durations else f"{'-':>12}"
        print(row)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeats", type=int, default=3, help="number of full-suite repeats (default: 3)")
    parser.add_argument("--expensive-trials", type=int, default=5, help="trials/config for keygen/sign/hash_sign (default: 5)")
    parser.add_argument("--cheap-trials", type=int, default=20, help="trials/config for verify/hash_verify (default: 20)")
    parser.add_argument("--quiet", action="store_true", help="suppress per-trial progress lines")
    args = parser.parse_args(argv)

    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    all_repeats = []
    for repeat in range(args.repeats):
        print(f"\n=== Repeat {repeat + 1}/{args.repeats} ===")
        records = run_suite(args.expensive_trials, args.cheap_trials, progress=not args.quiet)
        for r in records:
            r["repeat"] = repeat
        all_repeats.append(records)
        print(f"\n--- Repeat {repeat + 1} summary ---")
        print_summary(summarize(records))

    flat = [r for repeat_records in all_repeats for r in repeat_records]
    overall_summary = summarize(flat)

    print("\n=== Overall summary (all repeats combined) ===")
    print_summary(overall_summary)

    print("\n=== Per-repeat mean (seconds), run-to-run variability ===")
    print_per_repeat_means(all_repeats)

    output = {
        "timestamp": timestamp,
        "params": {
            "repeats": args.repeats,
            "expensive_trials": args.expensive_trials,
            "cheap_trials": args.cheap_trials,
        },
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
