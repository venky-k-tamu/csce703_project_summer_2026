"""Performance benchmark suite for ML-DSA-65 (FIPS 204).

Not part of the default `pytest` run (not named `test_*.py`) -- run
explicitly:

    python3 -m mldsa.tests.perf.bench_mldsa [options]

Unlike SLH-DSA, ML-DSA's keygen/sign/verify are all the same order of
magnitude (tens of milliseconds), so this suite uses a single uniform
trial count rather than SLH-DSA's expensive-vs-cheap split.
"""

import argparse
import json
import os
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from mldsa import hash_sign, hash_verify, keygen, sign, verify

DEFAULT_API = {
    "keygen": keygen,
    "sign": sign,
    "verify": verify,
    "hash_sign": hash_sign,
    "hash_verify": hash_verify,
}

RESULTS_DIR = Path(__file__).parent / "results"

MSG_SIZES = {"small": 32, "large": 16384}

CONFIGS = [
    {"name": "keygen", "op": "keygen"},
    {"name": "sign/det/small", "op": "sign", "deterministic": True, "msg_size": "small"},
    {"name": "sign/det/large", "op": "sign", "deterministic": True, "msg_size": "large"},
    {"name": "sign/hedged/small", "op": "sign", "deterministic": False, "msg_size": "small"},
    {"name": "sign/hedged/large", "op": "sign", "deterministic": False, "msg_size": "large"},
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
    pk, sk = api["keygen"]()
    msg = _message(config.get("msg_size", "small"))
    fixture = {"pk": pk, "sk": sk, "msg": msg}
    op = config["op"]
    if op == "verify":
        fixture["sig"] = api["sign"](sk, msg, deterministic=True)
    elif op == "hash_verify":
        fixture["sig"] = api["hash_sign"](sk, msg, hash_alg=config["hash_alg"], deterministic=True)
    return fixture


def _run_once(config, fixture, api):
    op = config["op"]
    if op == "keygen":
        t0 = time.perf_counter()
        api["keygen"]()
        return time.perf_counter() - t0
    if op == "sign":
        t0 = time.perf_counter()
        api["sign"](fixture["sk"], fixture["msg"], deterministic=config["deterministic"])
        return time.perf_counter() - t0
    if op == "verify":
        t0 = time.perf_counter()
        ok = api["verify"](fixture["pk"], fixture["msg"], fixture["sig"])
        dt = time.perf_counter() - t0
        assert ok
        return dt
    if op == "hash_sign":
        t0 = time.perf_counter()
        api["hash_sign"](fixture["sk"], fixture["msg"], hash_alg=config["hash_alg"], deterministic=True)
        return time.perf_counter() - t0
    if op == "hash_verify":
        t0 = time.perf_counter()
        ok = api["hash_verify"](fixture["pk"], fixture["msg"], fixture["sig"], hash_alg=config["hash_alg"])
        dt = time.perf_counter() - t0
        assert ok
        return dt
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
                print(f"  {config['name']:<22} trial {i + 1}/{trials}: {dt * 1000:.3f} ms")
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
    header = f"{'config':<22}{'n':>6}{'mean(ms)':>11}{'median(ms)':>12}{'stdev(ms)':>11}{'min(ms)':>10}{'max(ms)':>10}"
    print(header)
    print("-" * len(header))
    for config in CONFIGS:
        name = config["name"]
        if name not in summary:
            continue
        s = summary[name]
        print(
            f"{name:<22}{s['n']:>6}{s['mean']*1000:>11.4f}{s['median']*1000:>12.4f}"
            f"{s['stdev']*1000:>11.4f}{s['min']*1000:>10.4f}{s['max']*1000:>10.4f}"
        )


def print_per_repeat_means(all_repeats):
    print(f"{'config':<22}" + "".join(f"{'repeat ' + str(i + 1):>14}" for i in range(len(all_repeats))))
    for config in CONFIGS:
        name = config["name"]
        row = f"{name:<22}"
        for repeat_records in all_repeats:
            durations = [r["seconds"] for r in repeat_records if r["config"] == name]
            row += f"{statistics.mean(durations)*1000:>14.4f}" if durations else f"{'-':>14}"
        print(row)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeats", type=int, default=3, help="number of full-suite repeats (default: 3)")
    parser.add_argument("--trials", type=int, default=50, help="trials per config (default: 50)")
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
