"""Subprocess entry point: benchmark one parameter set in isolation.

Invoked by bench_param_sets.py as `python3 -m slhdsa.tests.perf._param_worker
<name>`, one subprocess per parameter set, so param_loader.load()'s
monkeypatch + reload (which mutates process-global module state) never
needs to be undone or interleaved with another parameter set.

Prints a single JSON line to stdout: {param_set, constants, raw, overall_summary}.
"""

import argparse
import json

from slhdsa.tests.perf import bench_slhdsa, param_loader

# keygen/sign/verify only -- det-vs-hedged, message size, and pre-hash
# algorithm were already shown (bench_slhdsa's own suite) not to matter
# for SLH-DSA-SHAKE-128s; this sweep's purpose is the category/speed axis,
# not re-litigating those, so it skips the redundant configs to bound
# runtime across 6 parameter sets whose signing costs differ by 10-100x.
CONFIGS = [
    {"name": "keygen", "op": "keygen"},
    {"name": "sign", "op": "sign", "randomize": False, "msg_size": "small"},
    {"name": "verify", "op": "verify", "msg_size": "small"},
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("param_set")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--expensive-trials", type=int, default=3)
    parser.add_argument("--cheap-trials", type=int, default=10)
    args = parser.parse_args()

    constants, api = param_loader.load(args.param_set)

    all_repeats = []
    for repeat in range(args.repeats):
        records = bench_slhdsa.run_suite(
            args.expensive_trials, args.cheap_trials, progress=False, api=api, configs=CONFIGS
        )
        for r in records:
            r["repeat"] = repeat
        all_repeats.append(records)

    flat = [r for rr in all_repeats for r in rr]
    print(
        json.dumps(
            {
                "param_set": args.param_set,
                "constants": constants,
                "raw": flat,
                "overall_summary": bench_slhdsa.summarize(flat),
            }
        )
    )


if __name__ == "__main__":
    main()
