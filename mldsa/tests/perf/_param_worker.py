"""Subprocess entry point: benchmark one ML-DSA parameter set in isolation.

Invoked by bench_param_sets.py as `python3 -m mldsa.tests.perf._param_worker
<name>`, one subprocess per parameter set, so param_loader.load()'s
monkeypatch + reload (which mutates process-global module state) never
needs to be undone or interleaved with another parameter set.

Prints a single JSON line to stdout: {param_set, constants, raw, overall_summary}.
"""

import argparse
import json

from mldsa.tests.perf import bench_mldsa, param_loader

# keygen/sign/verify only -- bench_mldsa.py already established (like
# bench_slhdsa.py did for SLH-DSA) that det-vs-hedged, message size, and
# pre-hash algorithm don't move the needle, so this sweep skips them to
# keep the cross-parameter-set comparison cheap.
CONFIGS = [
    {"name": "keygen", "op": "keygen"},
    {"name": "sign", "op": "sign", "deterministic": True, "msg_size": "small"},
    {"name": "verify", "op": "verify", "msg_size": "small"},
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("param_set")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--trials", type=int, default=50)
    args = parser.parse_args()

    constants, api = param_loader.load(args.param_set)

    all_repeats = []
    for repeat in range(args.repeats):
        records = bench_mldsa.run_suite(args.trials, progress=False, api=api, configs=CONFIGS)
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
                "overall_summary": bench_mldsa.summarize(flat),
            }
        )
    )


if __name__ == "__main__":
    main()
