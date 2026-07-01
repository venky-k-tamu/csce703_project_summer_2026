# hardware/ — SystemVerilog PQC Accelerator

Hardware acceleration for the PQC schemes implemented in software elsewhere
in this repo. **Phase 1 target: a shared Keccak-f[1600] / SHAKE / SHA3
core** — the one primitive every scheme depends on.

> **Status: scaffold (Phase 0).** Directory structure, plan, and skeletons
> only. No functional RTL yet — module bodies are marked `TODO`. See
> [`docs/PLAN.md`](docs/PLAN.md) for the phased plan and design decisions.

## Why Keccak is the shared core

All three schemes bottom out in the same permutation:

| Scheme | Keccak usage |
|--------|--------------|
| ML-KEM-768 (FIPS 203)  | SHA3-256 (`H`), SHA3-512 (`G`), SHAKE256 (`J`,`PRF`), SHAKE128 (`SampleNTT` XOF) |
| ML-DSA-65 (FIPS 204)   | SHAKE256 (`H`), SHAKE128 (`ExpandA`/`G` XOF) |
| SLH-DSA-SHAKE-128s (FIPS 205) | SHAKE256 for **everything** (F, H, T_l, PRF, PRF_msg, H_msg) |

One permutation core + a parameterizable sponge (rate + domain byte +
fixed/XOF output) covers every case:

| Mode     | Rate (bytes) | Domain | Output |
|----------|:------------:|:------:|:------:|
| SHAKE128 | 168 | `0x1F` | arbitrary (XOF) |
| SHAKE256 | 136 | `0x1F` | arbitrary (XOF) |
| SHA3-256 | 136 | `0x06` | 32 bytes |
| SHA3-512 |  72 | `0x06` | 64 bytes |

## Layout

```
hardware/
  docs/PLAN.md         authoritative phased plan + decisions
  rtl/keccak/          keccak_pkg, keccak_round, keccak_f1600,
                       keccak_sponge, shake_xof  (FIPS 202)
  tb/keccak/           UVM env: seq_item, driver, monitor, agent,
                       scoreboard, sequences, env, test, uvm_pkg
  tb/top/              tb_keccak.sv — DUT + interface + run_test()
  tb/vectors/          gen_vectors.py — golden vectors from Python
  sim/                 Makefile + filelists (rtl.f, tb.f)
```

Every RTL module maps to a FIPS 202 section and cites algorithm/table
numbers in its docstring — same convention as the software side.

## Verification approach

UVM environment; the **golden model is the Python reference**. Rather than
bridge Python and SystemVerilog live, `tb/vectors/gen_vectors.py` exports
per-mode `(message, expected_digest)` files (from `hashlib`, cross-checked
against `mlkem/mldsa/slhdsa` hash wrappers and the NIST KATs). The UVM
scoreboard loads them and compares the DUT's squeeze output.

## Building & running

Requires a UVM-capable simulator (Questa / VCS / Xcelium). From `hardware/sim/`:

```
make vectors            # regenerate golden vector files (needs python3)
make sim SIM=questa     # compile + run (SIM=questa|vcs|xcelium)
make sim TEST=keccak_shake256_test
make clean
```

See [`docs/PLAN.md`](docs/PLAN.md) for phase-by-phase next steps.
