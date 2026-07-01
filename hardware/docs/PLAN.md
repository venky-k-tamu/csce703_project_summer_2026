# Hardware Accelerator — Plan

Authoritative plan for the SystemVerilog PQC accelerator. Mirrors the
role of the software `docs/PLAN.md`: phases, decisions, and layout.

## Goal

A synthesizable, reusable **Keccak-f[1600] / SHAKE / SHA3 core** — the
single primitive shared by all three PQC schemes in this repo — verified
in simulation against the existing Python reference (used as the golden
model) and the NIST KAT vectors.

Later phases stack lattice (NTT) and hash-based (WOTS/XMSS/FORS) datapaths
on top of this core, but **Phase 1 is the Keccak core only**.

## Scope & non-goals (this phase)

- **Simulation-only.** Portable, vendor-neutral RTL. No board files, no
  vendor IP, no timing constraints yet. An FPGA/ASIC backend is a later,
  additive phase under `hardware/syn/` or `hardware/fpga/`.
- **UVM verification** (commercial sim: Questa / VCS / Xcelium). The
  golden model is exported from the Python reference to plain vector
  files that the UVM scoreboard reads (see `tb/vectors/`), so RTL
  verification does not require a live Python↔SV bridge.
- **No performance/area optimization yet.** Baseline microarchitecture is
  **one Keccak round per cycle** (24 cycles/permutation) — the clearest
  mapping to FIPS 202 and the easiest to verify. Unrolling, pipelining,
  and multi-lane variants are deferred and must be justified by a measured
  need, exactly as in the software non-goals.

## Why Keccak first

All three schemes bottom out in Keccak (see the table in `hardware/README.md`).
SLH-DSA is almost entirely SHAKE256; ML-DSA and ML-KEM use SHAKE128/256 for
sampling plus SHA3-256/512 for hashing. One permutation core + a
parameterizable sponge covers every case, so it is the highest-leverage
first block and unblocks all later work.

## Target: FIPS 202 (SHA-3 / SHAKE)

The core is defined entirely by FIPS 202. Reference the section numbers in
module docstrings, the same convention the software side uses:

- **§3.2** — the five step mappings θ, ρ, π, χ, ι (one round).
- **Table 1** — round constants `RC[0..23]`.
- **§3.2.2 / Table 2** — ρ rotation offsets.
- **Algorithm 8 (SPONGE)** / **§4** — absorb/pad/squeeze.
- **§6.1–6.2** — SHA3-256/512 (domain `0x06`) and SHAKE128/256
  (domain `0x1F`) instantiations, rates r = 1088/512/1344/1088 bits.

Golden reference: Python `hashlib.shake_128/256`, `sha3_256/512`, which the
software layers (`mlkem/hashes.py`, `mldsa/hashes.py`, `slhdsa/hashes.py`)
already wrap and which the KATs already exercise transitively.

## RTL module stack (`hardware/rtl/`)

Bottom-up dependency stack, mirroring the software convention (each layer
only uses those below it):

```
shake_xof.sv     Mode-select wrapper: SHAKE128/256, SHA3-256/512.
                 Picks rate + domain byte + fixed/XOF output. FIPS 202 §6.
keccak_sponge.sv Sponge: byte-stream absorb (with pad10*1), permute,
                 squeeze. Parameterized RATE_BYTES + DOMAIN. FIPS 202 §4.
keccak_f1600.sv  Permutation: 24-round FSM around keccak_round. §3.2.
keccak_round.sv  One round = θ·ρ·π·χ·ι (combinational). §3.2.
keccak_pkg.sv    lane/state typedefs, RC[24], rho offsets, mode enum,
                 rate/domain constants. FIPS 202 Table 1 & 2.
```

State representation: `state_t = lane_t [0:4][0:4]`, `lane_t = logic[63:0]`.
Lane `A[x][y]`; bit `(x,y,z)` per FIPS 202 §3.1.2. Byte↔lane conversion is
little-endian (§B.1) — this is the #1 thing to recheck if KAT bytes mismatch,
the hardware analogue of the software (col,row) byte-order pitfall.

Handshake (baseline): a simple valid/ready byte interface — `in_*` to absorb
the message with an `in_last` marker, `out_*` to squeeze; `mode` and (for XOF)
`out_len` are latched at start. AXI-Stream alignment is a later option.

## UVM environment (`hardware/tb/`)

Standard UVM agent + scoreboard, transaction = one (mode, message,
out_len) → expected-digest case:

```
tb/keccak/keccak_if.sv          clocking/handshake interface to the DUT
tb/keccak/keccak_seq_item.svh   transaction: mode, msg[], out_len, exp_digest[]
tb/keccak/keccak_sequence.svh   KAT-file-driven + directed + random sequences
tb/keccak/keccak_driver.svh     drives absorb/squeeze handshake
tb/keccak/keccak_monitor.svh    reconstructs transactions from the bus
tb/keccak/keccak_agent.svh      sequencer + driver + monitor
tb/keccak/keccak_scoreboard.svh compares DUT squeeze vs exp_digest
tb/keccak/keccak_env.svh        agent + scoreboard + config
tb/keccak/keccak_test.svh       base test + one test per mode
tb/keccak/keccak_uvm_pkg.sv     package that includes the above
tb/top/tb_keccak.sv             DUT + interface + run_test()
```

Golden vectors: `tb/vectors/gen_vectors.py` emits per-mode stimulus/expected
files (from Python `hashlib`, cross-checked against the repo's hash wrappers).
The scoreboard loads them; no live Python process is needed during simulation.

## Simulation flow (`hardware/sim/`)

- `filelists/rtl.f`, `filelists/tb.f` — compile order, single source of truth.
- `Makefile` — `make vectors` (regenerate golden files), `make sim`
  (compile + run, sim selectable via `SIM=questa|vcs|xcelium`), `make clean`.
- UVM requires a commercial simulator; the Makefile documents the assumption
  and the `+UVM_TESTNAME` plusarg per test.

## Phases

Each phase ends green and gets a single commit
(`HW Phase N: …`), matching the repo's per-phase commit convention.

- **Phase 0 — Scaffold (this commit).** Directory tree, `PLAN.md`,
  `README.md`, module/UVM skeletons with fixed port lists and constant
  tables, filelists, Makefile, vector generator. Nothing functional yet.
- **Phase 1 — `keccak_round` + `keccak_f1600`.** Implement the five step
  mappings and the 24-round FSM. Unit-verify the permutation against a
  known Keccak-f[1600] test vector (all-zero input → known state).
- **Phase 2 — `keccak_sponge`.** Absorb with `pad10*1`, squeeze; verify
  SHAKE256 empty-message and multi-block messages against golden vectors.
- **Phase 3 — `shake_xof` + full UVM env.** All four modes, KAT-driven
  scoreboard, directed + randomized sequences, coverage on mode × message
  length × output length.
- **Phase 4+ (future).** NTT datapath (ML-KEM/ML-DSA), then hash-based
  chains (SLH-DSA), each reusing this core. Separate plan when reached.

## Open decisions (revisit before Phase 1)

- **Absorb bus width.** 8-bit (simplest, matches byte-oriented FIPS 202)
  vs 64-bit lane-at-a-time (fewer cycles). Default 8-bit for Phase 1.
- **Rate mismatch mid-stream.** Modes have different rates; `mode` is
  latched at `start` and constant per message — no mid-message switching.
- **Verilator smoke path.** UVM needs a commercial sim, but a thin
  non-UVM SV testbench under `tb/top/` could give an open-source smoke
  test for `keccak_f1600`. Decide if worth maintaining two TB paths.
