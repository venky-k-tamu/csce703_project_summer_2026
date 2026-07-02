# tb/smoke — open-source smoke test (Icarus)

A thin, self-checking SystemVerilog testbench that exercises the whole Keccak
datapath (`keccak_round` → `keccak_f1600` → `keccak_sponge` → `shake_xof`)
without a commercial simulator. This is the fast regression that complements
the UVM environment (`tb/keccak/`), which needs Questa/VCS/Xcelium.

Run from `hardware/sim/`:

```
make smoke
```

That runs `gen_smoke.py` (writes `fixtures/*.hex` + `smoke_cases.svh` from
Python `hashlib`), compiles with Icarus, and self-checks. Expected tail:

```
=== 7/7 cases passed ===
```

Cases cover all four modes (SHAKE128/256, SHA3-256/512), plus multi-block
absorb (200-byte message > rate) and multi-block squeeze (168/300-byte XOF
output). Generated files are git-ignored; `make smoke` recreates them.

## Handshake note

The absorb interface uses a **terminator-beat** protocol (see
`keccak_sponge.sv`): drive message bytes on beats with `in_last=0`, then one
final `in_valid=1, in_last=1` beat (data ignored) to finalize — an empty
message is just that terminator beat.

The TB driver is **ready-gated**: it waits (at negedge) for `in_ready` /
`out_valid` to park high while holding the complementary handshake signal
low, then pulses for one cycle. This avoids sampling races and is robust
across simulator NBA-ordering differences.
