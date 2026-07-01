// keccak_f1600.sv — the Keccak-f[1600] permutation: 24 rounds of keccak_round.
// FIPS 202 §3.3 (Algorithm 7, KECCAK-p[1600,24] = KECCAK-f[1600]).
//
// Baseline microarchitecture: ONE ROUND PER CYCLE (24 cycles/permutation).
// Unrolling/pipelining is a deferred optimization (see docs/PLAN.md).

import keccak_pkg::*;

module keccak_f1600 (
    input  logic   clk,
    input  logic   rst_n,
    input  logic   start,       // 1-cycle pulse: latch state_in, begin permuting
    input  state_t state_in,    // initial state (sponge already XOR'd rate block)
    output state_t state_out,   // permuted state (valid when done=1)
    output logic   done         // 1-cycle pulse when the 24 rounds complete
);

  // TODO Phase 1:
  //   - hold current state in a register `A`
  //   - round counter 0..NUM_ROUNDS-1
  //   - instantiate keccak_round with round_const = RC[round_idx]
  //   - on `start`, load state_in and run; assert `done` after round 23
  //   - a small FSM: IDLE -> RUN(24) -> done pulse -> IDLE

  // Skeleton stubs so the module elaborates; REPLACE in Phase 1.
  assign state_out = state_in;
  assign done      = 1'b0;

  // Suppress unused warnings until implemented.
  wire _unused = &{1'b0, clk, rst_n, start};

endmodule : keccak_f1600
