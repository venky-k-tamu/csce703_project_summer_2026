// keccak_round.sv — one Keccak-f[1600] round: theta, rho, pi, chi, iota.
// Purely combinational. FIPS 202 §3.2 (Algorithms 1-6).
//
// Phase 1 TODO: implement the five step mappings. Left as a skeleton so the
// port contract is fixed before the datapath is filled in.

import keccak_pkg::*;

module keccak_round (
    input  state_t a_in,          // input state A[x][y]
    input  lane_t  round_const,   // RC for this round (from keccak_pkg::RC)
    output state_t a_out          // output state after one full round
);

  // TODO Phase 1:
  //   theta:  C[x]     = A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4]
  //           D[x]     = C[x-1] ^ rotl(C[x+1], 1)
  //           A'[x][y] = A[x][y] ^ D[x]                              (§3.2.1)
  //   rho:    B[x][y]  = rotl(A'[x][y], RHO[x][y])                   (§3.2.2)
  //   pi:     B'[y][2x+3y] = B[x][y]   (i.e. remap lane positions)   (§3.2.3)
  //   chi:    C[x][y]  = B'[x][y] ^ ((~B'[x+1][y]) & B'[x+2][y])     (§3.2.4)
  //   iota:   a_out[0][0] = C[0][0] ^ round_const; else C[x][y]      (§3.2.5)
  //
  // All x/y arithmetic is mod 5; rotl is a 64-bit left rotate.

  // Placeholder pass-through so the module elaborates; REMOVE in Phase 1.
  assign a_out = a_in;

endmodule : keccak_round
