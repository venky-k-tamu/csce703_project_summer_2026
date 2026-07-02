// keccak_round.sv — one Keccak-f[1600] round: theta, rho, pi, chi, iota.
// Purely combinational. FIPS 202 §3.2 (Algorithms 1-6).

import keccak_pkg::*;

module keccak_round (
    input  state_t a_in,          // input state A[x][y]
    input  lane_t  round_const,   // RC for this round (from keccak_pkg::RC)
    output state_t a_out          // output state after one full round
);

  // 64-bit left rotate; n may be 0 (rho offset for x=y=0).
  function automatic lane_t rotl(input lane_t v, input int unsigned n);
    int unsigned s;
    s = n % 64;
    rotl = (s == 0) ? v : ((v << s) | (v >> (64 - s)));
  endfunction

  lane_t  c [0:4];   // theta column parities
  lane_t  d [0:4];   // theta D[x]
  state_t at;        // after theta
  state_t b;         // after rho + pi
  integer x, y;

  always_comb begin
    // -- theta (§3.2.1) --
    for (x = 0; x < 5; x++)
      c[x] = a_in[x][0] ^ a_in[x][1] ^ a_in[x][2] ^ a_in[x][3] ^ a_in[x][4];
    for (x = 0; x < 5; x++)
      d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
    for (x = 0; x < 5; x++)
      for (y = 0; y < 5; y++)
        at[x][y] = a_in[x][y] ^ d[x];

    // -- rho (§3.2.2) then pi (§3.2.3), fused:
    //    rho: ar[X][Y] = rotl(at[X][Y], RHO[X][Y])
    //    pi:  b[x][y]  = ar[(x+3y) mod 5][x]
    for (x = 0; x < 5; x++)
      for (y = 0; y < 5; y++)
        b[x][y] = rotl(at[(x + 3*y) % 5][x], rho((x + 3*y) % 5, x));

    // -- chi (§3.2.4) --
    for (x = 0; x < 5; x++)
      for (y = 0; y < 5; y++)
        a_out[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]);

    // -- iota (§3.2.5) --
    a_out[0][0] = a_out[0][0] ^ round_const;
  end

endmodule : keccak_round
