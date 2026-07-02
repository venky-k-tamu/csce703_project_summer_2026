// keccak_f1600.sv — the Keccak-f[1600] permutation: 24 rounds of keccak_round.
// FIPS 202 §3.3 (Algorithm 7, KECCAK-p[1600,24] = KECCAK-f[1600]).
//
// Microarchitecture: ONE ROUND PER CYCLE (24 cycles/permutation).

import keccak_pkg::*;

module keccak_f1600 (
    input  logic   clk,
    input  logic   rst_n,
    input  logic   start,       // 1-cycle pulse: latch state_in, begin permuting
    input  state_t state_in,    // initial state (sponge already XOR'd rate block)
    output state_t state_out,   // permuted state (valid when done=1)
    output logic   done         // 1-cycle pulse when the 24 rounds complete
);

  state_t     a_reg;            // working state
  state_t     round_out;        // combinational next state for current round
  logic [4:0] round;           // 0 .. NUM_ROUNDS-1
  logic       running;
  integer     xx, yy;

  keccak_round u_round (
      .a_in        (a_reg),
      .round_const (rc(round)),
      .a_out       (round_out)
  );

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      running <= 1'b0;
      done    <= 1'b0;
      round   <= 5'd0;
    end
    else begin
      done <= 1'b0;                       // default: single-cycle pulse
      if (start && !running) begin
        for (xx = 0; xx < 5; xx++)        // load fresh state (element-wise:
          for (yy = 0; yy < 5; yy++)      // iverilog has no whole-uarray copy)
            a_reg[xx][yy] <= state_in[xx][yy];
        round   <= 5'd0;
        running <= 1'b1;
      end
      else if (running) begin
        for (xx = 0; xx < 5; xx++)        // apply round `round`
          for (yy = 0; yy < 5; yy++)
            a_reg[xx][yy] <= round_out[xx][yy];
        if (round == NUM_ROUNDS - 1) begin
          running <= 1'b0;
          done    <= 1'b1;               // final round applied
        end
        else begin
          round <= round + 5'd1;
        end
      end
    end
  end

  genvar gx, gy;
  generate
    for (gx = 0; gx < 5; gx++)
      for (gy = 0; gy < 5; gy++)
        assign state_out[gx][gy] = a_reg[gx][gy];
  endgenerate

endmodule : keccak_f1600
