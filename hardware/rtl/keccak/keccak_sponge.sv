// keccak_sponge.sv — sponge construction around keccak_f1600.
// Absorb (with pad10*1), permute, squeeze. FIPS 202 §4 (Algorithm 8, SPONGE).
//
// State is held as a 200-byte little-endian view `sb` (FIPS 202 §B.1: byte i
// occupies bits [8*(i%8) +: 8] of lane A[(i/8)%5][(i/8)/5]). Absorb/squeeze
// are byte-indexed into `sb`; it is packed to/from state_t only around the
// permutation.
//
// Absorb protocol (terminator-beat): drive message bytes on beats with
// in_valid=1, in_last=0. Then drive ONE beat with in_valid=1, in_last=1
// (in_data ignored) to finalize. An empty message is just that terminator
// beat. This keeps the empty-message case free of extra sideband.

import keccak_pkg::*;

module keccak_sponge (
    input  logic         clk,
    input  logic         rst_n,

    input  logic         start,       // latch mode/out_len, clear state
    input  keccak_mode_e mode,
    input  logic [31:0]  out_len,     // requested output bytes

    input  logic         in_valid,
    input  logic [7:0]   in_data,
    input  logic         in_last,     // terminator beat (no data absorbed)
    output logic         in_ready,

    output logic         out_valid,
    output logic [7:0]   out_data,
    output logic         out_last,
    input  logic         out_ready,

    output logic         busy
);

  // ---- FSM ---------------------------------------------------------------
  typedef enum logic [2:0] {
    S_IDLE, S_ABSORB, S_FINISH, S_PERMUTE, S_SQUEEZE
  } state_e;
  state_e st;

  // where to resume after a permutation completes
  state_e after_perm;

  // ---- sponge state + bookkeeping ---------------------------------------
  logic [7:0]   sb [0:199];      // 200-byte state
  keccak_mode_e mode_q;
  logic [31:0]  outlen_q;
  int unsigned  pos;             // next absorb byte position within rate block
  int unsigned  optr;            // squeeze byte position within rate block
  logic [31:0]  ocnt;            // output bytes emitted so far (current index)

  // per-mode rate / domain
  int unsigned  rate;
  logic [7:0]   dom;
  always_comb begin
    rate = rate_bytes(mode_q);
    dom  = domain_byte(mode_q);
  end

  // ---- permutation instance ---------------------------------------------
  state_t perm_in, perm_out;
  logic   perm_start, perm_done;
  integer L, k;

  // pack sb -> state_t (little-endian lanes)
  always_comb begin
    for (L = 0; L < 25; L++)
      for (k = 0; k < 8; k++)
        perm_in[L % 5][L / 5][8*k +: 8] = sb[8*L + k];
  end

  keccak_f1600 u_perm (
      .clk       (clk),
      .rst_n     (rst_n),
      .start     (perm_start),
      .state_in  (perm_in),
      .state_out (perm_out),
      .done      (perm_done)
  );

  // ---- combinational outputs (state-derived) ----------------------------
  assign in_ready  = (st == S_ABSORB);
  assign out_valid = (st == S_SQUEEZE);
  assign out_data  = sb[optr];
  assign out_last  = (st == S_SQUEEZE) && (ocnt == outlen_q - 1);
  assign busy      = (st != S_IDLE);

  // ---- main FSM ----------------------------------------------------------
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      st         <= S_IDLE;
      perm_start <= 1'b0;
      pos        <= 0;
      optr       <= 0;
      ocnt       <= 0;
      mode_q     <= MODE_SHAKE256;
    end
    else begin
      perm_start <= 1'b0;                 // default: single-cycle pulse

      case (st)
        // -------------------------------------------------------------
        S_IDLE: begin
          if (start) begin
            mode_q   <= mode;
            outlen_q <= out_len;
            for (int i = 0; i < 200; i++) sb[i] <= 8'h00;
            pos <= 0;
            st  <= S_ABSORB;
          end
        end

        // -------------------------------------------------------------
        S_ABSORB: begin
          if (in_valid) begin
            if (in_last) begin
              st <= S_FINISH;            // terminator: no data absorbed
            end
            else begin
              sb[pos] <= sb[pos] ^ in_data;
              if (pos == rate - 1) begin // block full -> permute, keep absorbing
                pos        <= 0;
                perm_start <= 1'b1;
                after_perm <= S_ABSORB;
                st         <= S_PERMUTE;
              end
              else begin
                pos <= pos + 1;
              end
            end
          end
        end

        // -------------------------------------------------------------
        S_FINISH: begin
          // pad10*1 with domain separation: domain byte at `pos`, 0x80 at end.
          // (If pos == rate-1 the two XORs combine on the same byte.)
          sb[pos]      <= sb[pos]      ^ dom;
          sb[rate - 1] <= sb[rate - 1] ^ 8'h80;
          ocnt         <= 0;
          perm_start   <= 1'b1;
          after_perm   <= S_SQUEEZE;
          st           <= S_PERMUTE;
        end

        // -------------------------------------------------------------
        S_PERMUTE: begin
          if (perm_done) begin
            for (L = 0; L < 25; L++)
              for (k = 0; k < 8; k++)
                sb[8*L + k] <= perm_out[L % 5][L / 5][8*k +: 8];
            if (after_perm == S_SQUEEZE) optr <= 0;
            st <= after_perm;
          end
        end

        // -------------------------------------------------------------
        S_SQUEEZE: begin
          if (out_ready) begin           // out_valid is high in this state
            if (ocnt == outlen_q - 1) begin
              st <= S_IDLE;              // final output byte consumed
            end
            else begin
              ocnt <= ocnt + 1;
              if (optr == rate - 1) begin // rate block exhausted -> re-permute
                optr       <= 0;
                perm_start <= 1'b1;
                after_perm <= S_SQUEEZE;
                st         <= S_PERMUTE;
              end
              else begin
                optr <= optr + 1;
              end
            end
          end
        end

        default: st <= S_IDLE;
      endcase
    end
  end

endmodule : keccak_sponge
