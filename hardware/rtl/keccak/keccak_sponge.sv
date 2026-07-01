// keccak_sponge.sv — sponge construction around keccak_f1600.
// Absorb (with pad10*1), permute, squeeze. FIPS 202 §4 (Algorithm 8, SPONGE).
//
// Rate and domain byte come from the selected mode. Byte<->lane packing is
// little-endian (FIPS 202 §B.1): the first absorbed byte is bits [7:0] of
// lane A[0][0], etc.

import keccak_pkg::*;

module keccak_sponge (
    input  logic         clk,
    input  logic         rst_n,

    // configuration, latched at `start`
    input  logic         start,
    input  keccak_mode_e mode,
    input  logic [31:0]  out_len,     // requested output bytes (XOF) / fixed len

    // absorb: byte stream in
    input  logic         in_valid,
    input  logic [7:0]   in_data,
    input  logic         in_last,     // marks final message byte
    output logic         in_ready,

    // squeeze: byte stream out
    output logic         out_valid,
    output logic [7:0]   out_data,
    output logic         out_last,    // last output byte for this request
    input  logic         out_ready,

    output logic         busy
);

  // TODO Phase 2:
  //   ABSORB:
  //     - accumulate incoming bytes into the rate region of the state
  //     - when a full rate block (rate_bytes(mode)) is buffered, XOR into
  //       state and run keccak_f1600
  //     - on in_last, apply pad10*1: XOR domain_byte(mode) at the current
  //       offset and 0x80 at the last byte of the rate block, then permute
  //   SQUEEZE:
  //     - stream out the first rate_bytes(mode) of state; if more output is
  //       needed (XOF), permute again and continue
  //     - assert out_last after out_len bytes have been emitted

  // Skeleton stubs so the module elaborates; REPLACE in Phase 2.
  keccak_mode_e mode_q;
  always_ff @(posedge clk or negedge rst_n)
    if (!rst_n) mode_q <= MODE_SHAKE256;
    else if (start) mode_q <= mode;

  assign in_ready  = 1'b0;
  assign out_valid = 1'b0;
  assign out_data  = 8'h00;
  assign out_last  = 1'b0;
  assign busy      = 1'b0;

  wire _unused = &{1'b0, in_valid, in_data, in_last, out_ready,
                   out_len, mode_q};

endmodule : keccak_sponge
