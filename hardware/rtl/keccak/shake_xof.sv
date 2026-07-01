// shake_xof.sv — top-level mode-select wrapper over keccak_sponge.
// Presents one interface for SHAKE128, SHAKE256, SHA3-256, SHA3-512.
// FIPS 202 §6.1 (SHA3-256/512) and §6.2 (SHAKE128/256).
//
// This is the block the PQC datapaths (ML-KEM/ML-DSA/SLH-DSA) will
// instantiate. It is the DUT the UVM environment drives.

import keccak_pkg::*;

module shake_xof (
    input  logic         clk,
    input  logic         rst_n,

    input  logic         start,
    input  keccak_mode_e mode,
    input  logic [31:0]  out_len,    // ignored for SHA3 (fixed 32/64)

    input  logic         in_valid,
    input  logic [7:0]   in_data,
    input  logic         in_last,
    output logic         in_ready,

    output logic         out_valid,
    output logic [7:0]   out_data,
    output logic         out_last,
    input  logic         out_ready,

    output logic         busy
);

  // For SHA3 modes, force the fixed output length regardless of out_len.
  logic [31:0] eff_out_len;
  always_comb begin
    unique case (mode)
      MODE_SHA3_256: eff_out_len = 32;
      MODE_SHA3_512: eff_out_len = 64;
      default:       eff_out_len = out_len;   // SHAKE: caller-specified
    endcase
  end

  keccak_sponge u_sponge (
      .clk       (clk),
      .rst_n     (rst_n),
      .start     (start),
      .mode      (mode),
      .out_len   (eff_out_len),
      .in_valid  (in_valid),
      .in_data   (in_data),
      .in_last   (in_last),
      .in_ready  (in_ready),
      .out_valid (out_valid),
      .out_data  (out_data),
      .out_last  (out_last),
      .out_ready (out_ready),
      .busy      (busy)
  );

endmodule : shake_xof
