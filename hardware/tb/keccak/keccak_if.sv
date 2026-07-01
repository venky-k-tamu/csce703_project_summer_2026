// keccak_if.sv — DUT interface + clocking blocks for the UVM environment.
// Mirrors the shake_xof port list.

interface keccak_if (input logic clk, input logic rst_n);
  import keccak_pkg::*;

  logic         start;
  keccak_mode_e mode;
  logic [31:0]  out_len;

  logic         in_valid;
  logic [7:0]   in_data;
  logic         in_last;
  logic         in_ready;

  logic         out_valid;
  logic [7:0]   out_data;
  logic         out_last;
  logic         out_ready;

  logic         busy;

  // Driver drives stimulus; samples ready/handshake.
  clocking drv_cb @(posedge clk);
    default input #1step output #1;
    output start, mode, out_len, in_valid, in_data, in_last, out_ready;
    input  in_ready, out_valid, out_data, out_last, busy;
  endclocking

  // Monitor is passive.
  clocking mon_cb @(posedge clk);
    default input #1step;
    input start, mode, out_len, in_valid, in_data, in_last, in_ready,
          out_valid, out_data, out_last, out_ready, busy;
  endclocking

  modport DRV (clocking drv_cb, input clk, input rst_n);
  modport MON (clocking mon_cb, input clk, input rst_n);
endinterface : keccak_if
