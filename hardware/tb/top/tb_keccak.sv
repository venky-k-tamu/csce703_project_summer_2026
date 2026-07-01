// tb_keccak.sv — top-level testbench: clock/reset, DUT, interface, run_test().

`timescale 1ns/1ps

module tb_keccak;
  import uvm_pkg::*;
  import keccak_uvm_pkg::*;
  `include "uvm_macros.svh"

  logic clk;
  logic rst_n;

  // 100 MHz clock.
  initial clk = 1'b0;
  always #5 clk = ~clk;

  // Reset.
  initial begin
    rst_n = 1'b0;
    repeat (5) @(posedge clk);
    rst_n = 1'b1;
  end

  // Interface + DUT.
  keccak_if vif (.clk(clk), .rst_n(rst_n));

  shake_xof dut (
      .clk       (clk),
      .rst_n     (rst_n),
      .start     (vif.start),
      .mode      (vif.mode),
      .out_len   (vif.out_len),
      .in_valid  (vif.in_valid),
      .in_data   (vif.in_data),
      .in_last   (vif.in_last),
      .in_ready  (vif.in_ready),
      .out_valid (vif.out_valid),
      .out_data  (vif.out_data),
      .out_last  (vif.out_last),
      .out_ready (vif.out_ready),
      .busy      (vif.busy)
  );

  initial begin
    uvm_config_db#(virtual keccak_if)::set(null, "*", "vif", vif);
    run_test();   // test chosen via +UVM_TESTNAME
  end
endmodule : tb_keccak
