// tb_smoke.sv — open-source (Icarus) self-checking smoke test for the Keccak
// core. NOT the UVM environment (that needs a commercial sim); this is the
// "open-sim smoke path" from docs/PLAN.md, run in CI-friendly form.
//
// Drives shake_xof through known SHAKE/SHA3 vectors (golden = Python hashlib,
// baked into fixtures by gen_smoke.py) and self-checks each digest.

`timescale 1ns/1ps

module tb_smoke;
  import keccak_pkg::*;

  localparam int MAXB = 512;

  logic         clk = 0;
  logic         rst_n = 0;
  logic         start = 0;
  keccak_mode_e mode = MODE_SHAKE256;
  logic [31:0]  out_len = 0;
  logic         in_valid = 0, in_last = 0, in_ready;
  logic [7:0]   in_data = 0, out_data;
  logic         out_valid, out_last, out_ready = 0, busy;

  // fixture buffers (reused per case, loaded via $readmemh)
  logic [7:0] msg [0:MAXB-1];
  logic [7:0] exp [0:MAXB-1];
  logic [7:0] got [0:MAXB-1];

  int total = 0, failed = 0;

  always #5 clk = ~clk;

  shake_xof dut (
      .clk(clk), .rst_n(rst_n), .start(start), .mode(mode), .out_len(out_len),
      .in_valid(in_valid), .in_data(in_data), .in_last(in_last),
      .in_ready(in_ready),
      .out_valid(out_valid), .out_data(out_data), .out_last(out_last),
      .out_ready(out_ready), .busy(busy)
  );

  // Absorb one message byte (last=0) or the terminator beat (last=1).
  // Ready-gated: in_ready stays high (DUT parks in ABSORB) until we pulse
  // in_valid, so waiting for it at negedge is race-free. Then assert the beat
  // for exactly one posedge to consume it.
  task automatic put_byte(input logic [7:0] b, input logic last);
    @(negedge clk);
    while (!in_ready) @(negedge clk);
    in_valid = 1; in_data = b; in_last = last;
    @(posedge clk);                     // consumed here
    @(negedge clk);
    in_valid = 0; in_last = 0;
  endtask

  // Run one hashing case and self-check the squeezed output.
  task automatic run_case(input int mode_i, input int msglen,
                          input int outlen, input string label);
    int i, errs;
    @(negedge clk);
    mode    = keccak_mode_e'(mode_i);
    out_len = outlen;
    start   = 1;  @(posedge clk);  @(negedge clk);  start = 0;

    // absorb: message bytes, then one terminator beat
    for (i = 0; i < msglen; i++) put_byte(msg[i], 1'b0);
    put_byte(8'h00, 1'b1);

    // squeeze: out_valid parks high until we pulse out_ready, so grab one
    // byte per iteration (sample at negedge, consume on the next posedge).
    for (i = 0; i < outlen; i++) begin
      @(negedge clk);
      while (!out_valid) @(negedge clk);
      got[i]    = out_data;
      out_ready = 1;
      @(posedge clk);
      @(negedge clk);
      out_ready = 0;
    end

    // check
    errs = 0;
    for (i = 0; i < outlen; i++) if (got[i] !== exp[i]) errs++;
    total++;
    if (errs != 0) begin
      failed++;
      $display("  [FAIL] %-42s  %0d/%0d bytes wrong", label, errs, outlen);
      $display("         got[0..7] = %02x %02x %02x %02x %02x %02x %02x %02x",
               got[0], got[1], got[2], got[3], got[4], got[5], got[6], got[7]);
      $display("         exp[0..7] = %02x %02x %02x %02x %02x %02x %02x %02x",
               exp[0], exp[1], exp[2], exp[3], exp[4], exp[5], exp[6], exp[7]);
    end
    else begin
      $display("  [PASS] %-42s  (%0d B)", label, outlen);
    end
  endtask

  initial begin
    // reset
    rst_n = 0;
    repeat (5) @(posedge clk);
    rst_n = 1;
    @(negedge clk);

    $display("=== Keccak core smoke test ===");
    `include "smoke_cases.svh"

    $display("=== %0d/%0d cases passed ===", total - failed, total);
    if (failed != 0) $fatal(1, "SMOKE TEST FAILED");
    $finish;
  end

  // safety timeout
  initial begin
    #20_000_000;
    $fatal(1, "TIMEOUT");
  end
endmodule : tb_smoke
