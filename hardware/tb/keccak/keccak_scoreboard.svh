// keccak_scoreboard.svh — compares the DUT digest against the expected value.
//
// For KAT sequences, exp_digest comes straight from the golden vector file.
// For random sequences, exp_digest is computed by a DPI/reference call (a
// C model of Keccak, or a pre-generated table) — see docs/PLAN.md open item.

class keccak_scoreboard extends uvm_scoreboard;
  `uvm_component_utils(keccak_scoreboard)

  uvm_analysis_imp #(keccak_seq_item, keccak_scoreboard) imp;

  int unsigned num_checked;
  int unsigned num_failed;

  function new(string name, uvm_component parent);
    super.new(name, parent);
    imp = new("imp", this);
  endfunction

  virtual function void write(keccak_seq_item item);
    num_checked++;
    if (item.exp_digest.size() == 0) begin
      `uvm_warning("SB", "no expected digest attached; skipping compare")
      return;
    end
    if (item.act_digest != item.exp_digest) begin
      num_failed++;
      `uvm_error("SB", $sformatf("MISMATCH mode=%s msg_len=%0d",
                 item.mode.name(), item.msg.size()))
    end
    else begin
      `uvm_info("SB", $sformatf("MATCH mode=%s msg_len=%0d",
                item.mode.name(), item.msg.size()), UVM_HIGH)
    end
  endfunction

  virtual function void report_phase(uvm_phase phase);
    if (num_failed == 0 && num_checked > 0)
      `uvm_info("SB", $sformatf("PASS: %0d/%0d transactions matched",
                num_checked, num_checked), UVM_LOW)
    else
      `uvm_error("SB", $sformatf("FAIL: %0d/%0d transactions mismatched",
                 num_failed, num_checked))
  endfunction
endclass : keccak_scoreboard
