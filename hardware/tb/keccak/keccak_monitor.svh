// keccak_monitor.svh — passively reconstructs completed transactions from the
// bus and publishes them to the scoreboard via analysis_port.

class keccak_monitor extends uvm_monitor;
  `uvm_component_utils(keccak_monitor)

  virtual keccak_if                    vif;
  uvm_analysis_port #(keccak_seq_item) ap;

  function new(string name, uvm_component parent);
    super.new(name, parent);
    ap = new("ap", this);
  endfunction

  virtual function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    if (!uvm_config_db#(virtual keccak_if)::get(this, "", "vif", vif))
      `uvm_fatal("MON", "no virtual interface set for keccak_monitor")
  endfunction

  virtual task run_phase(uvm_phase phase);
    // TODO Phase 3:
    //   - on start, capture mode/out_len
    //   - collect absorbed bytes on in_valid&&in_ready into msg[]
    //   - collect squeezed bytes on out_valid&&out_ready into act_digest[]
    //   - on out_last, build a keccak_seq_item and ap.write(item)
    forever @(vif.mon_cb);
  endtask
endclass : keccak_monitor
