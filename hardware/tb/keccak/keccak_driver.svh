// keccak_driver.svh — drives one transaction onto the shake_xof handshake:
// pulse start (with mode/out_len), stream msg bytes with in_valid/in_last,
// then accept squeezed bytes with out_ready into req.act_digest.

class keccak_driver extends uvm_driver #(keccak_seq_item);
  `uvm_component_utils(keccak_driver)

  virtual keccak_if vif;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  virtual function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    if (!uvm_config_db#(virtual keccak_if)::get(this, "", "vif", vif))
      `uvm_fatal("DRV", "no virtual interface set for keccak_driver")
  endfunction

  virtual task run_phase(uvm_phase phase);
    forever begin
      seq_item_port.get_next_item(req);
      drive(req);
      seq_item_port.item_done();
    end
  endtask

  virtual task drive(keccak_seq_item item);
    // TODO Phase 3:
    //   - wait for reset deassert
    //   - drive mode/out_len, pulse start
    //   - foreach msg byte: drive in_data/in_valid, set in_last on final byte,
    //     wait for in_ready handshake
    //   - drive out_ready; collect out_data while out_valid until out_last;
    //     store into item.act_digest
    `uvm_info("DRV", $sformatf("drive mode=%s msg_len=%0d out_len=%0d",
              item.mode.name(), item.msg.size(), item.out_len), UVM_HIGH)
  endtask
endclass : keccak_driver
