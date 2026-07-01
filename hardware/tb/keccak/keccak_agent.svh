// keccak_agent.svh — sequencer + driver + monitor.

typedef uvm_sequencer #(keccak_seq_item) keccak_sequencer;

class keccak_agent extends uvm_agent;
  `uvm_component_utils(keccak_agent)

  keccak_sequencer sqr;
  keccak_driver    drv;
  keccak_monitor   mon;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  virtual function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    mon = keccak_monitor::type_id::create("mon", this);
    if (get_is_active() == UVM_ACTIVE) begin
      sqr = keccak_sequencer::type_id::create("sqr", this);
      drv = keccak_driver::type_id::create("drv", this);
    end
  endfunction

  virtual function void connect_phase(uvm_phase phase);
    if (get_is_active() == UVM_ACTIVE)
      drv.seq_item_port.connect(sqr.seq_item_export);
  endfunction
endclass : keccak_agent
