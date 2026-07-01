// keccak_test.svh — base test plus one KAT test per mode.
// Select at runtime with +UVM_TESTNAME=<name>.

class keccak_base_test extends uvm_test;
  `uvm_component_utils(keccak_base_test)

  keccak_env env;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  virtual function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    env = keccak_env::type_id::create("env", this);
  endfunction
endclass : keccak_base_test


// Runs the golden-vector sequence for a given mode's vector file.
class keccak_kat_test extends keccak_base_test;
  `uvm_component_utils(keccak_kat_test)

  string vector_file = "vectors/shake256.vec";   // override per-test/plusarg

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  virtual task run_phase(uvm_phase phase);
    keccak_kat_sequence seq = keccak_kat_sequence::type_id::create("seq");
    seq.vector_file = vector_file;
    phase.raise_objection(this);
    seq.start(env.agent.sqr);
    phase.drop_objection(this);
  endtask
endclass : keccak_kat_test


// Constrained-random smoke test across all modes.
class keccak_rand_test extends keccak_base_test;
  `uvm_component_utils(keccak_rand_test)

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  virtual task run_phase(uvm_phase phase);
    keccak_rand_sequence seq = keccak_rand_sequence::type_id::create("seq");
    phase.raise_objection(this);
    seq.start(env.agent.sqr);
    phase.drop_objection(this);
  endtask
endclass : keccak_rand_test
