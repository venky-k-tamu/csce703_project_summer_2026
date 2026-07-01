// keccak_env.svh — top-level environment: agent + scoreboard.

class keccak_env extends uvm_env;
  `uvm_component_utils(keccak_env)

  keccak_agent      agent;
  keccak_scoreboard sb;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  virtual function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    agent = keccak_agent::type_id::create("agent", this);
    sb    = keccak_scoreboard::type_id::create("sb", this);
  endfunction

  virtual function void connect_phase(uvm_phase phase);
    agent.mon.ap.connect(sb.imp);
  endfunction
endclass : keccak_env
