// keccak_seq_item.svh — one hashing transaction: (mode, message) -> digest.
// The expected digest is filled in from a golden vector (KAT) or left null
// for random stimulus that the scoreboard checks against a reference.

class keccak_seq_item extends uvm_sequence_item;

  rand keccak_pkg::keccak_mode_e mode;
  rand byte unsigned             msg[];       // message bytes
  rand int unsigned              out_len;     // requested output length (XOF)

  // Populated by the sequence (from golden vectors) / scoreboard.
       byte unsigned             exp_digest[];
       byte unsigned             act_digest[];

  constraint c_out_len {
    out_len inside {[1:1088]};
    // SHA3 modes have a fixed output length.
    (mode == keccak_pkg::MODE_SHA3_256) -> out_len == 32;
    (mode == keccak_pkg::MODE_SHA3_512) -> out_len == 64;
  }
  constraint c_msg_len { msg.size() inside {[0:512]}; }

  `uvm_object_utils_begin(keccak_seq_item)
    `uvm_field_enum(keccak_pkg::keccak_mode_e, mode, UVM_ALL_ON)
    `uvm_field_int(out_len, UVM_ALL_ON)
    `uvm_field_array_int(msg, UVM_ALL_ON)
    `uvm_field_array_int(exp_digest, UVM_ALL_ON)
    `uvm_field_array_int(act_digest, UVM_ALL_ON)
  `uvm_object_utils_end

  function new(string name = "keccak_seq_item");
    super.new(name);
  endfunction

endclass : keccak_seq_item
