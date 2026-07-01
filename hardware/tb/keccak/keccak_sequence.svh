// keccak_sequence.svh — stimulus sequences.
//   keccak_kat_sequence  : replays golden vectors from tb/vectors/ files.
//   keccak_rand_sequence : constrained-random messages/modes.

class keccak_kat_sequence extends uvm_sequence #(keccak_seq_item);
  `uvm_object_utils(keccak_kat_sequence)

  string vector_file = "";   // set via config_db / plusarg

  function new(string name = "keccak_kat_sequence");
    super.new(name);
  endfunction

  virtual task body();
    // TODO Phase 3:
    //   - open `vector_file` (produced by tb/vectors/gen_vectors.py)
    //   - for each record: parse mode, msg[], out_len, exp_digest[]
    //   - `uvm_do_with(req) { req.mode == ...; req.msg == ...; }
    //   - attach exp_digest for the scoreboard
    `uvm_info("KAT_SEQ", $sformatf("would replay vectors from %s", vector_file),
              UVM_LOW)
  endtask
endclass : keccak_kat_sequence


class keccak_rand_sequence extends uvm_sequence #(keccak_seq_item);
  `uvm_object_utils(keccak_rand_sequence)

  int unsigned num_txns = 50;

  function new(string name = "keccak_rand_sequence");
    super.new(name);
  endfunction

  virtual task body();
    repeat (num_txns) begin
      keccak_seq_item req = keccak_seq_item::type_id::create("req");
      start_item(req);
      if (!req.randomize())
        `uvm_error("RAND_SEQ", "randomize failed")
      finish_item(req);
    end
  endtask
endclass : keccak_rand_sequence
