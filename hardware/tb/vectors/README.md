# tb/vectors — golden vectors for the Keccak core

`gen_vectors.py` emits one `.vec` file per DUT mode
(`shake128.vec`, `shake256.vec`, `sha3_256.vec`, `sha3_512.vec`). The UVM
`keccak_kat_sequence` loads a file and the scoreboard compares each
`(message, out_len) -> expected_digest` record against the DUT.

The reference is Python's `hashlib` (SHA-3/SHAKE), which is the same
primitive the software layers wrap and the NIST KATs exercise transitively
— so agreeing with these files means agreeing with the KATs at the hash
boundary.

Generated files are **not committed** (see `.gitignore`); regenerate with:

```
make vectors        # from hardware/sim/
# or:
python3 gen_vectors.py
```

Record format (one per line, `#` comments ignored):

```
<msg_hex>:<out_len_bytes>:<expected_digest_hex>
```

Message lengths are chosen to straddle the rate-block boundaries (rate =
168/136/72 bytes), and XOF modes include multi-block output lengths to
exercise the squeeze path.
