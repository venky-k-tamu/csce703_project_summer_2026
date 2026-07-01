// RTL compile order for the Keccak core. Paths relative to hardware/sim/.
// Package first, then bottom-up module stack.
../rtl/keccak/keccak_pkg.sv
../rtl/keccak/keccak_round.sv
../rtl/keccak/keccak_f1600.sv
../rtl/keccak/keccak_sponge.sv
../rtl/keccak/shake_xof.sv
